package resource

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/apex/log"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/fatih/color"
	awsls "github.com/jckuester/awsls/aws"
	awslsRes "github.com/jckuester/awsls/resource"
	"github.com/jckuester/awstools-lib/aws"
	"github.com/jckuester/awstools-lib/terraform"
	"github.com/jckuester/terradozer/pkg/provider"
	terradozerRes "github.com/jckuester/terradozer/pkg/resource"
	"github.com/zclconf/go-cty/cty"
	"gopkg.in/yaml.v2"
	"os"
	"sort"
	"strings"
	"sync"
)

type destroyableResources struct {
	resourceType string
	resources    []destroyableResourceInfo
}

type destroyableResourceInfo struct {
	identity    terraform.Resource
	destroyable terradozerRes.DestroyableResource
}

func List(ctx context.Context, parallel int, filter *Filter, clients map[aws.ClientKey]aws.Client,
	providers map[aws.ClientKey]provider.TerraformProvider, outputType string) []terradozerRes.DestroyableResource {

	initializedClients := make(map[aws.ClientKey]aws.Client, len(clients))
	for key, client := range clients {
		err := client.SetAccountID(ctx)
		if err != nil {
			log.WithError(err).Fatal("failed to set account ID")
			continue
		}
		initializedClients[key] = client
	}

	destroyableRes := map[string][]terradozerRes.DestroyableResource{}
	typeChan := make(chan string)
	updatableResChan := make(chan updateRequestRequest)
	destroyableResChan := make(chan destroyableResources)

	var rg sync.WaitGroup
	rg.Add(parallel)
	for i := 0; i < parallel; i++ {
		go updateResources(ctx, &rg, providers, updatableResChan)
	}

	var pg sync.WaitGroup
	pg.Add(parallel)
	for i := 0; i < parallel; i++ {
		go discover(ctx, &pg, filter, initializedClients, providers, typeChan, updatableResChan, destroyableResChan)
	}

	var cg sync.WaitGroup
	cg.Add(1)
	go func(oType string, input <-chan destroyableResources) {
		for {
			select {
			case <-ctx.Done():
				cg.Done()
				return
			case d, more := <-input:
				if !more {
					cg.Done()
					return
				}
				print(d.resources, oType)
				if len(d.resources) > 0 {
					resources := make([]terradozerRes.DestroyableResource, len(d.resources))
					for i, r := range d.resources {
						resources[i] = r.destroyable
					}
					destroyableRes[d.resourceType] = resources
				}
			}
		}
	}(outputType, destroyableResChan)

	for _, rType := range filter.Types() {
		select {
		case <-ctx.Done():
			return nil
		default:
			typeChan <- rType
		}
	}

	close(typeChan)
	pg.Wait()
	close(updatableResChan)
	rg.Wait()
	close(destroyableResChan)
	cg.Wait()

	var resources []terradozerRes.DestroyableResource
	for _, rType := range filter.Types() {
		if r, ok := destroyableRes[rType]; ok {
			for _, v := range r {
				resources = append(resources, v)
			}
		}
	}

	return resources
}

func discover(ctx context.Context, wg *sync.WaitGroup, filter *Filter,
	clients map[aws.ClientKey]aws.Client, providers map[aws.ClientKey]provider.TerraformProvider,
	input <-chan string, update chan<- updateRequestRequest, output chan<- destroyableResources) {
	for {
		select {
		case <-ctx.Done():
			wg.Done()
			return
		case rType, more := <-input:
			if !more {
				wg.Done()
				return
			}
			for key, client := range clients {
				resources, err := awsls.ListResourcesByType(ctx, &client, rType)
				if err != nil {
					log.WithError(err).Fatal("failed to list awsls supported resources")
					continue
				}

				filteredRes := filter.Apply(resources)

				if len(filteredRes) > 0 {
					var ug sync.WaitGroup
					ug.Add(len(filteredRes))

					updatableResources := make([]*updatableResource, len(filteredRes))
					for i := 0; i < len(filteredRes); i++ {
						updatableResources[i] = &updatableResource{r: &filteredRes[i]}
					}
					for _, r := range updatableResources {
						update <- updateRequestRequest{r, &ug}
					}

					if !waitWithCancel(ctx, &ug) {
						return
					}

					var updatedResources []terraform.Resource
					for _, r := range updatableResources {
						if isError(rType, r) {
							fmt.Fprint(os.Stderr, color.RedString("Error %s: %v\n", rType, r.error))
						} else if r.r != nil {
							updatedResources = append(updatedResources, *r.r)
						}
					}

					filteredRes = updatedResources
				}

				// Secondary filtering of resources which have just had the needed data loaded
				filteredRes = filter.Apply(filteredRes)

				p := providers[key]

				output <- toDestroyableResources(rType, filteredRes, &p)

				switch rType {
				case "aws_iam_user":
					aupType, attachedPolicies := getAttachedUserPolicies(ctx, filteredRes, client, &p)
					output <- toDestroyableResources(aupType, attachedPolicies, &p)

					iupType, inlinePolicies := getInlineUserPolicies(ctx, filteredRes, client, &p)
					output <- toDestroyableResources(iupType, inlinePolicies, &p)
				case "aws_iam_policy":
					paType, policyAttachments := getPolicyAttachments(filteredRes, &p)
					output <- toDestroyableResources(paType, policyAttachments, &p)
				case "aws_efs_file_system":
					emtType, mountTargets := getEfsMountTargets(ctx, filteredRes, client, &p)
					output <- toDestroyableResources(emtType, mountTargets, &p)
				}
			}
		}
	}
}

func isError(rType string, resource *updatableResource) bool {
	if resource.error == nil {
		return false
	}
	//if rType == "aws_launch_configuration" && strings.Contains(resource.error.Error(), "InvalidAMIID.NotFound") {
	//	return false
	//}
	return true
}

func waitWithCancel(ctx context.Context, wg *sync.WaitGroup) bool {
	c := make(chan struct{})
	go func() {
		defer close(c)
		wg.Wait()
	}()
	select {
	case <-c:
		return true
	case <-ctx.Done():
		return false
	}
}

type updateRequestRequest struct {
	u  *updatableResource
	wg *sync.WaitGroup
}

type updatableResource struct {
	r     *terraform.Resource
	error error
}

func updateResources(ctx context.Context, wg *sync.WaitGroup, providers map[aws.ClientKey]provider.TerraformProvider, input <-chan updateRequestRequest) {
	for {
		select {
		case <-ctx.Done():
			wg.Done()
			return
		case r, more := <-input:
			if !more {
				wg.Done()
				return
			}

			key := aws.ClientKey{
				Profile: r.u.r.Profile,
				Region:  r.u.r.Region,
			}

			p, more := providers[key]

			if !more {
				panic(fmt.Sprintf("could not find Terraform AWS Provider for key: %v", key))
			}

			r.u.r.UpdatableResource = terradozerRes.New(r.u.r.Type, r.u.r.ID, nil, &p)

			log.WithFields(log.Fields{
				"type":    r.u.r.Type,
				"id":      r.u.r.ID,
				"region":  r.u.r.Region,
				"profile": r.u.r.Profile,
			}).Debugf("start updating Terraform state of resource")

			err := r.u.r.UpdateState()
			if err != nil {
				r.u.error = err
				r.wg.Done()
				continue
			}

			log.WithFields(log.Fields{
				"type":    r.u.r.Type,
				"id":      r.u.r.ID,
				"region":  r.u.r.Region,
				"profile": r.u.r.Profile,
			}).Debugf("updated Terraform state of resource")

			// filter out resources that no longer exist
			// (e.g., ECS clusters in state INACTIVE)
			if r.u.r.State() == nil || r.u.r.State().IsNull() {
				r.u.r = nil
				r.wg.Done()
				continue
			}

			r.wg.Done()
		}
	}
}

func toDestroyableResources(resourceType string, resources []terraform.Resource, provider *provider.TerraformProvider) destroyableResources {
	resourcesWithState := make([]destroyableResourceInfo, len(resources))
	for i, resource := range resources {
		resourcesWithState[i] = destroyableResourceInfo{
			resource,
			terradozerRes.NewWithState(resource.Type, resource.ID, provider, resource.State()),
		}
	}
	return destroyableResources{
		resourceType,
		resourcesWithState,
	}
}

func getAttachedUserPolicies(ctx context.Context, users []terraform.Resource, client aws.Client,
	provider *provider.TerraformProvider) (string, []terraform.Resource) {
	const rType = "aws_iam_user_policy_attachment"
	var result []terraform.Resource

	for _, user := range users {
		pg := iam.NewListAttachedUserPoliciesPaginator(client.Iamconn, &iam.ListAttachedUserPoliciesInput{
			UserName: &user.ID,
		})

		for pg.HasMorePages() {
			page, err := pg.NextPage(ctx)
			if err != nil {
				fmt.Fprint(os.Stderr, color.RedString("Error: %s\n", err))
				continue
			}

			for _, attachedPolicy := range page.AttachedPolicies {
				r := terraform.Resource{
					Type: rType,
					ID:   *attachedPolicy.PolicyArn,
				}

				r.UpdatableResource = terradozerRes.New(r.Type, r.ID, map[string]cty.Value{
					"user":       cty.StringVal(user.ID),
					"policy_arn": cty.StringVal(*attachedPolicy.PolicyArn),
				}, provider)

				err := r.UpdateState()
				if err != nil {
					fmt.Fprint(os.Stderr, color.RedString("Error: %s\n", err))
					continue
				}

				result = append(result, r)
			}
		}
	}

	return rType, result
}

func getInlineUserPolicies(ctx context.Context, users []terraform.Resource, client aws.Client,
	provider *provider.TerraformProvider) (string, []terraform.Resource) {
	const rType = "aws_iam_user_policy"
	var result []terraform.Resource

	for _, user := range users {
		pg := iam.NewListUserPoliciesPaginator(client.Iamconn, &iam.ListUserPoliciesInput{
			UserName: &user.ID,
		})

		for pg.HasMorePages() {
			page, err := pg.NextPage(ctx)
			if err != nil {
				fmt.Fprint(os.Stderr, color.RedString("Error: %s\n", err))
				continue
			}

			for _, inlinePolicy := range page.PolicyNames {
				r := terraform.Resource{
					Type: rType,
					ID:   user.ID + ":" + inlinePolicy,
				}

				r.UpdatableResource = terradozerRes.New(r.Type, r.ID, nil, provider)

				err := r.UpdateState()
				if err != nil {
					fmt.Fprint(os.Stderr, color.RedString("Error: %s\n", err))
					continue
				}

				result = append(result, r)
			}
		}
	}

	return rType, result
}

func getPolicyAttachments(policies []terraform.Resource, provider *provider.TerraformProvider) (string, []terraform.Resource) {
	const rType = "aws_iam_policy_attachment"
	var result []terraform.Resource

	for _, policy := range policies {
		arn, err := awslsRes.GetAttribute("arn", &policy)
		if err != nil {
			fmt.Fprint(os.Stderr, color.RedString("Error: %s\n", err))
			continue
		}

		r := terraform.Resource{
			Type: rType,
			// Note: ID is only set for pretty printing (could be also left empty)
			ID: policy.ID,
		}

		r.UpdatableResource = terradozerRes.New(r.Type, r.ID, map[string]cty.Value{
			"policy_arn": cty.StringVal(arn),
		}, provider)

		err = r.UpdateState()
		if err != nil {
			fmt.Fprint(os.Stderr, color.RedString("Error: %v\n", err))
			continue
		}

		result = append(result, r)
	}

	return rType, result
}

func getEfsMountTargets(ctx context.Context, efsFileSystems []terraform.Resource, client aws.Client,
	provider *provider.TerraformProvider) (string, []terraform.Resource) {
	const rType = "aws_efs_mount_target"
	var result []terraform.Resource

	for _, fs := range efsFileSystems {
		// TODO result is paginated, but there is no paginator API function
		req, err := client.Efsconn.DescribeMountTargets(ctx, &efs.DescribeMountTargetsInput{
			FileSystemId: &fs.ID,
		})

		if err != nil {
			fmt.Fprint(os.Stderr, color.RedString("Error: %v\n", err))
			continue
		}

		for _, mountTarget := range req.MountTargets {
			r := terraform.Resource{
				Type: "aws_efs_mount_target",
				ID:   *mountTarget.MountTargetId,
			}

			r.UpdatableResource = terradozerRes.New(r.Type, r.ID, nil, provider)

			err = r.UpdateState()
			if err != nil {
				fmt.Fprint(os.Stderr, color.RedString("Error: %s\n", err))
				continue
			}

			result = append(result, r)
		}
	}

	return rType, result
}

func print(res []destroyableResourceInfo, outputType string) {
	if len(res) == 0 {
		return
	}

	resources := make([]terraform.Resource, len(res))
	for i, r := range res {
		resources[i] = r.identity
	}

	switch strings.ToLower(outputType) {
	case "string":
		printString(resources)
	case "json":
		printJson(resources)
	case "yaml":
		printYaml(resources)
	default:
		log.WithField("output", outputType).Fatal("Unsupported output type")
	}
}

func printString(res []terraform.Resource) {
	fmt.Printf("\n\t---\n\tType: %s\n\tFound: %d\n\n", res[0].Type, len(res))

	for _, r := range res {
		printStat := fmt.Sprintf("\t\tId:\t\t%s", r.ID)
		if r.Tags != nil {
			if len(r.Tags) > 0 {
				var keys []string
				for k := range r.Tags {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				printStat += "\n\t\tTags:\t\t"
				for _, k := range keys {
					printStat += fmt.Sprintf("[%s: %v] ", k, r.Tags[k])
				}
			}
		}
		printStat += "\n"
		if r.CreatedAt != nil {
			printStat += fmt.Sprintf("\t\tCreated:\t%s", r.CreatedAt)
			printStat += "\n"
		}
		fmt.Println(printStat)
	}
	fmt.Print("\t---\n\n")
}

func printJson(res []terraform.Resource) {
	b, err := json.Marshal(res)
	if err != nil {
		log.WithError(err).Fatal("failed to marshal resources into JSON")
	}

	fmt.Print(string(b))
}

func printYaml(res []terraform.Resource) {
	b, err := yaml.Marshal(res)
	if err != nil {
		log.WithError(err).Fatal("failed to marshal resources into YAML")
	}

	fmt.Print(string(b))
}
