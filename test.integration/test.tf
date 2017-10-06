variable "profile" {
  description = "Use a specific profile from your credential file"
}

variable "region" {
  default = "us-west-2"
}

provider "aws" {
  version = ">= 0.1.4"

  region = "${var.region}"
  profile = "${var.profile}"
}

terraform {
  required_version = ">= 0.10.0"
}

resource "aws_vpc" "foo" {
  cidr_block = "10.0.0.0/16"

  tags {
    Name = "foo"
  }
}

resource "aws_subnet" "foo" {
  vpc_id = "${aws_vpc.foo.id}"
  cidr_block = "${cidrsubnet(aws_vpc.foo.cidr_block, 8, count.index + 10)}"
  availability_zone = "${var.region}a"

  tags {
    Name = "foo"
  }
}

resource "aws_internet_gateway" "foo" {
  vpc_id = "${aws_vpc.foo.id}"

  tags {
    Name = "foo"
  }
}

resource "aws_security_group" "foo" {
  name = "foo"
  description = "Allow traffic on port 80"
  vpc_id = "${aws_vpc.foo.id}"

  ingress {
    from_port = 80
    to_port = 80
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags {
    Name = "foo"
  }
}

resource "aws_elb" "foo" {
  name = "foo"
  subnets = [ "${aws_subnet.foo.id}" ]
  security_groups = [ "${aws_security_group.foo.id}" ]

  listener {
    instance_port = 80
    instance_protocol = "tcp"
    lb_port = 80
    lb_protocol = "tcp"
  }

  # It seems tags don't exist for ELBs
  tags {
    Name = "foo"
  }
}

resource "aws_instance" "foo" {
  ami = "${data.aws_ami.foo.id}"
  instance_type = "t2.micro"
  security_groups = ["${aws_security_group.foo.id}"]
  subnet_id = "${aws_subnet.foo.id}"

  tags {
    Name = "foo"
  }
}

resource "aws_launch_configuration" "foo" {
  name_prefix = "foo-"
  image_id = "${data.aws_ami.foo.id}"
  instance_type = "t2.micro"
  associate_public_ip_address = true

  security_groups = [
    "${aws_security_group.foo.id}"
  ]

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_autoscaling_group" "foo" {
  name_prefix = "foo-"
  max_size = "1"
  min_size = "1"

  launch_configuration = "${aws_launch_configuration.foo.id}"
  vpc_zone_identifier = ["${aws_subnet.foo.id}"]

  load_balancers = ["${aws_elb.foo.id}"]

  tag {
    key = "Name"
    value = "foo"
    propagate_at_launch = false
  }
}

data "aws_ami" "foo" {
  most_recent = true
  owners = ["099720109477"]

  filter {
    name = "name"
    values = ["*ubuntu-trusty-14.04-amd64-server-*"]
  }

  filter {
    name = "state"
    values = ["available"]
  }

  filter {
    name = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name = "is-public"
    values = ["true"]
  }
}
