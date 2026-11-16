locals {
  tags = {
    Project   = var.name
    ManagedBy = "terraform"
  }

  argocd_dir = "${path.module}/../../argocd"

  user_data = templatefile("${path.module}/cloud-init.yaml.tftpl", {
    k3s_version    = var.k3s_version
    appproject_b64 = base64encode(file("${local.argocd_dir}/appproject.yaml"))
    root_app_b64   = base64encode(file("${local.argocd_dir}/root-app.yaml"))
    bootstrap_b64  = base64encode(file("${local.argocd_dir}/bootstrap.sh"))
  })
}

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd*/ubuntu-noble-24.04-${var.cpu_architecture}-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Must stay clear of the k3s pod range 10.42.0.0/16 and service range 10.43.0.0/16.
resource "aws_vpc" "this" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = var.name }
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id

  tags = { Name = var.name }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.this.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true

  tags = { Name = "${var.name}-public" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }

  tags = { Name = "${var.name}-public" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

resource "aws_security_group" "this" {
  name        = "${var.name}-sg"
  description = "zedr control server: 443 public, 22 and 6443 admin only"
  vpc_id      = aws_vpc.this.id

  ingress {
    description = "HTTPS for agents and operators, TLS ends in the control server"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "SSH, admin only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.admin_cidr
  }

  ingress {
    description = "Kubernetes API, admin only"
    from_port   = 6443
    to_port     = 6443
    protocol    = "tcp"
    cidr_blocks = var.admin_cidr
  }

  egress {
    description = "Image, chart and package pulls"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = var.name }
}

resource "aws_key_pair" "this" {
  key_name   = "${var.name}-admin"
  public_key = var.ssh_public_key
}

resource "aws_instance" "this" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.this.id]
  key_name               = aws_key_pair.this.key_name
  user_data              = local.user_data

  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = var.root_volume_gb
    encrypted             = true
    delete_on_termination = true

    tags = merge(local.tags, { Name = var.name })
  }

  tags = { Name = var.name }

  # cloud-init runs on the first boot only, so a newer AMI or changed user data must not restart a running box.
  lifecycle {
    ignore_changes = [ami, user_data]
  }
}

resource "aws_eip" "this" {
  domain   = "vpc"
  instance = aws_instance.this.id

  tags = { Name = var.name }

  depends_on = [aws_internet_gateway.this]
}
