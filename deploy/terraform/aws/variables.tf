variable "region" {
  description = "AWS region to deploy into."
  type        = string
}

variable "name" {
  description = "Name prefix and tag for every resource."
  type        = string
  default     = "zedr"
}

variable "instance_type" {
  description = "EC2 instance type. Its architecture must match cpu_architecture."
  type        = string
  default     = "t4g.small"
}

variable "cpu_architecture" {
  description = "Architecture used to pick the Ubuntu AMI: arm64 or amd64."
  type        = string
  default     = "arm64"

  validation {
    condition     = contains(["arm64", "amd64"], var.cpu_architecture)
    error_message = "cpu_architecture must be arm64 or amd64."
  }
}

variable "root_volume_gb" {
  description = "Size of the encrypted gp3 root volume in GB. It holds the OS, the container images and the database."
  type        = number
  default     = 30

  validation {
    condition     = var.root_volume_gb >= 20
    error_message = "root_volume_gb must be at least 20."
  }
}

variable "admin_cidr" {
  description = "IPv4 CIDRs allowed to reach SSH (22) and the Kubernetes API (6443)."
  type        = list(string)

  validation {
    condition     = length(var.admin_cidr) > 0 && alltrue([for cidr in var.admin_cidr : can(cidrnetmask(cidr)) && !endswith(cidr, "/0")])
    error_message = "admin_cidr must hold at least one valid IPv4 CIDR and no /0 range."
  }
}

variable "ssh_public_key" {
  description = "SSH public key installed for the ubuntu user."
  type        = string
}

variable "k3s_version" {
  description = "k3s release installed by cloud-init. Keep it within the Kubernetes versions the pinned ArgoCD supports."
  type        = string
  default     = "v1.35.10+k3s1"
}
