variable "region" {
  description = "AWS region. Keep us-east-1 for cheapest Free Tier coverage."
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Free-form environment tag (prod, staging, demo)."
  type        = string
  default     = "prod"
}

variable "project_name" {
  description = "Prefix applied to every resource Name tag."
  type        = string
  default     = "sentinelops"
}

variable "instance_type" {
  description = "EC2 instance type. t3.micro is Free Tier eligible in us-east-1."
  type        = string
  default     = "t3.micro"
}

variable "root_volume_size_gb" {
  description = "Root EBS size (gp3). Free Tier gives 30 GB total; 20 leaves headroom."
  type        = number
  default     = 20
}

variable "ssh_key_name" {
  description = <<EOT
    Name of an existing EC2 key pair in the target region. Create one with:
      aws ec2 create-key-pair --key-name sentinelops-demo --region us-east-1 \
          --query 'KeyMaterial' --output text > ~/.ssh/sentinelops-demo.pem
      chmod 400 ~/.ssh/sentinelops-demo.pem
  EOT
  type        = string
}

variable "allow_ssh_cidr" {
  description = <<EOT
    CIDR allowed to SSH to port 22. Set this to YOUR_PUBLIC_IP/32 — NEVER 0.0.0.0/0.
    Find your IP with: curl -s https://checkip.amazonaws.com
  EOT
  type        = string
}

variable "domain_name" {
  description = "Public hostname (Caddy will get a Let's Encrypt cert for it). Leave blank to skip DNS hints in outputs."
  type        = string
  default     = ""
}

variable "repo_url" {
  description = "HTTPS clone URL for the SentinelOps repo. user_data clones this into /opt/sentinelops."
  type        = string
  default     = "https://github.com/YOUR-USERNAME/SOC_Project.git"
}

variable "repo_branch" {
  description = "Git branch/ref the EC2 box should check out."
  type        = string
  default     = "main"
}
