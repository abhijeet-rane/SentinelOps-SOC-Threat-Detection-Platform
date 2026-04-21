# =============================================================================
# SentinelOps — AWS infrastructure (root module)
#
# Stands up the minimum free-tier footprint to run the whole stack on one box:
#   - Custom VPC (10.0.0.0/16) with a single public subnet in one AZ
#   - Internet Gateway + public route table
#   - Security group: 22 (SSH from allow_ssh_cidr), 80, 443 from the internet
#   - EC2 t3.micro (Ubuntu 22.04 LTS) with an attached 20 GB gp3 root volume
#   - Elastic IP so the box's public IP survives stop/start
#   - user_data bootstraps Docker + Compose, clones the repo, prints next steps
#
# Cost: t3.micro + 20 GB gp3 + 1 EIP (attached) fits inside AWS Free Tier
#       (first 12 months). EBS gp3 beyond 30 GB = $0.08/GB/mo.
# =============================================================================

terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.60"
    }
  }

  # ─── Remote state (optional; leave commented for local tfstate) ─────────
  # Uncomment and create the bucket first if you want state in S3:
  # backend "s3" {
  #   bucket         = "sentinelops-tfstate-<your-account-id>"
  #   key            = "prod/terraform.tfstate"
  #   region         = "us-east-1"
  #   encrypt        = true
  #   dynamodb_table = "sentinelops-tflock"
  # }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project     = "SentinelOps"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

# ─── Latest Ubuntu 22.04 LTS AMI (Canonical, us-east-1) ──────────────────────
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# ─── Read the first AZ in the chosen region ──────────────────────────────────
data "aws_availability_zones" "available" {
  state = "available"
}
