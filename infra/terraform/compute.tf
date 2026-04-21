# =============================================================================
# Compute: single EC2 + Elastic IP
# =============================================================================

resource "aws_instance" "app" {
  ami                         = data.aws_ami.ubuntu.id
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.app.id]
  key_name                    = var.ssh_key_name
  associate_public_ip_address = true

  # IMDSv2 required — closes the SSRF-to-creds vector.
  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = var.root_volume_size_gb
    encrypted             = true
    delete_on_termination = true
    tags = {
      Name = "${var.project_name}-root"
    }
  }

  user_data = templatefile("${path.module}/user_data.sh", {
    repo_url    = var.repo_url
    repo_branch = var.repo_branch
  })

  # Hard-replace if user_data changes — simplest way to re-run bootstrap.
  user_data_replace_on_change = true

  tags = {
    Name = "${var.project_name}-${var.environment}"
  }
}

resource "aws_eip" "app" {
  domain   = "vpc"
  instance = aws_instance.app.id

  tags = {
    Name = "${var.project_name}-eip"
  }

  depends_on = [aws_internet_gateway.main]
}
