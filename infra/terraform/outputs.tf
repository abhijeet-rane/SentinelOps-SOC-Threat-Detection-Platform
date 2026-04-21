output "public_ip" {
  description = "Elastic IP attached to the EC2 instance. Point your DNS A-record at this."
  value       = aws_eip.app.public_ip
}

output "public_dns" {
  description = "AWS-assigned public DNS (not stable across stop/start — use public_ip for DNS)."
  value       = aws_instance.app.public_dns
}

output "ssh_command" {
  description = "Ready-to-paste SSH command once the instance is up (~60 s)."
  value       = "ssh -i ~/.ssh/${var.ssh_key_name}.pem ubuntu@${aws_eip.app.public_ip}"
}

output "dns_hint" {
  description = "Exactly what to set in your DNS provider (Route53, Cloudflare, Hostinger)."
  value       = var.domain_name == "" ? "Set var.domain_name later; no DNS hint generated." : <<EOT

    ┌──────────────────────────────────────────┐
    │  DNS action required                     │
    ├──────────────────────────────────────────┤
    │  Type : A                                │
    │  Name : ${var.domain_name}
    │  Value: ${aws_eip.app.public_ip}
    │  TTL  : 300                              │
    └──────────────────────────────────────────┘

  EOT
}

output "first_boot_log" {
  description = "Tail user_data bootstrap progress here."
  value       = "ssh ubuntu@${aws_eip.app.public_ip} sudo tail -f /var/log/sentinelops-bootstrap.log"
}
