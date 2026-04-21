#!/usr/bin/env bash
# =============================================================================
# SentinelOps — EC2 bootstrap (cloud-init user_data)
#
# Runs ONCE on first boot (or whenever the instance is replaced). Installs
# Docker + Compose, clones the repo, and leaves the box ready for you to:
#   1. scp your .env into /opt/sentinelops/.env
#   2. docker compose -f docker-compose.prod.yml --env-file /opt/sentinelops/.env up -d --build
#
# All output is appended to /var/log/sentinelops-bootstrap.log for easy review.
# =============================================================================

set -euxo pipefail
exec > >(tee -a /var/log/sentinelops-bootstrap.log) 2>&1

echo "[bootstrap] $(date -Iseconds) — starting"

# ─── System packages ─────────────────────────────────────────────────────────
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y \
    ca-certificates curl gnupg git ufw jq unattended-upgrades

# ─── Unattended security upgrades ────────────────────────────────────────────
cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

# ─── Docker Engine + Compose plugin (from the official Docker APT repo) ─────
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg

echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
  > /etc/apt/sources.list.d/docker.list

apt-get update -y
apt-get install -y \
    docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

systemctl enable --now docker

# Let `ubuntu` run docker without sudo.
usermod -aG docker ubuntu

# ─── Host firewall: belt-and-braces alongside the AWS SG ────────────────────
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 443/udp
ufw --force enable

# ─── Clone the repo ─────────────────────────────────────────────────────────
install -d -o ubuntu -g ubuntu /opt/sentinelops
sudo -u ubuntu git clone --branch "${repo_branch}" --depth 1 "${repo_url}" /opt/sentinelops/repo

# Drop a clearly-named placeholder .env so the next step is obvious.
cat >/opt/sentinelops/.env.example <<'EOF'
# >>> REPLACE THIS FILE with real secrets, then delete .env.example <<<
# Expected keys (see soc_platform/.env.example at repo root for the canonical list):
#   DOMAIN_NAME, ACME_EMAIL
#   POSTGRES_DB, POSTGRES_USER, POSTGRES_PASSWORD
#   REDIS_PASSWORD
#   RABBITMQ_USER, RABBITMQ_PASSWORD
#   JWT_SECRET_KEY, JWT_ISSUER, JWT_AUDIENCE, JWT_ACCESS_TOKEN_EXPIRATION_MINUTES, JWT_REFRESH_TOKEN_EXPIRATION_DAYS
#   SENDGRID_API_KEY, EMAIL_FROM_ADDRESS, EMAIL_FROM_NAME, EMAIL_REPLY_TO
#   ABUSEIPDB_API_KEY, VIRUSTOTAL_API_KEY
EOF
chown ubuntu:ubuntu /opt/sentinelops/.env.example

# ─── Marker file so the operator sees "bootstrap done" on SSH ───────────────
cat >/etc/motd <<'MOTD'

    ╭─── SentinelOps EC2 ──────────────────────────────────────────╮
    │                                                              │
    │  Bootstrap complete. Remaining steps:                        │
    │                                                              │
    │   1. From your laptop:                                       │
    │      scp .env ubuntu@<this-host>:/opt/sentinelops/.env       │
    │                                                              │
    │   2. SSH in and launch the stack:                            │
    │      cd /opt/sentinelops/repo/soc_platform                   │
    │      docker compose -f docker-compose.prod.yml \             │
    │        --env-file /opt/sentinelops/.env up -d --build        │
    │                                                              │
    │   3. Watch it come up:                                       │
    │      docker compose -f docker-compose.prod.yml logs -f       │
    │                                                              │
    │  Bootstrap log: /var/log/sentinelops-bootstrap.log           │
    ╰──────────────────────────────────────────────────────────────╯

MOTD

echo "[bootstrap] $(date -Iseconds) — done"
