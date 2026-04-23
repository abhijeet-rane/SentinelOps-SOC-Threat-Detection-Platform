# SentinelOps

> Enterprise-grade Security Operations Center platform — log ingestion, rule + ML detection, threat-intel enrichment, SOAR automation, tamper-evident audit trail, and deployable to AWS Free Tier with one `terraform apply`.

[![Tests](https://img.shields.io/badge/tests-271%2F271%20passing-brightgreen)]()
[![.NET](https://img.shields.io/badge/.NET-10-512BD4)]()
[![React](https://img.shields.io/badge/React-19-61DAFB)]()
[![Python](https://img.shields.io/badge/Python-3.11-3776AB)]()
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791)]()
[![Docker](https://img.shields.io/badge/Docker-compose--prod-2496ED)]()
[![Terraform](https://img.shields.io/badge/Terraform-AWS-7B42BC)]()
[![License](https://img.shields.io/badge/license-MIT-blue)]()

---

## Table of Contents

- [What is SentinelOps](#what-is-sentinelops)
- [Highlights](#highlights)
- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [Feature Tour](#feature-tour)
  - [Detection and Response](#detection-and-response)
  - [Threat Intelligence](#threat-intelligence)
  - [Authentication and RBAC](#authentication-and-rbac)
  - [Observability](#observability)
  - [Async Infrastructure](#async-infrastructure)
  - [Real-Time Dashboard](#real-time-dashboard)
  - [Attack Simulator](#attack-simulator)
- [Quick Start (Development)](#quick-start-development)
- [Production Deployment](#production-deployment)
- [Repository Layout](#repository-layout)
- [Security Properties](#security-properties)
- [Detection Rules Catalog](#detection-rules-catalog)
- [Testing](#testing)
- [Development Roadmap](#development-roadmap)
- [License](#license)

---

## What is SentinelOps

SentinelOps is a full-stack Security Operations Center platform that turns raw endpoint telemetry into triaged alerts, correlated incidents, automated responses, and compliance reports — without any piece being a black box. It ships as seven loosely-coupled services orchestrated by Docker Compose and is deployable to AWS Free Tier (t3.micro + EIP) with a single Terraform apply.

**Three properties that distinguish it from a toy project:**

1. **Real, not simulated.** Threat intel hits AbuseIPDB, VirusTotal, and URLhaus with live API keys (cached in Redis to respect free-tier quotas). Email ships through a SendGrid-verified sending domain in production and MailHog in development. Detection rules map to actual MITRE ATT&CK techniques and are unit-tested against real event sequences. A bundled red-team CLI (`sentinelattack`) exercises every rule end-to-end in under 60 seconds.

2. **Pluggable adapters everywhere.** Threat-feed sources, SOAR action targets (firewall, identity provider, EDR, notifier), email senders, and ML providers are all behind interfaces. Adding a new firewall vendor or intel feed is a single class plus one DI registration.

3. **Enterprise hygiene.** Strongly-typed config with fail-fast validation in Production, Polly retry and circuit breaker on every outbound HTTP call, Serilog JSON logs enriched with W3C Trace Context, RFC 7807 ProblemDetails error responses, hash-chained immutable audit log with integrity-verification endpoint, API versioning, Hangfire-managed background jobs, OpenTelemetry traces and metrics, SignalR real-time push with a Redis backplane, and a full Docker + Terraform deployment path.

---

## Highlights

| | |
|---|---|
| **271 / 271 tests passing** | xUnit + FluentAssertions + Moq + EF Core InMemory + WebApplicationFactory integration (Docker Postgres required for integration tests) |
| **10 heuristic detection rules** + Sigma engine + YARA-lite + 3 ML models | See [Detection Rules Catalog](#detection-rules-catalog) |
| **11 MITRE ATT&CK techniques** covered | T1021, T1041, T1046, T1071, T1078, T1087, T1110, T1204, T1567, T1568.002, T1572 |
| **8 attack scenarios** in the red-team CLI | `sentinelattack full-kill-chain` validates the whole stack in ~60 s |
| **3 ML anomaly models** (Python micro-service) | Isolation Forest (login), DBSCAN (UEBA), Modified Z-Score (network) |
| **3 real threat-intel feeds** | AbuseIPDB · VirusTotal · URLhaus — bulk sync every 6 h, cached in Redis |
| **4 RBAC roles × 20+ granular permissions** | Permission claims embedded in JWT, custom `PermissionAuthorizationHandler` |
| **SHA-256 hash-chained audit log** | Cryptographic chain of custody; `GET /auditlog/integrity` verifies the whole chain |
| **Real-time dashboard** | SignalR AlertHub over Redis backplane — new alerts in connected browsers in under 500 ms |
| **Full observability** | OpenTelemetry traces to Jaeger + Prometheus metrics (token-gated) + Grafana dashboards |
| **Production-ready deployment** | Multi-stage Dockerfiles, `docker-compose.prod.yml`, Caddy auto-TLS, Terraform for AWS Free Tier |

---

## Architecture

```
                                   Internet (HTTPS 443 / HTTP/3)
                                              │
                                       ┌──────┴───────┐
                                       │   Caddy 2    │   auto-TLS (Let's Encrypt)
                                       └──────┬───────┘
                                              │
                 ┌────────────────────────────┼────────────────────────────┐
                 │                            │                            │
         ┌───────▼───────┐            ┌───────▼───────┐           ┌────────▼────────┐
         │   Dashboard   │            │   .NET API    │           │  SignalR Hub    │
         │ (nginx + SPA) │            │ (ASP.NET 10)  │           │  /hubs/alerts   │
         └───────────────┘            └───────┬───────┘           └─────────────────┘
                                              │
                     ┌────────────────────────┼───────────────────┐
                     │              │         │          │         │
              ┌──────▼──────┐ ┌─────▼────┐ ┌──▼──────┐ ┌─▼────────────────┐
              │ PostgreSQL  │ │  Redis   │ │RabbitMQ │ │  Python ML       │
              │ (OLTP +     │ │(cache +  │ │(ingest  │ │  (FastAPI on     │
              │  Hangfire)  │ │ SignalR) │ │ queue)  │ │   port 8001)     │
              └──────▲──────┘ └──────────┘ └────▲────┘ └──────────────────┘
                     │                          │
              Detection Engine             Windows Desktop Agent
              (15 s cycle)                  (HMAC-SHA256 signed)

External feeds: AbuseIPDB · VirusTotal · URLhaus · SendGrid
```

Layered under Clean Architecture:

| Project | Role |
|---|---|
| `SOCPlatform.Core` | Entities, enums, DTOs, interfaces — depends on nothing |
| `SOCPlatform.Infrastructure` | EF Core, external clients, email, threat-intel, audit interceptor |
| `SOCPlatform.Detection` | Detection engine, 10 heuristic rules, Sigma engine, YARA-lite, playbook engine |
| `SOCPlatform.API` | ASP.NET Core host, controllers, middleware, SignalR hubs, auth |
| `SOCPlatform.DesktopAgent` | WPF tray app, 6 Windows collectors, offline buffer, HMAC-signed client |
| `SOCPlatform.AttackSim` | System.CommandLine red-team CLI (`sentinelattack`) with 8 scenarios |
| `SOCPlatform.ML` | Standalone Python FastAPI microservice for anomaly detection |
| `SOCPlatform.Tests` | 241 unit + integration tests |
| `soc-dashboard` | React 19 + Vite 7 SPA |

See [`DEPLOYMENT.md`](../DEPLOYMENT.md) for the end-to-end production deployment walkthrough.

---

## Tech Stack

**Backend**: .NET 10, ASP.NET Core, Entity Framework Core 10, FluentValidation 11, BCrypt.Net (workFactor 12), Polly v8, Serilog (Compact JSON), Hangfire 1.8, SignalR 10, OpenTelemetry, Scalar/OpenAPI, System.CommandLine

**Data tier**: PostgreSQL 16 (JSONB + Hangfire store) · Redis 7 (distributed cache + SignalR backplane + rate-limit counters) · RabbitMQ 3.13 (log ingestion queue)

**Frontend**: React 19 · Vite 7 · React Router 7 · @microsoft/signalr · Recharts · Framer Motion · Lucide React · ESLint

**Machine Learning**: Python 3.11 · FastAPI 0.115 · Uvicorn (2 workers) · scikit-learn 1.5 · NumPy · SciPy · Pandas 2.2 · joblib

**Observability**: OpenTelemetry Collector → OTLP gRPC → Jaeger 1.60 (traces) · Prometheus 2.55 (metrics) · Grafana 11.3 (dashboards) · Serilog.Enrichers.Span (TraceId/SpanId in logs)

**DevOps and Infrastructure**: Docker + Docker Compose (dev stack + `docker-compose.prod.yml` for prod) · Caddy 2.8 (reverse proxy + auto-TLS) · Terraform (AWS Free Tier VPC + t3.micro + EIP in us-east-1) · GitHub Actions (build → push to GHCR → optional SSH deploy) · UFW + unattended-upgrades on EC2

---

## Feature Tour

### Detection and Response

The heart of the platform. A 15-second hosted service pulls new `SecurityEvents` and dispatches them concurrently to every enabled `IDetectionRule`.

| Rule | Mechanism | Window | Threshold | MITRE |
|---|---|---|---|---|
| Brute Force Detection | 5+ login failures from same source IP | 5 min | 5 events | T1110 |
| Port Scan Detection | 20+ distinct destination ports from same source | 60 s | 20 ports | T1046 |
| Privilege Escalation (Unusual Hours) | SpecialPrivilegeAssigned outside 08:00–18:00 local | Instant | 1 event | T1078 |
| Account Enumeration | 10+ distinct accounts failed from same IP | 5 min | 10 accounts | T1087 |
| Suspicious File Hash | Match against ThreatIntelIndicator hashes | Instant | Exact | T1204 |
| Policy Violation | Access against /admin, /config, /secrets, System32 | Instant | Pattern | — |
| After-Hours Sensitive Activity | FileAccess / ConfigChange / DataExport outside hours | Instant | 1 event | — |
| **Lateral Movement** | Same user → 3+ distinct hosts | 30 min | 3 hosts | T1021 |
| **C2 Beaconing** | Coefficient of variation of inter-arrival times | 60 min | CV < 0.2 | T1071 |
| **DGA Domain Detection** | Bigram frequency of DNS labels | Per query | score < −6.3 | T1568.002 |
| **DNS Tunneling** | Shannon entropy + label length | Per query | H > 4.0, len > 30 | T1572 |
| **Data Exfiltration** | Rolling 100 MB / h OR off-hours cloud upload | 60 min / instant | multi | T1041 / T1567 |

Plus: **Sigma engine** (parses community YAML rules), **YARA-lite** (pure-C# subset matcher, no libyara dependency), and **3 ML anomaly detectors** in the Python sidecar (Isolation Forest on logins, DBSCAN UEBA, Modified Z-Score on network volume).

**SOAR**: four pluggable adapter interfaces (`IFirewallAdapter`, `IIdentityAdapter`, `INotificationAdapter`, `IEndpointAdapter`). The `PlaybookEngine` evaluates each new alert against active playbooks; auto-actions run immediately, approval-gated ones queue a `PendingExecution` for a manager to approve or reject with a reason. Four seeded playbooks ship by default: Block Malicious IP (24 h), Temporary Account Lockout (30 min with approval), Notify SOC Manager (critical severity), Auto-Escalate Critical Alert.

### Threat Intelligence

`IThreatFeedAdapter` with three production implementations:

| Feed | Type | Cadence | Notes |
|---|---|---|---|
| AbuseIPDB | Commercial (free tier) | on-demand + 6-hourly bulk | IP reputation, confidence threshold 90% |
| VirusTotal | Commercial (free tier) | on-demand + 6-hourly | File hash, URL, domain scoring |
| URLhaus (abuse.ch) | Open-source | 6-hourly bulk | ~5 000 active malicious URLs |

Every feed client is wrapped in a **Polly** resilience stack (3-retry exponential backoff + 5-failure circuit breaker + 30 s timeout). Lookups are **Redis-cached with a 1 h TTL**. On match, `ThreatIntelEnrichmentService` sets `IsThreatIntelMatch = true` on the event and bumps alert severity.

### Authentication and RBAC

- **JWT HS256** access tokens (15 min) + refresh tokens (7 days)
- **BCrypt.Net** password hashing at **workFactor 12** (~300 ms per hash)
- **Account lockout** after 5 consecutive failures (15 min lockout)
- **Self-service password reset** — single-use SHA-256-stored tokens with 60 min TTL, delivered via SendGrid
- **Multi-factor authentication (TOTP, RFC 6238)** — optional for analysts, **required** for SOC Manager + System Administrator. Secrets AES-encrypted at rest via ASP.NET Data Protection; 10 single-use backup codes (BCrypt-hashed); short-lived `mfaToken` with dedicated audience so a stolen challenge cannot reach normal endpoints; 10-attempts / 10-min / IP rate-limit on `/mfa/verify`. First-time enrollment is self-service from the login screen (`/auth/mfa/enroll-setup` + `/auth/mfa/enroll-complete` accept the `mfaToken` directly)
- **Permission claims** embedded in every JWT; policy-based `[Authorize(Policy = "...")]` + custom `PermissionAuthorizationHandler`
- Four roles seeded: **SOC Analyst L1**, **SOC Analyst L2**, **SOC Manager**, **System Administrator**

### Observability

- **Serilog** structured JSON logs with correlation IDs and W3C Trace Context (`TraceId` + `SpanId` on every line via `Serilog.Enrichers.Span`)
- **OpenTelemetry** traces exported via OTLP gRPC to Jaeger; `AspNetCore`, `HttpClient`, `EF Core`, and runtime instrumentations enabled
- **Prometheus** scrape endpoint at `/metrics` (token-gated in production via `MetricsAuthMiddleware`)
- Custom `SocMetrics` meter: events ingested, alerts fired by rule, playbook executions, ML inference latency, threat-intel cache hit rate
- Three Grafana dashboards under `observability/grafana`: Ingestion Overview, Detection Performance, External Service Health

### Async Infrastructure

- **RabbitMQ** durable queue decouples ingestion API from detection engine
- **Hangfire** recurring jobs: `ThreatFeedSyncJob` (every 6 h), `LogRetentionJob` (daily), `SoarApprovalTimeoutJob` (every 5 min)
- **Background services** for detection engine, correlation engine, playbook engine — all hosted via `BackgroundService`

### Real-Time Dashboard

- `AlertHub` SignalR endpoint at `/hubs/alerts` (JWT-authenticated via `accessTokenFactory`)
- Redis backplane lets multiple API replicas broadcast to all connected browsers
- Client emits `alert:new`, `alert:batch`, `presence:online` events
- Exponential-backoff auto-reconnect on the client; presence tracking for "who else is online"

### Attack Simulator

The bundled `sentinelattack` CLI (under `SOCPlatform.AttackSim`) exercises the whole detection pipeline end-to-end:

```bash
dotnet sentinelattack.dll full-kill-chain \
       --url https://sentinelops.example.com \
       --user admin --password ... --wait 60
```

Eight scenarios run sequentially, events are POSTed to the admin-only `/api/v1/simulator/inject` endpoint, and the CLI polls `/api/v1/alerts` to confirm every expected rule fired. Exit code is non-zero on any miss, making it CI-friendly.

| Scenario | MITRE | Expected Rule |
|---|---|---|
| `brute-force` | T1110 | Brute Force Detection |
| `port-scan` | T1046 | Port Scan Detection |
| `priv-esc` | T1078 | Privilege Escalation (Unusual Hours) |
| `c2-beacon` | T1071 | C2 Beaconing |
| `dga` | T1568.002 | DGA Domain Detection |
| `dns-tunnel` | T1572 | DNS Tunneling |
| `lateral` | T1021 | Lateral Movement |
| `exfil` | T1041 / T1567 | Data Exfiltration |

---

## Quick Start (Development)

### Prerequisites

- .NET 10 SDK
- Node 20 + pnpm 9 (or npm 10)
- Docker Desktop (for postgres / redis / rabbitmq)
- Python 3.11 (only if you want to run the ML service locally)

### 1. Bring up dependencies

```bash
cd soc_platform
docker compose up -d          # postgres · redis · rabbitmq · mailhog
```

### 2. Backend

```bash
cp .env.example .env.local    # fill in real secrets if you have them; dev defaults work without
cd src/SOCPlatform.API
dotnet run --launch-profile http
# → http://localhost:5101 · OpenAPI at /scalar · Hangfire at /hangfire · Health at /health
```

### 3. Frontend

```bash
cd src/soc-dashboard
npm install
npm run dev
# → http://localhost:5173
```

### 4. (Optional) ML service

```bash
cd src/SOCPlatform.ML
python -m venv venv && . venv/bin/activate
pip install -r requirements.txt
ML_SERVICE_API_KEY=dev-ml-key ML_REQUIRE_AUTH=false uvicorn app:app --port 8001
```

### 5. Log in

Default seeded users (passwords come from `appsettings.Development.json` or the `SEED_*_PASSWORD` env vars):

| Role | Username | Default password |
|---|---|---|
| System Administrator | `admin` | `Admin@Soc2026!` |
| SOC Manager | `soc.manager` | `Manager@Soc2026!` |
| SOC Analyst L2 | `analyst.l2` | `Analyst@Soc2026!` |
| SOC Analyst L1 | `analyst.l1` | `Analyst@Soc2026!` |

If none of those are set anywhere, the seeder generates random passwords and logs them **once** at WARN level so you can rescue the accounts — change them immediately after first login.

### 6. Fire a full attack kill-chain

```bash
cd src/SOCPlatform.AttackSim
dotnet run -- full-kill-chain --url http://localhost:5101 \
            --user admin --password Admin@Soc2026! --wait 30
```

Expected output: `PASS · 8 passed · 0 failed · 8 total`.

---

## Production Deployment

SentinelOps is deployable to a single AWS t3.micro EC2 instance (Free Tier) in **~10 minutes**:

```bash
cd soc_platform/infra/terraform
cp terraform.tfvars.example terraform.tfvars
# fill in ssh_key_name, allow_ssh_cidr, domain_name, repo_url
terraform init && terraform apply
```

Terraform provisions a custom VPC, public subnet, security group (22 scoped to your IP, 80/443 world), Ubuntu 22.04 LTS EC2 with IMDSv2, a 20 GB encrypted gp3 root volume, and an Elastic IP. `user_data.sh` auto-installs Docker + Compose, configures UFW, clones the repo, and leaves an MOTD with the next steps.

Caddy 2 at the edge provisions a free Let's Encrypt certificate via HTTP-01 challenge, terminates TLS, and routes `/api/*`, `/hubs/*`, `/health` to the API and everything else to the dashboard.

Full step-by-step walkthrough with AWS account bootstrap, IAM user creation, billing alarm, DNS cutover, `openssl rand -hex 32` secret generation, verification checklist, operations runbook, troubleshooting, and teardown: **[`DEPLOYMENT.md`](../DEPLOYMENT.md)** (680 lines).

---

## Repository Layout

```
SOC_Project/
├── DEPLOYMENT.md                  ← 680-line production deployment walkthrough
├── SentinelOps-Project-Documentation.docx
├── .github/workflows/
│   ├── ci.yml                     ← build + test on every push
│   └── deploy.yml                 ← build images → GHCR → SSH deploy (gated)
│
└── soc_platform/
    ├── README.md                  ← (this file)
    ├── docker-compose.yml         ← dev stack (postgres · redis · rabbitmq · mailhog · observability profile)
    ├── docker-compose.prod.yml    ← prod stack (7 services behind Caddy)
    ├── deploy/Caddyfile           ← reverse-proxy + auto-TLS config
    ├── .env.example               ← every env var the stack reads, with prod notes
    │
    ├── infra/terraform/           ← AWS IaC (VPC · SG · t3.micro · EIP · user_data.sh)
    │
    ├── observability/
    │   ├── prometheus/prometheus.yml
    │   └── grafana/sentinelops-dashboard.json
    │
    └── src/
        ├── SOCPlatform.API/              ← ASP.NET Core 10 host
        ├── SOCPlatform.Core/             ← entities, DTOs, interfaces (zero deps)
        ├── SOCPlatform.Detection/        ← rules, detection engine, playbook engine
        ├── SOCPlatform.Infrastructure/   ← EF Core, adapters, email, threat-intel
        ├── SOCPlatform.DesktopAgent/     ← WPF tray app (6 Windows collectors)
        ├── SOCPlatform.AttackSim/        ← red-team CLI (sentinelattack)
        ├── SOCPlatform.ML/               ← Python FastAPI microservice
        ├── SOCPlatform.Tests/            ← 241 xUnit tests
        └── soc-dashboard/                ← React 19 + Vite 7 SPA
```

---

## Security Properties

### CIA Triad mapping

- **Confidentiality** — TLS 1.3 at the edge (Caddy auto-TLS), BCrypt(12) password hashing, JWT with per-role permission claims, env-var secrets never committed, AWS IMDSv2 required on EC2, encrypted EBS root volume.
- **Integrity** — Hash-chained `AuditLog` (SHA-256 of `prev.Hash || current.Json`), HMAC-SHA256 agent ingestion signing with 5 min replay window, EF Core `SaveChangesInterceptor` makes tampering mathematically detectable, CSP headers prevent client-side injection, strict TLS validation + optional certificate pinning in the desktop agent.
- **Availability** — Polly retry + circuit breaker + timeout on every external HttpClient, Redis distributed rate limiting, Kestrel request-size limits, account lockout after 5 failures (blocks credential-stuffing DoS), Docker healthchecks + `unless-stopped` restart policy, RabbitMQ durable queue means ingestion survives detection-engine restarts, Hangfire auto-retries.

### Post-deployment hardening

After an external security review flagged seven gaps, a dedicated hardening pass closed every finding while keeping all 241 tests green (commit `f12653f`):

1. `appsettings.json` secrets blanked; dev values live in git-ignored `appsettings.Development.json`. Program.cs fails fast in Production if any required secret is unset or still a placeholder.
2. `DatabaseSeeder` reads seed passwords from config; when unset, generates a random password and logs it once at WARN.
3. Desktop agent's `ApiClientService` now defaults to strict PKI validation, supports SHA-256 thumbprint pinning, and only relaxes on an explicit `allowInvalidCerts=true` flag (with a loud warning on every construction).
4. ML service now enforces an `X-API-Key` header via `ApiKeyMiddleware`; `ML_CORS_ORIGINS` defaults to empty (service-to-service only); refuses to start if the key is missing.
5. `HmacRequestSigningMiddleware` rejects missing `X-Signature` / `X-Timestamp` headers with 401 in non-Development.
6. New `MetricsAuthMiddleware` token-gates `/metrics` via `Authorization: Bearer <METRICS_SCRAPE_TOKEN>` in non-Development. Swagger is no longer routed in the production Caddyfile.
7. `InputSanitizationMiddleware` XML-docs rewritten to clarify it is **secondary** defense; real input safety comes from EF Core parameterised queries, FluentValidation, output encoding, and CSP.

### Cryptographic controls at a glance

| Control | Algorithm | Parameters |
|---|---|---|
| Password hashing | BCrypt | workFactor = 12 |
| JWT signing | HMAC-SHA256 | secret ≥ 32 bytes, validated at startup |
| MFA TOTP | HMAC-SHA1 (RFC 6238) | 160-bit secret, 30 s period, ±1 window tolerance |
| MFA secret at rest | AES (ASP.NET Data Protection) | Purpose-scoped protector keys |
| MFA backup codes | BCrypt | workFactor = 12, single-use, 10 codes per user |
| MFA challenge token | JWT HS256 | audience `SOCPlatform.Mfa`, 5 min TTL |
| Agent request signing | HMAC-SHA256 | `timestamp ∥ method ∥ path ∥ SHA-256(body)` |
| Audit log chain | SHA-256 | `Hash = SHA-256(prev.Hash ∥ current.Json)` |
| TLS (edge) | TLS 1.3 (Caddy) | Let's Encrypt auto-rotation |
| Password reset token | 32 random bytes → Base64URL | 60 min TTL, SHA-256 stored, single-use |
| Desktop agent TLS | Strict PKI default + optional SHA-256 thumbprint pinning | — |

---

## Detection Rules Catalog

See the full table in [Feature Tour → Detection and Response](#detection-and-response). Rule implementations live under:

- `src/SOCPlatform.Detection/Rules/*.cs` — seven baseline rules
- `src/SOCPlatform.Detection/Rules/Advanced/*.cs` — five advanced rules (statistical, correlation)
- `src/SOCPlatform.Detection/Rules/Sigma/` — Sigma YAML engine
- `src/SOCPlatform.Detection/Rules/Yara/` — YARA-lite pure-C# matcher

Sigma rule files can be dropped into `detection-rules/sigma/*.yml` and are picked up on the next detection cycle. No restart required for Sigma additions; C# rules require a redeploy.

---

## Testing

```bash
cd soc_platform
docker compose up -d postgres        # integration tests need Postgres
dotnet test src/SOCPlatform.Tests/SOCPlatform.Tests.csproj -c Release
# → Passed!  - Failed: 0, Passed: 241, Skipped: 0, Total: 241  (≈ 30 s)
```

Test breakdown:

| Category | Count |
|---|---|
| Detection rule unit tests | ~45 |
| Attack scenario round-trip | 9 |
| Controller + RBAC integration (needs Postgres) | ~75 |
| Auth flows (login, password reset, lockout) | ~25 |
| Cryptographic correctness (HMAC, hash chain, BCrypt) | ~12 |
| Validators, mappers, helpers | ~75 |

The `SOCPlatform.AttackSim` CLI's `full-kill-chain` subcommand acts as a black-box end-to-end regression gate — 8 real attack scenarios through the live API and Postgres in about a minute.

---

## Development Roadmap

### Completed

| Phase | Commit | What shipped |
|---|---|---|
| **0 — Foundation Hardening** | `65dd3c0` | Strongly-typed config, Serilog, global exception handler, security-headers middleware, hash-chained audit log |
| **1 — Auth polish** | `3b5362a` | Self-service password reset with SendGrid |
| **2 — Threat intel** | `a387007` | AbuseIPDB + VirusTotal + URLhaus adapters with Polly + Redis cache |
| **3 — SOAR framework** | `2d32863` | Four pluggable adapters + playbook engine with approval gates |
| **4 — Advanced detection** | `4e91178` | 5 advanced rules + Sigma + YARA-lite engines |
| **5 — SignalR real-time** | `7bf3c40` | AlertHub + Redis backplane + live dashboard ticker |
| **6 — Observability** | `2308ff3` | OpenTelemetry + Prometheus + Grafana + 3 dashboards |
| **7 — Attack Simulator CLI** | `7d7e893` | `sentinelattack` with 8 MITRE-mapped scenarios |
| **8 — Cloud-Ready Deployment** | `5c5d9e1` | Multi-stage Dockerfiles + `docker-compose.prod.yml` + Caddy auto-TLS + Terraform for AWS Free Tier + GitHub Actions deploy workflow + `DEPLOYMENT.md` |
| **Security hardening pass** | `f12653f` | Closed 7 findings from external security review; added `MetricsAuthMiddleware`, strict TLS in agent, ML service auth, fail-fast secret validation |
| **9 — TOTP MFA** | *(next commit)* | RFC 6238 TOTP + AES-encrypted secrets + 10 BCrypt-hashed backup codes + `mfaToken` audience-isolated challenge + tiered enforcement (mandatory for Manager / Admin) + React enrollment wizard + 27 new tests |

### Planned / deferred

- **Forensics / Evidence dashboard page** — visualise the audit-log chain, add a "Verify Integrity" button, export signed evidence bundles
- **Shodan / Censys** as a fourth threat-intel feed (OSINT practical)
- **Docker image CVE scanning** (Trivy or Docker Scout) in the CI pipeline
- **AWS Secrets Manager** integration so the EC2 instance fetches secrets at container-start via an instance profile
- **RDS managed Postgres** instead of containerised Postgres — free-tier-eligible `db.t4g.micro` with automatic backups and point-in-time recovery
- **Multi-AZ resilience** (ASG + ALB) — breaks Free Tier but gets real HA
- **AWS WAF** in front of Caddy for the OWASP top-10 managed ruleset
- **VPC Flow Logs** to CloudWatch

---

## License

[MIT](../LICENSE) © 2026 Abhijeet Rane
