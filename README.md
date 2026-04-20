# SentinelOps

> Enterprise-grade Security Operations Center platform — log ingestion, rule + ML detection, threat-intel enrichment, SOAR automation, and compliance reporting from a single pane of glass.

[![CI](https://img.shields.io/badge/CI-passing-brightgreen)]()
[![.NET](https://img.shields.io/badge/.NET-10-512BD4)]()
[![C%23](https://img.shields.io/badge/C%23-13-239120)]()
[![React](https://img.shields.io/badge/React-19-61DAFB)]()
[![Python](https://img.shields.io/badge/Python-3.11-3776AB)]()
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791)]()
[![Tests](https://img.shields.io/badge/tests-153%2F153%20passing-brightgreen)]()
[![License](https://img.shields.io/badge/license-MIT-blue)]()

---

## Table of contents

- [What is SentinelOps](#what-is-sentinelops)
- [Highlights](#highlights)
- [Architecture](#architecture)
- [Tech stack](#tech-stack)
- [Features](#features)
  - [Detection & response](#detection--response)
  - [Threat intelligence](#threat-intelligence)
  - [Authentication & authorization](#authentication--authorization)
  - [Observability & resilience](#observability--resilience)
  - [Async infrastructure](#async-infrastructure)
  - [Frontend](#frontend)
- [Quick start](#quick-start)
- [Service URLs](#service-urls)
- [Repository layout](#repository-layout)
- [Security properties](#security-properties)
- [Detection rules](#detection-rules)
- [Threat-intel sources](#threat-intel-sources)
- [Tests](#tests)
- [Roadmap](#roadmap)
- [License](#license)

---

## What is SentinelOps

SentinelOps is a full-stack Security Operations Center platform built to demonstrate end-to-end SOC engineering: how raw endpoint events become triaged alerts, get correlated into incidents, trigger automated responses, and surface as compliance reports — without any single piece being a black box.

**Three concrete characteristics:**

1. **Real, not simulated.** Threat intel hits AbuseIPDB and VirusTotal with live API keys (cached in Redis to respect free-tier quotas). Email goes through verified `wallystudio.in` SendGrid sending domain in production, MailHog in development. Detection rules are mapped to actual MITRE ATT&CK techniques and unit-tested against real event sequences.
2. **Pluggable adapters everywhere.** Threat-feed sources, SOAR action targets, email senders, and ML providers are all behind interfaces. Adding a new firewall vendor or feed is a single class + one DI registration.
3. **Enterprise hygiene.** Strongly-typed config with fail-fast validation, Polly retry/circuit-breaker on every outbound HTTP call, Serilog JSON logs with correlation IDs across the stack, RFC 7807 ProblemDetails errors, hash-chained immutable audit log, API versioning, Hangfire-managed background jobs.

---

## Highlights

| | |
|---|---|
| **153/153 tests passing** | xUnit + FluentAssertions + Moq + EF Core InMemory + WebApplicationFactory integration |
| **7 detection rules** mapped to MITRE ATT&CK | Brute-force (T1110), port scan (T1046), priv-esc (T1078), account enumeration (T1087), after-hours (T1078), suspicious hash (T1204), policy violation |
| **3 ML anomaly models** (Python microservice) | Isolation Forest (login), DBSCAN (UEBA), Modified Z-Score (network) |
| **3 real threat-intel feeds** | AbuseIPDB · VirusTotal · URLhaus (1 500+ indicators per 6h sync) |
| **5 endpoint collectors** (WPF agent) | Windows Event Log auth/file/privilege, WMI USB, .NET TCP connections — HMAC-SHA256 signed, SQLite offline buffer |
| **5 RBAC roles × 18 granular permissions** | Permission claims in JWT, custom `PermissionAuthorizationHandler` |
| **SHA-256 hash-chained audit trail** | Tamper-evident; `/auditlog/integrity` endpoint verifies the entire chain |
| **Hangfire dashboard** at `/hangfire` (Admin only) | Background-job retries, history, recurring-job scheduler |
| **Scalar API docs** at `/scalar` | Modern OpenAPI UI; OpenAPI v1 spec at `/openapi/v1.json` |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          SentinelOps — High-level architecture                  │
└─────────────────────────────────────────────────────────────────────────────────┘

  ┌──────────────────┐                                       ┌──────────────────┐
  │  WPF Endpoint    │                                       │   React 19 SOC   │
  │  Agent (C#)      │                                       │   Dashboard      │
  │                  │                                       │   (Vite 7)       │
  │  Collectors:     │                                       │                  │
  │  Auth Events     │                                       │  11 pages        │
  │  File Access     │                                       │  MITRE heatmap   │
  │  Privileges      │                                       │  Live alerts     │
  │  USB devices     │                                       │  SOAR approvals  │
  │  TCP conns       │                                       │  Compliance rpt  │
  └────────┬─────────┘                                       └────────▲─────────┘
           │ HMAC-SHA256                                              │ JWT
           │ SQLite offline                                           │ /api/v1/*
           │ buffer                                                   │
           ▼                                                          │
  ┌─────────────────────────────────────────────────────────────────────────────┐
  │                  ASP.NET Core 10 Backend  (port 5101)                       │
  │  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐                 │
  │  │ 11 Controllers │  │ 5 Middleware   │  │ Auth/RBAC      │                 │
  │  │ /api/v1/*      │  │ pipeline       │  │ JWT + perms    │                 │
  │  └────────┬───────┘  └────────────────┘  └────────────────┘                 │
  │           │                                                                  │
  │  ┌────────▼─────────┐ ┌─────────────────┐ ┌─────────────────┐               │
  │  │ Detection Engine │ │ Correlation     │ │ Playbook Engine │               │
  │  │ 7 rules · 15 s   │ │ Engine · 30 s   │ │ SOAR · 10 s     │               │
  │  └──────────────────┘ └─────────────────┘ └─────────────────┘               │
  │                                                                              │
  │  ┌──────────────────────┐  ┌─────────────────────────────────────────┐      │
  │  │ ThreatFeedCoordinator│  │ Background services / Hangfire jobs     │      │
  │  │  AbuseIPDB           │  │  • LogProcessing · LogRetention         │      │
  │  │  VirusTotal          │  │  • ThreatFeedSyncJob (every 6 h)        │      │
  │  │  URLhaus (bulk)      │  │  • Recurring + ad-hoc execution         │      │
  │  └──────────────────────┘  └─────────────────────────────────────────┘      │
  └──────────┬─────────────────────────────────┬────────────────────────────────┘
             │                                 │
   ┌─────────▼──────────┐    ┌─────────────────▼─────────────┐   ┌────────────┐
   │ FastAPI ML service │    │ PostgreSQL 16                 │   │ Redis 7    │
   │ (Python · :8001)   │    │ • EF Core schema (15 tables)  │   │ Cache +    │
   │                    │    │ • Hangfire job storage        │   │ SignalR    │
   │ Isolation Forest   │    │ • Hash-chained audit log      │   │ backplane  │
   │ DBSCAN UEBA        │    └───────────────────────────────┘   └────────────┘
   │ Modified Z-Score   │                                                       
   └────────────────────┘    ┌───────────────────────────────┐   ┌────────────┐ 
                             │ RabbitMQ 3.13                 │   │ MailHog    │ 
                             │ (log ingestion queue)         │   │ (dev SMTP) │ 
                             └───────────────────────────────┘   └────────────┘ 
                                                                                
                             ┌───────────────────────────────────────┐          
                             │ External integrations                 │          
                             │ • SendGrid (verified wallystudio.in)  │          
                             │ • AbuseIPDB · VirusTotal API          │          
                             │ • URLhaus CSV feed                    │          
                             └───────────────────────────────────────┘          
```

---

## Tech stack

| Layer | Stack |
|---|---|
| **Backend API** | ASP.NET Core 10 (C# 13) · EF Core 10 + Npgsql · FluentValidation · Asp.Versioning · Scalar |
| **Auth** | JWT Bearer (HS256) · BCrypt (workFactor 12) · permission-claim RBAC |
| **Detection** | In-process `BackgroundService` · 7 rule classes implementing `IDetectionRule` |
| **SOAR** | Pluggable `IPlaybookAction` · approval workflow · audit-trailed execution |
| **ML microservice** | Python 3.11 · FastAPI · scikit-learn (Isolation Forest, DBSCAN, MAD/Z-score) |
| **Endpoint agent** | WPF · .NET 10 · MailKit-style HMAC signing · SQLite offline buffer |
| **Frontend** | React 19 · Vite 7 · Recharts · Framer Motion · CSS variables |
| **Datastore** | PostgreSQL 16 (primary + Hangfire job storage) |
| **Cache** | Redis 7 (`IDistributedCache` + SignalR backplane) |
| **Messaging** | RabbitMQ 3.13 (log ingestion queue groundwork) |
| **Background jobs** | Hangfire + `Hangfire.PostgreSql` |
| **Observability** | Serilog (Compact JSON) · Correlation-Id middleware · `IExceptionHandler` (.NET 10) |
| **Resilience** | Polly retry (3× exp back-off) + circuit-breaker (5 fails / 30 s) + 10 s timeout |
| **Email** | `IEmailSender` abstraction · MailHog (dev) · SendGrid (prod, verified `wallystudio.in`) |
| **Threat intel** | Pluggable `IThreatFeedAdapter` · AbuseIPDB · VirusTotal · URLhaus · Redis cache |
| **Containerization** | Docker Compose (Postgres + Redis + RabbitMQ + MailHog) |
| **CI/CD** | GitHub Actions · 4 parallel jobs (backend, desktop, ML, frontend) |

---

## Features

### Detection & response

| | |
|---|---|
| **7 rule-based detectors** | All MITRE ATT&CK-mapped; 54 unit tests + 4 performance tests (10k events / 2 s for brute-force) |
| **Correlation engine** | Groups related alerts into incidents using 30-min sliding window + entity overlap (user / device / IP) |
| **SOAR playbooks** | 4 actions: BlockIp, LockAccount, NotifyManager, EscalateAlert (3 more in Phase 3) |
| **Approval workflow** | Required-approval playbooks queue under `Pending`; SOC-Manager approves/rejects |
| **SLA tracking** | Per-severity deadlines: Critical 1 h · High 4 h · Medium 8 h · Low 24 h. Breach indicators in dashboard |
| **ML anomaly detection** | 3 models served by FastAPI sidecar, called via Polly-protected `HttpClient` |

### Threat intelligence

| | |
|---|---|
| **Pluggable `IThreatFeedAdapter`** | One adapter per source. Adding ThreatFox / MISP / OTX = one class + one DI line |
| **AbuseIPDB live** | IP reputation, score 0–100 → confidence. Free-tier 1 k/day budget protected by Redis cache |
| **VirusTotal live** | File hash + URL + domain + IP. Maps engine ratio to threat level |
| **URLhaus bulk** | CSV poller, ~1 500 indicators per 6 h sync. Each URL emits both URL + Domain rows |
| **`ThreatFeedCoordinator`** | Local-DB lookup → Redis cache → live adapters in parallel → upsert + re-query |
| **Cache hits *and* misses** | 1 h TTL on both — stops repeat probes from burning AbuseIPDB free-tier budget |
| **Multi-source merge** | Same IOC from multiple feeds collapses to one row with `Source = "AbuseIPDB, VirusTotal"` |
| **Hangfire bulk sync** | Recurring `0 */6 * * *`, manual via `POST /api/v1/threatintel/sync` |

### Authentication & authorization

| | |
|---|---|
| **JWT Bearer** | HS256 · 15-min access · 7-day refresh-token rotation · `ClockSkew=0` |
| **BCrypt password hashing** | `workFactor: 12` |
| **Account lockout** | 5 failed attempts → 15-min lockout |
| **Self-service password reset** | Hashed single-use token (SHA-256 of 32-byte CSPRNG), 1 h TTL, enumeration-safe, revokes all refresh tokens on success |
| **Permission-based RBAC** | 5 roles × 18 permissions. Custom `PermissionAuthorizationHandler` checks JWT `Permission` claims |
| **Hash-chained audit log** | SHA-256 chain over JSON payload + previous hash; tamper detection via `/auditlog/integrity` |

### Observability & resilience

| | |
|---|---|
| **Serilog (Compact JSON)** | Console + daily-rolling file with 14-day retention; enriched with `CorrelationId` / `TraceId` / `SpanId` |
| **Correlation-Id middleware** | Reads/issues `X-Correlation-Id` header; pushed into Serilog `LogContext` so every log line for a request shares one ID |
| **`IExceptionHandler` (.NET 10)** | RFC 7807 `ProblemDetails` with correlation ID; replaces legacy global-exception middleware |
| **Polly resilience** | All outbound HttpClients (ML, AbuseIPDB, VirusTotal, SendGrid) wrapped in retry + circuit-breaker + per-attempt timeout |
| **Strongly-typed `IOptions<T>` + `ValidateOnStart`** | 8 options classes, fail-fast on missing/invalid config |
| **Health checks** | 8 split across `/health/live` and `/health/ready` (Postgres, Redis, RabbitMQ, ML, AbuseIPDB, VirusTotal, SMTP, self) |
| **OWASP security headers** | 7 headers including HSTS, CSP, X-Frame-Options, Permissions-Policy |
| **Sliding-window rate limiting** | Dashboard 100 req/min/IP; ingestion 1000 req/min/key |

### Async infrastructure

| | |
|---|---|
| **Redis** | `IDistributedCache` for threat-intel cache + SignalR backplane |
| **Hangfire** | Postgres-backed job storage; `/hangfire` dashboard restricted to Admin role via custom `IDashboardAuthorizationFilter` |
| **RabbitMQ** | Container + management UI (groundwork for replacing in-process `Channel<Log>` in a future phase) |
| **MailHog** | Local SMTP capture for dev — test password-reset emails at `http://localhost:8025` |
| **Scalar API docs** | Modern OpenAPI UI at `/scalar`, replaces basic `MapOpenApi` |
| **API versioning** | All routes versioned `/api/v1/*` via `Asp.Versioning.Mvc` |
| **Background services** | `DetectionEngine` (15 s) · `CorrelationEngine` (30 s) · `PlaybookEngine` (10 s) · `LogProcessing` · `LogRetention` |

### Frontend

13 React pages: Login · Forgot Password · Reset Password · Dashboard · Alerts · Incidents · Analytics · MITRE ATT&CK heatmap · Playbooks · Threat Intel · Reports · Audit Log · Settings.

| | |
|---|---|
| Animated KPI cards | Framer Motion staggered entrance + animated counters |
| Filterable alert queue | Severity / status / sort / SLA-breach indicators / MITRE technique tags |
| MITRE ATT&CK heatmap | CSS-grid matrix coloured by hit count; tactics × techniques |
| SOAR approval workflow | Pending-approval table; analyst approves/rejects |
| Threat-intel enrichment | Lookup form for IP / domain / hash; live results from real adapters |
| Compliance report builder | NIST CSF · ISO 27001 · SOC 2 mappings; PDF / Excel export |
| Audit log viewer | Hash-chain integrity verification button |
| Toast notifications | Success / error / warning / info, auto-dismiss 4 s |

---

## Quick start

### Prerequisites

| Tool | Version |
|---|---|
| Docker Desktop | latest |
| .NET SDK | 10.0+ |
| Node.js | 20+ |
| pnpm | 9+ |
| Python | 3.11+ |

### Run

Open four terminals:

```bash
# 1. Datastores (Postgres + Redis + RabbitMQ + MailHog)
cd soc_platform
docker compose up -d

# 2. Backend API → http://localhost:5101
cd src/SOCPlatform.API
dotnet run

# 3. ML microservice → http://localhost:8001
cd src/SOCPlatform.ML
python -m venv venv && source venv/bin/activate     # Windows: .\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py

# 4. Frontend → http://localhost:5173
cd src/soc-dashboard
pnpm install
pnpm dev
```

Login with `admin` / `Admin@Soc2026!`.

Full step-by-step instructions, troubleshooting, and test commands are in [HOW_TO_RUN.md](../HOW_TO_RUN.md).

---

## Service URLs

| Service | URL | Auth |
|---|---|---|
| **React dashboard** | http://localhost:5173 | `admin` / `Admin@Soc2026!` |
| **REST API** | http://localhost:5101/api/v1 | JWT Bearer |
| **Scalar API docs** | http://localhost:5101/scalar | — |
| **OpenAPI v1 spec** | http://localhost:5101/openapi/v1.json | — |
| **Health (live)** | http://localhost:5101/health/live | — |
| **Health (ready)** | http://localhost:5101/health/ready | — |
| **Hangfire dashboard** | http://localhost:5101/hangfire | JWT Admin role |
| **ML microservice** | http://localhost:8001/docs | — |
| **MailHog inbox** | http://localhost:8025 | — |
| **RabbitMQ admin** | http://localhost:15672 | `socadmin` / `SocRabbitDev2026` |
| **PostgreSQL** | `localhost:5433` (db `socplatform`) | `socadmin` / `SocDev2026` |
| **Redis** | `localhost:6379` | `SocRedisDev2026` |

---

## Repository layout

```
soc_platform/
├── docker-compose.yml             # Postgres + Redis + RabbitMQ + MailHog
├── .env.example                   # secrets template (real values in .env.local, git-ignored)
│
└── src/
    ├── SOCPlatform.Core/          # Domain entities · enums · interfaces · DTOs (zero framework deps)
    │
    ├── SOCPlatform.Infrastructure/
    │   ├── Configuration/         # 8 strongly-typed Options classes with DataAnnotations validation
    │   ├── Data/                  # SOCDbContext · DatabaseSeeder · 4 EF migrations
    │   ├── Email/                 # IEmailSender impls (Smtp/MailHog · SendGrid)
    │   ├── Jobs/                  # ThreatFeedSyncJob (Hangfire recurring)
    │   ├── Repositories/          # Generic Repository<T> + Unit of Work
    │   ├── Resilience/            # Polly PolicyRegistry (named clients with retry/CB/timeout)
    │   ├── Services/              # Auth · Audit · LogIngestion · ThreatIntel (legacy CRUD) · …
    │   └── ThreatIntel/
    │       ├── Adapters/          # AbuseIpDb · VirusTotal · URLhaus
    │       ├── Cache/             # IThreatIntelCache + RedisThreatIntelCache
    │       └── ThreatFeedCoordinator.cs
    │
    ├── SOCPlatform.Detection/
    │   ├── Rules/                 # 7 IDetectionRule implementations
    │   ├── Playbooks/             # 4 IPlaybookAction implementations + PlaybookEngine
    │   ├── DetectionEngine.cs     # BackgroundService, 15 s polling
    │   └── CorrelationEngine.cs   # 30 s polling, 30-min window
    │
    ├── SOCPlatform.API/
    │   ├── Controllers/           # 11 versioned controllers (api/v1/*)
    │   ├── Authorization/         # PermissionAuthorizationHandler · HangfireDashboardAuthFilter
    │   ├── ExceptionHandlers/     # GlobalExceptionHandler (.NET 10 IExceptionHandler)
    │   ├── HealthChecks/          # AbuseIPDB · VirusTotal · SMTP custom checks
    │   ├── Middleware/            # CorrelationId · ApiKey · HMAC · InputSanitization · RequestSize
    │   ├── Validators/            # FluentValidation rules
    │   └── Program.cs             # Bootstrap (Serilog, Hangfire, Redis, SignalR, Scalar, …)
    │
    ├── SOCPlatform.DesktopAgent/  # WPF endpoint agent · 5 collectors · HMAC client · SQLite buffer
    │
    ├── SOCPlatform.ML/            # FastAPI Python service · 3 anomaly models · pytest suite
    │
    ├── SOCPlatform.Tests/         # 153 tests (xUnit + FluentAssertions + Moq + EF InMemory)
    │   ├── Audit/                 # 12 hash-chain integrity tests
    │   ├── Auth/                  # 30 RBAC + 14 password-reset unit + 6 password-reset integration
    │   ├── Detection/             # 54 rule tests (positive + negative scenarios)
    │   ├── Performance/           # 4 benchmark tests (10 k events / 2 s)
    │   └── ThreatIntel/           # 33 adapter / cache / coordinator tests
    │
    └── soc-dashboard/             # React 19 · Vite 7 · 13 pages
```

---

## Security properties

- **Defense in depth.** 5-layer middleware (HMAC signing → API key → input sanitization → request size cap → rate limiter) before requests ever reach a controller.
- **Hashed at rest.** Password reset tokens stored as SHA-256 hex of a 32-byte CSPRNG secret — leak-proof. Passwords as BCrypt with workFactor 12.
- **Tamper-evident audit log.** SHA-256 over `(payload + previous_hash)`. Modifying any past entry breaks the chain at and after that point. `/auditlog/integrity` recomputes the chain on demand.
- **HMAC-signed agent ingestion.** Each `POST /api/v1/logs/ingest` signs `timestamp + method + path + SHA256(body)` with the API key; rejected if timestamp is more than 5 minutes old (replay protection).
- **Enumeration-safe password reset.** `POST /api/v1/auth/forgot-password` always returns `202 Accepted` regardless of whether the email exists.
- **Refresh-token revocation.** Every successful password reset clears `RefreshToken` and `RefreshTokenExpiry` on the user, forcing fresh login on every device.
- **Strict CORS whitelist.** No wildcards in production.
- **OWASP security headers.** `X-Content-Type-Options: nosniff` · `X-Frame-Options: DENY` · `Strict-Transport-Security` · `Content-Security-Policy` · `Referrer-Policy` · `Permissions-Policy` · `X-Permitted-Cross-Domain-Policies: none`.
- **No secrets in git.** All secrets externalized to `.env.local` (git-ignored). `.env.example` documents the full set; production uses environment variables (compatible with AWS Secrets Manager).
- **Fail-fast configuration.** `IOptions<T>.ValidateOnStart()` causes the API to refuse to boot if any required config is missing or invalid.
- **Threat-intel rate-limit protection.** Redis-cached hits *and* misses with 1-hour TTL prevent attackers from exhausting your AbuseIPDB free-tier 1 000/day budget.
- **Hangfire dashboard locked.** `/hangfire` requires authentication and the `Admin` role via custom `IDashboardAuthorizationFilter`.

---

## Detection rules

All seven rules are MITRE ATT&CK-mapped and unit-tested.

| Rule | MITRE | Threshold | Window | Severity |
|---|---|---|---|---|
| **Brute-force** | T1110 (Credential Access) | ≥ 5 failed logins from same source IP | 5 min | High |
| **Port scan** | T1046 (Network Discovery) | ≥ 20 distinct destination ports from same source | 60 s | Medium |
| **Privilege escalation** | T1078 (Valid Accounts) | `SpecialPrivilegeAssigned` / `SensitivePrivilegeUse` outside 08:00–18:00 UTC | — | Critical |
| **Account enumeration** | T1087 (Account Discovery) | ≥ 10 distinct usernames targeted from same source | 5 min | High |
| **After-hours activity** | T1078 (Valid Accounts) | `LoginSuccess` / `FileAccess` / `USBDeviceConnected` / `ProcessCreate` outside 08:00–18:00 | — | Medium |
| **Suspicious hash** | T1204 (User Execution) | `IsThreatIntelMatch` flag + matching `FileHash` | — | Critical |
| **Policy violation** | — | `EventAction = FileAccess` AND `EventCategory = Security` | — | Medium |

SLA deadline at alert creation: **Critical 1 h · High 4 h · Medium 8 h · Low 24 h**.

---

## Threat-intel sources

| Source | Type | Modes | Free-tier limits | Status |
|---|---|---|---|---|
| **AbuseIPDB** | IP reputation | Per-indicator lookup | 1 000 lookups/day | Live (real key) |
| **VirusTotal** | File hash · URL · domain · IP | Per-indicator lookup | 4 req/min · 500/day | Live (real key) |
| **URLhaus** (abuse.ch) | Malicious URL + host | Bulk CSV poll every 6 h | none — open feed | Live (no key needed) |
| **Existing local IOC table** | Multi-type | Local DB lookup | — | Always-on |

Coordinator pipeline:

```
EnrichAsync(value, type, useExternal)
  ├─▶ Local DB exact match (fast, free)
  └─▶ if useExternal:
        for each adapter that SupportsType(type):
          1. Cache check (Redis, 1 h TTL — covers hits AND misses)
          2. Live adapter call if cache miss
          3. UPSERT hit into local IOC table (CreateAsync merges by (type,value))
        Re-query local DB so caller sees the freshly persisted matches
```

---

## Tests

| Suite | Framework | Count | Notes |
|---|---|---|---|
| Detection rules | xUnit + FluentAssertions | 54 | Positive + negative scenarios for every rule |
| Audit hash-chain integrity | xUnit | 12 | Tampering detection, insertion attacks, hash determinism |
| Auth — RBAC integration | xUnit + WebApplicationFactory + real Postgres | 30 | All 5 roles × endpoint matrix |
| Auth — password reset unit | xUnit + EF Core InMemory + Moq | 14 | Token gen, expiry, single-use, enum-safety |
| Auth — password reset integration | xUnit + WebApplicationFactory | 6 | End-to-end forgot → reset → login |
| Threat-intel adapters | xUnit + stub HttpClient | 17 | Score mapping, endpoint routing, error tolerance |
| Threat-intel cache | xUnit + `MemoryDistributedCache` | 6 | Hit/miss caching, key isolation, corrupt-JSON tolerance |
| Threat-intel coordinator | xUnit + EF Core InMemory + Moq | 6 | Cache short-circuit, miss caching, multi-adapter sync |
| Performance benchmarks | xUnit + Stopwatch | 4 | 10 k brute-force / 2 s · 5 k port-scan / 1 s · 1 k all-rules / 500 ms |
| ML models | pytest | 35 | Three models · happy path + edge cases |
| **Total .NET** | | **153** | All passing |

CI: GitHub Actions, 4 parallel jobs (backend + Postgres · desktop Windows · ML Python · frontend pnpm).

---

## Roadmap

Foundation hardening, auth polish, and the threat-intel pipeline are shipped. Remaining phases below.

| # | Phase | Status | Highlights |
|---|---|---|---|
| **0** | Foundation hardening | Shipped | Secrets externalization · API versioning · Serilog + correlation IDs · `IExceptionHandler` · Polly · 8 health checks · Redis · RabbitMQ · MailHog · Hangfire · Scalar |
| **1** | Auth polish | Shipped | Password reset (hashed single-use tokens) · refresh-token revocation · audit-trailed reset events |
| **2** | Real threat intel | Shipped | `IThreatFeedAdapter` pipeline · AbuseIPDB · VirusTotal · URLhaus · Redis cache · 6 h Hangfire sync · multi-source merge |
| **3** | Pluggable SOAR framework | Shipped | `IFirewallAdapter` · `IIdentityAdapter` · `INotificationAdapter` · `IEndpointAdapter` · 3 missing actions (IsolateEndpoint · DisableUser · ResetCredentials) · approval-timeout escalation |
| **4** | Advanced detection | Planned | YARA · Sigma rule engine · lateral movement · DNS tunneling · C2 beaconing · DGA · data exfil heuristics |
| **5** | SignalR real-time | Planned | `AlertHub` (`/hubs/alerts`) · live alert ticker · toast on Critical · Redis backplane already in place |
| **6** | Observability | Planned | OpenTelemetry traces + metrics · Prometheus `/metrics` endpoint · Grafana dashboard JSON · Jaeger (optional) |
| **7** | Attack simulator CLI | Planned | `dotnet attacksim brute-force / port-scan / c2-beacon / dga / exfil / full-kill-chain` — synthesize events, hit `/api/v1/ingest`, prove detection report |
| **8** | Cloud-ready | Planned | Multi-stage Dockerfiles · Terraform modules (VPC · RDS · EC2 t2.micro · Secrets Manager · CloudWatch · ECR · ALB) · GitHub Actions deploy job |
| **9** | Polish & demo materials | Planned | ADRs · demo script · Postman collection · architecture decision rationale · screen recordings |

---

## License

MIT

## Author

Built by Abhijeet Rane - every layer (collectors, detection, ML, SOAR, audit) implemented end-to-end rather than glued together from off-the-shelf SIEM components.
