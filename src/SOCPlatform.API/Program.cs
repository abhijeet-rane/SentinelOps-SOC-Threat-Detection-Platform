using System.Text;
using System.Threading.RateLimiting;
using Asp.Versioning;
using DotNetEnv;
using FluentValidation;
using FluentValidation.AspNetCore;
using Hangfire;
using Hangfire.PostgreSql;
using HealthChecks.UI.Client;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using Scalar.AspNetCore;
using Serilog;
using Serilog.Enrichers.Span;
using SOCPlatform.API.Authorization;
using SOCPlatform.API.ExceptionHandlers;
using SOCPlatform.API.HealthChecks;
using SOCPlatform.API.Hubs;
using SOCPlatform.API.Middleware;
using SOCPlatform.Core.Interfaces;
using SOCPlatform.Detection;
using SOCPlatform.Detection.Playbooks;
using SOCPlatform.Detection.Rules;
using SOCPlatform.Infrastructure;
using SOCPlatform.Infrastructure.Configuration;
using SOCPlatform.Infrastructure.Data;
using SOCPlatform.Infrastructure.Jobs;
using SOCPlatform.Infrastructure.Observability;
using SOCPlatform.Infrastructure.Services;

// ────────────────────────────────────────────────────────────────────────────
// 0. Load .env.local (Development) — must run before WebApplication.CreateBuilder
//    so env vars are available for IConfiguration.
// ────────────────────────────────────────────────────────────────────────────
LoadDotEnv();

var builder = WebApplication.CreateBuilder(args);

// ────────────────────────────────────────────────────────────────────────────
// 1. Configuration: env-var override mapping (.env.local → IConfiguration)
//    Maps SCREAMING_SNAKE env vars onto the strongly-typed config sections.
// ────────────────────────────────────────────────────────────────────────────
ApplyEnvOverrides(builder.Configuration);

// ────────────────────────────────────────────────────────────────────────────
// 2. Serilog: structured JSON logs + correlation enrichment
// ────────────────────────────────────────────────────────────────────────────
builder.Host.UseSerilog((ctx, services, lc) => lc
    .ReadFrom.Configuration(ctx.Configuration)
    .ReadFrom.Services(services)
    .Enrich.FromLogContext()
    .Enrich.WithMachineName()
    .Enrich.WithThreadId()
    .Enrich.WithSpan()                     // ← TraceId + SpanId from current Activity
    .Enrich.WithProperty("Application", "SOCPlatform.API")
    .Enrich.WithProperty("Environment", ctx.HostingEnvironment.EnvironmentName)
    .WriteTo.Console(new Serilog.Formatting.Compact.RenderedCompactJsonFormatter())
    .WriteTo.File(
        new Serilog.Formatting.Compact.RenderedCompactJsonFormatter(),
        path: "logs/socplatform-.log",
        rollingInterval: RollingInterval.Day,
        retainedFileCountLimit: 14));

// ────────────────────────────────────────────────────────────────────────────
// 3. Infrastructure (DB, repositories, services, options, resilient HttpClients)
// ────────────────────────────────────────────────────────────────────────────
builder.Services.AddInfrastructure(builder.Configuration);

// ────────────────────────────────────────────────────────────────────────────
// 3b. OpenTelemetry (metrics + traces)
// ────────────────────────────────────────────────────────────────────────────
// Prometheus scrape endpoint at /metrics (see pipeline below).
// OTLP traces only if OTEL_EXPORTER_OTLP_ENDPOINT is set (Jaeger all-in-one
// default: http://localhost:4317). Metrics go through Prometheus regardless.
if (!builder.Environment.IsEnvironment("Testing"))
{
    var serviceName = "SOCPlatform.API";
    var otlpEndpoint = Environment.GetEnvironmentVariable("OTEL_EXPORTER_OTLP_ENDPOINT");

    builder.Services.AddOpenTelemetry()
        .ConfigureResource(r => r.AddService(serviceName, serviceVersion: "1.0.0"))
        .WithMetrics(m => m
            .AddMeter(SocMetrics.MeterName)
            .AddAspNetCoreInstrumentation()
            .AddHttpClientInstrumentation()
            .AddRuntimeInstrumentation()
            .AddPrometheusExporter())
        .WithTracing(t =>
        {
            t.AddSource(SocActivitySource.Name)
             .AddAspNetCoreInstrumentation(o => o.Filter = ctx =>
                 // Don't spam traces for metrics scrapes and health probes
                 !ctx.Request.Path.StartsWithSegments("/metrics") &&
                 !ctx.Request.Path.StartsWithSegments("/health"))
             .AddHttpClientInstrumentation();

            if (!string.IsNullOrWhiteSpace(otlpEndpoint))
            {
                t.AddOtlpExporter(o => o.Endpoint = new Uri(otlpEndpoint));
            }
        });
}

// ────────────────────────────────────────────────────────────────────────────
// 4. Detection Engine + Playbook Engine
// ────────────────────────────────────────────────────────────────────────────
// Baseline rules
builder.Services.AddSingleton<IDetectionRule, BruteForceRule>();
builder.Services.AddSingleton<IDetectionRule, PrivilegeEscalationRule>();
builder.Services.AddSingleton<IDetectionRule, PortScanRule>();
builder.Services.AddSingleton<IDetectionRule, SuspiciousHashRule>();
builder.Services.AddSingleton<IDetectionRule, PolicyViolationRule>();
builder.Services.AddSingleton<IDetectionRule, AccountEnumerationRule>();
builder.Services.AddSingleton<IDetectionRule, AfterHoursActivityRule>();
// Advanced heuristic rules (Phase 4)
builder.Services.AddSingleton<IDetectionRule, SOCPlatform.Detection.Rules.Advanced.C2BeaconingRule>();
builder.Services.AddSingleton<IDetectionRule, SOCPlatform.Detection.Rules.Advanced.DgaDetectionRule>();
builder.Services.AddSingleton<IDetectionRule, SOCPlatform.Detection.Rules.Advanced.DnsTunnelingRule>();
builder.Services.AddSingleton<IDetectionRule, SOCPlatform.Detection.Rules.Advanced.DataExfiltrationRule>();
builder.Services.AddSingleton<IDetectionRule, SOCPlatform.Detection.Rules.Advanced.LateralMovementRule>();
// Sigma + YARA rule engines (Phase 4)
builder.Services.AddSingleton<SOCPlatform.Detection.Rules.Sigma.SigmaRuleLoader>();
builder.Services.AddSingleton<IDetectionRule, SOCPlatform.Detection.Rules.Sigma.SigmaDetectionRule>();
builder.Services.AddSingleton<SOCPlatform.Detection.Rules.Yara.YaraRuleLoader>();
builder.Services.AddSingleton<IDetectionRule, SOCPlatform.Detection.Rules.Yara.YaraDetectionRule>();

builder.Services.AddHostedService<DetectionEngine>();
builder.Services.AddHostedService<CorrelationEngine>();

// SOAR actions — scoped because they pull in scoped adapters (DbContext, IEmailSender).
builder.Services.AddScoped<IPlaybookAction, BlockIpAction>();
builder.Services.AddScoped<IPlaybookAction, LockAccountAction>();
builder.Services.AddScoped<IPlaybookAction, NotifyManagerAction>();
builder.Services.AddScoped<IPlaybookAction, EscalateAlertAction>();
builder.Services.AddScoped<IPlaybookAction, IsolateEndpointAction>();
builder.Services.AddScoped<IPlaybookAction, DisableUserAction>();
builder.Services.AddScoped<IPlaybookAction, ResetCredentialsAction>();
builder.Services.AddHostedService<PlaybookEngine>();

builder.Services.AddScoped<ReportService>();

// ────────────────────────────────────────────────────────────────────────────
// 5. Authentication (JWT) — reads strongly-typed JwtOptions
// ────────────────────────────────────────────────────────────────────────────
var jwtOptions = builder.Configuration.GetSection(JwtOptions.SectionName).Get<JwtOptions>()
    ?? throw new InvalidOperationException("JwtSettings section missing in configuration.");

builder.Services.AddAuthentication(opts =>
{
    opts.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    opts.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(opts =>
{
    opts.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtOptions.Issuer,
        ValidAudience = jwtOptions.Audience,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtOptions.SecretKey)),
        ClockSkew = TimeSpan.Zero
    };

    // SignalR: token via query string for /hubs/* endpoints
    opts.Events = new JwtBearerEvents
    {
        OnMessageReceived = ctx =>
        {
            var token = ctx.Request.Query["access_token"];
            if (!string.IsNullOrEmpty(token) && ctx.HttpContext.Request.Path.StartsWithSegments("/hubs"))
                ctx.Token = token;
            return Task.CompletedTask;
        }
    };
});

builder.Services.AddSingleton<IAuthorizationHandler, PermissionAuthorizationHandler>();
builder.Services.AddAuthorization(o => o.AddPermissionPolicies());

// ────────────────────────────────────────────────────────────────────────────
// 6. API Versioning
// ────────────────────────────────────────────────────────────────────────────
builder.Services
    .AddApiVersioning(o =>
    {
        o.DefaultApiVersion = new ApiVersion(1, 0);
        o.AssumeDefaultVersionWhenUnspecified = true;
        o.ReportApiVersions = true;
    })
    .AddMvc()
    .AddApiExplorer(o =>
    {
        o.GroupNameFormat = "'v'VVV";
        o.SubstituteApiVersionInUrl = true;
    });

// ────────────────────────────────────────────────────────────────────────────
// 7. Rate Limiting (sliding window)
// ────────────────────────────────────────────────────────────────────────────
builder.Services.AddRateLimiter(o =>
{
    o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

    o.AddPolicy("dashboard", ctx =>
        RateLimitPartition.GetSlidingWindowLimiter(
            partitionKey: ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new SlidingWindowRateLimiterOptions
            {
                PermitLimit = 100,
                Window = TimeSpan.FromMinutes(1),
                SegmentsPerWindow = 6,
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 5
            }));

    o.AddPolicy("ingestion", ctx =>
        RateLimitPartition.GetSlidingWindowLimiter(
            partitionKey: ctx.Request.Headers["X-API-Key"].ToString(),
            factory: _ => new SlidingWindowRateLimiterOptions
            {
                PermitLimit = 1000,
                Window = TimeSpan.FromMinutes(1),
                SegmentsPerWindow = 10,
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 50
            }));

    // MFA code verify: a stolen password must not be able to brute-force
    // 6-digit codes. 10 attempts / 10 min / IP is plenty for an honest user
    // who fat-fingered a code or two, and crushes any online brute force.
    o.AddPolicy("mfa-verify", ctx =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 10,
                Window = TimeSpan.FromMinutes(10),
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 0,
            }));
});

// ────────────────────────────────────────────────────────────────────────────
// 8. CORS — uses CorsOptions.AllowedOrigins
// ────────────────────────────────────────────────────────────────────────────
var corsOpts = builder.Configuration.GetSection(CorsOptions.SectionName).Get<CorsOptions>() ?? new CorsOptions();
builder.Services.AddCors(o => o.AddPolicy("SOCDashboard", p => p
    .WithOrigins(corsOpts.AllowedOrigins)
    .AllowAnyHeader()
    .AllowAnyMethod()
    .AllowCredentials()));

// ────────────────────────────────────────────────────────────────────────────
// 9. SignalR + Redis backplane — AlertHub for real-time alert push
// ────────────────────────────────────────────────────────────────────────────
var redisOpts = builder.Configuration.GetSection(RedisOptions.SectionName).Get<RedisOptions>() ?? new RedisOptions();
builder.Services.AddSignalR()
    .AddStackExchangeRedis(redisOpts.ConnectionString, o => o.Configuration.ChannelPrefix = StackExchange.Redis.RedisChannel.Literal("socplatform-signalr"));

// IAlertNotifier → SignalRAlertNotifier in prod, NullAlertNotifier in tests.
// Detection engine always gets a working notifier, even in isolated test runs.
if (builder.Environment.IsEnvironment("Testing"))
    builder.Services.AddSingleton<IAlertNotifier, NullAlertNotifier>();
else
    builder.Services.AddSingleton<IAlertNotifier, SignalRAlertNotifier>();

// ────────────────────────────────────────────────────────────────────────────
// 10. Distributed Cache (Redis)
// ────────────────────────────────────────────────────────────────────────────
builder.Services.AddStackExchangeRedisCache(o =>
{
    o.Configuration = redisOpts.ConnectionString;
    o.InstanceName = redisOpts.InstanceName;
});

// ────────────────────────────────────────────────────────────────────────────
// 11. Hangfire (Postgres backend) — skipped in Testing to avoid the schema
// installer race when multiple WebApplicationFactory<Program> instances boot
// in parallel. No test exercises Hangfire.
// ────────────────────────────────────────────────────────────────────────────
if (!builder.Environment.IsEnvironment("Testing"))
{
    var hangfireConn = builder.Configuration.GetConnectionString("Hangfire")
        ?? builder.Configuration.GetConnectionString("DefaultConnection")
        ?? throw new InvalidOperationException("Hangfire connection string missing.");

    builder.Services.AddHangfire(cfg => cfg
        .SetDataCompatibilityLevel(CompatibilityLevel.Version_180)
        .UseSimpleAssemblyNameTypeSerializer()
        .UseRecommendedSerializerSettings()
        .UsePostgreSqlStorage(c => c.UseNpgsqlConnection(hangfireConn)));
    builder.Services.AddHangfireServer();
}

// ────────────────────────────────────────────────────────────────────────────
// 12. FluentValidation
// ────────────────────────────────────────────────────────────────────────────
builder.Services.AddValidatorsFromAssemblyContaining<Program>();
builder.Services.AddFluentValidationAutoValidation();

// ────────────────────────────────────────────────────────────────────────────
// 13. Global Exception Handler (.NET 10 IExceptionHandler) + ProblemDetails
// ────────────────────────────────────────────────────────────────────────────
builder.Services.AddExceptionHandler<GlobalExceptionHandler>();
builder.Services.AddProblemDetails();

// ────────────────────────────────────────────────────────────────────────────
// 14. Health Checks
// ────────────────────────────────────────────────────────────────────────────
var rabbitOpts = builder.Configuration.GetSection(RabbitMqOptions.SectionName).Get<RabbitMqOptions>() ?? new RabbitMqOptions();
var mlOpts     = builder.Configuration.GetSection(MlServiceOptions.SectionName).Get<MlServiceOptions>() ?? new MlServiceOptions();

// Only register dependency-backed health checks when the upstream config is
// populated. This keeps startup robust in Testing (WebApplicationFactory
// injects test config after CreateBuilder) and dev without the full stack up.
// In Production, ValidateRequiredSecrets has already rejected empty values
// for the DB / Redis / Rabbit / ML keys below, so they're guaranteed here.
var hcBuilder = builder.Services.AddHealthChecks()
    .AddCheck("self", () => HealthCheckResult.Healthy(), tags: ["live"]);

var pgConn = builder.Configuration.GetConnectionString("DefaultConnection");
if (!string.IsNullOrWhiteSpace(pgConn))
    hcBuilder.AddNpgSql(pgConn, name: "postgres", tags: ["ready", "db"]);

if (!string.IsNullOrWhiteSpace(redisOpts.Host))
    hcBuilder.AddRedis(redisOpts.ConnectionString, name: "redis", tags: ["ready", "cache"]);

if (!string.IsNullOrWhiteSpace(rabbitOpts.Host))
{
    hcBuilder.AddRabbitMQ(
        sp => new RabbitMQ.Client.ConnectionFactory
        {
            HostName = rabbitOpts.Host,
            Port = rabbitOpts.Port,
            UserName = rabbitOpts.UserName,
            Password = rabbitOpts.Password,
            VirtualHost = rabbitOpts.VirtualHost
        }.CreateConnectionAsync(),
        name: "rabbitmq", tags: ["ready", "queue"]);
}

if (!string.IsNullOrWhiteSpace(mlOpts.BaseUrl) && Uri.TryCreate(mlOpts.BaseUrl, UriKind.Absolute, out var mlBaseUri))
{
    hcBuilder.AddUrlGroup(new Uri(mlBaseUri, "/api/ml/status"),
                          name: "ml-service", tags: ["ready", "external"]);
}

hcBuilder
    .AddCheck<AbuseIpDbHealthCheck>("abuseipdb", tags: ["ready", "external"])
    .AddCheck<VirusTotalHealthCheck>("virustotal", tags: ["ready", "external"])
    .AddCheck<SmtpHealthCheck>("smtp", tags: ["ready", "external"]);

// ────────────────────────────────────────────────────────────────────────────
// 15. Controllers + OpenAPI + Scalar
// ────────────────────────────────────────────────────────────────────────────
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddOpenApi();

builder.Services.AddSingleton<AuditSaveChangesInterceptor>();

var app = builder.Build();

// ────────────────────────────────────────────────────────────────────────────
// Fail-fast secret validation (Production + Staging only).
// Development and Testing tolerate missing values so local + CI runs work.
// ────────────────────────────────────────────────────────────────────────────
ValidateRequiredSecrets(app);

// ════════════════════════════════════════════════════════════════════════════
//                              PIPELINE (order matters)
// ════════════════════════════════════════════════════════════════════════════

// 1. Correlation ID — must be first so every log carries it
app.UseMiddleware<CorrelationIdMiddleware>();

// 2. Serilog request logging
app.UseSerilogRequestLogging(o =>
{
    o.MessageTemplate = "HTTP {RequestMethod} {RequestPath} → {StatusCode} in {Elapsed:0.00}ms";
});

// 3. Global exception handler (.NET 10 native)
app.UseExceptionHandler();
app.UseStatusCodePages();

// 4. Security headers (OWASP)
app.Use(async (ctx, next) =>
{
    var h = ctx.Response.Headers;
    h["X-Content-Type-Options"]            = "nosniff";
    h["X-Frame-Options"]                   = "DENY";
    h["X-Permitted-Cross-Domain-Policies"] = "none";
    h["Referrer-Policy"]                   = "strict-origin-when-cross-origin";
    h["Permissions-Policy"]                = "camera=(), microphone=(), geolocation=(), payment=()";
    h["Strict-Transport-Security"]         = "max-age=31536000; includeSubDomains; preload";
    h["Content-Security-Policy"]           =
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
        "img-src 'self' data:; connect-src 'self' http://localhost:5173 http://localhost:5101 ws: wss:";
    await next();
});

// 5. Request size + input sanitization
app.UseMiddleware<RequestSizeLimitMiddleware>();
app.UseMiddleware<InputSanitizationMiddleware>();

// 6. Rate limiting
app.UseRateLimiter();

// 7. CORS (before auth)
app.UseCors("SOCDashboard");

// 8. HMAC + API key (agent ingestion path)
app.UseMiddleware<HmacRequestSigningMiddleware>();
app.UseMiddleware<ApiKeyAuthenticationMiddleware>();

// 9. Auth
app.UseAuthentication();
app.UseAuthorization();

// 10. Endpoints
app.MapControllers();
app.MapHub<AlertHub>("/hubs/alerts");

// Prometheus scrape endpoint. Token-gated by MetricsAuthMiddleware in
// Production/Staging — Prometheus must send `Authorization: Bearer <token>`
// where <token> matches Security:MetricsScrapeToken. Dev is open for
// developer convenience; Testing is disabled entirely.
if (!app.Environment.IsEnvironment("Testing"))
{
    app.UseWhen(
        ctx => ctx.Request.Path.StartsWithSegments("/metrics", StringComparison.OrdinalIgnoreCase),
        branch => branch.UseMiddleware<MetricsAuthMiddleware>());

    app.MapPrometheusScrapingEndpoint("/metrics");
}

// Health endpoints
app.MapHealthChecks("/health/live", new HealthCheckOptions
{
    Predicate = r => r.Tags.Contains("live"),
    ResponseWriter = UIResponseWriter.WriteHealthCheckUIResponse
});
app.MapHealthChecks("/health/ready", new HealthCheckOptions
{
    Predicate = r => r.Tags.Contains("ready"),
    ResponseWriter = UIResponseWriter.WriteHealthCheckUIResponse
});
app.MapHealthChecks("/health", new HealthCheckOptions
{
    ResponseWriter = UIResponseWriter.WriteHealthCheckUIResponse
});

// Hangfire dashboard + recurring jobs (disabled in Testing — see Hangfire registration above)
if (!app.Environment.IsEnvironment("Testing"))
{
    app.UseHangfireDashboard("/hangfire", new DashboardOptions
    {
        Authorization = [new HangfireDashboardAuthFilter()],
        DashboardTitle = "SentinelOps · Background Jobs"
    });

    var recurringJobs = app.Services.GetRequiredService<IRecurringJobManager>();

    // Threat-feed bulk sync every 6 hours.
    recurringJobs.AddOrUpdate<ThreatFeedSyncJob>(
        recurringJobId: ThreatFeedSyncJob.RecurringJobId,
        methodCall: job => job.RunAsync(CancellationToken.None),
        cronExpression: "0 */6 * * *",
        options: new RecurringJobOptions { TimeZone = TimeZoneInfo.Utc });

    // SOAR approval-timeout sweep every 5 minutes.
    recurringJobs.AddOrUpdate<ApprovalTimeoutEscalationJob>(
        recurringJobId: ApprovalTimeoutEscalationJob.RecurringJobId,
        methodCall: job => job.RunAsync(CancellationToken.None),
        cronExpression: "*/5 * * * *",
        options: new RecurringJobOptions { TimeZone = TimeZoneInfo.Utc });

    // SLA-breach counter: every minute, count newly-breached alerts into the
    // socp_sla_breaches_total Prometheus counter.
    recurringJobs.AddOrUpdate<SlaBreachTrackerJob>(
        recurringJobId: SlaBreachTrackerJob.RecurringJobId,
        methodCall: job => job.RunAsync(CancellationToken.None),
        cronExpression: "* * * * *",
        options: new RecurringJobOptions { TimeZone = TimeZoneInfo.Utc });
}

// OpenAPI + Scalar
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference("/scalar", o =>
    {
        o.Title = "SentinelOps SOC API";
        o.Theme = ScalarTheme.BluePlanet;
    });
}

// ────────────────────────────────────────────────────────────────────────────
// Auto-migrate + seed in Development AND Testing.
// Testing is included so CI integration tests (which use WebApplicationFactory
// with Environment=Testing) get a populated schema without an explicit
// `dotnet ef database update` step. EF's MigrateAsync uses a Postgres
// advisory lock so concurrent factory startups serialize safely. The seed
// step catches DbUpdateException to tolerate a TOCTOU race when two factories
// race past the "if no roles exist" check at the same time.
// ────────────────────────────────────────────────────────────────────────────
if (app.Environment.IsDevelopment() || app.Environment.IsEnvironment("Testing"))
{
    using var scope = app.Services.CreateScope();
    var db = scope.ServiceProvider.GetRequiredService<SOCDbContext>();
    await db.Database.MigrateAsync();

    try
    {
        var seeder = scope.ServiceProvider.GetRequiredService<DatabaseSeeder>();
        await seeder.SeedAsync();
    }
    catch (Microsoft.EntityFrameworkCore.DbUpdateException)
    {
        // Concurrent factory startup raced past idempotency check — safe to ignore.
    }
}

app.Run();

// ════════════════════════════════════════════════════════════════════════════
//                              HELPERS
// ════════════════════════════════════════════════════════════════════════════

static void LoadDotEnv()
{
    // Walk up from CWD to find .env.local (project may be run from any subdir)
    var dir = new DirectoryInfo(Directory.GetCurrentDirectory());
    while (dir is not null)
    {
        var envFile = Path.Combine(dir.FullName, ".env.local");
        if (File.Exists(envFile))
        {
            Env.Load(envFile);
            return;
        }
        dir = dir.Parent;
    }
}

static void ApplyEnvOverrides(IConfigurationBuilder builder)
{
    var map = new Dictionary<string, string>
    {
        ["SENDGRID_API_KEY"]      = "Email:SendGrid:ApiKey",
        ["EMAIL_FROM_ADDRESS"]    = "Email:FromAddress",
        ["EMAIL_FROM_NAME"]       = "Email:FromName",
        ["EMAIL_REPLY_TO"]        = "Email:ReplyTo",
        ["EMAIL_PROVIDER"]        = "Email:Provider",
        ["SMTP_HOST"]             = "Email:Smtp:Host",
        ["SMTP_PORT"]             = "Email:Smtp:Port",
        ["ABUSEIPDB_API_KEY"]     = "ThreatIntel:AbuseIpDb:ApiKey",
        ["VIRUSTOTAL_API_KEY"]    = "ThreatIntel:VirusTotal:ApiKey",
        ["JWT_SECRET_KEY"]        = "JwtSettings:SecretKey",
        ["REDIS_HOST"]            = "Redis:Host",
        ["REDIS_PORT"]            = "Redis:Port",
        ["REDIS_PASSWORD"]        = "Redis:Password",
        ["RABBITMQ_HOST"]         = "RabbitMq:Host",
        ["RABBITMQ_PORT"]         = "RabbitMq:Port",
        ["RABBITMQ_USER"]         = "RabbitMq:UserName",
        ["RABBITMQ_PASSWORD"]     = "RabbitMq:Password",
        ["ML_SERVICE_URL"]             = "MlService:BaseUrl",
        ["ML_SERVICE_API_KEY"]         = "MlService:ApiKey",
        ["METRICS_SCRAPE_TOKEN"]       = "Security:MetricsScrapeToken",
        ["REQUIRE_HMAC_INGESTION"]     = "Security:RequireHmacIngestion",
        ["ALLOW_INSECURE_AGENT_TLS"]   = "Security:AllowInsecureAgentTls",
        ["SEED_ADMIN_PASSWORD"]        = "Seed:AdminPassword",
        ["SEED_MANAGER_PASSWORD"]      = "Seed:ManagerPassword",
        ["SEED_L2_PASSWORD"]           = "Seed:L2Password",
        ["SEED_L1_PASSWORD"]           = "Seed:L1Password",
    };

    var overrides = new Dictionary<string, string?>();
    foreach (var (envKey, configKey) in map)
    {
        var value = Environment.GetEnvironmentVariable(envKey);
        if (!string.IsNullOrEmpty(value))
            overrides[configKey] = value;
    }
    if (overrides.Count > 0)
        builder.AddInMemoryCollection(overrides);
}

// ────────────────────────────────────────────────────────────────────────────
// Fail-fast in Production if a required secret is blank / still a placeholder.
// Every key here is something the app needs to function at all — a blank means
// "operator forgot to set the env var" and we'd rather crash than boot in a
// known-broken state.
// ────────────────────────────────────────────────────────────────────────────
static void ValidateRequiredSecrets(WebApplication app)
{
    if (!app.Environment.IsProduction() && !app.Environment.IsStaging()) return;

    var cfg = app.Configuration;
    var missing = new List<string>();

    void Require(string key, Func<string?, bool>? extraCheck = null)
    {
        var v = cfg[key];
        if (string.IsNullOrWhiteSpace(v) || (extraCheck is not null && extraCheck(v)))
            missing.Add(key);
    }

    // Database + cache + queue
    Require("ConnectionStrings:DefaultConnection");
    Require("ConnectionStrings:Hangfire");
    Require("Redis:Host");
    Require("Redis:Password");
    Require("RabbitMq:Host");
    Require("RabbitMq:UserName");
    Require("RabbitMq:Password");

    // JWT — reject the literal placeholder shipped in appsettings.json,
    // and anything shorter than 32 chars (≈ 256 bits for HS256).
    Require("JwtSettings:SecretKey", v =>
        (v ?? "").Contains("CHANGE-THIS-IN-PRODUCTION", StringComparison.OrdinalIgnoreCase) ||
        (v ?? "").Contains("dev-only-key", StringComparison.OrdinalIgnoreCase) ||
        (v ?? "").Length < 32);

    // ML service key — required for service-to-service auth.
    Require("MlService:BaseUrl");
    Require("MlService:ApiKey");

    // /metrics token — required so Prometheus is not world-scrapable.
    Require("Security:MetricsScrapeToken");

    if (missing.Count == 0) return;

    var logger = app.Services.GetRequiredService<ILogger<Program>>();
    logger.LogCritical(
        "Startup aborted: {Count} required configuration value(s) are unset or still a placeholder in {Env}: {Keys}. " +
        "Populate them via environment variables or appsettings secrets and retry.",
        missing.Count, app.Environment.EnvironmentName, string.Join(", ", missing));

    throw new InvalidOperationException(
        $"Refusing to start {app.Environment.EnvironmentName} with missing secrets: {string.Join(", ", missing)}");
}

// Allow WebApplicationFactory<Program> in test project
public partial class Program { }
