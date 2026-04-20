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
using Scalar.AspNetCore;
using Serilog;
using SOCPlatform.API.Authorization;
using SOCPlatform.API.ExceptionHandlers;
using SOCPlatform.API.HealthChecks;
using SOCPlatform.API.Middleware;
using SOCPlatform.Detection;
using SOCPlatform.Detection.Playbooks;
using SOCPlatform.Detection.Rules;
using SOCPlatform.Infrastructure;
using SOCPlatform.Infrastructure.Configuration;
using SOCPlatform.Infrastructure.Data;
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
// 4. Detection Engine + Playbook Engine
// ────────────────────────────────────────────────────────────────────────────
builder.Services.AddSingleton<IDetectionRule, BruteForceRule>();
builder.Services.AddSingleton<IDetectionRule, PrivilegeEscalationRule>();
builder.Services.AddSingleton<IDetectionRule, PortScanRule>();
builder.Services.AddSingleton<IDetectionRule, SuspiciousHashRule>();
builder.Services.AddSingleton<IDetectionRule, PolicyViolationRule>();
builder.Services.AddSingleton<IDetectionRule, AccountEnumerationRule>();
builder.Services.AddSingleton<IDetectionRule, AfterHoursActivityRule>();
builder.Services.AddHostedService<DetectionEngine>();
builder.Services.AddHostedService<CorrelationEngine>();

builder.Services.AddSingleton<IPlaybookAction, BlockIpAction>();
builder.Services.AddSingleton<IPlaybookAction, LockAccountAction>();
builder.Services.AddSingleton<IPlaybookAction, NotifyManagerAction>();
builder.Services.AddSingleton<IPlaybookAction, EscalateAlertAction>();
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
// 9. SignalR + Redis backplane (Phase 5 will add hubs)
// ────────────────────────────────────────────────────────────────────────────
var redisOpts = builder.Configuration.GetSection(RedisOptions.SectionName).Get<RedisOptions>() ?? new RedisOptions();
builder.Services.AddSignalR()
    .AddStackExchangeRedis(redisOpts.ConnectionString, o => o.Configuration.ChannelPrefix = StackExchange.Redis.RedisChannel.Literal("socplatform-signalr"));

// ────────────────────────────────────────────────────────────────────────────
// 10. Distributed Cache (Redis)
// ────────────────────────────────────────────────────────────────────────────
builder.Services.AddStackExchangeRedisCache(o =>
{
    o.Configuration = redisOpts.ConnectionString;
    o.InstanceName = redisOpts.InstanceName;
});

// ────────────────────────────────────────────────────────────────────────────
// 11. Hangfire (Postgres backend)
// ────────────────────────────────────────────────────────────────────────────
var hangfireConn = builder.Configuration.GetConnectionString("Hangfire")
    ?? builder.Configuration.GetConnectionString("DefaultConnection")
    ?? throw new InvalidOperationException("Hangfire connection string missing.");

builder.Services.AddHangfire(cfg => cfg
    .SetDataCompatibilityLevel(CompatibilityLevel.Version_180)
    .UseSimpleAssemblyNameTypeSerializer()
    .UseRecommendedSerializerSettings()
    .UsePostgreSqlStorage(c => c.UseNpgsqlConnection(hangfireConn)));
builder.Services.AddHangfireServer();

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

builder.Services.AddHealthChecks()
    // Liveness: just proves the process is up (no deps).
    .AddCheck("self", () => HealthCheckResult.Healthy(), tags: ["live"])

    // Readiness deps:
    .AddNpgSql(builder.Configuration.GetConnectionString("DefaultConnection")!,
               name: "postgres", tags: ["ready", "db"])
    .AddRedis(redisOpts.ConnectionString, name: "redis", tags: ["ready", "cache"])
    .AddRabbitMQ(
        sp => new RabbitMQ.Client.ConnectionFactory
        {
            HostName = rabbitOpts.Host,
            Port = rabbitOpts.Port,
            UserName = rabbitOpts.UserName,
            Password = rabbitOpts.Password,
            VirtualHost = rabbitOpts.VirtualHost
        }.CreateConnectionAsync(),
        name: "rabbitmq", tags: ["ready", "queue"])
    .AddUrlGroup(new Uri($"{mlOpts.BaseUrl.TrimEnd('/')}/api/ml/status"),
                 name: "ml-service", tags: ["ready", "external"])
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

// Hangfire dashboard (Admin only)
app.UseHangfireDashboard("/hangfire", new DashboardOptions
{
    Authorization = [new HangfireDashboardAuthFilter()],
    DashboardTitle = "SentinelOps · Background Jobs"
});

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
// Auto-migrate + seed in Development
// ────────────────────────────────────────────────────────────────────────────
if (app.Environment.IsDevelopment())
{
    using var scope = app.Services.CreateScope();
    var db = scope.ServiceProvider.GetRequiredService<SOCDbContext>();
    await db.Database.MigrateAsync();

    var seeder = scope.ServiceProvider.GetRequiredService<DatabaseSeeder>();
    await seeder.SeedAsync();
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
        ["ML_SERVICE_URL"]        = "MlService:BaseUrl",
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

// Allow WebApplicationFactory<Program> in test project
public partial class Program { }
