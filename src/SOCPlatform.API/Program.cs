using System.Text;
using System.Threading.RateLimiting;
using FluentValidation;
using FluentValidation.AspNetCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using SOCPlatform.API.Authorization;
using SOCPlatform.API.Middleware;
using SOCPlatform.Detection;
using SOCPlatform.Detection.Rules;
using SOCPlatform.Detection.Playbooks;
using SOCPlatform.Infrastructure;
using SOCPlatform.Infrastructure.Data;
using SOCPlatform.Infrastructure.Services;

var builder = WebApplication.CreateBuilder(args);

// ──────────────────────────────────────────────────
//  Infrastructure (DB, Repositories, Background Services)
// ──────────────────────────────────────────────────
builder.Services.AddInfrastructure(builder.Configuration);

// ──────────────────────────────────────────────────
//  Detection Engine (Rules + Background Services)
// ──────────────────────────────────────────────────
builder.Services.AddSingleton<IDetectionRule, BruteForceRule>();
builder.Services.AddSingleton<IDetectionRule, PrivilegeEscalationRule>();
builder.Services.AddSingleton<IDetectionRule, PortScanRule>();
builder.Services.AddSingleton<IDetectionRule, SuspiciousHashRule>();
builder.Services.AddSingleton<IDetectionRule, PolicyViolationRule>();
builder.Services.AddSingleton<IDetectionRule, AccountEnumerationRule>();
builder.Services.AddSingleton<IDetectionRule, AfterHoursActivityRule>();
builder.Services.AddHostedService<DetectionEngine>();
builder.Services.AddHostedService<CorrelationEngine>();

// ──────────────────────────────────────────────────
//  SOAR Playbook Engine (Actions + Background Service)
// ──────────────────────────────────────────────────
builder.Services.AddSingleton<IPlaybookAction, BlockIpAction>();
builder.Services.AddSingleton<IPlaybookAction, LockAccountAction>();
builder.Services.AddSingleton<IPlaybookAction, NotifyManagerAction>();
builder.Services.AddSingleton<IPlaybookAction, EscalateAlertAction>();
builder.Services.AddHostedService<PlaybookEngine>();

// ──────────────────────────────────────────────────
//  Reporting & Compliance
// ──────────────────────────────────────────────────
builder.Services.AddScoped<ReportService>();

// ──────────────────────────────────────────────────
//  ML Integration (Python microservice on port 8001)
// ──────────────────────────────────────────────────
builder.Services.AddHttpClient<MlIntegrationService>(client =>
{
    client.BaseAddress = new Uri("http://localhost:8001");
    client.Timeout = TimeSpan.FromSeconds(30);
});

// ──────────────────────────────────────────────────
//  Authentication (JWT Bearer)
// ──────────────────────────────────────────────────
var jwtSettings = builder.Configuration.GetSection("JwtSettings");
var secretKey = Encoding.UTF8.GetBytes(jwtSettings["SecretKey"]
    ?? throw new InvalidOperationException("JWT SecretKey not configured"));

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtSettings["Issuer"],
        ValidAudience = jwtSettings["Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(secretKey),
        ClockSkew = TimeSpan.Zero // No tolerance for token expiry
    };

    // Support SignalR token via query string
    options.Events = new JwtBearerEvents
    {
        OnMessageReceived = context =>
        {
            var accessToken = context.Request.Query["access_token"];
            var path = context.HttpContext.Request.Path;
            if (!string.IsNullOrEmpty(accessToken) && path.StartsWithSegments("/hubs"))
            {
                context.Token = accessToken;
            }
            return Task.CompletedTask;
        }
    };
});

// ──────────────────────────────────────────────────
//  Authorization (Permission-based RBAC)
// ──────────────────────────────────────────────────
builder.Services.AddSingleton<IAuthorizationHandler, PermissionAuthorizationHandler>();
builder.Services.AddAuthorization(options => options.AddPermissionPolicies());

// ──────────────────────────────────────────────────
//  Rate Limiting
// ──────────────────────────────────────────────────
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

    // Dashboard API: 100 requests/minute per IP
    options.AddPolicy("dashboard", context =>
        RateLimitPartition.GetSlidingWindowLimiter(
            partitionKey: context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new SlidingWindowRateLimiterOptions
            {
                PermitLimit = 100,
                Window = TimeSpan.FromMinutes(1),
                SegmentsPerWindow = 6,
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 5
            }));

    // Ingestion API: 1000 requests/minute per API key
    options.AddPolicy("ingestion", context =>
        RateLimitPartition.GetSlidingWindowLimiter(
            partitionKey: context.Request.Headers["X-API-Key"].ToString(),
            factory: _ => new SlidingWindowRateLimiterOptions
            {
                PermitLimit = 1000,
                Window = TimeSpan.FromMinutes(1),
                SegmentsPerWindow = 10,
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 50
            }));
});

// ──────────────────────────────────────────────────
//  FluentValidation
// ──────────────────────────────────────────────────
builder.Services.AddValidatorsFromAssemblyContaining<Program>();
builder.Services.AddFluentValidationAutoValidation();

// ──────────────────────────────────────────────────
//  CORS (Whitelist-only)
// ──────────────────────────────────────────────────
var allowedOrigins = builder.Configuration.GetSection("CorsSettings:AllowedOrigins").Get<string[]>()
    ?? new[] { "http://localhost:5173" };

builder.Services.AddCors(options =>
{
    options.AddPolicy("SOCDashboard", policy =>
    {
        policy.WithOrigins(allowedOrigins)
              .AllowAnyHeader()
              .AllowAnyMethod()
              .AllowCredentials(); // Required for SignalR
    });
});

// ──────────────────────────────────────────────────
//  SignalR (Real-time updates)
// ──────────────────────────────────────────────────
builder.Services.AddSignalR();

// ──────────────────────────────────────────────────
//  Controllers & API
// ──────────────────────────────────────────────────
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddOpenApi();

// ──────────────────────────────────────────────────
//  Build & Configure Pipeline
// ──────────────────────────────────────────────────
// ──────────────────────────────────────────────────
//  Audit Interceptor (EF Core)
// ──────────────────────────────────────────────────
builder.Services.AddSingleton<AuditSaveChangesInterceptor>();

// Health checks
builder.Services.AddHealthChecks()
    .AddDbContextCheck<SOCDbContext>("database");

var app = builder.Build();

// ──────────────────────────────────────────────────
//  Middleware Pipeline (order matters!)
// ──────────────────────────────────────────────────

// 0. Global exception handler (must be first to catch everything)
app.UseMiddleware<GlobalExceptionMiddleware>();

// 1. Security Headers (applies to all responses)
app.Use(async (context, next) =>
{
    context.Response.Headers.Append("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Append("X-Frame-Options", "DENY");
    context.Response.Headers.Append("X-XSS-Protection", "0");
    context.Response.Headers.Append("Referrer-Policy", "strict-origin-when-cross-origin");
    context.Response.Headers.Append("Permissions-Policy",
        "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), usb=()");
    context.Response.Headers.Append("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    context.Response.Headers.Append("Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' http://localhost:5173 http://localhost:5101 ws: wss:");
    await next();
});

// 2. Request size limit (5MB – blocks oversized payloads early)
app.UseMiddleware<RequestSizeLimitMiddleware>();

// 3. Input sanitization (XSS/SQLi – blocks malicious query params)
app.UseMiddleware<InputSanitizationMiddleware>();

// 4. Rate limiting
app.UseRateLimiter();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

// CORS must come before auth and controllers
app.UseCors("SOCDashboard");

// 5. HMAC request signing verification (agent ingestion)
app.UseMiddleware<HmacRequestSigningMiddleware>();

// 6. API key authentication (agent ingestion)
app.UseMiddleware<ApiKeyAuthenticationMiddleware>();

// 7. JWT authentication + RBAC authorization
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.MapHealthChecks("/health");

// ──────────────────────────────────────────────────
//  Auto-migrate & Seed database in development
// ──────────────────────────────────────────────────
if (app.Environment.IsDevelopment())
{
    using var scope = app.Services.CreateScope();
    var db = scope.ServiceProvider.GetRequiredService<SOCDbContext>();
    await db.Database.MigrateAsync();

    var seeder = scope.ServiceProvider.GetRequiredService<DatabaseSeeder>();
    await seeder.SeedAsync();
}

app.Run();
