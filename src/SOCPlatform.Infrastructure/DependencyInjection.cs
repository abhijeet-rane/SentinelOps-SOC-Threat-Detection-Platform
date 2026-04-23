using System.Threading.Channels;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using SOCPlatform.Core.Entities;
using SOCPlatform.Core.Interfaces;
using SOCPlatform.Core.Soar;
using SOCPlatform.Infrastructure.Configuration;
using SOCPlatform.Infrastructure.Data;
using SOCPlatform.Infrastructure.Email;
using SOCPlatform.Infrastructure.Jobs;
using SOCPlatform.Infrastructure.Observability;
using SOCPlatform.Infrastructure.Repositories;
using SOCPlatform.Infrastructure.Resilience;
using SOCPlatform.Infrastructure.Services;
using SOCPlatform.Infrastructure.Soar;
using SOCPlatform.Infrastructure.Soar.Adapters;
using SOCPlatform.Infrastructure.ThreatIntel;
using SOCPlatform.Infrastructure.ThreatIntel.Adapters;
using SOCPlatform.Infrastructure.ThreatIntel.Cache;

namespace SOCPlatform.Infrastructure;

/// <summary>
/// Dependency injection registration for all Infrastructure services.
/// </summary>
public static class DependencyInjection
{
    public static IServiceCollection AddInfrastructure(this IServiceCollection services, IConfiguration configuration)
    {
        // ── Strongly-typed options with startup validation ────────────────────
        services.AddOptionsWithValidation<JwtOptions>(configuration, JwtOptions.SectionName);
        services.AddOptionsWithValidation<RedisOptions>(configuration, RedisOptions.SectionName);
        services.AddOptionsWithValidation<RabbitMqOptions>(configuration, RabbitMqOptions.SectionName);
        services.AddOptionsWithValidation<EmailOptions>(configuration, EmailOptions.SectionName);
        services.AddOptionsWithValidation<MlServiceOptions>(configuration, MlServiceOptions.SectionName);
        services.AddOptionsWithValidation<AuthOptions>(configuration, AuthOptions.SectionName);

        services.Configure<ThreatIntelOptions>(configuration.GetSection(ThreatIntelOptions.SectionName));
        services.Configure<CorsOptions>(configuration.GetSection(CorsOptions.SectionName));
        services.Configure<SoarOptions>(configuration.GetSection(SoarOptions.SectionName));

        // ── Database ──────────────────────────────────────────────────────────
        services.AddDbContext<SOCDbContext>((sp, options) =>
        {
            options.UseNpgsql(configuration.GetConnectionString("DefaultConnection"));
            options.AddInterceptors(sp.GetRequiredService<AuditSaveChangesInterceptor>());
        });

        // ── Repositories / UoW ────────────────────────────────────────────────
        services.AddScoped(typeof(IRepository<>), typeof(Repository<>));
        services.AddScoped<IUnitOfWork, UnitOfWork>();
        services.AddScoped<DatabaseSeeder>();

        // ── Data Protection (required by MfaService for secret encryption) ──
        // Keys are stored by default in %LOCALAPPDATA%/ASP.NET/DataProtection-Keys
        // on Windows and /home/$USER/.aspnet/DataProtection-Keys on Linux. For
        // production behind Docker this volume is persisted via docker-compose.
        services.AddDataProtection();

        // ── Application services ──────────────────────────────────────────────
        services.AddScoped<IMfaService, MfaService>();
        services.AddScoped<IAuthService, AuthService>();
        services.AddScoped<IAuditService, AuditService>();
        services.AddScoped<IPasswordResetService, PasswordResetService>();
        services.AddScoped<ILogIngestionService, LogIngestionService>();
        services.AddScoped<ThreatIntelService>();

        // ── Threat-intel adapter pipeline ──────────────────────────────────
        services.AddSingleton<IThreatIntelCache, RedisThreatIntelCache>();
        services.AddSingleton<IThreatFeedAdapter, AbuseIpDbAdapter>();
        services.AddSingleton<IThreatFeedAdapter, VirusTotalAdapter>();
        services.AddSingleton<IThreatFeedAdapter, UrlhausAdapter>();
        services.AddScoped<ThreatFeedCoordinator>();
        services.AddScoped<ThreatFeedSyncJob>();

        // ── SOAR adapter pipeline ──────────────────────────────────────────
        // Adapters are scoped because they touch the scoped DbContext.
        services.AddScoped<SimulatedActionRecorder>();
        services.AddScoped<IFirewallAdapter, SimulatedFirewallAdapter>();
        services.AddScoped<IIdentityAdapter, SimulatedIdentityAdapter>();
        services.AddScoped<IEndpointAdapter, SimulatedEndpointAdapter>();
        services.AddScoped<INotificationAdapter, EmailNotificationAdapter>(); // real, via IEmailSender
        services.AddScoped<ApprovalTimeoutEscalationJob>();

        // ── Email sender (provider chosen via EmailOptions.Provider) ──────────
        services.AddSingleton<IEmailSender>(sp =>
        {
            var opts = sp.GetRequiredService<IOptions<EmailOptions>>().Value;
            return opts.Provider.Equals("SendGrid", StringComparison.OrdinalIgnoreCase)
                ? ActivatorUtilities.CreateInstance<SendGridEmailSender>(sp)
                : ActivatorUtilities.CreateInstance<SmtpEmailSender>(sp);
        });

        // ── Resilient HttpClients (Polly) ─────────────────────────────────────
        services.AddResilientHttpClient(PolicyRegistry.MlServiceClient, client =>
        {
            var ml = configuration.GetSection(MlServiceOptions.SectionName).Get<MlServiceOptions>()
                     ?? new MlServiceOptions();
            client.BaseAddress = new Uri(ml.BaseUrl);
            client.Timeout = TimeSpan.FromSeconds(ml.TimeoutSeconds);
            if (!string.IsNullOrWhiteSpace(ml.ApiKey))
                client.DefaultRequestHeaders.Add("X-API-Key", ml.ApiKey);
        }, timeoutSeconds: 30);

        services.AddResilientHttpClient(PolicyRegistry.AbuseIpDbClient, client =>
        {
            var ti = configuration.GetSection(ThreatIntelOptions.SectionName).Get<ThreatIntelOptions>()
                     ?? new ThreatIntelOptions();
            client.BaseAddress = new Uri(ti.AbuseIpDb.BaseUrl);
            if (!string.IsNullOrWhiteSpace(ti.AbuseIpDb.ApiKey))
                client.DefaultRequestHeaders.Add("Key", ti.AbuseIpDb.ApiKey);
            client.DefaultRequestHeaders.Add("Accept", "application/json");
        });

        services.AddResilientHttpClient(PolicyRegistry.VirusTotalClient, client =>
        {
            var ti = configuration.GetSection(ThreatIntelOptions.SectionName).Get<ThreatIntelOptions>()
                     ?? new ThreatIntelOptions();
            client.BaseAddress = new Uri(ti.VirusTotal.BaseUrl);
            if (!string.IsNullOrWhiteSpace(ti.VirusTotal.ApiKey))
                client.DefaultRequestHeaders.Add("x-apikey", ti.VirusTotal.ApiKey);
            client.DefaultRequestHeaders.Add("Accept", "application/json");
        });

        // ── Legacy MlIntegrationService (keeps existing typed-client wiring) ─
        services.AddHttpClient<MlIntegrationService>(client =>
        {
            var ml = configuration.GetSection(MlServiceOptions.SectionName).Get<MlServiceOptions>()
                     ?? new MlServiceOptions();
            client.BaseAddress = new Uri(ml.BaseUrl);
            client.Timeout = TimeSpan.FromSeconds(ml.TimeoutSeconds);
            if (!string.IsNullOrWhiteSpace(ml.ApiKey))
                client.DefaultRequestHeaders.Add("X-API-Key", ml.ApiKey);
        });

        // ── In-app log processing queue (kept for backward-compat) ────────────
        services.AddSingleton(Channel.CreateBounded<Log>(new BoundedChannelOptions(10_000)
        {
            FullMode = BoundedChannelFullMode.Wait
        }));

        // ── Background services ───────────────────────────────────────────────
        services.AddHostedService<LogRetentionService>();
        services.AddHostedService<LogProcessingService>();

        // ── Audit interceptor ─────────────────────────────────────────────────
        services.AddSingleton<AuditSaveChangesInterceptor>();

        // ── Observability (Phase 6) ───────────────────────────────────────────
        // IMeterFactory is registered by Microsoft.Extensions.Hosting. SocMetrics
        // is singleton so every component shares the same Counter/Histogram.
        services.AddSingleton<SocMetrics>();
        services.AddScoped<SlaBreachTrackerJob>();

        return services;
    }

    /// <summary>
    /// Bind + validate options at startup (fail-fast on missing/invalid config).
    /// </summary>
    private static IServiceCollection AddOptionsWithValidation<TOptions>(
        this IServiceCollection services, IConfiguration configuration, string sectionName)
        where TOptions : class
    {
        services.AddOptions<TOptions>()
            .Bind(configuration.GetSection(sectionName))
            .ValidateDataAnnotations()
            .ValidateOnStart();
        return services;
    }
}
