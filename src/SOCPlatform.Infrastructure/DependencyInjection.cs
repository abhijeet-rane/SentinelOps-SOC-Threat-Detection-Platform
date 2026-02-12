using System.Threading.Channels;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using SOCPlatform.Core.Entities;
using SOCPlatform.Core.Interfaces;
using SOCPlatform.Infrastructure.Data;
using SOCPlatform.Infrastructure.Repositories;
using SOCPlatform.Infrastructure.Services;

namespace SOCPlatform.Infrastructure;

/// <summary>
/// Dependency injection registration for all Infrastructure services.
/// </summary>
public static class DependencyInjection
{
    public static IServiceCollection AddInfrastructure(this IServiceCollection services, IConfiguration configuration)
    {
        // Database
        services.AddDbContext<SOCDbContext>((sp, options) =>
        {
            options.UseNpgsql(configuration.GetConnectionString("DefaultConnection"));
            options.AddInterceptors(sp.GetRequiredService<AuditSaveChangesInterceptor>());
        });

        // Repositories
        services.AddScoped(typeof(IRepository<>), typeof(Repository<>));
        services.AddScoped<IUnitOfWork, UnitOfWork>();

        // Seeder
        services.AddScoped<DatabaseSeeder>();

        // Application services
        services.AddScoped<IAuthService, AuthService>();
        services.AddScoped<IAuditService, AuditService>();
        services.AddScoped<ILogIngestionService, LogIngestionService>();
        services.AddScoped<ThreatIntelService>();

        // In-app log processing queue (bounded channel, 10K capacity)
        services.AddSingleton(Channel.CreateBounded<Log>(new BoundedChannelOptions(10_000)
        {
            FullMode = BoundedChannelFullMode.Wait
        }));

        // Background services
        services.AddHostedService<LogRetentionService>();
        services.AddHostedService<LogProcessingService>();

        // Audit interceptor
        services.AddSingleton<AuditSaveChangesInterceptor>();

        return services;
    }
}
