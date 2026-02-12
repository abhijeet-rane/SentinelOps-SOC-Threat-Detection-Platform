using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Hosting;
using SOCPlatform.Infrastructure.Data;

namespace SOCPlatform.Infrastructure.Services;

/// <summary>
/// Background service that periodically cleans up old logs based on retention policy.
/// Runs once daily, deleting logs older than the configured retention period.
/// </summary>
public class LogRetentionService : BackgroundService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<LogRetentionService> _logger;
    private readonly int _retentionDays;

    public LogRetentionService(
        IServiceProvider serviceProvider,
        IConfiguration configuration,
        ILogger<LogRetentionService> logger)
    {
        _serviceProvider = serviceProvider;
        _logger = logger;
        _retentionDays = configuration.GetValue<int>("LogRetention:RetentionDays", 14);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Log retention service started. Retention period: {Days} days", _retentionDays);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await CleanupOldLogsAsync(stoppingToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during log retention cleanup");
            }

            // Run once every 24 hours
            await Task.Delay(TimeSpan.FromHours(24), stoppingToken);
        }
    }

    private async Task CleanupOldLogsAsync(CancellationToken stoppingToken)
    {
        using var scope = _serviceProvider.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<SOCDbContext>();

        var cutoffDate = DateTime.UtcNow.AddDays(-_retentionDays);

        // Delete old logs in batches to avoid blocking
        const int batchSize = 1000;
        int totalDeleted = 0;

        while (!stoppingToken.IsCancellationRequested)
        {
            var deletedCount = await context.Logs
                .Where(l => l.IngestedAt < cutoffDate)
                .Take(batchSize)
                .ExecuteDeleteAsync(stoppingToken);

            totalDeleted += deletedCount;

            if (deletedCount < batchSize)
                break;

            // Small delay between batches to reduce DB load
            await Task.Delay(100, stoppingToken);
        }

        if (totalDeleted > 0)
        {
            _logger.LogInformation("Log retention cleanup: deleted {Count} logs older than {Days} days",
                totalDeleted, _retentionDays);
        }
    }
}
