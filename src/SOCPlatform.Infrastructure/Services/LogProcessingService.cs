using System.Threading.Channels;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SOCPlatform.Core.Entities;
using SOCPlatform.Core.Interfaces;

namespace SOCPlatform.Infrastructure.Services;

/// <summary>
/// BackgroundService that reads from the Channel&lt;Log&gt; queue and enriches logs
/// with threat intelligence data. Runs continuously while the app is alive.
/// </summary>
public class LogProcessingService : BackgroundService
{
    private readonly Channel<Log> _channel;
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<LogProcessingService> _logger;

    public LogProcessingService(
        Channel<Log> channel,
        IServiceProvider serviceProvider,
        ILogger<LogProcessingService> logger)
    {
        _channel = channel;
        _serviceProvider = serviceProvider;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Log processing service started – awaiting logs");

        await foreach (var log in _channel.Reader.ReadAllAsync(stoppingToken))
        {
            try
            {
                using var scope = _serviceProvider.CreateScope();
                var ingestionService = scope.ServiceProvider.GetRequiredService<ILogIngestionService>();
                await ingestionService.EnrichLogAsync(log);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error enriching log {LogId}", log.Id);
            }
        }

        _logger.LogInformation("Log processing service stopped");
    }
}
