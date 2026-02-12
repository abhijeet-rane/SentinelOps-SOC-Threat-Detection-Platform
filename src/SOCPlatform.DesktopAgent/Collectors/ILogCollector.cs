using SOCPlatform.Core.DTOs;

namespace SOCPlatform.DesktopAgent.Collectors;

/// <summary>
/// Base interface for all log collectors.
/// Each collector gathers specific types of events from the local machine.
/// </summary>
public interface ILogCollector
{
    string Name { get; }
    bool IsEnabled { get; }
    Task<List<LogIngestionDto>> CollectAsync(CancellationToken cancellationToken);
}
