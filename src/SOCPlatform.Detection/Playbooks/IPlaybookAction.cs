using SOCPlatform.Core.Entities;

namespace SOCPlatform.Detection.Playbooks;

/// <summary>
/// Interface for playbook action handlers. Each handler implements a specific automated response.
/// </summary>
public interface IPlaybookAction
{
    /// <summary>The type of action this handler performs.</summary>
    Core.Enums.PlaybookActionType ActionType { get; }

    /// <summary>
    /// Execute the automated response against the given alert.
    /// Returns a result message describing what was done.
    /// </summary>
    Task<string> ExecuteAsync(Alert alert, string? actionConfig, CancellationToken ct = default);
}
