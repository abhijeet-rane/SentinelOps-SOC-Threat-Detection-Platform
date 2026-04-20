using System.ComponentModel.DataAnnotations;

namespace SOCPlatform.Infrastructure.Configuration;

public sealed class SoarOptions
{
    public const string SectionName = "Soar";

    /// <summary>
    /// Pending playbook executions awaiting approval older than this many minutes
    /// trigger an escalation notification to the SOC Manager. Defaults to 30 min.
    /// </summary>
    [Range(1, 1440)] public int ApprovalTimeoutMinutes { get; init; } = 30;

    /// <summary>
    /// Optional auto-reject behavior — pending approvals older than this hard limit
    /// are auto-rejected. 0 disables. Defaults to 0 (escalate but never auto-reject).
    /// </summary>
    [Range(0, 10080)] public int AutoRejectAfterMinutes { get; init; } = 0;
}
