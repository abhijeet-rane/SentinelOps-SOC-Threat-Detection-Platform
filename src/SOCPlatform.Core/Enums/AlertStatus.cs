namespace SOCPlatform.Core.Enums;

/// <summary>
/// Represents the lifecycle status of a security alert.
/// Follows real SOC alert workflow: NEW → IN_PROGRESS → ESCALATED → RESOLVED → CLOSED
/// </summary>
public enum AlertStatus
{
    New = 0,
    InProgress = 1,
    Escalated = 2,
    Resolved = 3,
    Closed = 4
}
