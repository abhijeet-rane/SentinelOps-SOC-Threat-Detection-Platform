namespace SOCPlatform.Core.Enums;

/// <summary>
/// Represents the lifecycle status of a security incident.
/// </summary>
public enum IncidentStatus
{
    Open = 0,
    Investigating = 1,
    Containment = 2,
    Eradication = 3,
    Recovery = 4,
    Resolved = 5,
    Closed = 6
}
