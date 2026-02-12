namespace SOCPlatform.Core.Enums;

/// <summary>
/// Types of automated response actions in SOAR playbooks.
/// </summary>
public enum PlaybookActionType
{
    BlockIp = 0,
    LockAccount = 1,
    NotifyManager = 2,
    EscalateAlert = 3,
    IsolateEndpoint = 4,
    DisableUser = 5,
    Custom = 99
}
