namespace SOCPlatform.Core.Enums;

/// <summary>
/// Granular permissions for RBAC enforcement.
/// Mapped to roles via RolePermission entities.
/// </summary>
public enum Permission
{
    // Alert permissions
    ViewAlerts = 100,
    AcknowledgeAlerts = 101,
    InvestigateAlerts = 102,
    EscalateAlerts = 103,

    // Incident permissions
    CreateIncidents = 200,
    ResolveIncidents = 201,
    ViewIncidents = 202,

    // Dashboard permissions
    ViewDashboards = 300,
    ViewOperationalKpis = 301,
    ViewExecutiveReports = 302,

    // Rule management (split: toggle vs CRUD)
    EnableDisableRules = 400,
    ManageRules = 401,

    // SOAR permissions
    ExecutePlaybooks = 500,
    ApproveResponses = 501,

    // Administration
    ManageUsers = 600,
    ManageApiKeys = 601,
    ViewAuditLogs = 602,
    ManageAuditLogs = 603,

    // System
    ViewSystemHealth = 700,
    ManageConfiguration = 701
}
