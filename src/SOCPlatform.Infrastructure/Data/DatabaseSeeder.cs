using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using SOCPlatform.Core.Entities;
using SOCPlatform.Core.Enums;

namespace SOCPlatform.Infrastructure.Data;

/// <summary>
/// Seeds the database with initial roles, permissions, detection rules,
/// threat intelligence indicators, response playbooks, and a default admin user.
/// </summary>
public class DatabaseSeeder
{
    private readonly SOCDbContext _context;
    private readonly ILogger<DatabaseSeeder> _logger;

    public DatabaseSeeder(SOCDbContext context, ILogger<DatabaseSeeder> logger)
    {
        _context = context;
        _logger = logger;
    }

    public async Task SeedAsync()
    {
        await SeedRolesAndPermissionsAsync();
        await SeedDefaultUsersAsync();
        await SeedDetectionRulesAsync();
        await SeedThreatIntelAsync();
        await SeedResponsePlaybooksAsync();
        await _context.SaveChangesAsync();
        _logger.LogInformation("Database seeding completed successfully");
    }

    // ──────────────────────────────────────────────────
    //  Roles & Permissions (refined RBAC matrix)
    // ──────────────────────────────────────────────────
    private async Task SeedRolesAndPermissionsAsync()
    {
        if (await _context.Roles.AnyAsync()) return;

        var socL1 = new Role
        {
            Id = Guid.Parse("10000000-0000-0000-0000-000000000001"),
            Name = "SOC Analyst L1",
            Description = "Level 1 analyst – monitor alerts, review logs, acknowledge and escalate incidents"
        };

        var socL2 = new Role
        {
            Id = Guid.Parse("10000000-0000-0000-0000-000000000002"),
            Name = "SOC Analyst L2",
            Description = "Level 2 analyst – deep investigation, correlation, incident resolution, playbook execution"
        };

        var socManager = new Role
        {
            Id = Guid.Parse("10000000-0000-0000-0000-000000000003"),
            Name = "SOC Manager",
            Description = "SOC Manager – dashboards, KPIs, reports, rule toggling, response approval, analyst oversight"
        };

        var sysAdmin = new Role
        {
            Id = Guid.Parse("10000000-0000-0000-0000-000000000004"),
            Name = "System Administrator",
            Description = "System Admin – configuration, user management, full rule CRUD, API keys, audit logs"
        };

        await _context.Roles.AddRangeAsync(socL1, socL2, socManager, sysAdmin);

        // SOC Analyst L1 permissions
        var l1Permissions = new[]
        {
            Permission.ViewAlerts,
            Permission.AcknowledgeAlerts,
            Permission.EscalateAlerts,
            Permission.ViewIncidents,
            Permission.ViewDashboards
        };

        // SOC Analyst L2 permissions
        var l2Permissions = new[]
        {
            Permission.ViewAlerts,
            Permission.AcknowledgeAlerts,
            Permission.InvestigateAlerts,
            Permission.EscalateAlerts,
            Permission.CreateIncidents,
            Permission.ResolveIncidents,
            Permission.ViewIncidents,
            Permission.ViewDashboards,
            Permission.ViewOperationalKpis,
            Permission.ExecutePlaybooks
        };

        // SOC Manager permissions (includes acknowledge for oversight)
        var managerPermissions = new[]
        {
            Permission.ViewAlerts,
            Permission.AcknowledgeAlerts,
            Permission.InvestigateAlerts,
            Permission.EscalateAlerts,
            Permission.CreateIncidents,
            Permission.ResolveIncidents,
            Permission.ViewIncidents,
            Permission.ViewDashboards,
            Permission.ViewOperationalKpis,
            Permission.ViewExecutiveReports,
            Permission.EnableDisableRules,
            Permission.ExecutePlaybooks,
            Permission.ApproveResponses,
            Permission.ViewAuditLogs
        };

        // System Administrator permissions
        var adminPermissions = new[]
        {
            Permission.ViewAlerts,
            Permission.ViewIncidents,
            Permission.ViewDashboards,
            Permission.ViewOperationalKpis,
            Permission.ViewExecutiveReports,
            Permission.EnableDisableRules,
            Permission.ManageRules,
            Permission.ManageUsers,
            Permission.ManageApiKeys,
            Permission.ViewAuditLogs,
            Permission.ManageAuditLogs,
            Permission.ViewSystemHealth,
            Permission.ManageConfiguration
        };

        AddPermissions(socL1.Id, l1Permissions);
        AddPermissions(socL2.Id, l2Permissions);
        AddPermissions(socManager.Id, managerPermissions);
        AddPermissions(sysAdmin.Id, adminPermissions);

        _logger.LogInformation("Seeded 4 roles with granular permissions");
    }

    private void AddPermissions(Guid roleId, Permission[] permissions)
    {
        foreach (var perm in permissions)
        {
            _context.RolePermissions.Add(new RolePermission
            {
                Id = Guid.NewGuid(),
                RoleId = roleId,
                Permission = perm
            });
        }
    }

    // ──────────────────────────────────────────────────
    //  Default Users
    // ──────────────────────────────────────────────────
    private async Task SeedDefaultUsersAsync()
    {
        if (await _context.Users.AnyAsync()) return;

        // Default admin user (password: Admin@Soc2026!)
        var adminUser = new User
        {
            Id = Guid.Parse("20000000-0000-0000-0000-000000000001"),
            Username = "admin",
            Email = "admin@socplatform.local",
            PasswordHash = BCrypt.Net.BCrypt.HashPassword("Admin@Soc2026!", workFactor: 12),
            RoleId = Guid.Parse("10000000-0000-0000-0000-000000000004"), // System Admin
            IsActive = true
        };

        // Default SOC Manager
        var managerUser = new User
        {
            Id = Guid.Parse("20000000-0000-0000-0000-000000000002"),
            Username = "soc.manager",
            Email = "manager@socplatform.local",
            PasswordHash = BCrypt.Net.BCrypt.HashPassword("Manager@Soc2026!", workFactor: 12),
            RoleId = Guid.Parse("10000000-0000-0000-0000-000000000003"), // SOC Manager
            IsActive = true
        };

        // Default L2 Analyst
        var l2Analyst = new User
        {
            Id = Guid.Parse("20000000-0000-0000-0000-000000000003"),
            Username = "analyst.l2",
            Email = "analyst.l2@socplatform.local",
            PasswordHash = BCrypt.Net.BCrypt.HashPassword("Analyst@Soc2026!", workFactor: 12),
            RoleId = Guid.Parse("10000000-0000-0000-0000-000000000002"), // SOC L2
            IsActive = true
        };

        // Default L1 Analyst
        var l1Analyst = new User
        {
            Id = Guid.Parse("20000000-0000-0000-0000-000000000004"),
            Username = "analyst.l1",
            Email = "analyst.l1@socplatform.local",
            PasswordHash = BCrypt.Net.BCrypt.HashPassword("Analyst@Soc2026!", workFactor: 12),
            RoleId = Guid.Parse("10000000-0000-0000-0000-000000000001"), // SOC L1
            IsActive = true
        };

        await _context.Users.AddRangeAsync(adminUser, managerUser, l2Analyst, l1Analyst);
        _logger.LogInformation("Seeded 4 default users (admin, manager, analyst.l2, analyst.l1)");
    }

    // ──────────────────────────────────────────────────
    //  Detection Rules (7 built-in rules from plan)
    // ──────────────────────────────────────────────────
    private async Task SeedDetectionRulesAsync()
    {
        if (await _context.DetectionRules.AnyAsync()) return;

        var rules = new List<DetectionRule>
        {
            new()
            {
                Id = Guid.Parse("30000000-0000-0000-0000-000000000001"),
                Name = "Brute Force Login",
                Description = "Detects brute-force login attempts: ≥5 failed logins in 5 minutes from the same source IP",
                RuleType = "Threshold",
                Severity = "High",
                MitreTechnique = "T1110",
                MitreTactic = "Credential Access",
                ThresholdCount = 5,
                TimeWindowSeconds = 300,
                IsActive = true,
                RuleLogic = """{"field":"EventAction","value":"LoginFailed","groupBy":"SourceIP","threshold":5,"windowSeconds":300}"""
            },
            new()
            {
                Id = Guid.Parse("30000000-0000-0000-0000-000000000002"),
                Name = "Privilege Escalation - After Hours",
                Description = "Detects admin access at unusual hours (22:00-06:00), potential privilege abuse",
                RuleType = "Temporal",
                Severity = "Critical",
                MitreTechnique = "T1078",
                MitreTactic = "Privilege Escalation",
                IsActive = true,
                RuleLogic = """{"field":"EventAction","value":"PrivilegeEscalation","timeRange":{"startHour":22,"endHour":6},"requiresAdminAccess":true}"""
            },
            new()
            {
                Id = Guid.Parse("30000000-0000-0000-0000-000000000003"),
                Name = "Port Scan Detection",
                Description = "Detects port scanning: ≥20 connection attempts to different ports in 1 minute from same source",
                RuleType = "Threshold",
                Severity = "Medium",
                MitreTechnique = "T1046",
                MitreTactic = "Discovery",
                ThresholdCount = 20,
                TimeWindowSeconds = 60,
                IsActive = true,
                RuleLogic = """{"field":"EventAction","value":"ConnectionAttempt","groupBy":"SourceIP","distinctField":"DestinationPort","threshold":20,"windowSeconds":60}"""
            },
            new()
            {
                Id = Guid.Parse("30000000-0000-0000-0000-000000000004"),
                Name = "Suspicious File Hash",
                Description = "Detects files whose hash matches known malicious indicators in threat intelligence database",
                RuleType = "ThreatIntel",
                Severity = "Critical",
                MitreTechnique = "T1204",
                MitreTactic = "Execution",
                IsActive = true,
                RuleLogic = """{"field":"FileHash","matchAgainst":"ThreatIntelIndicators","indicatorType":"FileHash"}"""
            },
            new()
            {
                Id = Guid.Parse("30000000-0000-0000-0000-000000000005"),
                Name = "Policy Violation - Restricted Access",
                Description = "Detects unauthorized access attempts to restricted resources or directories",
                RuleType = "Pattern",
                Severity = "Medium",
                MitreTechnique = "T1078",
                MitreTactic = "Defense Evasion",
                IsActive = true,
                RuleLogic = """{"field":"EventAction","value":"AccessDenied","resourcePatterns":["/admin","/config","/secrets","System32"]}"""
            },
            new()
            {
                Id = Guid.Parse("30000000-0000-0000-0000-000000000006"),
                Name = "Account Enumeration",
                Description = "Detects account enumeration: ≥10 failed logins to different accounts from the same IP in 5 minutes",
                RuleType = "Threshold",
                Severity = "High",
                MitreTechnique = "T1087",
                MitreTactic = "Discovery",
                ThresholdCount = 10,
                TimeWindowSeconds = 300,
                IsActive = true,
                RuleLogic = """{"field":"EventAction","value":"LoginFailed","groupBy":"SourceIP","distinctField":"AffectedUser","threshold":10,"windowSeconds":300}"""
            },
            new()
            {
                Id = Guid.Parse("30000000-0000-0000-0000-000000000007"),
                Name = "After-Hours Sensitive Activity",
                Description = "Detects sensitive operations (file access, config changes) outside business hours (18:00-08:00)",
                RuleType = "Temporal",
                Severity = "Medium",
                MitreTechnique = "T1078",
                MitreTactic = "Initial Access",
                IsActive = true,
                RuleLogic = """{"field":"EventCategory","values":["FileAccess","ConfigChange","DataExport"],"timeRange":{"startHour":18,"endHour":8}}"""
            }
        };

        await _context.DetectionRules.AddRangeAsync(rules);
        _logger.LogInformation("Seeded {Count} detection rules", rules.Count);
    }

    // ──────────────────────────────────────────────────
    //  Threat Intelligence Indicators (sample data)
    // ──────────────────────────────────────────────────
    private async Task SeedThreatIntelAsync()
    {
        if (await _context.ThreatIntelIndicators.AnyAsync()) return;

        var indicators = new List<ThreatIntelIndicator>
        {
            // Known malicious IPs (sample data)
            new() { Id = Guid.NewGuid(), IndicatorType = IndicatorType.IpAddress, Value = "185.220.101.1", Source = "AbuseIPDB", ThreatLevel = "High", Description = "Tor exit node – frequent scanner", IsActive = true },
            new() { Id = Guid.NewGuid(), IndicatorType = IndicatorType.IpAddress, Value = "45.155.205.233", Source = "AbuseIPDB", ThreatLevel = "Critical", Description = "Known botnet C2 server", IsActive = true },
            new() { Id = Guid.NewGuid(), IndicatorType = IndicatorType.IpAddress, Value = "194.26.29.113", Source = "ThreatFox", ThreatLevel = "High", Description = "Brute-force attack source", IsActive = true },
            new() { Id = Guid.NewGuid(), IndicatorType = IndicatorType.IpAddress, Value = "91.240.118.172", Source = "Feodo Tracker", ThreatLevel = "Critical", Description = "Emotet distribution server", IsActive = true },
            new() { Id = Guid.NewGuid(), IndicatorType = IndicatorType.IpAddress, Value = "23.129.64.210", Source = "AbuseIPDB", ThreatLevel = "Medium", Description = "Tor exit node", IsActive = true },

            // Known malicious domains
            new() { Id = Guid.NewGuid(), IndicatorType = IndicatorType.Domain, Value = "evil-login.com", Source = "PhishTank", ThreatLevel = "Critical", Description = "Credential phishing site", IsActive = true },
            new() { Id = Guid.NewGuid(), IndicatorType = IndicatorType.Domain, Value = "malware-drop.xyz", Source = "URLhaus", ThreatLevel = "Critical", Description = "Malware distribution domain", IsActive = true },
            new() { Id = Guid.NewGuid(), IndicatorType = IndicatorType.Domain, Value = "c2-callback.net", Source = "ThreatFox", ThreatLevel = "High", Description = "Command & control callback domain", IsActive = true },

            // Known malicious file hashes
            new() { Id = Guid.NewGuid(), IndicatorType = IndicatorType.FileHash, Value = "e99a18c428cb38d5f260853678922e03", Source = "VirusTotal", ThreatLevel = "Critical", Description = "Known ransomware payload (MD5)", IsActive = true },
            new() { Id = Guid.NewGuid(), IndicatorType = IndicatorType.FileHash, Value = "d41d8cd98f00b204e9800998ecf8427e", Source = "MalwareBazaar", ThreatLevel = "High", Description = "Trojan dropper (MD5)", IsActive = true },
            new() { Id = Guid.NewGuid(), IndicatorType = IndicatorType.FileHash, Value = "5d41402abc4b2a76b9719d911017c592", Source = "VirusTotal", ThreatLevel = "High", Description = "Keylogger payload (MD5)", IsActive = true },
        };

        await _context.ThreatIntelIndicators.AddRangeAsync(indicators);
        _logger.LogInformation("Seeded {Count} threat intelligence indicators", indicators.Count);
    }

    // ──────────────────────────────────────────────────
    //  Response Playbooks
    // ──────────────────────────────────────────────────
    private async Task SeedResponsePlaybooksAsync()
    {
        if (await _context.ResponsePlaybooks.AnyAsync()) return;

        var playbooks = new List<ResponsePlaybook>
        {
            new()
            {
                Id = Guid.Parse("40000000-0000-0000-0000-000000000001"),
                Name = "Block Malicious IP",
                Description = "Adds the source IP to the firewall blocklist to prevent further communication",
                ActionType = PlaybookActionType.BlockIp,
                RequiresApproval = false,
                IsActive = true,
                TriggerCondition = "Alert.Severity >= High AND Alert.SourceIP IS NOT NULL",
                ActionConfig = """{"action":"block_ip","target":"firewall","duration_hours":24,"log":true}"""
            },
            new()
            {
                Id = Guid.Parse("40000000-0000-0000-0000-000000000002"),
                Name = "Temporary Account Lockout",
                Description = "Temporarily locks the affected user account for 30 minutes pending investigation",
                ActionType = PlaybookActionType.LockAccount,
                RequiresApproval = true,
                IsActive = true,
                TriggerCondition = "Alert.DetectionRule == 'Brute Force Login' AND Alert.Severity >= High",
                ActionConfig = """{"action":"lock_account","duration_minutes":30,"notify_user":true,"require_password_reset":false}"""
            },
            new()
            {
                Id = Guid.Parse("40000000-0000-0000-0000-000000000003"),
                Name = "Notify SOC Manager",
                Description = "Sends an immediate notification to the SOC Manager for critical alerts",
                ActionType = PlaybookActionType.NotifyManager,
                RequiresApproval = false,
                IsActive = true,
                TriggerCondition = "Alert.Severity == Critical",
                ActionConfig = """{"action":"notify","channel":"dashboard","priority":"urgent","include_alert_details":true}"""
            },
            new()
            {
                Id = Guid.Parse("40000000-0000-0000-0000-000000000004"),
                Name = "Auto-Escalate Critical Alert",
                Description = "Automatically escalates critical alerts that remain unacknowledged after 15 minutes",
                ActionType = PlaybookActionType.EscalateAlert,
                RequiresApproval = false,
                IsActive = true,
                TriggerCondition = "Alert.Severity == Critical AND Alert.Status == New AND Alert.Age > 15min",
                ActionConfig = """{"action":"escalate","escalate_to":"SOC Manager","create_incident":true,"sla_override":true}"""
            }
        };

        await _context.ResponsePlaybooks.AddRangeAsync(playbooks);
        _logger.LogInformation("Seeded {Count} response playbooks", playbooks.Count);
    }
}
