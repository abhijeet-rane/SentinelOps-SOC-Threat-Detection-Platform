using Microsoft.EntityFrameworkCore;
using SOCPlatform.Core.Entities;

namespace SOCPlatform.Infrastructure.Data;

/// <summary>
/// Entity Framework Core DbContext for the SOC Platform.
/// Configures all entity mappings, indexes, and JSONB columns for PostgreSQL.
/// </summary>
public class SOCDbContext : DbContext
{
    public SOCDbContext(DbContextOptions<SOCDbContext> options) : base(options) { }

    public DbSet<User> Users => Set<User>();
    public DbSet<Role> Roles => Set<Role>();
    public DbSet<RolePermission> RolePermissions => Set<RolePermission>();
    public DbSet<Log> Logs => Set<Log>();
    public DbSet<SecurityEvent> SecurityEvents => Set<SecurityEvent>();
    public DbSet<Alert> Alerts => Set<Alert>();
    public DbSet<Incident> Incidents => Set<Incident>();
    public DbSet<IncidentNote> IncidentNotes => Set<IncidentNote>();
    public DbSet<IncidentEvidence> IncidentEvidence => Set<IncidentEvidence>();
    public DbSet<DetectionRule> DetectionRules => Set<DetectionRule>();
    public DbSet<ThreatIntelIndicator> ThreatIntelIndicators => Set<ThreatIntelIndicator>();
    public DbSet<ResponsePlaybook> ResponsePlaybooks => Set<ResponsePlaybook>();
    public DbSet<PlaybookExecution> PlaybookExecutions => Set<PlaybookExecution>();
    public DbSet<AuditLog> AuditLogs => Set<AuditLog>();
    public DbSet<ApiKey> ApiKeys => Set<ApiKey>();
    public DbSet<PasswordResetToken> PasswordResetTokens => Set<PasswordResetToken>();
    public DbSet<SimulatedActionLog> SimulatedActionLogs => Set<SimulatedActionLog>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // ──────────────────────────────────────
        //  User
        // ──────────────────────────────────────
        modelBuilder.Entity<User>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.Username).IsUnique();
            entity.HasIndex(e => e.Email).IsUnique();
            entity.Property(e => e.Username).HasMaxLength(100).IsRequired();
            entity.Property(e => e.Email).HasMaxLength(255).IsRequired();
            entity.Property(e => e.PasswordHash).HasMaxLength(500).IsRequired();

            // ── MFA columns ──
            // MfaSecret: AES-encrypted TOTP secret (Data Protection ciphertext),
            //            stored as raw bytes. Null = no secret yet.
            entity.Property(e => e.MfaSecret).HasColumnType("bytea");

            // MfaBackupCodes: JSONB array of BCrypt-hashed single-use recovery codes.
            // EF needs a value-converter + comparer because List<string> is a mutable
            // reference type. We use System.Text.Json for serialisation.
            entity.Property(e => e.MfaBackupCodes)
                  .HasColumnType("jsonb")
                  .HasConversion(
                      v => System.Text.Json.JsonSerializer.Serialize(v ?? new List<string>(), (System.Text.Json.JsonSerializerOptions?)null),
                      v => string.IsNullOrWhiteSpace(v)
                            ? new List<string>()
                            : System.Text.Json.JsonSerializer.Deserialize<List<string>>(v, (System.Text.Json.JsonSerializerOptions?)null) ?? new List<string>(),
                      new Microsoft.EntityFrameworkCore.ChangeTracking.ValueComparer<List<string>>(
                          (a, b) => (a ?? new()).SequenceEqual(b ?? new()),
                          v => v.Aggregate(0, (h, s) => HashCode.Combine(h, s.GetHashCode())),
                          v => v.ToList()));

            entity.HasOne(e => e.Role)
                  .WithMany(r => r.Users)
                  .HasForeignKey(e => e.RoleId)
                  .OnDelete(DeleteBehavior.Restrict);
        });

        // ──────────────────────────────────────
        //  SimulatedActionLog
        // ──────────────────────────────────────
        modelBuilder.Entity<SimulatedActionLog>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.ExecutedAt);
            entity.HasIndex(e => e.AlertId);
            entity.HasIndex(e => new { e.AdapterName, e.Action });

            entity.Property(e => e.AdapterName).HasMaxLength(100).IsRequired();
            entity.Property(e => e.Action).HasMaxLength(50).IsRequired();
            entity.Property(e => e.Target).HasMaxLength(255).IsRequired();
            entity.Property(e => e.Reason).HasMaxLength(1000);
            entity.Property(e => e.ErrorDetail).HasMaxLength(2000);
        });

        // ──────────────────────────────────────
        //  PasswordResetToken
        // ──────────────────────────────────────
        modelBuilder.Entity<PasswordResetToken>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.TokenHash).IsUnique();
            entity.HasIndex(e => e.UserId);
            entity.HasIndex(e => e.ExpiresAt);

            entity.Property(e => e.TokenHash).HasMaxLength(64).IsRequired();
            entity.Property(e => e.RequestIpAddress).HasMaxLength(45);
            entity.Property(e => e.RequestUserAgent).HasMaxLength(500);

            entity.HasOne(e => e.User)
                  .WithMany()
                  .HasForeignKey(e => e.UserId)
                  .OnDelete(DeleteBehavior.Cascade);
        });

        // ──────────────────────────────────────
        //  Role
        // ──────────────────────────────────────
        modelBuilder.Entity<Role>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.Name).IsUnique();
            entity.Property(e => e.Name).HasMaxLength(50).IsRequired();
            entity.Property(e => e.Description).HasMaxLength(500);
        });

        // ──────────────────────────────────────
        //  RolePermission
        // ──────────────────────────────────────
        modelBuilder.Entity<RolePermission>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => new { e.RoleId, e.Permission }).IsUnique();

            entity.HasOne(e => e.Role)
                  .WithMany(r => r.Permissions)
                  .HasForeignKey(e => e.RoleId)
                  .OnDelete(DeleteBehavior.Cascade);
        });

        // ──────────────────────────────────────
        //  Log (JSONB columns for PostgreSQL)
        // ──────────────────────────────────────
        modelBuilder.Entity<Log>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.Timestamp);
            entity.HasIndex(e => e.IngestedAt);
            entity.HasIndex(e => e.Source);
            entity.HasIndex(e => e.EndpointId);
            entity.HasIndex(e => e.SourceIP);

            entity.Property(e => e.Source).HasMaxLength(100).IsRequired();
            entity.Property(e => e.EventType).HasMaxLength(100).IsRequired();
            entity.Property(e => e.Severity).HasMaxLength(20);
            entity.Property(e => e.SourceIP).HasMaxLength(45);
            entity.Property(e => e.Hostname).HasMaxLength(255);
            entity.Property(e => e.Username).HasMaxLength(255);
            entity.Property(e => e.ProcessName).HasMaxLength(255);

            entity.Property(e => e.RawData).HasColumnType("jsonb");
            entity.Property(e => e.NormalizedData).HasColumnType("jsonb");
        });

        // ──────────────────────────────────────
        //  SecurityEvent
        // ──────────────────────────────────────
        modelBuilder.Entity<SecurityEvent>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.Timestamp);
            entity.HasIndex(e => e.EventCategory);
            entity.HasIndex(e => e.MitreTechnique);
            entity.HasIndex(e => e.SourceIP);

            entity.Property(e => e.EventCategory).HasMaxLength(100).IsRequired();
            entity.Property(e => e.EventAction).HasMaxLength(100).IsRequired();
            entity.Property(e => e.Severity).HasMaxLength(20);
            entity.Property(e => e.MitreTechnique).HasMaxLength(20);
            entity.Property(e => e.MitreTactic).HasMaxLength(100);
            entity.Property(e => e.SourceIP).HasMaxLength(45);
            entity.Property(e => e.DestinationIP).HasMaxLength(45);
            entity.Property(e => e.FileHash).HasMaxLength(128);

            entity.Property(e => e.Metadata).HasColumnType("jsonb");

            entity.HasOne(e => e.Log)
                  .WithMany(l => l.Events)
                  .HasForeignKey(e => e.LogId)
                  .OnDelete(DeleteBehavior.Cascade);
        });

        // ──────────────────────────────────────
        //  Alert
        // ──────────────────────────────────────
        modelBuilder.Entity<Alert>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.Status);
            entity.HasIndex(e => e.Severity);
            entity.HasIndex(e => e.CreatedAt);
            entity.HasIndex(e => e.AssignedTo);
            entity.HasIndex(e => e.MitreTechnique);

            entity.Property(e => e.Title).HasMaxLength(500).IsRequired();
            entity.Property(e => e.Description).HasMaxLength(5000);
            entity.Property(e => e.DetectionRuleName).HasMaxLength(200);
            entity.Property(e => e.MitreTechnique).HasMaxLength(20);
            entity.Property(e => e.MitreTactic).HasMaxLength(100);
            entity.Property(e => e.AffectedUser).HasMaxLength(255);
            entity.Property(e => e.AffectedDevice).HasMaxLength(255);
            entity.Property(e => e.SourceIP).HasMaxLength(45);
            entity.Property(e => e.RecommendedAction).HasMaxLength(2000);

            entity.HasOne(e => e.Event)
                  .WithMany(ev => ev.Alerts)
                  .HasForeignKey(e => e.EventId)
                  .OnDelete(DeleteBehavior.SetNull);

            entity.HasOne(e => e.AssignedAnalyst)
                  .WithMany(u => u.AssignedAlerts)
                  .HasForeignKey(e => e.AssignedTo)
                  .OnDelete(DeleteBehavior.SetNull);

            entity.HasOne(e => e.Incident)
                  .WithMany(i => i.Alerts)
                  .HasForeignKey(e => e.IncidentId)
                  .OnDelete(DeleteBehavior.SetNull);

            entity.HasOne(e => e.DetectionRule)
                  .WithMany(r => r.Alerts)
                  .HasForeignKey(e => e.DetectionRuleId)
                  .OnDelete(DeleteBehavior.SetNull);
        });

        // ──────────────────────────────────────
        //  Incident
        // ──────────────────────────────────────
        modelBuilder.Entity<Incident>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.Status);
            entity.HasIndex(e => e.CreatedAt);

            entity.Property(e => e.Title).HasMaxLength(500).IsRequired();
            entity.Property(e => e.Description).HasMaxLength(5000);
            entity.Property(e => e.RootCause).HasMaxLength(5000);
            entity.Property(e => e.ImpactAssessment).HasMaxLength(5000);
        });

        // ──────────────────────────────────────
        //  IncidentNote
        // ──────────────────────────────────────
        modelBuilder.Entity<IncidentNote>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Content).HasMaxLength(10000).IsRequired();

            entity.HasOne(e => e.Incident)
                  .WithMany(i => i.Notes)
                  .HasForeignKey(e => e.IncidentId)
                  .OnDelete(DeleteBehavior.Cascade);
        });

        // ──────────────────────────────────────
        //  IncidentEvidence
        // ──────────────────────────────────────
        modelBuilder.Entity<IncidentEvidence>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.FileName).HasMaxLength(500).IsRequired();
            entity.Property(e => e.FileType).HasMaxLength(100);
            entity.Property(e => e.StoragePath).HasMaxLength(1000);
            entity.Property(e => e.Hash).HasMaxLength(128);

            entity.HasOne(e => e.Incident)
                  .WithMany(i => i.Evidence)
                  .HasForeignKey(e => e.IncidentId)
                  .OnDelete(DeleteBehavior.Cascade);
        });

        // ──────────────────────────────────────
        //  DetectionRule (JSONB rule logic)
        // ──────────────────────────────────────
        modelBuilder.Entity<DetectionRule>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.Name).IsUnique();
            entity.HasIndex(e => e.IsActive);

            entity.Property(e => e.Name).HasMaxLength(200).IsRequired();
            entity.Property(e => e.Description).HasMaxLength(2000);
            entity.Property(e => e.RuleType).HasMaxLength(50).IsRequired();
            entity.Property(e => e.Severity).HasMaxLength(20);
            entity.Property(e => e.MitreTechnique).HasMaxLength(20);
            entity.Property(e => e.MitreTactic).HasMaxLength(100);

            entity.Property(e => e.RuleLogic).HasColumnType("jsonb");
        });

        // ──────────────────────────────────────
        //  ThreatIntelIndicator (Enterprise-grade IOC)
        // ──────────────────────────────────────
        modelBuilder.Entity<ThreatIntelIndicator>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.Value);
            entity.HasIndex(e => e.IndicatorType);
            entity.HasIndex(e => e.IsActive);
            entity.HasIndex(e => e.ThreatLevel);
            entity.HasIndex(e => new { e.IndicatorType, e.Value }).IsUnique();

            entity.Property(e => e.Value).HasMaxLength(500).IsRequired();
            entity.Property(e => e.Source).HasMaxLength(200);
            entity.Property(e => e.ThreatType).HasMaxLength(100);
            entity.Property(e => e.ThreatLevel).HasMaxLength(20);
            entity.Property(e => e.Description).HasMaxLength(2000);
            entity.Property(e => e.Tags).HasMaxLength(500);
            entity.Property(e => e.AssociatedCVEs).HasMaxLength(500);
            entity.Property(e => e.MitreTechniques).HasMaxLength(200);
            entity.Property(e => e.GeoCountry).HasMaxLength(100);
            entity.Property(e => e.ASN).HasMaxLength(200);
        });

        // ──────────────────────────────────────
        //  ResponsePlaybook (JSONB config)
        // ──────────────────────────────────────
        modelBuilder.Entity<ResponsePlaybook>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.Name).IsUnique();

            entity.Property(e => e.Name).HasMaxLength(200).IsRequired();
            entity.Property(e => e.Description).HasMaxLength(2000);
            entity.Property(e => e.TriggerCondition).HasMaxLength(1000);

            entity.Property(e => e.ActionConfig).HasColumnType("jsonb");
        });

        // ──────────────────────────────────────
        //  PlaybookExecution
        // ──────────────────────────────────────
        modelBuilder.Entity<PlaybookExecution>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.Status);

            entity.Property(e => e.Status).HasMaxLength(50);
            entity.Property(e => e.Result).HasMaxLength(5000);
            entity.Property(e => e.ErrorMessage).HasMaxLength(2000);

            entity.HasOne(e => e.Playbook)
                  .WithMany(p => p.Executions)
                  .HasForeignKey(e => e.PlaybookId)
                  .OnDelete(DeleteBehavior.Restrict);

            entity.HasOne(e => e.Alert)
                  .WithMany(a => a.PlaybookExecutions)
                  .HasForeignKey(e => e.AlertId)
                  .OnDelete(DeleteBehavior.Restrict);
        });

        // ──────────────────────────────────────
        //  AuditLog (Immutable, hash chain)
        // ──────────────────────────────────────
        modelBuilder.Entity<AuditLog>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.Timestamp);
            entity.HasIndex(e => e.UserId);
            entity.HasIndex(e => e.Action);

            entity.Property(e => e.Action).HasMaxLength(100).IsRequired();
            entity.Property(e => e.Resource).HasMaxLength(200).IsRequired();
            entity.Property(e => e.ResourceId).HasMaxLength(100);
            entity.Property(e => e.OldValue).HasMaxLength(10000);
            entity.Property(e => e.NewValue).HasMaxLength(10000);
            entity.Property(e => e.Details).HasMaxLength(5000);
            entity.Property(e => e.IpAddress).HasMaxLength(45);
            entity.Property(e => e.UserAgent).HasMaxLength(500);
            entity.Property(e => e.EntryHash).HasMaxLength(128).IsRequired();
            entity.Property(e => e.PreviousHash).HasMaxLength(128);

            entity.HasOne(e => e.User)
                  .WithMany(u => u.AuditLogs)
                  .HasForeignKey(e => e.UserId)
                  .OnDelete(DeleteBehavior.SetNull);
        });

        // ──────────────────────────────────────
        //  ApiKey
        // ──────────────────────────────────────
        modelBuilder.Entity<ApiKey>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.KeyPrefix);
            entity.HasIndex(e => e.EndpointId);

            entity.Property(e => e.Name).HasMaxLength(200).IsRequired();
            entity.Property(e => e.KeyHash).HasMaxLength(256).IsRequired();
            entity.Property(e => e.KeyPrefix).HasMaxLength(16);
        });
    }
}
