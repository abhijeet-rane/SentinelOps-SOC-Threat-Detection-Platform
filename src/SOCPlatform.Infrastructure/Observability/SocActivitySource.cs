using System.Diagnostics;

namespace SOCPlatform.Infrastructure.Observability;

/// <summary>
/// Shared <see cref="ActivitySource"/> for custom traces inside SentinelOps.
/// OpenTelemetry subscribes with <c>builder.AddSource(SocActivitySource.Name)</c>.
/// Use it around work that isn't auto-instrumented (detection cycles, playbook
/// execution, threat-feed sync) so you get spans in Jaeger for those phases.
/// </summary>
public static class SocActivitySource
{
    public const string Name = "socplatform";
    public const string Version = "1.0.0";

    public static readonly ActivitySource Instance = new(Name, Version);
}
