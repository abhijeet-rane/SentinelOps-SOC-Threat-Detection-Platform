using SOCPlatform.Core.DTOs;

namespace SOCPlatform.AttackSim.Scenarios;

/// <summary>
/// 60 outbound transfers summing to ~180 MB to one IP inside 45 min → volume trigger.
/// Also includes off-hours Dropbox upload → cloud-storage trigger.
/// </summary>
public sealed class DataExfilScenario : IAttackScenario
{
    public string Name => "exfil";
    public string Description => "Large outbound transfer + off-hours cloud upload — T1041 / T1567";
    public string[] ExpectedRules => ["Data Exfiltration"];

    public List<SyntheticSecurityEventDto> Build()
    {
        var events = new List<SyntheticSecurityEventDto>();
        // Anchored to NOW so the DetectionEngine watermark always picks up the batch.
        // 200 ms spacing → 60 chunks span 12 s, well inside the 60-min volume window.
        var now = DateTime.UtcNow;
        const string srcIp = "10.0.0.88";
        const string dstIp = "45.67.89.10";
        const long chunkBytes = 3L * 1024 * 1024; // 3 MB each — 60 chunks ≈ 180 MB

        for (int i = 0; i < 60; i++)
        {
            events.Add(new SyntheticSecurityEventDto
            {
                EventCategory  = "Network",
                EventAction    = "NetworkConnection",
                Severity       = "Low",
                SourceIP       = srcIp,
                DestinationIP  = dstIp,
                AffectedDevice = "WRK-088",
                AffectedUser   = "bob",
                MitreTechnique = "T1041",
                MitreTactic    = "Exfiltration",
                Metadata       = new Dictionary<string, object?> { ["bytes_out"] = chunkBytes },
                Timestamp      = now.AddMilliseconds(i * 200),
            });
        }

        // Off-hours cloud-storage upload → cloud-storage trigger.
        // Rule checks Timestamp.ToUniversalTime().Hour outside 08:00-18:00 UTC.
        // We use TOMORROW 02:00 UTC so the timestamp is both (a) > engine watermark
        // and (b) guaranteed off-hours UTC regardless of when the demo is run.
        events.Add(new SyntheticSecurityEventDto
        {
            EventCategory  = "Network",
            EventAction    = "HttpUpload",
            Severity       = "Low",
            SourceIP       = srcIp,
            DestinationIP  = "162.125.1.1",
            AffectedDevice = "WRK-088",
            AffectedUser   = "bob",
            MitreTechnique = "T1567",
            MitreTactic    = "Exfiltration",
            Metadata       = new Dictionary<string, object?>
            {
                ["bytes_out"] = 20L * 1024 * 1024,
                ["destination_domain"] = "dropbox.com"
            },
            Timestamp = DateTime.UtcNow.Date.AddDays(1).AddHours(2),
        });

        return events;
    }
}
