using SOCPlatform.Core.Entities;

namespace SOCPlatform.Detection.Rules.Advanced;

/// <summary>
/// Data exfiltration heuristics. Two independent triggers:
///   1. Outbound volume &gt; 100 MB to a single external destination in 1 hour
///   2. Off-hours upload to a known cloud-storage service (Dropbox, Drive, transfer.sh, WeTransfer, …)
///
/// Requires events with metadata field <c>bytes_out</c> (long, bytes transferred).
/// Off-hours = outside 08:00-18:00 UTC.
///
/// MITRE ATT&amp;CK: T1041 – Exfiltration Over C2 Channel,
///                 T1567 – Exfiltration Over Web Service
/// </summary>
public sealed class DataExfiltrationRule : IDetectionRule
{
    public string Name => "Data Exfiltration";
    public string MitreTechnique => "T1041";
    public string MitreTactic => "Exfiltration";
    public string Severity => "Critical";
    public bool IsEnabled { get; set; } = true;

    private static readonly HashSet<string> CloudStorageDomains = new(StringComparer.OrdinalIgnoreCase)
    {
        "dropbox.com", "transfer.sh", "wetransfer.com",
        "drive.google.com", "docs.google.com",
        "onedrive.live.com", "1drv.ms",
        "mega.nz", "mega.co.nz",
        "box.com", "pcloud.com",
        "sendspace.com", "anonfiles.com", "file.io"
    };

    private readonly long _volumeThresholdBytes;
    private readonly TimeSpan _window;

    public DataExfiltrationRule(long volumeThresholdBytes = 100L * 1024 * 1024, int windowMinutes = 60)
    {
        _volumeThresholdBytes = volumeThresholdBytes;
        _window = TimeSpan.FromMinutes(windowMinutes);
    }

    public Task<List<Alert>> EvaluateAsync(List<SecurityEvent> events, CancellationToken ct = default)
    {
        var alerts = new List<Alert>();

        var candidates = events
            .Where(e => e.EventAction is "NetworkConnection" or "FileUpload" or "HttpUpload")
            .Select(e => new { Event = e,
                               Bytes = EventFieldExtractor.GetLong(e, "bytes_out") ?? 0,
                               Domain = EventFieldExtractor.GetString(e, "destination_domain") })
            .ToList();

        // ── Trigger 1: Volume to single destination ───────────────────────────
        var byDest = candidates
            .Where(x => !string.IsNullOrEmpty(x.Event.DestinationIP) && x.Bytes > 0)
            .GroupBy(x => x.Event.DestinationIP!);

        foreach (var group in byDest)
        {
            var ordered = group.OrderBy(x => x.Event.Timestamp).ToList();
            var start = ordered.First().Event.Timestamp;

            // Rolling sum inside the window
            long runningBytes = 0;
            foreach (var item in ordered)
            {
                if (item.Event.Timestamp - start > _window) break;
                runningBytes += item.Bytes;
                if (runningBytes < _volumeThresholdBytes) continue;

                var mb = runningBytes / 1024.0 / 1024.0;
                alerts.Add(new Alert
                {
                    Title = $"High-volume data egress to {group.Key}",
                    Description = $"{mb:F1} MB transferred to {group.Key} inside a {_window.TotalMinutes:F0}-min window (threshold {_volumeThresholdBytes / 1024 / 1024} MB).",
                    Severity = Core.Enums.Severity.Critical,
                    DetectionRuleName = Name,
                    MitreTechnique = MitreTechnique,
                    MitreTactic = MitreTactic,
                    SourceIP = item.Event.SourceIP,
                    AffectedDevice = item.Event.AffectedDevice,
                    AffectedUser = item.Event.AffectedUser,
                    EventId = item.Event.Id,
                    RecommendedAction = $"Throttle/block destination {group.Key}, identify the uploading process, review DLP logs"
                });
                break; // one alert per destination
            }
        }

        // ── Trigger 2: Off-hours upload to known cloud storage ────────────────
        foreach (var x in candidates)
        {
            if (string.IsNullOrEmpty(x.Domain)) continue;
            if (!CloudStorageDomains.Any(d => x.Domain.EndsWith(d, StringComparison.OrdinalIgnoreCase))) continue;

            var hourUtc = x.Event.Timestamp.ToUniversalTime().Hour;
            var isBusinessHour = hourUtc >= 8 && hourUtc < 18;
            if (isBusinessHour) continue;

            alerts.Add(new Alert
            {
                Title = $"Off-hours upload to cloud storage: {x.Domain}",
                Description = $"Upload to {x.Domain} at {x.Event.Timestamp:u} (outside 08:00-18:00 UTC). " +
                              $"{x.Bytes / 1024.0:F1} KB transferred.",
                Severity = Core.Enums.Severity.High,
                DetectionRuleName = Name,
                MitreTechnique = "T1567",
                MitreTactic = MitreTactic,
                SourceIP = x.Event.SourceIP,
                AffectedDevice = x.Event.AffectedDevice,
                AffectedUser = x.Event.AffectedUser,
                EventId = x.Event.Id,
                RecommendedAction = "Confirm user intent, inspect file content, review cloud-storage policy"
            });
        }

        return Task.FromResult(alerts);
    }
}
