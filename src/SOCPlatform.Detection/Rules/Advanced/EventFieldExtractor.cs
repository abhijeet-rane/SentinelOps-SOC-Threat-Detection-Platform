using System.Text.Json;
using SOCPlatform.Core.Entities;

namespace SOCPlatform.Detection.Rules.Advanced;

/// <summary>
/// Small, exception-tolerant helper that digs into a SecurityEvent's JSONB
/// <see cref="SecurityEvent.Metadata"/> bag. Every advanced rule uses it, so
/// keeping the code in one place means one test case each instead of five.
/// </summary>
internal static class EventFieldExtractor
{
    public static string? GetString(SecurityEvent e, string key)
    {
        if (string.IsNullOrEmpty(e.Metadata)) return null;
        try
        {
            using var doc = JsonDocument.Parse(e.Metadata);
            return doc.RootElement.TryGetProperty(key, out var v) && v.ValueKind == JsonValueKind.String
                ? v.GetString()
                : null;
        }
        catch { return null; }
    }

    public static long? GetLong(SecurityEvent e, string key)
    {
        if (string.IsNullOrEmpty(e.Metadata)) return null;
        try
        {
            using var doc = JsonDocument.Parse(e.Metadata);
            return doc.RootElement.TryGetProperty(key, out var v) && v.ValueKind == JsonValueKind.Number
                ? v.GetInt64()
                : null;
        }
        catch { return null; }
    }

    /// <summary>Shannon entropy (bits per char) of the string. Higher = more random.</summary>
    public static double ShannonEntropy(string s)
    {
        if (string.IsNullOrEmpty(s)) return 0;
        var frequencies = s.GroupBy(c => c).ToDictionary(g => g.Key, g => g.Count());
        double entropy = 0;
        foreach (var pair in frequencies)
        {
            var p = (double)pair.Value / s.Length;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }
}
