using System.Text.RegularExpressions;

namespace SOCPlatform.Infrastructure.Services;

/// <summary>
/// Service for masking Personally Identifiable Information (PII) in log data and audit trails.
/// Prevents sensitive data (emails, IPs, SSNs, credit cards) from being stored in plain text.
/// </summary>
public static partial class PiiMaskingService
{
    /// <summary>
    /// Masks all recognized PII patterns in the input string.
    /// </summary>
    public static string MaskPii(string? input)
    {
        if (string.IsNullOrWhiteSpace(input)) return input ?? string.Empty;

        var result = input;
        result = MaskEmails(result);
        result = MaskIpAddresses(result);
        result = MaskSsns(result);
        result = MaskCreditCards(result);
        return result;
    }

    /// <summary>
    /// Masks email addresses: user@domain.com → u***@domain.com
    /// </summary>
    public static string MaskEmails(string input)
    {
        return EmailPattern().Replace(input, match =>
        {
            var local = match.Groups[1].Value;
            var domain = match.Groups[2].Value;
            var masked = local.Length <= 1 ? "*" : local[0] + new string('*', Math.Min(local.Length - 1, 5));
            return $"{masked}@{domain}";
        });
    }

    /// <summary>
    /// Masks IP addresses: 192.168.1.100 → 192.168.xxx.xxx
    /// </summary>
    public static string MaskIpAddresses(string input)
    {
        return IpAddressPattern().Replace(input, match =>
        {
            var parts = match.Value.Split('.');
            return $"{parts[0]}.{parts[1]}.xxx.xxx";
        });
    }

    /// <summary>
    /// Masks SSNs: 123-45-6789 → ***-**-6789
    /// </summary>
    public static string MaskSsns(string input)
    {
        return SsnPattern().Replace(input, "***-**-$1");
    }

    /// <summary>
    /// Masks credit card numbers: 1234-5678-9012-3456 → ****-****-****-3456
    /// </summary>
    public static string MaskCreditCards(string input)
    {
        return CreditCardPattern().Replace(input, match =>
        {
            var lastFour = match.Value[^4..];
            return $"****-****-****-{lastFour}";
        });
    }

    [GeneratedRegex(@"([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})")]
    private static partial Regex EmailPattern();

    [GeneratedRegex(@"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")]
    private static partial Regex IpAddressPattern();

    [GeneratedRegex(@"\b\d{3}-\d{2}-(\d{4})\b")]
    private static partial Regex SsnPattern();

    [GeneratedRegex(@"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b")]
    private static partial Regex CreditCardPattern();
}
