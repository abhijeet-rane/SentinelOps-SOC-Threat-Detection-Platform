using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http;
using Microsoft.Extensions.Logging;
using Polly;
using Polly.Extensions.Http;

namespace SOCPlatform.Infrastructure.Resilience;

/// <summary>
/// Centralized Polly policies for outbound HTTP calls (ML service, AbuseIPDB, VirusTotal, SendGrid).
/// </summary>
public static class PolicyRegistry
{
    public const string MlServiceClient    = "ml-service";
    public const string AbuseIpDbClient    = "abuseipdb";
    public const string VirusTotalClient   = "virustotal";
    public const string SendGridClient     = "sendgrid";

    /// <summary>
    /// Standard retry: 3 retries with exponential back-off (2s, 4s, 8s) on transient HTTP failures + 5xx + 408.
    /// </summary>
    public static IAsyncPolicy<HttpResponseMessage> RetryPolicy() =>
        HttpPolicyExtensions
            .HandleTransientHttpError()
            .OrResult(r => r.StatusCode == HttpStatusCode.RequestTimeout)
            .WaitAndRetryAsync(
                retryCount: 3,
                sleepDurationProvider: attempt => TimeSpan.FromSeconds(Math.Pow(2, attempt)),
                onRetry: (outcome, delay, attempt, ctx) =>
                {
                    if (ctx.TryGetValue("logger", out var lo) && lo is ILogger logger)
                    {
                        logger.LogWarning(
                            "[Polly] Retry {Attempt} after {Delay}ms — {Status} {Reason}",
                            attempt, delay.TotalMilliseconds,
                            outcome.Result?.StatusCode, outcome.Exception?.Message);
                    }
                });

    /// <summary>
    /// Circuit breaker: opens for 30s after 5 consecutive failures.
    /// </summary>
    public static IAsyncPolicy<HttpResponseMessage> CircuitBreakerPolicy() =>
        HttpPolicyExtensions
            .HandleTransientHttpError()
            .CircuitBreakerAsync(
                handledEventsAllowedBeforeBreaking: 5,
                durationOfBreak: TimeSpan.FromSeconds(30));

    /// <summary>
    /// 10-second timeout per attempt (separate from circuit/retry).
    /// </summary>
    public static IAsyncPolicy<HttpResponseMessage> TimeoutPolicy(int seconds = 10) =>
        Polly.Policy.TimeoutAsync<HttpResponseMessage>(TimeSpan.FromSeconds(seconds));

    /// <summary>
    /// Configures one named HttpClient with the standard policy stack: timeout → retry → circuit-breaker.
    /// </summary>
    public static IHttpClientBuilder AddResilientHttpClient(
        this IServiceCollection services,
        string name,
        Action<HttpClient> configureClient,
        int timeoutSeconds = 10) =>
        services.AddHttpClient(name, configureClient)
            .AddPolicyHandler(TimeoutPolicy(timeoutSeconds))
            .AddPolicyHandler(RetryPolicy())
            .AddPolicyHandler(CircuitBreakerPolicy());
}
