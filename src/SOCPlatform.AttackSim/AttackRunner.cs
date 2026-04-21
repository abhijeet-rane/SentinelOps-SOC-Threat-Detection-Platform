using SOCPlatform.AttackSim.Scenarios;
using SOCPlatform.Core.DTOs;

namespace SOCPlatform.AttackSim;

/// <summary>
/// Runs one or more <see cref="IAttackScenario"/> against a live API:
///   1. Login as admin
///   2. Record "since" timestamp
///   3. POST synthesised events to /simulator/inject
///   4. Poll /alerts every 5 s (up to 45 s) for the expected detection rules
///   5. Print per-scenario pass/fail report
///   6. Exit 0 only if every scenario's ExpectedRules fire
/// </summary>
public sealed class AttackRunner
{
    private readonly ApiClient _client;
    private readonly string _baseUrl;
    private readonly string _username;
    private readonly string _password;
    private readonly TimeSpan _waitTimeout;

    public AttackRunner(string baseUrl, string username, string password, int waitSeconds = 45)
    {
        _baseUrl = baseUrl;
        _username = username;
        _password = password;
        _waitTimeout = TimeSpan.FromSeconds(waitSeconds);
        _client = new ApiClient(baseUrl);
    }

    public async Task<int> RunAsync(IReadOnlyList<IAttackScenario> scenarios, CancellationToken ct)
    {
        Console.WriteLine($"┌─ SentinelOps Attack Simulator ──────────────────────────────");
        Console.WriteLine($"│  target      : {_baseUrl}");
        Console.WriteLine($"│  scenarios   : {scenarios.Count}");
        Console.WriteLine($"│  wait/cycle  : {_waitTimeout.TotalSeconds:F0}s (detection engine polls every 15 s)");
        Console.WriteLine($"└─────────────────────────────────────────────────────────────\n");

        try
        {
            Console.Write("Authenticating… ");
            await _client.LoginAsync(_username, _password, ct);
            Console.WriteLine("OK\n");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"FAILED: {ex.Message}");
            return 2;
        }

        int passed = 0, failed = 0;
        foreach (var scenario in scenarios)
        {
            var ok = await RunOneAsync(scenario, ct);
            if (ok) passed++; else failed++;
        }

        Console.WriteLine(new string('─', 65));
        var verdict = failed == 0 ? "PASS" : "FAIL";
        Console.WriteLine($"  {verdict}  ·  {passed} passed · {failed} failed · {scenarios.Count} total");
        Console.WriteLine(new string('─', 65));
        return failed == 0 ? 0 : 1;
    }

    private async Task<bool> RunOneAsync(IAttackScenario scenario, CancellationToken ct)
    {
        Console.WriteLine($"▶ {scenario.Name}");
        Console.WriteLine($"  └ {scenario.Description}");
        Console.WriteLine($"  └ expected rule(s): {string.Join(" · ", scenario.ExpectedRules)}");

        var events = scenario.Build();
        // 5 s grace window so clock-skew doesn't hide the first alert
        var since = DateTime.UtcNow.AddSeconds(-5);

        try
        {
            var result = await _client.InjectAsync(new SimulatorInjectRequest
            {
                ScenarioTag = scenario.Name,
                Events = events
            }, ct);
            Console.WriteLine($"  └ injected {result.EventsInserted} events (ids {result.FirstEventId}..{result.LastEventId})");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  └ ✗ inject failed: {ex.Message}\n");
            return false;
        }

        Console.Write("  └ waiting for detection");
        var deadline = DateTime.UtcNow.Add(_waitTimeout);
        HashSet<string>? matched = null;

        while (DateTime.UtcNow < deadline)
        {
            ct.ThrowIfCancellationRequested();
            await Task.Delay(5_000, ct);
            Console.Write('.');

            var alerts = await _client.GetAlertsSinceAsync(since, ct);
            matched = scenario.ExpectedRules
                .Where(r => alerts.Any(a => string.Equals(a.DetectionRuleName, r, StringComparison.OrdinalIgnoreCase)))
                .ToHashSet();

            if (matched.Count == scenario.ExpectedRules.Length) break;
        }
        Console.WriteLine();

        matched ??= new HashSet<string>();
        var allFired = matched.Count == scenario.ExpectedRules.Length;
        if (allFired)
        {
            Console.WriteLine($"  └ ✓ PASS  ·  all {matched.Count} expected rule(s) fired\n");
            return true;
        }

        var missing = scenario.ExpectedRules.Except(matched).ToList();
        Console.WriteLine($"  └ ✗ FAIL  ·  missing: {string.Join(", ", missing)}\n");
        return false;
    }
}
