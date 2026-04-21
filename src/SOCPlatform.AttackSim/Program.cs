using System.CommandLine;
using SOCPlatform.AttackSim;
using SOCPlatform.AttackSim.Scenarios;

// ── Registry of every scenario the CLI can run ────────────────────────────
var all = new IAttackScenario[]
{
    new BruteForceScenario(),
    new PortScanScenario(),
    new PrivEscScenario(),
    new C2BeaconScenario(),
    new DgaScenario(),
    new DnsTunnelScenario(),
    new LateralMovementScenario(),
    new DataExfilScenario(),
};

// ── Shared options ────────────────────────────────────────────────────────
var urlOpt      = new Option<string>("--url",      () => "http://localhost:5101", "SentinelOps API base URL");
var userOpt     = new Option<string>("--user",     () => "admin",                  "Admin username");
var passOpt     = new Option<string>("--password", () => "Admin@Soc2026!",         "Admin password");
var waitOpt     = new Option<int>   ("--wait",     () => 45,                       "Seconds to wait for each scenario's alerts");

// ── Root + subcommands ────────────────────────────────────────────────────
var root = new RootCommand("SentinelOps attack simulator — synthesises attack events, injects them into the platform, then verifies the expected detection rules fired.");
root.AddGlobalOption(urlOpt);
root.AddGlobalOption(userOpt);
root.AddGlobalOption(passOpt);
root.AddGlobalOption(waitOpt);

// Per-scenario commands: `sentinelattack brute-force`, `sentinelattack c2-beacon`, …
foreach (var scenario in all)
{
    var cmd = new Command(scenario.Name, scenario.Description);
    cmd.SetHandler(async (url, user, pwd, wait) =>
    {
        var runner = new AttackRunner(url, user, pwd, wait);
        Environment.ExitCode = await runner.RunAsync(new[] { scenario }, CancellationToken.None);
    }, urlOpt, userOpt, passOpt, waitOpt);
    root.AddCommand(cmd);
}

// Combined command — runs every scenario in sequence, like a kill-chain drill
var fullCmd = new Command("full-kill-chain", "Run every attack scenario back-to-back and verify every detection rule fires.");
fullCmd.SetHandler(async (url, user, pwd, wait) =>
{
    var runner = new AttackRunner(url, user, pwd, wait);
    Environment.ExitCode = await runner.RunAsync(all, CancellationToken.None);
}, urlOpt, userOpt, passOpt, waitOpt);
root.AddCommand(fullCmd);

// `sentinelattack list` — handy for discovery
var listCmd = new Command("list", "List every available scenario and the detection rule(s) it expects to trigger.");
listCmd.SetHandler(() =>
{
    Console.WriteLine("Available scenarios:");
    foreach (var s in all)
        Console.WriteLine($"  {s.Name,-20}  {s.Description}\n                        → {string.Join(", ", s.ExpectedRules)}");
});
root.AddCommand(listCmd);

return await root.InvokeAsync(args);
