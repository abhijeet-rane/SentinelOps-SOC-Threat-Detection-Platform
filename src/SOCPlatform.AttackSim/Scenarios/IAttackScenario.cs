using SOCPlatform.Core.DTOs;

namespace SOCPlatform.AttackSim.Scenarios;

/// <summary>
/// Each attack scenario knows how to synthesise SecurityEvents and what
/// detection rule name(s) it expects to fire. AttackRunner calls Build()
/// then watches /api/v1/alerts for those rule names to appear.
/// </summary>
public interface IAttackScenario
{
    /// <summary>CLI command name (e.g. "brute-force").</summary>
    string Name { get; }

    /// <summary>Short description for --help.</summary>
    string Description { get; }

    /// <summary>Detection rule names (<see cref="Alert.DetectionRuleName"/>) that should fire.</summary>
    string[] ExpectedRules { get; }

    /// <summary>Synthesise the events the scenario needs.</summary>
    List<SyntheticSecurityEventDto> Build();
}
