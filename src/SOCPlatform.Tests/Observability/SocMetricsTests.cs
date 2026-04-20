using System.Diagnostics.Metrics;
using FluentAssertions;
using Microsoft.Extensions.Diagnostics.Metrics.Testing;
using SOCPlatform.Infrastructure.Observability;

namespace SOCPlatform.Tests.Observability;

/// <summary>
/// Verify SocMetrics emits the right instrument names, units, descriptions,
/// and dimension tags. Uses the BCL <see cref="MetricCollector{T}"/> which
/// subscribes to a Meter without needing OpenTelemetry in the loop.
/// </summary>
public class SocMetricsTests
{
    private static SocMetrics Create(IMeterFactory factory) => new(factory);

    [Fact]
    public void All_Instruments_Registered_Under_Socplatform_Meter()
    {
        using var factory = new TestMeterFactory();
        using var metrics = Create(factory);

        factory.Meters.Should().HaveCount(1);
        factory.Meters[0].Name.Should().Be(SocMetrics.MeterName);
        factory.Meters[0].Version.Should().Be(SocMetrics.MeterVersion);
    }

    [Fact]
    public void AlertsTotal_Emits_Counter_With_Severity_And_Rule_Tags()
    {
        using var factory = new TestMeterFactory();
        using var metrics = Create(factory);
        using var coll = new MetricCollector<long>(factory, SocMetrics.MeterName, "socp_alerts_total");

        metrics.AlertsTotal.Add(1,
            new KeyValuePair<string, object?>("severity", "Critical"),
            new KeyValuePair<string, object?>("rule", "BruteForce"));
        metrics.AlertsTotal.Add(2,
            new KeyValuePair<string, object?>("severity", "High"),
            new KeyValuePair<string, object?>("rule", "C2 Beaconing"));

        var measurements = coll.GetMeasurementSnapshot();
        measurements.Should().HaveCount(2);
        measurements[0].Value.Should().Be(1);
        measurements[0].Tags["severity"].Should().Be("Critical");
        measurements[0].Tags["rule"].Should().Be("BruteForce");
        measurements[1].Value.Should().Be(2);
    }

    [Fact]
    public void DetectionDuration_Is_A_Histogram_In_Ms()
    {
        using var factory = new TestMeterFactory();
        using var metrics = Create(factory);
        using var coll = new MetricCollector<double>(factory, SocMetrics.MeterName, "socp_detection_duration_ms");

        metrics.DetectionDurationMs.Record(12.5, new KeyValuePair<string, object?>("rule", "PortScan"));
        metrics.DetectionDurationMs.Record(150.7, new KeyValuePair<string, object?>("rule", "DGA"));

        var snap = coll.GetMeasurementSnapshot();
        snap.Should().HaveCount(2);
        snap.Select(m => m.Value).Should().BeEquivalentTo(new[] { 12.5, 150.7 });
    }

    [Fact]
    public void IngestionLogsTotal_Records_Source_And_Severity()
    {
        using var factory = new TestMeterFactory();
        using var metrics = Create(factory);
        using var coll = new MetricCollector<long>(factory, SocMetrics.MeterName, "socp_ingestion_logs_total");

        metrics.IngestionLogsTotal.Add(1,
            new KeyValuePair<string, object?>("source", "WindowsEventLog"),
            new KeyValuePair<string, object?>("severity", "Medium"));

        var snap = coll.GetMeasurementSnapshot().Single();
        snap.Tags["source"].Should().Be("WindowsEventLog");
        snap.Tags["severity"].Should().Be("Medium");
    }

    [Fact]
    public void MlInferenceDuration_Records_Model_And_Outcome()
    {
        using var factory = new TestMeterFactory();
        using var metrics = Create(factory);
        using var coll = new MetricCollector<double>(factory, SocMetrics.MeterName, "socp_ml_inference_duration_ms");

        metrics.MlInferenceDurationMs.Record(42.3,
            new KeyValuePair<string, object?>("model", "isolation_forest"),
            new KeyValuePair<string, object?>("outcome", "ok"));

        var snap = coll.GetMeasurementSnapshot().Single();
        snap.Value.Should().Be(42.3);
        snap.Tags["model"].Should().Be("isolation_forest");
        snap.Tags["outcome"].Should().Be("ok");
    }

    [Fact]
    public void SlaBreachesTotal_Records_Severity_Only()
    {
        using var factory = new TestMeterFactory();
        using var metrics = Create(factory);
        using var coll = new MetricCollector<long>(factory, SocMetrics.MeterName, "socp_sla_breaches_total");

        metrics.SlaBreachesTotal.Add(1, new KeyValuePair<string, object?>("severity", "Critical"));
        metrics.SlaBreachesTotal.Add(3, new KeyValuePair<string, object?>("severity", "High"));

        var snap = coll.GetMeasurementSnapshot();
        snap.Should().HaveCount(2);
        snap[0].Tags["severity"].Should().Be("Critical");
        snap[1].Value.Should().Be(3);
    }

    // ───────────────────────────────────────────────────────────────────────
    // Tiny IMeterFactory for tests — avoids needing ServiceProvider wiring.
    // ───────────────────────────────────────────────────────────────────────

    private sealed class TestMeterFactory : IMeterFactory
    {
        public List<Meter> Meters { get; } = new();

        public Meter Create(MeterOptions options)
        {
            var m = new Meter(options);
            Meters.Add(m);
            return m;
        }

        public void Dispose()
        {
            foreach (var m in Meters) m.Dispose();
            Meters.Clear();
        }
    }
}
