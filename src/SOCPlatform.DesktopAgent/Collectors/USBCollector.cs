using System.Management;
using System.Text.Json;
using SOCPlatform.Core.DTOs;

namespace SOCPlatform.DesktopAgent.Collectors;

/// <summary>
/// Monitors USB device plug/unplug events using WMI.
/// Detects new USB mass storage devices for data exfiltration monitoring.
/// </summary>
public class USBCollector : ILogCollector
{
    public string Name => "USBCollector";
    public bool IsEnabled => true;

    private readonly Guid _endpointId;
    private readonly HashSet<string> _knownDevices = new();
    private bool _initialized;

    public USBCollector(Guid endpointId)
    {
        _endpointId = endpointId;
    }

    public Task<List<LogIngestionDto>> CollectAsync(CancellationToken cancellationToken)
    {
        var logs = new List<LogIngestionDto>();

        try
        {
            var currentDevices = new HashSet<string>();

            using var searcher = new ManagementObjectSearcher(
                "SELECT * FROM Win32_DiskDrive WHERE InterfaceType='USB'");

            foreach (var device in searcher.Get())
            {
                cancellationToken.ThrowIfCancellationRequested();

                var deviceId = device["DeviceID"]?.ToString() ?? "Unknown";
                var model = device["Model"]?.ToString() ?? "Unknown";
                var serialNumber = device["SerialNumber"]?.ToString();
                var size = device["Size"]?.ToString();

                currentDevices.Add(deviceId);

                // Report new devices (not seen in previous scan)
                if (_initialized && !_knownDevices.Contains(deviceId))
                {
                    logs.Add(new LogIngestionDto
                    {
                        EndpointId = _endpointId,
                        Source = "USBMonitor",
                        EventType = "USBDeviceConnected",
                        Severity = "Medium",
                        RawData = JsonSerializer.Serialize(new
                        {
                            DeviceId = deviceId,
                            Model = model,
                            SerialNumber = serialNumber,
                            SizeBytes = size,
                            InterfaceType = "USB"
                        }),
                        Hostname = Environment.MachineName,
                        Timestamp = DateTime.UtcNow
                    });
                }
            }

            // Detect removed devices
            if (_initialized)
            {
                foreach (var oldDevice in _knownDevices.Except(currentDevices))
                {
                    logs.Add(new LogIngestionDto
                    {
                        EndpointId = _endpointId,
                        Source = "USBMonitor",
                        EventType = "USBDeviceDisconnected",
                        Severity = "Low",
                        RawData = JsonSerializer.Serialize(new
                        {
                            DeviceId = oldDevice,
                            Note = "USB device removed"
                        }),
                        Hostname = Environment.MachineName,
                        Timestamp = DateTime.UtcNow
                    });
                }
            }

            _knownDevices.Clear();
            foreach (var d in currentDevices) _knownDevices.Add(d);
            _initialized = true;
        }
        catch (Exception)
        {
            // WMI may not be available
        }

        return Task.FromResult(logs);
    }
}
