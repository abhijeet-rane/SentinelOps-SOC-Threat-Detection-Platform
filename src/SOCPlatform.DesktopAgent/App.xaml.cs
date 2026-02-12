using System.Drawing;
using System.IO;
using System.Text.Json;
using System.Windows;
using Hardcodet.Wpf.TaskbarNotification;
using SOCPlatform.DesktopAgent.Services;

namespace SOCPlatform.DesktopAgent;

/// <summary>
/// Application startup logic: loads config, initializes services, creates system tray icon.
/// </summary>
public partial class App : Application
{
    private TaskbarIcon? _trayIcon;
    private CollectionService? _collectionService;
    private ApiClientService? _apiClient;
    private OfflineBufferService? _offlineBuffer;
    private MainWindow? _mainWindow;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // Load agent configuration
        var config = LoadConfig();

        // Initialize services
        _apiClient = new ApiClientService(config.ApiBaseUrl, config.ApiKey);
        _offlineBuffer = new OfflineBufferService();
        _collectionService = new CollectionService(
            _apiClient,
            _offlineBuffer,
            config.EndpointId,
            TimeSpan.FromSeconds(config.CollectionIntervalSeconds));

        // Create main window
        _mainWindow = new MainWindow(_collectionService, _apiClient);

        // Create system tray icon
        _trayIcon = new TaskbarIcon
        {
            ToolTipText = "SOC Platform Agent - Running",
            Icon = SystemIcons.Shield
        };

        // Context menu
        var contextMenu = new System.Windows.Controls.ContextMenu();

        var showItem = new System.Windows.Controls.MenuItem { Header = "Show Status" };
        showItem.Click += (_, _) => { _mainWindow.Show(); _mainWindow.Activate(); };

        var exitItem = new System.Windows.Controls.MenuItem { Header = "Exit Agent" };
        exitItem.Click += (_, _) =>
        {
            _collectionService?.Stop();
            _offlineBuffer?.Dispose();
            _apiClient?.Dispose();
            _trayIcon?.Dispose();
            Shutdown();
        };

        contextMenu.Items.Add(showItem);
        contextMenu.Items.Add(new System.Windows.Controls.Separator());
        contextMenu.Items.Add(exitItem);
        _trayIcon.ContextMenu = contextMenu;

        // Double-click to show window
        _trayIcon.TrayMouseDoubleClick += (_, _) => { _mainWindow.Show(); _mainWindow.Activate(); };

        // Update tray tooltip on status change
        _collectionService.StatusChanged += status =>
        {
            Current.Dispatcher.Invoke(() =>
            {
                if (_trayIcon != null)
                    _trayIcon.ToolTipText = $"SOC Agent: {status}";
            });
        };

        // Show the window on first launch
        _mainWindow.Show();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _collectionService?.Stop();
        _offlineBuffer?.Dispose();
        _apiClient?.Dispose();
        _trayIcon?.Dispose();
        base.OnExit(e);
    }

    private static AgentConfig LoadConfig()
    {
        var configPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "SOCPlatform", "Agent", "agent_config.json");

        if (File.Exists(configPath))
        {
            var json = File.ReadAllText(configPath);
            return JsonSerializer.Deserialize<AgentConfig>(json) ?? AgentConfig.Default;
        }

        // Create default config
        Directory.CreateDirectory(Path.GetDirectoryName(configPath)!);
        var defaultConfig = AgentConfig.Default;
        File.WriteAllText(configPath, JsonSerializer.Serialize(defaultConfig, new JsonSerializerOptions { WriteIndented = true }));
        return defaultConfig;
    }
}

public class AgentConfig
{
    public string ApiBaseUrl { get; set; } = "http://localhost:5101";
    public string ApiKey { get; set; } = "test-api-key-for-soc-platform-2026";
    public Guid EndpointId { get; set; } = Guid.NewGuid();
    public int CollectionIntervalSeconds { get; set; } = 30;

    public static AgentConfig Default => new();
}
