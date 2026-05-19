using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Threading;
using Hardcodet.Wpf.TaskbarNotification;
using SOCPlatform.DesktopAgent.Models;
using SOCPlatform.DesktopAgent.Services;

namespace SOCPlatform.DesktopAgent;

/// <summary>
/// Application with full SOC Platform Agent functionality
/// </summary>
public partial class App : Application
{
    private TaskbarIcon? _notifyIcon;
    private Window? _mainWindow;
    private CollectionService? _collectionService;
    private ApiClientService? _apiClient;
    private OfflineBufferService? _offlineBuffer;
    private AgentConfig? _config;
    private DispatcherTimer? _updateTimer;

    // UI elements for real-time updates
    private System.Windows.Controls.TextBlock? _statusText;
    private System.Windows.Controls.TextBlock? _connectionText;
    private System.Windows.Controls.TextBlock? _logsCollectedText;
    private System.Windows.Controls.TextBlock? _logsSentText;
    private System.Windows.Controls.TextBlock? _bufferedText;
    private System.Windows.Controls.StackPanel? _activityPanel;
    private System.Windows.Controls.Button? _toggleButton;
    private readonly List<string> _activityHistory = new();

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        try
        {
            // Load configuration
            _config = LoadConfiguration();

            // Initialize services
            _offlineBuffer = new OfflineBufferService();
            _apiClient = new ApiClientService(
                _config.ApiBaseUrl,
                _config.ApiKey,
                _config.PinnedThumbprintSha256,
                _config.AllowInvalidCerts);
            _collectionService = new CollectionService(
                _apiClient,
                _offlineBuffer,
                _config.EndpointId,
                TimeSpan.FromSeconds(_config.CollectionIntervalSeconds));

            // Subscribe to status changes
            _collectionService.StatusChanged += OnStatusChanged;

            // Create system tray icon
            _notifyIcon = new TaskbarIcon
            {
                Icon = new System.Drawing.Icon(Application.GetResourceStream(new Uri("pack://application:,,,/agent.ico")).Stream),
                ToolTipText = "SOC Platform Agent - Running"
            };

            // Add context menu to tray icon
            var contextMenu = new System.Windows.Controls.ContextMenu();
            
            var showMenuItem = new System.Windows.Controls.MenuItem { Header = "Show Window" };
            showMenuItem.Click += (s, args) => ShowMainWindow();
            contextMenu.Items.Add(showMenuItem);
            
            contextMenu.Items.Add(new System.Windows.Controls.Separator());
            
            var exitMenuItem = new System.Windows.Controls.MenuItem { Header = "Exit" };
            exitMenuItem.Click += (s, args) => ExitApplication();
            contextMenu.Items.Add(exitMenuItem);
            
            _notifyIcon.ContextMenu = contextMenu;
            
            // Double-click to show window
            _notifyIcon.TrayMouseDoubleClick += (s, args) => ShowMainWindow();

            // Create the main window
            _mainWindow = CreateMainWindow();

            // Handle window closing - minimize to tray instead
            _mainWindow.Closing += (s, args) =>
            {
                args.Cancel = true;
                _mainWindow.Hide();
                _notifyIcon?.ShowBalloonTip("SOC Platform Agent", "Agent minimized to system tray", Hardcodet.Wpf.TaskbarNotification.BalloonIcon.Info);
            };

            // Set the main window so the application doesn't exit
            MainWindow = _mainWindow;
            
            // Start the collection service
            _collectionService.Start();
            
            // Start UI update timer
            _updateTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(1)
            };
            _updateTimer.Tick += UpdateUI;
            _updateTimer.Start();

            // Show the window on startup
            _mainWindow.Show();
            
            // Show tray notification
            _notifyIcon?.ShowBalloonTip("SOC Platform Agent", "Agent started successfully", Hardcodet.Wpf.TaskbarNotification.BalloonIcon.Info);
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                $"STARTUP ERROR:\n\n{ex.GetType().Name}\n\nMessage: {ex.Message}\n\nStack Trace:\n{ex.StackTrace}\n\nInner Exception: {ex.InnerException?.Message}",
                "Critical Error",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
            
            // Write to a log file
            try
            {
                var logPath = System.IO.Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                    "SOCAgent_Error.txt");
                System.IO.File.WriteAllText(logPath, $"Error at {DateTime.Now}\n\n{ex}");
                MessageBox.Show($"Error details saved to:\n{logPath}", "Error Log", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch { }
            
            Shutdown(1);
        }
    }

    private Window CreateMainWindow()
    {
        var window = new Window
        {
            Title = "SOC Platform Agent",
            Width = 500,
            Height = 500,
            WindowStartupLocation = WindowStartupLocation.CenterScreen,
            ResizeMode = ResizeMode.CanResize,
            Icon = System.Windows.Media.Imaging.BitmapFrame.Create(
                Application.GetResourceStream(new Uri("pack://application:,,,/agent.ico")).Stream)
        };

        var stackPanel = new System.Windows.Controls.StackPanel
        {
            Margin = new Thickness(20)
        };

        // Title
        var title = new System.Windows.Controls.TextBlock
        {
            Text = "🛡️ SOC Platform Agent",
            FontSize = 20,
            FontWeight = FontWeights.Bold,
            Margin = new Thickness(0, 0, 0, 20),
            HorizontalAlignment = HorizontalAlignment.Center
        };
        stackPanel.Children.Add(title);

        // Status Grid
        var statusGrid = new System.Windows.Controls.Grid
        {
            Margin = new Thickness(0, 0, 0, 15)
        };
        statusGrid.ColumnDefinitions.Add(new System.Windows.Controls.ColumnDefinition { Width = new GridLength(150) });
        statusGrid.ColumnDefinitions.Add(new System.Windows.Controls.ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        statusGrid.RowDefinitions.Add(new System.Windows.Controls.RowDefinition());
        statusGrid.RowDefinitions.Add(new System.Windows.Controls.RowDefinition());
        statusGrid.RowDefinitions.Add(new System.Windows.Controls.RowDefinition());
        statusGrid.RowDefinitions.Add(new System.Windows.Controls.RowDefinition());
        statusGrid.RowDefinitions.Add(new System.Windows.Controls.RowDefinition());

        // Status
        var statusLabel = new System.Windows.Controls.TextBlock { Text = "Status:", FontWeight = FontWeights.Bold };
        System.Windows.Controls.Grid.SetRow(statusLabel, 0);
        System.Windows.Controls.Grid.SetColumn(statusLabel, 0);
        statusGrid.Children.Add(statusLabel);

        _statusText = new System.Windows.Controls.TextBlock
        {
            Text = "Starting...",
            Foreground = System.Windows.Media.Brushes.Orange,
            FontWeight = FontWeights.Bold
        };
        System.Windows.Controls.Grid.SetRow(_statusText, 0);
        System.Windows.Controls.Grid.SetColumn(_statusText, 1);
        statusGrid.Children.Add(_statusText);

        // Connection
        var connectionLabel = new System.Windows.Controls.TextBlock { Text = "Connection:", FontWeight = FontWeights.Bold, Margin = new Thickness(0, 5, 0, 0) };
        System.Windows.Controls.Grid.SetRow(connectionLabel, 1);
        System.Windows.Controls.Grid.SetColumn(connectionLabel, 0);
        statusGrid.Children.Add(connectionLabel);

        _connectionText = new System.Windows.Controls.TextBlock
        {
            Text = "Checking...",
            Margin = new Thickness(0, 5, 0, 0)
        };
        System.Windows.Controls.Grid.SetRow(_connectionText, 1);
        System.Windows.Controls.Grid.SetColumn(_connectionText, 1);
        statusGrid.Children.Add(_connectionText);

        // Logs Collected
        var collectedLabel = new System.Windows.Controls.TextBlock { Text = "Logs Collected:", FontWeight = FontWeights.Bold, Margin = new Thickness(0, 5, 0, 0) };
        System.Windows.Controls.Grid.SetRow(collectedLabel, 2);
        System.Windows.Controls.Grid.SetColumn(collectedLabel, 0);
        statusGrid.Children.Add(collectedLabel);

        _logsCollectedText = new System.Windows.Controls.TextBlock
        {
            Text = "0",
            Margin = new Thickness(0, 5, 0, 0)
        };
        System.Windows.Controls.Grid.SetRow(_logsCollectedText, 2);
        System.Windows.Controls.Grid.SetColumn(_logsCollectedText, 1);
        statusGrid.Children.Add(_logsCollectedText);

        // Logs Sent
        var sentLabel = new System.Windows.Controls.TextBlock { Text = "Logs Sent:", FontWeight = FontWeights.Bold, Margin = new Thickness(0, 5, 0, 0) };
        System.Windows.Controls.Grid.SetRow(sentLabel, 3);
        System.Windows.Controls.Grid.SetColumn(sentLabel, 0);
        statusGrid.Children.Add(sentLabel);

        _logsSentText = new System.Windows.Controls.TextBlock
        {
            Text = "0",
            Margin = new Thickness(0, 5, 0, 0)
        };
        System.Windows.Controls.Grid.SetRow(_logsSentText, 3);
        System.Windows.Controls.Grid.SetColumn(_logsSentText, 1);
        statusGrid.Children.Add(_logsSentText);

        // Buffered
        var bufferedLabel = new System.Windows.Controls.TextBlock { Text = "Buffered (offline):", FontWeight = FontWeights.Bold, Margin = new Thickness(0, 5, 0, 0) };
        System.Windows.Controls.Grid.SetRow(bufferedLabel, 4);
        System.Windows.Controls.Grid.SetColumn(bufferedLabel, 0);
        statusGrid.Children.Add(bufferedLabel);

        _bufferedText = new System.Windows.Controls.TextBlock
        {
            Text = "0",
            Margin = new Thickness(0, 5, 0, 0)
        };
        System.Windows.Controls.Grid.SetRow(_bufferedText, 4);
        System.Windows.Controls.Grid.SetColumn(_bufferedText, 1);
        statusGrid.Children.Add(_bufferedText);

        stackPanel.Children.Add(statusGrid);

        // Last Activity Section
        var activityBorder = new System.Windows.Controls.Border
        {
            Background = System.Windows.Media.Brushes.LightGray,
            CornerRadius = new CornerRadius(4),
            Padding = new Thickness(10),
            Margin = new Thickness(0, 0, 0, 15),
            MaxHeight = 120
        };

        var activityScrollViewer = new System.Windows.Controls.ScrollViewer
        {
            VerticalScrollBarVisibility = System.Windows.Controls.ScrollBarVisibility.Auto,
            MaxHeight = 100
        };

        var activityContainer = new System.Windows.Controls.StackPanel();
        
        var activityTitle = new System.Windows.Controls.TextBlock
        {
            Text = "Recent Activity",
            FontSize = 11,
            FontWeight = FontWeights.Bold,
            Margin = new Thickness(0, 0, 0, 5)
        };
        activityContainer.Children.Add(activityTitle);

        _activityPanel = new System.Windows.Controls.StackPanel();
        
        var initialActivity = new System.Windows.Controls.TextBlock
        {
            Text = "Waiting for first collection cycle...",
            FontSize = 10,
            TextWrapping = TextWrapping.Wrap,
            Foreground = System.Windows.Media.Brushes.Gray
        };
        _activityPanel.Children.Add(initialActivity);

        activityContainer.Children.Add(_activityPanel);
        activityScrollViewer.Content = activityContainer;
        activityBorder.Child = activityScrollViewer;
        stackPanel.Children.Add(activityBorder);

        // Buttons
        var buttonPanel = new System.Windows.Controls.StackPanel
        {
            Orientation = System.Windows.Controls.Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Center,
            Margin = new Thickness(0, 10, 0, 0)
        };

        // Toggle button
        _toggleButton = new System.Windows.Controls.Button
        {
            Content = "Stop",
            Width = 100,
            Height = 35,
            Margin = new Thickness(5),
            FontSize = 14,
            FontWeight = FontWeights.Bold,
            Background = System.Windows.Media.Brushes.OrangeRed,
            Foreground = System.Windows.Media.Brushes.White
        };
        _toggleButton.Click += ToggleButton_Click;
        buttonPanel.Children.Add(_toggleButton);

        // Minimize button
        var minimizeButton = new System.Windows.Controls.Button
        {
            Content = "Minimize to Tray",
            Width = 120,
            Height = 35,
            Margin = new Thickness(5),
            FontSize = 14,
            FontWeight = FontWeights.Bold,
            Background = System.Windows.Media.Brushes.LightBlue,
            Foreground = System.Windows.Media.Brushes.Black
        };
        minimizeButton.Click += (s, args) => 
        {
            _mainWindow?.Hide();
            _notifyIcon?.ShowBalloonTip("SOC Platform Agent", "Agent minimized to system tray", Hardcodet.Wpf.TaskbarNotification.BalloonIcon.Info);
        };
        buttonPanel.Children.Add(minimizeButton);

        // Exit button
        var exitButton = new System.Windows.Controls.Button
        {
            Content = "Exit",
            Width = 100,
            Height = 35,
            Margin = new Thickness(5),
            FontSize = 14,
            FontWeight = FontWeights.Bold,
            Background = System.Windows.Media.Brushes.LightCoral,
            Foreground = System.Windows.Media.Brushes.White
        };
        exitButton.Click += (s, args) => ExitApplication();
        buttonPanel.Children.Add(exitButton);

        stackPanel.Children.Add(buttonPanel);

        window.Content = stackPanel;
        return window;
    }

    private void ToggleButton_Click(object sender, RoutedEventArgs e)
    {
        if (_collectionService == null || _toggleButton == null) return;

        if (_collectionService.IsRunning)
        {
            _collectionService.Stop();
            _toggleButton.Content = "Start";
            _toggleButton.Background = System.Windows.Media.Brushes.Green;
        }
        else
        {
            _collectionService.Start();
            _toggleButton.Content = "Stop";
            _toggleButton.Background = System.Windows.Media.Brushes.OrangeRed;
        }
    }

    private void UpdateUI(object? sender, EventArgs e)
    {
        if (_collectionService == null || _apiClient == null) return;

        // Update statistics
        if (_logsCollectedText != null)
            _logsCollectedText.Text = _collectionService.TotalLogsCollected.ToString();

        if (_logsSentText != null)
            _logsSentText.Text = _collectionService.TotalLogsSent.ToString();

        if (_bufferedText != null)
            _bufferedText.Text = _collectionService.BufferedCount.ToString();

        // Update status
        if (_statusText != null)
        {
            if (_collectionService.IsRunning)
            {
                _statusText.Text = "Running";
                _statusText.Foreground = System.Windows.Media.Brushes.Green;
            }
            else
            {
                _statusText.Text = "Stopped";
                _statusText.Foreground = System.Windows.Media.Brushes.Red;
            }
        }

        // Update connection status
        if (_connectionText != null)
        {
            if (_apiClient.IsConnected)
            {
                _connectionText.Text = "Connected";
                _connectionText.Foreground = System.Windows.Media.Brushes.Green;
            }
            else
            {
                _connectionText.Text = "Disconnected (buffering)";
                _connectionText.Foreground = System.Windows.Media.Brushes.Orange;
            }
        }
    }

    private void OnStatusChanged(string status)
    {
        Dispatcher.Invoke(() =>
        {
            var timestamp = DateTime.Now.ToString("HH:mm:ss");
            
            // Create more descriptive messages
            string displayMessage = status switch
            {
                var s when s.StartsWith("Initialized") => $"🔧 {status}",
                var s when s.Contains("Collected") && s.Contains("logs") => 
                    $"📥 Collected {ExtractNumber(s)} security events from Windows",
                var s when s.StartsWith("Sent") && s.Contains("logs to API") => 
                    $"✅ Successfully sent {ExtractNumber(s)} events to SOC Platform",
                var s when s.StartsWith("Buffered") && s.Contains("logs offline") => 
                    $"💾 Buffered {ExtractNumber(s)} events offline (API unavailable)",
                var s when s.StartsWith("Flushed") && s.Contains("buffered batches") => 
                    $"🔄 Flushed {ExtractNumber(s)} buffered batches to API",
                "Running" => "▶️ Collection service started",
                "Stopped" => "⏸️ Collection service stopped",
                var s when s.Contains("error") || s.Contains("Error") => $"❌ {s}",
                _ => status
            };

            var activityText = $"[{timestamp}] {displayMessage}";
            _activityHistory.Add(activityText);

            // Keep only last 10 activities
            if (_activityHistory.Count > 10)
            {
                _activityHistory.RemoveAt(0);
            }

            // Update UI
            if (_activityPanel != null)
            {
                _activityPanel.Children.Clear();
                
                // Show activities in reverse order (newest first)
                for (int i = _activityHistory.Count - 1; i >= 0; i--)
                {
                    var activityLine = new System.Windows.Controls.TextBlock
                    {
                        Text = _activityHistory[i],
                        FontSize = 10,
                        TextWrapping = TextWrapping.Wrap,
                        Margin = new Thickness(0, 2, 0, 2),
                        Foreground = _activityHistory[i].Contains("❌") ? System.Windows.Media.Brushes.Red :
                                    _activityHistory[i].Contains("✅") ? System.Windows.Media.Brushes.DarkGreen :
                                    _activityHistory[i].Contains("💾") ? System.Windows.Media.Brushes.Orange :
                                    System.Windows.Media.Brushes.Black
                    };
                    _activityPanel.Children.Add(activityLine);
                }
            }
        });
    }

    private static int ExtractNumber(string text)
    {
        var match = System.Text.RegularExpressions.Regex.Match(text, @"\d+");
        return match.Success ? int.Parse(match.Value) : 0;
    }

    private AgentConfig LoadConfiguration()
    {
        var appData = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "SOCPlatform", "Agent");
        Directory.CreateDirectory(appData);

        var configPath = Path.Combine(appData, "agent_config.json");

        if (File.Exists(configPath))
        {
            try
            {
                var json = File.ReadAllText(configPath);
                return JsonSerializer.Deserialize<AgentConfig>(json) ?? new AgentConfig();
            }
            catch
            {
                // Fall through to create default config
            }
        }

        // Create default config
        var config = new AgentConfig();
        var configJson = JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(configPath, configJson);

        return config;
    }

    private void ShowMainWindow()
    {
        if (_mainWindow != null)
        {
            _mainWindow.Show();
            _mainWindow.WindowState = WindowState.Normal;
            _mainWindow.Activate();
        }
    }

    private void ExitApplication()
    {
        var result = MessageBox.Show(
            "Are you sure you want to exit the SOC Platform Agent?",
            "Confirm Exit",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);
        
        if (result == MessageBoxResult.Yes)
        {
            _updateTimer?.Stop();
            _collectionService?.Stop();
            _apiClient?.Dispose();
            _offlineBuffer?.Dispose();
            _notifyIcon?.Dispose();
            Shutdown(0);
        }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _updateTimer?.Stop();
        _collectionService?.Stop();
        _apiClient?.Dispose();
        _offlineBuffer?.Dispose();
        _notifyIcon?.Dispose();
        base.OnExit(e);
    }
}
