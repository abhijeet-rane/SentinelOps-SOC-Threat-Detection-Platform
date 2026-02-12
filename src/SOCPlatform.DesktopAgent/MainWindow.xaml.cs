using System.ComponentModel;
using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;
using SOCPlatform.DesktopAgent.Services;

namespace SOCPlatform.DesktopAgent;

public partial class MainWindow : Window
{
    private readonly CollectionService _collectionService;
    private readonly ApiClientService _apiClient;
    private readonly DispatcherTimer _uiTimer;

    public MainWindow(CollectionService collectionService, ApiClientService apiClient)
    {
        InitializeComponent();

        _collectionService = collectionService;
        _apiClient = apiClient;

        // Subscribe to status updates
        _collectionService.StatusChanged += OnStatusChanged;

        // UI refresh timer
        _uiTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
        _uiTimer.Tick += (_, _) => RefreshUI();
        _uiTimer.Start();

        // Start collection
        _collectionService.Start();
        StatusText.Text = "Running";
    }

    private void RefreshUI()
    {
        LogsCollectedText.Text = _collectionService.TotalLogsCollected.ToString("N0");
        LogsSentText.Text = _collectionService.TotalLogsSent.ToString("N0");
        BufferedText.Text = _collectionService.BufferedCount.ToString("N0");

        if (_apiClient.IsConnected)
        {
            ConnectionText.Text = "Connected";
            ConnectionText.Foreground = new SolidColorBrush(Color.FromRgb(0xA6, 0xE3, 0xA1)); // Green
        }
        else
        {
            ConnectionText.Text = "Disconnected (buffering)";
            ConnectionText.Foreground = new SolidColorBrush(Color.FromRgb(0xF3, 0x8B, 0xA8)); // Red
        }
    }

    private void OnStatusChanged(string status)
    {
        Dispatcher.Invoke(() =>
        {
            LastActivityText.Text = $"[{DateTime.Now:HH:mm:ss}] {status}";
        });
    }

    private void ToggleButton_Click(object sender, RoutedEventArgs e)
    {
        if (_collectionService.IsRunning)
        {
            _collectionService.Stop();
            StatusText.Text = "Stopped";
            StatusText.Foreground = new SolidColorBrush(Color.FromRgb(0xF3, 0x8B, 0xA8));
            ToggleButton.Content = "Start";
            ToggleButton.Background = new SolidColorBrush(Color.FromRgb(0xA6, 0xE3, 0xA1));
        }
        else
        {
            _collectionService.Start();
            StatusText.Text = "Running";
            StatusText.Foreground = new SolidColorBrush(Color.FromRgb(0xA6, 0xE3, 0xA1));
            ToggleButton.Content = "Stop";
            ToggleButton.Background = new SolidColorBrush(Color.FromRgb(0xF3, 0x8B, 0xA8));
        }
    }

    private void HideButton_Click(object sender, RoutedEventArgs e)
    {
        Hide();
    }

    private void Window_Closing(object sender, CancelEventArgs e)
    {
        // Minimize to tray instead of closing
        e.Cancel = true;
        Hide();
    }
}