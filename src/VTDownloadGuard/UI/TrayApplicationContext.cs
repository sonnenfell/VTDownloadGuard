using System;
using System.Diagnostics;
using System.Drawing;
using System.Windows.Forms;
using VTDownloadGuard.Models;
using VTDownloadGuard.Services;

namespace VTDownloadGuard.UI;

public sealed class TrayApplicationContext : ApplicationContext
{
    private const int RecentScansTabIndex = 0;
    private const int SettingsTabIndex = 4;

    private enum BalloonKind
    {
        None = 0,
        UnsafeAlert = 1,
        MissingApiKey = 2,
        AuthError = 3,
        UpdateAvailable = 4
    }

    private sealed class SingleInstanceMessageWindow : NativeWindow, IDisposable
    {
        private readonly uint _showMessageId;
        private readonly Action _onShowRequested;

        public SingleInstanceMessageWindow(uint showMessageId, Action onShowRequested)
        {
            _showMessageId = showMessageId;
            _onShowRequested = onShowRequested;
            CreateHandle(new CreateParams());
        }

        protected override void WndProc(ref Message m)
        {
            if (m.Msg == (int)_showMessageId && _showMessageId != 0)
            {
                _onShowRequested();
                return;
            }

            base.WndProc(ref m);
        }

        public void Dispose()
        {
            if (Handle != IntPtr.Zero)
            {
                DestroyHandle();
            }
        }
    }

    private readonly ScanEngine _engine;
    private readonly AppPaths _paths;
    private readonly AppLogger _logger;
    private readonly VirusTotalClient _vtClient;
    private readonly UpdateService _updateService;
    private readonly TrayIconFactory _iconFactory;

    private readonly Control _marshalControl;
    private readonly SingleInstanceMessageWindow _messageWindow;
    private readonly NotifyIcon _notifyIcon;
    private readonly ContextMenuStrip _contextMenu;
    private readonly System.Windows.Forms.Timer _scanAnimTimer;

    private readonly ToolStripMenuItem _statusMenuItem;
    private readonly ToolStripMenuItem _viewLatestAlertMenuItem;
    private readonly ToolStripMenuItem _markReviewedMenuItem;
    private readonly ToolStripSeparator _alertSeparator;
    private readonly ToolStripMenuItem _openDashboardMenuItem;
    private readonly ToolStripMenuItem _scanFileMenuItem;
    private readonly ToolStripMenuItem _pauseResumeMenuItem;
    private readonly ToolStripMenuItem _checkUpdatesMenuItem;
    private readonly ToolStripMenuItem _exitMenuItem;

    private DashboardForm? _dashboard;
    private BalloonKind _lastBalloonKind;
    private ScanRecord? _lastUnsafeRecord;
    private DateTimeOffset _lastAuthBalloonUtc = DateTimeOffset.MinValue;
    private int _scanAnimFrame;
    private bool _exiting;
    private bool? _lastAutoUpdateEnabled;
    private bool? _lastAutoUpdateCriticalOnly;
    private string? _lastUpdateRepository;

    public TrayApplicationContext(
        ScanEngine engine,
        VirusTotalClient vtClient,
        UpdateService updateService,
        AppPaths paths,
        AppLogger logger,
        uint showDashboardMessageId,
        bool openDashboardOnStart)
    {
        _engine = engine;
        _vtClient = vtClient;
        _updateService = updateService;
        _paths = paths;
        _logger = logger;
        _iconFactory = new TrayIconFactory();

        // Force creation of a hidden UI-thread control handle before launching background tasks.
        _marshalControl = new Control();
        _ = _marshalControl.Handle;

        _messageWindow = new SingleInstanceMessageWindow(showDashboardMessageId, () => ShowDashboard());

        _scanAnimTimer = new System.Windows.Forms.Timer { Interval = 600 };
        _scanAnimTimer.Tick += (_, _) =>
        {
            _scanAnimFrame ^= 1;
            if (_engine.CurrentTrayStatus == TrayStatus.Scanning)
            {
                _notifyIcon!.Icon = _iconFactory.GetIcon(TrayStatus.Scanning, _scanAnimFrame);
            }
            else
            {
                _scanAnimTimer.Stop();
            }
        };

        _statusMenuItem = new ToolStripMenuItem("Status: Initializing...") { Enabled = false };
        _viewLatestAlertMenuItem = new ToolStripMenuItem("View Latest Alert Report");
        _viewLatestAlertMenuItem.Click += (_, _) => OpenLatestAlertUrl();

        _markReviewedMenuItem = new ToolStripMenuItem("Mark Alerts Reviewed");
        _markReviewedMenuItem.Click += (_, _) => _engine.AcknowledgeAllUnsafe();

        _alertSeparator = new ToolStripSeparator();

        _openDashboardMenuItem = new ToolStripMenuItem("Open Dashboard & Settings...");
        _openDashboardMenuItem.Font = new Font(_openDashboardMenuItem.Font, FontStyle.Bold);
        _openDashboardMenuItem.Click += (_, _) => ShowDashboard();

        _scanFileMenuItem = new ToolStripMenuItem("Scan a File Now...");
        _scanFileMenuItem.Click += (_, _) => PromptManualFileScan();

        _pauseResumeMenuItem = new ToolStripMenuItem("Pause Monitoring");
        _pauseResumeMenuItem.Click += (_, _) => _engine.SetPaused(!_engine.IsPaused);

        _checkUpdatesMenuItem = new ToolStripMenuItem("Check for Updates...");
        _checkUpdatesMenuItem.Click += async (_, _) => await CheckForUpdatesManuallyAsync();

        _exitMenuItem = new ToolStripMenuItem("Exit");
        _exitMenuItem.Click += (_, _) => ExitApplication();

        _contextMenu = new ContextMenuStrip();
        _contextMenu.Items.AddRange(
        [
            _statusMenuItem,
            _viewLatestAlertMenuItem,
            _markReviewedMenuItem,
            _alertSeparator,
            _openDashboardMenuItem,
            _scanFileMenuItem,
            _pauseResumeMenuItem,
            new ToolStripSeparator(),
            _checkUpdatesMenuItem,
            _exitMenuItem
        ]);
        ApplyContextMenuTheme();

        _notifyIcon = new NotifyIcon
        {
            Icon = _iconFactory.GetIcon(TrayStatus.Safe),
            ContextMenuStrip = _contextMenu,
            Visible = true
        };
        _notifyIcon.MouseClick += (_, e) =>
        {
            if (e.Button == MouseButtons.Left)
            {
                ShowDashboard();
            }
        };
        _notifyIcon.DoubleClick += (_, _) => ShowDashboard();
        _notifyIcon.BalloonTipClicked += (_, _) => OnBalloonTipClicked();

        _engine.StatusChanged += OnEngineStatusChanged;
        _engine.UnsafeFileDetected += OnUnsafeFileDetected;
        _engine.ApiAuthFailed += OnApiAuthFailed;

        _engine.Start();
        SyncAutoUpdateConfiguration();
        UpdateTrayVisuals();

        if (openDashboardOnStart)
        {
            bool needsOnboarding = !_engine.CurrentSettings.OnboardingCompleted;
            bool needsKey = !_engine.HasApiKey;
            if (needsOnboarding)
            {
                ShowDashboard(RecentScansTabIndex, focusApiKey: false);
            }
            else
            {
                ShowDashboard(needsKey ? SettingsTabIndex : RecentScansTabIndex, focusApiKey: needsKey);
            }
        }
        else if (!_engine.HasApiKey)
        {
            _lastBalloonKind = BalloonKind.MissingApiKey;
            _notifyIcon.ShowBalloonTip(
                8000,
                "VTDownloadGuard Setup",
                "Click here to add your free VirusTotal API key and enable automatic download scanning.",
                ToolTipIcon.Info);
        }
    }

    private void ApplyContextMenuTheme()
    {
        ThemePalette palette = ThemePalette.Resolve(_engine.CurrentSettings.ThemeMode);
        _contextMenu.BackColor = palette.CardBg;
        _contextMenu.ForeColor = palette.TextPrimary;
        _contextMenu.Renderer = new ThemedToolStripRenderer(palette);
    }

    private void OnEngineStatusChanged()
    {
        MarshalToUi(UpdateTrayVisuals);
    }

    private void OnUnsafeFileDetected(ScanRecord record)
    {
        MarshalToUi(() =>
        {
            _lastUnsafeRecord = record;
            _lastBalloonKind = BalloonKind.UnsafeAlert;

            string firstThreat = record.DetectionNames.Count > 0 ? $"\n{record.DetectionNames[0]}" : string.Empty;
            string sourceInfo = string.IsNullOrWhiteSpace(record.SourceService) ? "VirusTotal" : record.SourceService;
            string body = $"{record.FileName}\n{record.MaliciousCount}/{record.TotalEngines} engines flagged this file ({sourceInfo}).{firstThreat}\nClick to open report.";
            _notifyIcon.ShowBalloonTip(10000, "Potentially Unsafe Program Detected", body, ToolTipIcon.Warning);
        });
    }

    private void OnApiAuthFailed(string message)
    {
        MarshalToUi(() =>
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            if (now - _lastAuthBalloonUtc < TimeSpan.FromMinutes(2))
            {
                return;
            }

            _lastAuthBalloonUtc = now;
            _lastBalloonKind = BalloonKind.AuthError;
            _notifyIcon.ShowBalloonTip(
                8000,
                "VirusTotal API Key Error",
                $"{message}\nClick here to update your API key in Settings.",
                ToolTipIcon.Error);
        });
    }

    private void UpdateTrayVisuals()
    {
        if (_exiting)
        {
            return;
        }

        SyncAutoUpdateConfiguration();
        ApplyContextMenuTheme();

        TrayStatus status = _engine.CurrentTrayStatus;
        if (status == TrayStatus.Scanning)
        {
            if (!_scanAnimTimer.Enabled)
            {
                _scanAnimFrame = 0;
                _scanAnimTimer.Start();
            }

            _notifyIcon.Icon = _iconFactory.GetIcon(TrayStatus.Scanning, _scanAnimFrame);
        }
        else
        {
            if (_scanAnimTimer.Enabled)
            {
                _scanAnimTimer.Stop();
            }

            _notifyIcon.Icon = _iconFactory.GetIcon(status);
        }

        string statusLine;
        string tooltip;
        switch (status)
        {
            case TrayStatus.NeedsSetup:
                statusLine = "Status: Setup needed (add API key)";
                tooltip = "VTDownloadGuard: Add VirusTotal API key";
                break;
            case TrayStatus.Unsafe:
                int unsafeCount = _engine.UnacknowledgedUnsafeCount;
                statusLine = $"Status: {unsafeCount} unsafe file alert(s)!";
                tooltip = $"VTDownloadGuard: {unsafeCount} UNSAFE program(s) detected!";
                break;
            case TrayStatus.Scanning:
                string active = _engine.ActiveFileName ?? "file";
                int queued = _engine.QueuedCount;
                statusLine = queued > 0
                    ? $"Status: Checking {active} ({queued} queued)"
                    : $"Status: Checking {active}...";
                tooltip = $"VTDownloadGuard: Checking {active}";
                break;
            default:
                if (_engine.IsPaused)
                {
                    statusLine = "Status: Monitoring paused";
                    tooltip = "VTDownloadGuard: Monitoring paused";
                }
                else
                {
                    statusLine = "Status: All checked and safe";
                    tooltip = "VTDownloadGuard: Everything checked and safe";
                }

                break;
        }

        _statusMenuItem.Text = statusLine;
        _notifyIcon.Text = ClampTooltip(tooltip);

        bool hasAlerts = _engine.UnacknowledgedUnsafeCount > 0;
        _viewLatestAlertMenuItem.Visible = hasAlerts;
        _markReviewedMenuItem.Visible = hasAlerts;
        _alertSeparator.Visible = hasAlerts;
        _pauseResumeMenuItem.Text = _engine.IsPaused ? "Resume Monitoring" : "Pause Monitoring";
    }

    private static string ClampTooltip(string text)
    {
        const int maxLen = 63;
        if (text.Length <= maxLen)
        {
            return text;
        }

        return text[..(maxLen - 3)] + "...";
    }

    private void OnBalloonTipClicked()
    {
        switch (_lastBalloonKind)
        {
            case BalloonKind.UnsafeAlert:
                OpenLatestAlertUrl();
                if (_engine.UnacknowledgedUnsafeCount > 1)
                {
                    ShowDashboard(tabIndex: RecentScansTabIndex);
                }

                break;

            case BalloonKind.MissingApiKey:
            case BalloonKind.AuthError:
                ShowDashboard(tabIndex: SettingsTabIndex, focusApiKey: true);
                break;

            case BalloonKind.UpdateAvailable:
                ShowDashboard(tabIndex: SettingsTabIndex, focusApiKey: false);
                break;

            default:
                ShowDashboard();
                break;
        }
    }

    private void OpenLatestAlertUrl()
    {
        var rec = _lastUnsafeRecord ?? _engine.LatestUnacknowledgedUnsafe;
        string? url = rec?.EffectiveReportUrl;
        if (rec is null || string.IsNullOrWhiteSpace(url))
        {
            ShowDashboard(tabIndex: RecentScansTabIndex);
            return;
        }

        try
        {
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            _logger.Warn($"Failed to open VirusTotal browser report: {ex.Message}");
            ShowDashboard(tabIndex: RecentScansTabIndex);
        }
    }

    private void ShowDashboard(int tabIndex = RecentScansTabIndex, bool focusApiKey = false)
    {
        if (_exiting)
        {
            return;
        }

        if (_dashboard is null || _dashboard.IsDisposed)
        {
            _dashboard = new DashboardForm(
                _engine,
                _paths,
                _logger,
                _iconFactory.AppIcon,
                _updateService,
                RequestShutdownForUpdate);
            _dashboard.FormClosed += (_, _) => _dashboard = null;
        }

        if (!_dashboard.Visible)
        {
            _dashboard.Show();
        }

        if (_dashboard.WindowState == FormWindowState.Minimized)
        {
            _dashboard.WindowState = FormWindowState.Normal;
        }

        _dashboard.SelectTab(tabIndex, focusApiKey);
        _dashboard.Activate();
        _dashboard.BringToFront();
    }

    private void PromptManualFileScan()
    {
        using var dialog = new OpenFileDialog
        {
            Title = "Select a file to scan with VirusTotal",
            CheckFileExists = true
        };
        if (dialog.ShowDialog() == DialogResult.OK)
        {
            _engine.EnqueueFile(dialog.FileName, manual: true);
        }
    }

    private void MarshalToUi(Action action)
    {
        if (_exiting || _marshalControl.IsDisposed || !_marshalControl.IsHandleCreated)
        {
            return;
        }

        try
        {
            _marshalControl.BeginInvoke(action);
        }
        catch (ObjectDisposedException)
        {
            // Shutting down.
        }
        catch (InvalidOperationException)
        {
            // Handle closed during shutdown.
        }
    }

    private void ExitApplication()
    {
        if (_exiting)
        {
            return;
        }

        _exiting = true;
        _engine.StatusChanged -= OnEngineStatusChanged;
        _engine.UnsafeFileDetected -= OnUnsafeFileDetected;
        _engine.ApiAuthFailed -= OnApiAuthFailed;

        _scanAnimTimer.Stop();
        _scanAnimTimer.Dispose();

        DashboardForm? dashboard = _dashboard;
        _dashboard = null;
        if (dashboard is not null && !dashboard.IsDisposed)
        {
            dashboard.Close();
            if (!dashboard.IsDisposed)
            {
                dashboard.Dispose();
            }
        }

        _notifyIcon.Visible = false;
        _notifyIcon.Dispose();
        _contextMenu.Dispose();
        _messageWindow.Dispose();
        _marshalControl.Dispose();

        _engine.Dispose();
        _vtClient.Dispose();
        _updateService.Dispose();
        _iconFactory.Dispose();

        ExitThread();
    }

    private void SyncAutoUpdateConfiguration()
    {
        AppSettings settings = _engine.CurrentSettings;
        if (_lastAutoUpdateEnabled == settings.AutoUpdateEnabled
            && _lastAutoUpdateCriticalOnly == settings.AutoUpdateCriticalOnly
            && string.Equals(_lastUpdateRepository, settings.UpdateRepository, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        _lastAutoUpdateEnabled = settings.AutoUpdateEnabled;
        _lastAutoUpdateCriticalOnly = settings.AutoUpdateCriticalOnly;
        _lastUpdateRepository = settings.UpdateRepository;

        _updateService.ConfigureAutoUpdates(
            settings,
            () => _engine.IsScanning,
            check => MarshalToUi(() =>
            {
                if (!_exiting)
                {
                    string kind = check.IsCritical ? "critical update" : "update";
                    _notifyIcon.ShowBalloonTip(
                        5000,
                        "Installing VTDownloadGuard Update",
                        $"Downloading {kind} {check.TagName}. Your settings and scan history will be preserved.",
                        ToolTipIcon.Info);
                }
            }),
            RequestShutdownForUpdate);
    }

    private async System.Threading.Tasks.Task CheckForUpdatesManuallyAsync()
    {
        if (_exiting)
        {
            return;
        }

        _checkUpdatesMenuItem.Enabled = false;
        try
        {
            UpdateCheckResult result = await _updateService.CheckForUpdatesAsync(_engine.CurrentSettings);
            if (_exiting)
            {
                return;
            }

            if (!result.Success)
            {
                _lastBalloonKind = BalloonKind.None;
                _notifyIcon.ShowBalloonTip(6000, "Update Check Failed", result.ErrorMessage, ToolTipIcon.Warning);
            }
            else if (result.UpdateAvailable)
            {
                _lastBalloonKind = BalloonKind.UpdateAvailable;
                string tag = string.IsNullOrWhiteSpace(result.TagName)
                    ? $"v{result.LatestVersion?.ToString(3)}"
                    : result.TagName;
                string prefix = result.IsCritical ? "Critical update" : "Update";
                _notifyIcon.ShowBalloonTip(
                    8000,
                    $"{prefix} Available: {tag}",
                    "Click here to open Settings and install the update.",
                    ToolTipIcon.Info);
                ShowDashboard(tabIndex: SettingsTabIndex, focusApiKey: false);
            }
            else
            {
                _lastBalloonKind = BalloonKind.None;
                _notifyIcon.ShowBalloonTip(
                    5000,
                    "VTDownloadGuard is Up to Date",
                    $"You are running the latest version (v{_updateService.CurrentVersion.ToString(3)}).",
                    ToolTipIcon.Info);
            }
        }
        finally
        {
            if (!_exiting)
            {
                _checkUpdatesMenuItem.Enabled = true;
            }
        }
    }

    private void RequestShutdownForUpdate()
    {
        MarshalToUi(ExitApplication);
    }
}
