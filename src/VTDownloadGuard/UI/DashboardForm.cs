using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Windows.Forms;
using VTDownloadGuard.Models;
using VTDownloadGuard.Services;

namespace VTDownloadGuard.UI;

public sealed class DashboardForm : Form
{
    private const int TabRecentScans = 0;
    private const int TabQueued = 1;
    private const int TabDirectories = 2;
    private const int TabApi = 3;
    private const int TabSettings = 4;
    private const int WmSetRedraw = 0x000B;
    private const int WsExComposited = 0x02000000;

    [DllImport("user32.dll")]
    private static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam);

    private readonly ScanEngine _engine;
    private readonly AppPaths _paths;
    private readonly AppLogger _logger;
    private readonly UpdateService _updateService;
    private readonly bool _ownsUpdateService;
    private readonly Action _requestShutdownForUpdate;
    private ThemePalette _palette;

    private readonly Font _headerTitleFont = new("Segoe UI Semibold", 13.5f);
    private readonly Font _sectionTitleFont = new("Segoe UI Semibold", 10.5f);
    private readonly Font _boldFont = new("Segoe UI Semibold", 9.0f);
    private readonly Font _bodyFont = new("Segoe UI", 9.0f);
    private readonly Font _smallFont = new("Segoe UI", 8.5f);
    private readonly Font _pillFont = new("Segoe UI Semibold", 8.2f);
    private readonly Font _monoFont = new("Consolas", 9.0f);

    // Header
    private readonly TableLayoutPanel _headerPanel;
    private readonly PictureBox _logoBox;
    private readonly Label _titleLabel;
    private readonly Label _statusPillLabel;
    private readonly Label _subtitleLabel;
    private readonly ModernButton _headerScanBtn;
    private readonly ModernButton _headerPauseBtn;
    private readonly ModernButton _headerTourBtn;
    private readonly ModernButton _headerUpdateBtn;
    private readonly ModernButton _acknowledgeBtn;
    private TutorialSession? _activeTutorial;
    private bool _onboardingPromptedThisInstance;
    private readonly ModernNavBar _navBar;
    private readonly Panel _contentHost;
    private readonly Panel _footerPanel;
    private readonly Label _footerLabel;
    private readonly Control[] _tabViews = new Control[5];
    private int _activeTabIndex;

    // Tab 0: Recent Scans
    private readonly Panel _historyFilterPanel;
    private readonly TextBox _historySearchBox;
    private readonly ComboBox _verdictFilterCombo;
    private readonly Label _historyCountLabel;
    private readonly DataGridView _historyGrid;
    private readonly ModernCardPanel _detailCard;
    private readonly Label _detailFileLabel;
    private readonly Label _detailShaLabel;
    private readonly Label _detailMetaLabel;
    private readonly ModernButton _openReportBtn;
    private readonly ModernButton _openLocationBtn;
    private readonly ModernButton _scanOnVtBtn;
    private readonly ModernButton _uploadSelectedBtn;
    private readonly ModernButton _clearHistoryBtn;
    private readonly List<ScanRecord> _displayedRecords = [];

    // Tab 1: Queued
    private readonly ModernCardPanel _queueBannerCard;
    private readonly Label _queueInfoLabel;
    private readonly Label _queueCountSummaryLabel;
    private readonly DataGridView _queueGrid;
    private readonly ModernButton _promoteQueueBtn;
    private readonly ModernButton _removeQueueBtn;
    private readonly ModernButton _clearQueueBtn;
    private readonly ModernButton _queueScanFileBtn;
    private readonly List<QueuedScanItem> _displayedQueue = [];

    // Tab 2: Directories
    private readonly DataGridView _directoriesGrid;
    private readonly ModernButton _addDirBtn;
    private readonly ModernButton _removeDirBtn;
    private readonly ModernButton _toggleSubfoldersBtn;
    private readonly ModernButton _toggleEnabledBtn;
    private readonly ModernButton _openDirBtn;
    private readonly List<WatchedDirectory> _displayedDirs = [];

    // Tab 3: API
    private readonly FlowLayoutPanel _apiScrollPanel;
    private readonly ModernCardPanel _vtQuotaCard;
    private readonly ModernCardPanel _localStatsCard;
    private readonly ModernCardPanel _secondaryServicesCard;
    private readonly Label _vtAccountLabel;
    private readonly Label _vtFetchedAtLabel;
    private readonly ModernButton _refreshQuotaBtn;
    private readonly Label _minuteQuotaValueLabel;
    private readonly ModernProgressBar _minuteQuotaBar;
    private readonly Label _hourlyQuotaValueLabel;
    private readonly ModernProgressBar _hourlyQuotaBar;
    private readonly Label _dailyQuotaValueLabel;
    private readonly ModernProgressBar _dailyQuotaBar;
    private readonly Label _monthlyQuotaValueLabel;
    private readonly ModernProgressBar _monthlyQuotaBar;
    private readonly Label _vtQuotaStatusLabel;
    private readonly Label _cacheCountValueLabel;
    private readonly Label _cacheHitsValueLabel;
    private readonly Label _secondarySavedValueLabel;
    private readonly ModernButton _clearCacheBtn;
    private readonly ModernButton _openDataFolderBtn;
    private readonly DataGridView _secondaryGrid;
    private readonly System.Windows.Forms.Timer _apiLiveTimer;
    private bool _quotaFetchInFlight;

    // Tab 4: Settings
    private readonly FlowLayoutPanel _settingsScrollPanel;
    private readonly ModernCardPanel _generalCard;
    private readonly ModernCardPanel _updatesCard;
    private readonly ModernCardPanel _vtSettingsCard;
    private readonly ModernCardPanel _secondarySettingsCard;
    private readonly ModernCardPanel _resetSettingsCard;
    private readonly Panel _settingsSaveBar;
    private readonly Label _settingsLegendLabel;
    private readonly ComboBox _themeCombo;
    private readonly CheckBox _startupCheckBox;
    private readonly Label _installedVersionLabel;
    private readonly Label _updateStatusLabel;
    private readonly LinkLabel _updateReleaseLink;
    private readonly ModernProgressBar _updateProgressBar;
    private readonly ModernButton _checkUpdatesBtn;
    private readonly ModernButton _installUpdateBtn;
    private readonly ComboBox _autoUpdateModeCombo;
    private readonly Label _updateHelperLabel;
    private string _latestReleaseUrl = string.Empty;
    private bool _updateActionInFlight;
    private bool _resourcesCleanedUp;
    private bool _isResizing;
    private readonly TextBox _apiKeyTextBox;
    private readonly ModernButton _toggleKeyVisibilityBtn;
    private readonly ModernButton _testKeyBtn;
    private readonly Label _keyStatusLabel;
    private readonly ComboBox _uploadPolicyCombo;
    private readonly ComboBox _filterModeCombo;
    private readonly TextBox _uploadExtTextBox;
    private readonly TextBox _archiveExtTextBox;
    private readonly ModernButton _resetExtBtn;
    private readonly Panel _thresholdContainer;
    private readonly ModernThresholdSlider _thresholdSlider;
    private readonly Label _thresholdDescLabel;
    private readonly NumericUpDown _rateLimitNumeric;
    private readonly NumericUpDown _maxUploadMbNumeric;
    private readonly NumericUpDown _maxHashMbNumeric;
    private readonly Label _rateLimitWarningLabel;
    private readonly Label _maxUploadWarningLabel;
    private readonly Label _maxHashWarningLabel;

    private readonly CheckBox _secondaryLowerRiskOnlyCheckBox;
    private readonly CheckBox _enableCirclCheckBox;
    private readonly CheckBox _enableMetaDefenderCheckBox;
    private readonly TextBox _metaDefenderKeyBox;
    private readonly ModernButton _toggleMdKeyBtn;
    private readonly ModernButton _testMdKeyBtn;
    private readonly Label _mdStatusLabel;
    private readonly CheckBox _enableMalwareBazaarCheckBox;
    private readonly TextBox _malwareBazaarKeyBox;
    private readonly ModernButton _toggleMbKeyBtn;
    private readonly ModernButton _testMbKeyBtn;
    private readonly Label _mbStatusLabel;

    private readonly ModernButton _saveSettingsBtn;
    private readonly ModernButton _resetDefaultsBtn;
    private readonly Label _saveConfirmLabel;

    private readonly List<ModernButton> _allButtons = [];
    private readonly List<ModernCardPanel> _allCards = [];
    private readonly List<ModernProgressBar> _allProgressBars = [];
    private readonly List<LinkLabel> _allLinks = [];
    private readonly List<Panel> _sectionDividers = [];
    private readonly List<Label> _wrappingSettingsLabels = [];
    private readonly List<(RecommendedStarIndicator Indicator, Func<bool> IsRecommended)> _recommendedIndicators = [];
    private readonly Dictionary<FlowLayoutPanel, int> _lastCardWidthByHost = [];
    private readonly List<(Control Card, TableLayoutPanel Inner)> _responsiveCards = [];
    private readonly ToolTip _settingsToolTip = new();

    protected override CreateParams CreateParams
    {
        get
        {
            CreateParams cp = base.CreateParams;
            cp.ExStyle |= WsExComposited;
            return cp;
        }
    }

    public DashboardForm(
        ScanEngine engine,
        AppPaths paths,
        AppLogger logger,
        Icon appIcon,
        UpdateService? updateService = null,
        Action? requestShutdownForUpdate = null)
    {
        _engine = engine;
        _paths = paths;
        _logger = logger;
        _ownsUpdateService = updateService is null;
        _updateService = updateService ?? new UpdateService(paths, logger);
        _requestShutdownForUpdate = requestShutdownForUpdate ?? Close;
        _palette = ThemePalette.Resolve(_engine.CurrentSettings.ThemeMode);

        Text = "VTDownloadGuard";
        Icon = appIcon;
        MinimumSize = new Size(940, 620);
        Size = new Size(1080, 720);
        StartPosition = FormStartPosition.CenterScreen;
        DoubleBuffered = true;
        Font = _bodyFont;

        _apiLiveTimer = new System.Windows.Forms.Timer { Interval = 1000 };
        _apiLiveTimer.Tick += (_, _) =>
        {
            if (Visible && _activeTabIndex == TabApi)
            {
                RefreshApiRateWindowOnly();
            }
        };

        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 4,
            Margin = new Padding(0),
            Padding = new Padding(0)
        };
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        Controls.Add(root);

        // Top Header Bar
        _headerPanel = new SmoothTableLayoutPanel
        {
            Dock = DockStyle.Fill,
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            ColumnCount = 2,
            RowCount = 1,
            Padding = new Padding(16, 12, 16, 10),
            Margin = new Padding(0),
            MinimumSize = new Size(0, 74)
        };
        _headerPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        _headerPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        _headerPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));

        var leftHeader = new TableLayoutPanel
        {
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            RowCount = 1,
            BackColor = Color.Transparent,
            Margin = new Padding(0),
            Padding = new Padding(0)
        };
        leftHeader.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        leftHeader.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        leftHeader.RowStyles.Add(new RowStyle(SizeType.AutoSize));

        _logoBox = new PictureBox
        {
            Size = new Size(34, 34),
            SizeMode = PictureBoxSizeMode.Zoom,
            Image = new Icon(appIcon, 48, 48).ToBitmap(),
            Anchor = AnchorStyles.Left,
            Margin = new Padding(0, 0, 10, 0),
            BackColor = Color.Transparent
        };
        leftHeader.Controls.Add(_logoBox, 0, 0);

        var titleStack = new TableLayoutPanel
        {
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            Anchor = AnchorStyles.Left | AnchorStyles.Right,
            ColumnCount = 1,
            RowCount = 2,
            BackColor = Color.Transparent,
            Margin = new Padding(0),
            Padding = new Padding(0)
        };
        titleStack.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        titleStack.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        titleStack.RowStyles.Add(new RowStyle(SizeType.AutoSize));

        var titleRow = new FlowLayoutPanel
        {
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            WrapContents = false,
            BackColor = Color.Transparent,
            Margin = new Padding(0),
            Padding = new Padding(0)
        };
        _titleLabel = new Label
        {
            Text = "VTDownloadGuard",
            AutoSize = true,
            Font = _headerTitleFont,
            Margin = new Padding(0, 0, 10, 0)
        };
        _statusPillLabel = new Label
        {
            AutoSize = true,
            Font = _pillFont,
            Padding = new Padding(8, 3, 8, 3),
            Margin = new Padding(0, 4, 0, 0)
        };
        titleRow.Controls.Add(_titleLabel);
        titleRow.Controls.Add(_statusPillLabel);

        _subtitleLabel = new Label
        {
            AutoSize = true,
            Font = _smallFont,
            Margin = new Padding(0, 2, 0, 0)
        };

        titleStack.Controls.Add(titleRow, 0, 0);
        titleStack.Controls.Add(_subtitleLabel, 0, 1);
        leftHeader.Controls.Add(titleStack, 1, 0);

        var rightHeader = new FlowLayoutPanel
        {
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            WrapContents = false,
            Anchor = AnchorStyles.Right,
            BackColor = Color.Transparent,
            Margin = new Padding(12, 0, 0, 0),
            Padding = new Padding(0)
        };
        _acknowledgeBtn = MakeButton("Mark Alerts Reviewed", ModernButtonVariant.Danger);
        _acknowledgeBtn.Visible = false;
        _acknowledgeBtn.Click += (_, _) => _engine.AcknowledgeAllUnsafe();

        _headerScanBtn = MakeButton("Scan File...", ModernButtonVariant.Primary);
        _headerScanBtn.Click += (_, _) => PromptManualFileScan();

        _headerPauseBtn = MakeButton("Pause", ModernButtonVariant.Secondary);
        _headerPauseBtn.Click += (_, _) => _engine.SetPaused(!_engine.IsPaused);

        _headerTourBtn = MakeButton("UI Tour", ModernButtonVariant.Ghost);
        _headerTourBtn.Click += (_, _) => StartUiTutorial();

        _headerUpdateBtn = MakeButton("Update Ready", ModernButtonVariant.Primary);
        _headerUpdateBtn.Visible = false;
        _headerUpdateBtn.Click += (_, _) => ScrollToUpdatesCard();

        rightHeader.Controls.AddRange([_acknowledgeBtn, _headerUpdateBtn, _headerScanBtn, _headerPauseBtn, _headerTourBtn]);

        _headerPanel.Controls.Add(leftHeader, 0, 0);
        _headerPanel.Controls.Add(rightHeader, 1, 0);
        root.Controls.Add(_headerPanel, 0, 0);

        // Navigation Strip
        _navBar = new ModernNavBar
        {
            Dock = DockStyle.Fill,
            Margin = new Padding(0),
            MinimumSize = new Size(0, 44)
        };
        _navBar.SetTabs("Recent Scans", "Queued", "Directories", "API", "Settings");
        _navBar.TabSelected += idx => SelectTab(idx);
        root.Controls.Add(_navBar, 0, 1);

        // Content Host
        _contentHost = new Panel { Dock = DockStyle.Fill, Padding = new Padding(14, 12, 14, 8) };
        root.Controls.Add(_contentHost, 0, 2);

        // Build Tab Views
        (_tabViews[TabRecentScans],
            _historyFilterPanel,
            _historySearchBox,
            _verdictFilterCombo,
            _historyCountLabel,
            _historyGrid,
            _detailCard,
            _detailFileLabel,
            _detailShaLabel,
            _detailMetaLabel,
            _openReportBtn,
            _openLocationBtn,
            _scanOnVtBtn,
            _uploadSelectedBtn,
            _clearHistoryBtn) = BuildRecentScansTab();

        (_tabViews[TabQueued],
            _queueBannerCard,
            _queueInfoLabel,
            _queueCountSummaryLabel,
            _queueGrid,
            _promoteQueueBtn,
            _removeQueueBtn,
            _clearQueueBtn,
            _queueScanFileBtn) = BuildQueuedTab();

        (_tabViews[TabDirectories],
            _directoriesGrid,
            _addDirBtn,
            _removeDirBtn,
            _toggleSubfoldersBtn,
            _toggleEnabledBtn,
            _openDirBtn) = BuildDirectoriesTab();

        (_tabViews[TabApi],
            _apiScrollPanel,
            _vtQuotaCard,
            _localStatsCard,
            _secondaryServicesCard,
            _vtAccountLabel,
            _vtFetchedAtLabel,
            _refreshQuotaBtn,
            _minuteQuotaValueLabel,
            _minuteQuotaBar,
            _hourlyQuotaValueLabel,
            _hourlyQuotaBar,
            _dailyQuotaValueLabel,
            _dailyQuotaBar,
            _monthlyQuotaValueLabel,
            _monthlyQuotaBar,
            _vtQuotaStatusLabel,
            _cacheCountValueLabel,
            _cacheHitsValueLabel,
            _secondarySavedValueLabel,
            _clearCacheBtn,
            _openDataFolderBtn,
            _secondaryGrid) = BuildApiTab();

        (_tabViews[TabSettings],
            _settingsScrollPanel,
            _generalCard,
            _updatesCard,
            _vtSettingsCard,
            _secondarySettingsCard,
            _resetSettingsCard,
            _settingsSaveBar,
            _settingsLegendLabel,
            _themeCombo,
            _startupCheckBox,
            _installedVersionLabel,
            _updateStatusLabel,
            _updateReleaseLink,
            _updateProgressBar,
            _checkUpdatesBtn,
            _installUpdateBtn,
            _autoUpdateModeCombo,
            _updateHelperLabel,
            _apiKeyTextBox,
            _toggleKeyVisibilityBtn,
            _testKeyBtn,
            _keyStatusLabel,
            _uploadPolicyCombo,
            _filterModeCombo,
            _uploadExtTextBox,
            _archiveExtTextBox,
            _resetExtBtn,
            _thresholdContainer,
            _thresholdSlider,
            _thresholdDescLabel,
            _rateLimitNumeric,
            _maxUploadMbNumeric,
            _maxHashMbNumeric,
            _rateLimitWarningLabel,
            _maxUploadWarningLabel,
            _maxHashWarningLabel,
            _secondaryLowerRiskOnlyCheckBox,
            _enableCirclCheckBox,
            _enableMetaDefenderCheckBox,
            _metaDefenderKeyBox,
            _toggleMdKeyBtn,
            _testMdKeyBtn,
            _mdStatusLabel,
            _enableMalwareBazaarCheckBox,
            _malwareBazaarKeyBox,
            _toggleMbKeyBtn,
            _testMbKeyBtn,
            _mbStatusLabel,
            _saveSettingsBtn,
            _resetDefaultsBtn,
            _saveConfirmLabel) = BuildSettingsTab();

        foreach (Control view in _tabViews)
        {
            view.Dock = DockStyle.Fill;
            view.Visible = false;
            _contentHost.Controls.Add(view);
        }

        // Footer Bar
        _footerPanel = new Panel
        {
            Dock = DockStyle.Fill,
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            Margin = new Padding(0),
            Padding = new Padding(16, 6, 16, 6)
        };
        _footerLabel = new Label
        {
            AutoSize = true,
            Dock = DockStyle.Left,
            Font = _smallFont,
            Text = "Closing this window keeps VTDownloadGuard running in the system tray. Right-click the tray icon and choose Exit to quit.",
            Margin = new Padding(0)
        };
        _footerPanel.Controls.Add(_footerLabel);
        root.Controls.Add(_footerPanel, 0, 3);

        _engine.StatusChanged += OnEngineChanged;
        _engine.QueueChanged += OnQueueChanged;
        _engine.ScanCompleted += OnScanCompleted;
        _updateService.UpdateStatusChanged += OnUpdateStatusChanged;

        LoadSettingsIntoControls();
        ApplyTheme(_palette);
        SelectTab(TabRecentScans);
        RefreshAll();
    }

    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        ThemePalette.ApplyWindowTheme(this, _palette);
    }

    protected override void OnVisibleChanged(EventArgs e)
    {
        base.OnVisibleChanged(e);
        UpdateApiTimerState();
    }

    protected override void OnShown(EventArgs e)
    {
        base.OnShown(e);
        if (!_onboardingPromptedThisInstance && !_engine.CurrentSettings.OnboardingCompleted)
        {
            _onboardingPromptedThisInstance = true;
            BeginInvoke(ShowOnboardingWizard);
        }
    }

    protected override void OnFormClosed(FormClosedEventArgs e)
    {
        CleanupSubscriptionsAndTimers();
        base.OnFormClosed(e);
    }

    private void ScrollToUpdatesCard()
    {
        SelectTab(TabSettings);
        _settingsScrollPanel.ScrollControlIntoView(_updatesCard);
    }

    private void CleanupSubscriptionsAndTimers()
    {
        if (_resourcesCleanedUp)
        {
            return;
        }

        _resourcesCleanedUp = true;
        _activeTutorial?.Dispose();
        _activeTutorial = null;
        _apiLiveTimer.Stop();
        _apiLiveTimer.Dispose();
        _engine.StatusChanged -= OnEngineChanged;
        _engine.QueueChanged -= OnQueueChanged;
        _engine.ScanCompleted -= OnScanCompleted;
        _updateService.UpdateStatusChanged -= OnUpdateStatusChanged;
        if (_ownsUpdateService)
        {
            _updateService.Dispose();
        }
    }

    public void ShowOnboardingWizard()
    {
        if (IsDisposed)
        {
            return;
        }

        _activeTutorial?.Dispose();
        using var dialog = new OnboardingDialog(_engine, _logger, Icon!);
        _ = dialog.ShowDialog(this);
        if (dialog.CompletedSetup)
        {
            LoadSettingsIntoControls();
            ThemePalette resolved = ThemePalette.Resolve(_engine.CurrentSettings.ThemeMode);
            ApplyTheme(resolved);
            RefreshAll();
            if (dialog.StartUiTourRequested)
            {
                StartUiTutorial();
            }
        }
    }

    public TutorialSession CreateTutorialSession()
    {
        IReadOnlyList<TutorialStep> steps =
        [
            new(
                TabRecentScans,
                () => _headerPanel,
                "Status Header and Quick Actions",
                "Shows your live protection status at a glance. From here you can manually scan any file, pause or resume monitoring, acknowledge alerts, or reopen this tour."),
            new(
                TabRecentScans,
                () => _navBar,
                "Navigation Tabs",
                "Switch between Recent Scans, the live Queued priority list, Watched Directories, live API Quotas, and Settings."),
            new(
                TabRecentScans,
                () => _historyGrid,
                "Recent Scans and Results",
                "Each scanned file displays its local Risk rating, final Verdict, detection count, and the service that answered it. Double-click any row to open the full online report."),
            new(
                TabQueued,
                () => _queueGrid,
                "Risk-Prioritized Scan Queue",
                "Waiting files are sorted automatically so Very High Risk items are checked first. You can move an item to the top, remove it, or clear the queue."),
            new(
                TabDirectories,
                () => _directoriesGrid,
                "Watched Directories",
                "Manage which folders VTDownloadGuard monitors automatically. Your Windows Downloads folder is initialized automatically, and you can add or toggle folders anytime."),
            new(
                TabApi,
                () => _vtQuotaCard,
                "API Quota and Screening Efficiency",
                "Monitor your live VirusTotal minute rate-limit window along with hourly, daily, and monthly account quotas directly from VirusTotal, plus local cache savings."),
            new(
                TabSettings,
                () => _thresholdContainer,
                "Detection Sensitivity and API Keys",
                "Use the color-coded slider to set how many vendors must flag a file before it counts as unsafe, and configure your VirusTotal and optional secondary service keys.",
                BeforeShow: () => _settingsScrollPanel.ScrollControlIntoView(_thresholdContainer))
        ];

        return new TutorialSession(this, steps, idx => SelectTab(idx), _palette);
    }

    public void StartUiTutorial()
    {
        if (IsDisposed)
        {
            return;
        }

        _activeTutorial?.Dispose();
        _activeTutorial = CreateTutorialSession();
        _activeTutorial.Closed += () => _activeTutorial = null;
        _activeTutorial.Start();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            CleanupSubscriptionsAndTimers();
            _settingsToolTip.Dispose();
            _headerTitleFont.Dispose();
            _sectionTitleFont.Dispose();
            _boldFont.Dispose();
            _bodyFont.Dispose();
            _smallFont.Dispose();
            _pillFont.Dispose();
            _monoFont.Dispose();
            _logoBox.Image?.Dispose();
        }

        base.Dispose(disposing);
    }

    protected override void OnResizeBegin(EventArgs e)
    {
        _isResizing = true;
        base.OnResizeBegin(e);
    }

    protected override void OnResizeEnd(EventArgs e)
    {
        base.OnResizeEnd(e);
        _isResizing = false;
        UpdateResponsiveCards(_apiScrollPanel, force: true);
        UpdateResponsiveCards(_settingsScrollPanel, force: true);
    }

    private static void SetRedraw(Control control, bool enabled)
    {
        if (control.IsDisposed || !control.IsHandleCreated)
        {
            return;
        }

        _ = SendMessage(control.Handle, WmSetRedraw, enabled ? 1 : 0, IntPtr.Zero);
    }

    public void SelectTab(int tabIndex, bool focusApiKey = false)
    {
        if (tabIndex < 0 || tabIndex >= _tabViews.Length)
        {
            return;
        }

        _activeTabIndex = tabIndex;
        _navBar.SelectedIndex = tabIndex;

        SetRedraw(_contentHost, false);
        _contentHost.SuspendLayout();
        try
        {
            for (int i = 0; i < _tabViews.Length; i++)
            {
                _tabViews[i].Visible = i == tabIndex;
            }

            if (tabIndex == TabQueued)
            {
                RefreshQueueGrid();
            }
            else if (tabIndex == TabDirectories)
            {
                RefreshDirectoriesGrid();
            }
            else if (tabIndex == TabApi)
            {
                UpdateResponsiveCards(_apiScrollPanel, force: true);
                RefreshApiTab();
            }
            else if (tabIndex == TabSettings)
            {
                UpdateResponsiveCards(_settingsScrollPanel, force: true);
            }
        }
        finally
        {
            _contentHost.ResumeLayout(true);
            SetRedraw(_contentHost, true);
            if (_contentHost.IsHandleCreated && !_contentHost.IsDisposed)
            {
                _contentHost.Invalidate(true);
                _contentHost.Update();
            }
        }

        if (tabIndex == TabApi)
        {
            MaybeAutoFetchQuota();
        }

        UpdateApiTimerState();

        if (focusApiKey && tabIndex == TabSettings)
        {
            _apiKeyTextBox.Focus();
            _apiKeyTextBox.SelectAll();
        }
    }

    private void UpdateApiTimerState()
    {
        bool shouldRun = Visible && _activeTabIndex == TabApi;
        if (shouldRun && !_apiLiveTimer.Enabled)
        {
            _apiLiveTimer.Start();
        }
        else if (!shouldRun && _apiLiveTimer.Enabled)
        {
            _apiLiveTimer.Stop();
        }
    }

    private ModernButton MakeButton(string text, ModernButtonVariant variant)
    {
        var btn = new ModernButton
        {
            Text = text,
            Variant = variant,
            AutoSize = true,
            Margin = new Padding(0, 0, 8, 0)
        };
        _allButtons.Add(btn);
        return btn;
    }

    private ModernCardPanel MakeCard()
    {
        var card = new ModernCardPanel { Padding = new Padding(16) };
        _allCards.Add(card);
        return card;
    }

    private ModernProgressBar MakeProgressBar()
    {
        var bar = new ModernProgressBar { Dock = DockStyle.Fill, Height = 12, Margin = new Padding(0, 4, 0, 8) };
        _allProgressBars.Add(bar);
        return bar;
    }

    private LinkLabel MakeLink(string text, string url)
    {
        var link = new LinkLabel { Text = text, AutoSize = true, Font = _smallFont };
        link.LinkClicked += (_, _) => OpenUrl(url);
        _allLinks.Add(link);
        return link;
    }

    private (
        Panel View,
        Panel FilterPanel,
        TextBox SearchBox,
        ComboBox VerdictFilter,
        Label CountLabel,
        DataGridView Grid,
        ModernCardPanel DetailCard,
        Label DetailFileLabel,
        Label DetailShaLabel,
        Label DetailMetaLabel,
        ModernButton OpenReportBtn,
        ModernButton OpenLocationBtn,
        ModernButton ScanOnVtBtn,
        ModernButton UploadBtn,
        ModernButton ClearBtn) BuildRecentScansTab()
    {
        var view = new Panel { Dock = DockStyle.Fill };
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3 };
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 42));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 118));

        var filterPanel = new Panel { Dock = DockStyle.Fill, Padding = new Padding(0, 0, 0, 8) };
        var searchBox = new TextBox
        {
            Width = 360,
            PlaceholderText = "Filter by filename, path, SHA-256, signer, or service...",
            Location = new Point(0, 4)
        };
        searchBox.TextChanged += (_, _) => RefreshHistoryGrid();

        var verdictFilter = new ComboBox
        {
            DropDownStyle = ComboBoxStyle.DropDownList,
            Width = 175,
            Location = new Point(372, 4)
        };
        verdictFilter.Items.AddRange(["All Verdicts", "Unsafe Only", "Low Risk", "Clean Only", "Unknown / Errors"]);
        verdictFilter.SelectedIndex = 0;
        verdictFilter.SelectedIndexChanged += (_, _) => RefreshHistoryGrid();

        var countLabel = new Label
        {
            AutoSize = true,
            Font = _smallFont,
            Location = new Point(560, 8)
        };

        filterPanel.Controls.AddRange([searchBox, verdictFilter, countLabel]);
        layout.Controls.Add(filterPanel, 0, 0);

        var gridCard = MakeCard();
        gridCard.Dock = DockStyle.Fill;
        gridCard.Padding = new Padding(1);
        var grid = new DataGridView { Dock = DockStyle.Fill };
        grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "Time", HeaderText = "Time", Width = 135 });
        grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "FileName", HeaderText = "File Name", Width = 185 });
        grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "Risk", HeaderText = "Risk", Width = 122 });
        grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "Verdict", HeaderText = "Verdict", Width = 96 });
        grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "Detections", HeaderText = "Detections", Width = 88 });
        grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "Source", HeaderText = "Source", Width = 140 });
        grid.Columns.Add(new DataGridViewTextBoxColumn
        {
            Name = "Details",
            HeaderText = "Details",
            AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill
        });
        grid.SelectionChanged += (_, _) => UpdateHistorySelectionDetails();
        grid.CellDoubleClick += (_, e) =>
        {
            if (e.RowIndex >= 0)
            {
                OpenSelectedReport();
            }
        };
        grid.CellPainting += OnHistoryGridCellPainting;
        gridCard.Controls.Add(grid);
        layout.Controls.Add(gridCard, 0, 1);

        var detailCard = MakeCard();
        detailCard.Dock = DockStyle.Fill;
        detailCard.Margin = new Padding(0, 10, 0, 0);
        detailCard.Padding = new Padding(12, 10, 12, 8);

        var detailLayout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 4 };
        detailLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        detailLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        detailLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        detailLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 38));

        var detailFileLabel = new Label { AutoSize = true, Font = _boldFont, AutoEllipsis = true, Dock = DockStyle.Top };
        var detailShaLabel = new Label { AutoSize = true, Font = _monoFont, AutoEllipsis = true, Dock = DockStyle.Top };
        var detailMetaLabel = new Label { AutoSize = true, Font = _smallFont, AutoEllipsis = true, Dock = DockStyle.Top };

        var actionsPanel = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = false,
            Margin = new Padding(0, 4, 0, 0)
        };
        var openReportBtn = MakeButton("Open Report", ModernButtonVariant.Primary);
        openReportBtn.Enabled = false;
        openReportBtn.Click += (_, _) => OpenSelectedReport();

        var openLocationBtn = MakeButton("Open Folder", ModernButtonVariant.Secondary);
        openLocationBtn.Enabled = false;
        openLocationBtn.Click += (_, _) => OpenSelectedFileLocation();

        var scanOnVtBtn = MakeButton("Scan on VT", ModernButtonVariant.Secondary);
        scanOnVtBtn.Enabled = false;
        scanOnVtBtn.Click += (_, _) => RescanSelectedOnVirusTotal();

        var uploadBtn = MakeButton("Upload to VT", ModernButtonVariant.Secondary);
        uploadBtn.Enabled = false;
        uploadBtn.Click += (_, _) => UploadSelectedRecord();

        var clearBtn = MakeButton("Clear History", ModernButtonVariant.Ghost);
        clearBtn.Click += (_, _) =>
        {
            if (MessageBox.Show(this, "Clear all scan history entries?", "Confirm Clear",
                MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
            {
                _engine.ClearHistory();
                RefreshHistoryGrid();
            }
        };

        actionsPanel.Controls.AddRange([openReportBtn, openLocationBtn, scanOnVtBtn, uploadBtn, clearBtn]);
        detailLayout.Controls.Add(detailFileLabel, 0, 0);
        detailLayout.Controls.Add(detailShaLabel, 0, 1);
        detailLayout.Controls.Add(detailMetaLabel, 0, 2);
        detailLayout.Controls.Add(actionsPanel, 0, 3);
        detailCard.Controls.Add(detailLayout);
        layout.Controls.Add(detailCard, 0, 2);

        view.Controls.Add(layout);
        return (view, filterPanel, searchBox, verdictFilter, countLabel, grid, detailCard,
            detailFileLabel, detailShaLabel, detailMetaLabel, openReportBtn, openLocationBtn, scanOnVtBtn, uploadBtn, clearBtn);
    }

    private (
        Panel View,
        ModernCardPanel BannerCard,
        Label InfoLabel,
        Label CountSummaryLabel,
        DataGridView Grid,
        ModernButton PromoteBtn,
        ModernButton RemoveBtn,
        ModernButton ClearBtn,
        ModernButton ScanFileBtn) BuildQueuedTab()
    {
        var view = new Panel { Dock = DockStyle.Fill };
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3 };
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 48));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 46));

        var bannerCard = MakeCard();
        bannerCard.Dock = DockStyle.Fill;
        bannerCard.Padding = new Padding(14, 10, 14, 10);
        bannerCard.Margin = new Padding(0, 0, 0, 10);

        var bannerRow = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1 };
        bannerRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        bannerRow.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));

        var infoLabel = new Label
        {
            Text = "Files are checked in risk order: Very High Risk first, then High, Medium, Low, and Likely Safe.",
            AutoSize = true,
            Anchor = AnchorStyles.Left,
            Font = _smallFont
        };
        var countSummaryLabel = new Label
        {
            Text = "Idle",
            AutoSize = true,
            Anchor = AnchorStyles.Right,
            Font = _boldFont
        };
        bannerRow.Controls.Add(infoLabel, 0, 0);
        bannerRow.Controls.Add(countSummaryLabel, 1, 0);
        bannerCard.Controls.Add(bannerRow);
        layout.Controls.Add(bannerCard, 0, 0);

        var gridCard = MakeCard();
        gridCard.Dock = DockStyle.Fill;
        gridCard.Padding = new Padding(1);
        var grid = new DataGridView { Dock = DockStyle.Fill };
        grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "Priority", HeaderText = "Priority", Width = 78 });
        grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "State", HeaderText = "State", Width = 112 });
        grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "FileName", HeaderText = "File Name", Width = 190 });
        grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "RiskCategory", HeaderText = "Risk Category", Width = 125 });
        grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "Reason", HeaderText = "Reason", Width = 230 });
        grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "Size", HeaderText = "Size", Width = 84 });
        grid.Columns.Add(new DataGridViewTextBoxColumn
        {
            Name = "Location",
            HeaderText = "Location",
            AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill
        });
        grid.SelectionChanged += (_, _) => UpdateQueueButtons();
        grid.CellPainting += OnQueueGridCellPainting;
        gridCard.Controls.Add(grid);
        layout.Controls.Add(gridCard, 0, 1);

        var actions = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.LeftToRight,
            Padding = new Padding(0, 8, 0, 0)
        };
        var promoteBtn = MakeButton("Move to Top", ModernButtonVariant.Primary);
        promoteBtn.Enabled = false;
        promoteBtn.Click += (_, _) =>
        {
            QueuedScanItem? item = GetSelectedQueueItem();
            if (item is not null && item.State == "Queued")
            {
                _engine.PromoteQueuedItem(item.FilePath);
            }
        };

        var removeBtn = MakeButton("Remove Selected", ModernButtonVariant.Secondary);
        removeBtn.Enabled = false;
        removeBtn.Click += (_, _) =>
        {
            QueuedScanItem? item = GetSelectedQueueItem();
            if (item is not null && item.State == "Queued")
            {
                _engine.RemoveQueuedItem(item.FilePath);
            }
        };

        var clearBtn = MakeButton("Clear Queue", ModernButtonVariant.Danger);
        clearBtn.Enabled = false;
        clearBtn.Click += (_, _) =>
        {
            if (_engine.QueuedCount > 0 && MessageBox.Show(this, "Remove all waiting items from the scan queue?",
                "Confirm Clear Queue", MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
            {
                _engine.ClearQueue();
            }
        };

        var scanFileBtn = MakeButton("Scan File...", ModernButtonVariant.Secondary);
        scanFileBtn.Click += (_, _) => PromptManualFileScan();

        actions.Controls.AddRange([promoteBtn, removeBtn, clearBtn, scanFileBtn]);
        layout.Controls.Add(actions, 0, 2);

        view.Controls.Add(layout);
        return (view, bannerCard, infoLabel, countSummaryLabel, grid, promoteBtn, removeBtn, clearBtn, scanFileBtn);
    }

    private (
        Panel View,
        DataGridView Grid,
        ModernButton AddBtn,
        ModernButton RemoveBtn,
        ModernButton ToggleSubfoldersBtn,
        ModernButton ToggleEnabledBtn,
        ModernButton OpenDirBtn) BuildDirectoriesTab()
    {
        var view = new Panel { Dock = DockStyle.Fill };
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2 };
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 46));

        var gridCard = MakeCard();
        gridCard.Dock = DockStyle.Fill;
        gridCard.Padding = new Padding(1);
        var grid = new DataGridView { Dock = DockStyle.Fill };
        grid.Columns.Add(new DataGridViewTextBoxColumn
        {
            Name = "Path",
            HeaderText = "Directory Path",
            AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill
        });
        grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "Subfolders", HeaderText = "Subfolders", Width = 110 });
        grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "Enabled", HeaderText = "Enabled", Width = 95 });
        grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "Status", HeaderText = "Status", Width = 180 });
        grid.SelectionChanged += (_, _) => UpdateDirectoryButtons();
        grid.CellPainting += OnDirectoryGridCellPainting;
        gridCard.Controls.Add(grid);
        layout.Controls.Add(gridCard, 0, 0);

        var actions = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.LeftToRight,
            Padding = new Padding(0, 8, 0, 0)
        };
        var addBtn = MakeButton("Add Folder...", ModernButtonVariant.Primary);
        addBtn.Click += (_, _) => AddWatchedFolder();

        var removeBtn = MakeButton("Remove Selected", ModernButtonVariant.Secondary);
        removeBtn.Enabled = false;
        removeBtn.Click += (_, _) => RemoveSelectedFolder();

        var toggleSubBtn = MakeButton("Toggle Subfolders", ModernButtonVariant.Secondary);
        toggleSubBtn.Enabled = false;
        toggleSubBtn.Click += (_, _) => ToggleSelectedDirectorySubfolders();

        var toggleEnabledBtn = MakeButton("Enable / Disable", ModernButtonVariant.Secondary);
        toggleEnabledBtn.Enabled = false;
        toggleEnabledBtn.Click += (_, _) => ToggleSelectedDirectoryEnabled();

        var openDirBtn = MakeButton("Open in Explorer", ModernButtonVariant.Secondary);
        openDirBtn.Enabled = false;
        openDirBtn.Click += (_, _) => OpenSelectedDirectoryInExplorer();

        actions.Controls.AddRange([addBtn, removeBtn, toggleSubBtn, toggleEnabledBtn, openDirBtn]);
        layout.Controls.Add(actions, 0, 1);

        view.Controls.Add(layout);
        return (view, grid, addBtn, removeBtn, toggleSubBtn, toggleEnabledBtn, openDirBtn);
    }

    private (
        Panel View,
        FlowLayoutPanel ScrollPanel,
        ModernCardPanel VtQuotaCard,
        ModernCardPanel LocalStatsCard,
        ModernCardPanel SecondaryCard,
        Label AccountLabel,
        Label FetchedAtLabel,
        ModernButton RefreshQuotaBtn,
        Label MinuteValueLabel,
        ModernProgressBar MinuteBar,
        Label HourlyValueLabel,
        ModernProgressBar HourlyBar,
        Label DailyValueLabel,
        ModernProgressBar DailyBar,
        Label MonthlyValueLabel,
        ModernProgressBar MonthlyBar,
        Label QuotaStatusLabel,
        Label CacheCountLabel,
        Label CacheHitsLabel,
        Label SecondarySavedLabel,
        ModernButton ClearCacheBtn,
        ModernButton OpenDataBtn,
        DataGridView SecondaryGrid) BuildApiTab()
    {
        var view = new Panel { Dock = DockStyle.Fill };
        var scroll = new SmoothFlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.TopDown,
            WrapContents = false,
            AutoScroll = true,
            Padding = new Padding(2, 2, 10, 12)
        };

        // Card 1: VirusTotal API Quota
        var vtCard = CreateResponsiveCard(scroll, out TableLayoutPanel vtTable, 2);
        vtTable.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        vtTable.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));

        int r = 0;
        var vtTitle = new Label { Text = "VirusTotal API Quota", Font = _sectionTitleFont, AutoSize = true, Margin = new Padding(0, 0, 0, 4) };
        var refreshBtn = MakeButton("Refresh from VirusTotal", ModernButtonVariant.Primary);
        refreshBtn.Click += async (_, _) => await RefreshVirusTotalQuotaAsync();
        vtTable.Controls.Add(vtTitle, 0, r);
        vtTable.Controls.Add(refreshBtn, 1, r++);

        var accountLabel = new Label { AutoSize = true, Font = _smallFont, Margin = new Padding(0, 0, 0, 2) };
        var fetchedAtLabel = new Label { AutoSize = true, Font = _smallFont, Anchor = AnchorStyles.Right, Margin = new Padding(0, 0, 0, 2) };
        vtTable.Controls.Add(accountLabel, 0, r);
        vtTable.Controls.Add(fetchedAtLabel, 1, r++);

        var minuteVal = AddQuotaRow(vtTable, ref r, "Minute Rate Window (local)", out var minuteBar);
        var hourlyVal = AddQuotaRow(vtTable, ref r, "Hourly Quota (VirusTotal)", out var hourlyBar);
        var dailyVal = AddQuotaRow(vtTable, ref r, "Daily Quota (VirusTotal)", out var dailyBar);
        var monthlyVal = AddQuotaRow(vtTable, ref r, "Monthly Quota (VirusTotal)", out var monthlyBar);

        var quotaStatusLabel = new Label { AutoSize = true, Font = _smallFont, Margin = new Padding(0, 4, 0, 0) };
        vtTable.SetColumnSpan(quotaStatusLabel, 2);
        vtTable.Controls.Add(quotaStatusLabel, 0, r);

        // Card 2: Local Screening Efficiency
        var localCard = CreateResponsiveCard(scroll, out TableLayoutPanel localTable, 3);
        localTable.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33.3f));
        localTable.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33.3f));
        localTable.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33.4f));

        var localTitle = new Label { Text = "Local Screening Efficiency", Font = _sectionTitleFont, AutoSize = true, Margin = new Padding(0, 0, 0, 10) };
        localTable.SetColumnSpan(localTitle, 3);
        localTable.Controls.Add(localTitle, 0, 0);

        var cacheCountVal = AddStatTile(localTable, 0, 1, "Cached Hashes");
        var cacheHitsVal = AddStatTile(localTable, 1, 1, "Cache Hits Today (VT Saved)");
        var secSavedVal = AddStatTile(localTable, 2, 1, "Secondary Lookups Saved Today");

        var localActions = new FlowLayoutPanel
        {
            AutoSize = true,
            FlowDirection = FlowDirection.LeftToRight,
            Margin = new Padding(0, 12, 0, 0)
        };
        var clearCacheBtn = MakeButton("Clear Hash Cache", ModernButtonVariant.Secondary);
        clearCacheBtn.Click += (_, _) =>
        {
            _engine.ClearCache();
            RefreshApiTab();
        };
        var openDataBtn = MakeButton("Open Data Folder", ModernButtonVariant.Secondary);
        openDataBtn.Click += (_, _) => OpenFolder(_paths.DataDirectory);
        localActions.Controls.AddRange([clearCacheBtn, openDataBtn]);
        localTable.SetColumnSpan(localActions, 3);
        localTable.Controls.Add(localActions, 0, 2);

        // Card 3: Secondary Hash Services
        var secCard = CreateResponsiveCard(scroll, out TableLayoutPanel secTable, 1);
        secTable.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

        var secTitle = new Label { Text = "Secondary Hash Lookup Services", Font = _sectionTitleFont, AutoSize = true, Margin = new Padding(0, 0, 0, 8) };
        secTable.Controls.Add(secTitle, 0, 0);

        var secGrid = new DataGridView
        {
            Dock = DockStyle.Top,
            Height = 152,
            ScrollBars = ScrollBars.Vertical
        };
        secGrid.Columns.Add(new DataGridViewTextBoxColumn { Name = "Service", HeaderText = "Service", Width = 175 });
        secGrid.Columns.Add(new DataGridViewTextBoxColumn { Name = "Enabled", HeaderText = "Status", Width = 95 });
        secGrid.Columns.Add(new DataGridViewTextBoxColumn { Name = "ApiKey", HeaderText = "API Key", Width = 115 });
        secGrid.Columns.Add(new DataGridViewTextBoxColumn { Name = "RequestsToday", HeaderText = "Requests Today", Width = 115 });
        secGrid.Columns.Add(new DataGridViewTextBoxColumn { Name = "HitsToday", HeaderText = "VT Calls Saved", Width = 115 });
        secGrid.Columns.Add(new DataGridViewTextBoxColumn
        {
            Name = "LastResult",
            HeaderText = "Last Status",
            AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill
        });
        secTable.Controls.Add(secGrid, 0, 1);

        scroll.SizeChanged += (_, _) => UpdateResponsiveCards(scroll);
        view.Controls.Add(scroll);
        return (view, scroll, vtCard, localCard, secCard, accountLabel, fetchedAtLabel, refreshBtn,
            minuteVal, minuteBar, hourlyVal, hourlyBar, dailyVal, dailyBar, monthlyVal, monthlyBar,
            quotaStatusLabel, cacheCountVal, cacheHitsVal, secSavedVal, clearCacheBtn, openDataBtn, secGrid);
    }

    private Label AddQuotaRow(TableLayoutPanel table, ref int rowIndex, string labelText, out ModernProgressBar bar)
    {
        var label = new Label { Text = labelText, AutoSize = true, Font = _boldFont, Margin = new Padding(0, 8, 0, 2) };
        var valLabel = new Label { Text = "-", AutoSize = true, Font = _smallFont, Anchor = AnchorStyles.Right, Margin = new Padding(0, 8, 0, 2) };
        table.Controls.Add(label, 0, rowIndex);
        table.Controls.Add(valLabel, 1, rowIndex++);

        bar = MakeProgressBar();
        table.SetColumnSpan(bar, 2);
        table.Controls.Add(bar, 0, rowIndex++);
        return valLabel;
    }

    private Label AddStatTile(TableLayoutPanel table, int col, int row, string caption)
    {
        var stack = new FlowLayoutPanel
        {
            FlowDirection = FlowDirection.TopDown,
            AutoSize = true,
            WrapContents = false,
            Margin = new Padding(0, 0, 16, 0)
        };
        var numLabel = new Label { Text = "0", AutoSize = true, Font = _headerTitleFont };
        var capLabel = new Label { Text = caption, AutoSize = true, Font = _smallFont };
        stack.Controls.AddRange([numLabel, capLabel]);
        table.Controls.Add(stack, col, row);
        return numLabel;
    }

    private (
        Panel View,
        FlowLayoutPanel ScrollPanel,
        ModernCardPanel GeneralCard,
        ModernCardPanel UpdatesCard,
        ModernCardPanel VtCard,
        ModernCardPanel SecondaryCard,
        ModernCardPanel ResetCard,
        Panel SaveBar,
        Label LegendLabel,
        ComboBox ThemeCombo,
        CheckBox StartupCheckBox,
        Label InstalledVersionLabel,
        Label UpdateStatusLabel,
        LinkLabel UpdateReleaseLink,
        ModernProgressBar UpdateProgressBar,
        ModernButton CheckUpdatesBtn,
        ModernButton InstallUpdateBtn,
        ComboBox AutoUpdateModeCombo,
        Label UpdateHelperLabel,
        TextBox ApiKeyBox,
        ModernButton ToggleKeyBtn,
        ModernButton TestKeyBtn,
        Label KeyStatusLabel,
        ComboBox UploadPolicyCombo,
        ComboBox FilterModeCombo,
        TextBox UploadExtBox,
        TextBox ArchiveExtBox,
        ModernButton ResetExtBtn,
        Panel ThresholdContainer,
        ModernThresholdSlider ThresholdSlider,
        Label ThresholdDescLabel,
        NumericUpDown RateLimitNum,
        NumericUpDown MaxUploadNum,
        NumericUpDown MaxHashMbNum,
        Label RateLimitWarningLabel,
        Label MaxUploadWarningLabel,
        Label MaxHashWarningLabel,
        CheckBox LowerRiskOnlyCheck,
        CheckBox EnableCirclCheck,
        CheckBox EnableMdCheck,
        TextBox MdKeyBox,
        ModernButton ToggleMdBtn,
        ModernButton TestMdBtn,
        Label MdStatusLabel,
        CheckBox EnableMbCheck,
        TextBox MbKeyBox,
        ModernButton ToggleMbBtn,
        ModernButton TestMbBtn,
        Label MbStatusLabel,
        ModernButton SaveBtn,
        ModernButton ResetDefaultsBtn,
        Label SaveConfirmLabel) BuildSettingsTab()
    {
        var view = new Panel { Dock = DockStyle.Fill };
        var root = new SmoothTableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2 };
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));

        var scroll = new SmoothFlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.TopDown,
            WrapContents = false,
            AutoScroll = true,
            Padding = new Padding(2, 2, 10, 12)
        };

        var legendLabel = new Label
        {
            Text = "* Marks the recommended choice in dropdowns. A star beside a setting means it is currently at its recommended value.",
            AutoSize = true,
            MaximumSize = new Size(760, 0),
            Font = _smallFont,
            Margin = new Padding(4, 0, 0, 10),
            Tag = "SettingsLegend"
        };
        _wrappingSettingsLabels.Add(legendLabel);
        scroll.Controls.Add(legendLabel);

        // Card 1: General and Appearance
        var generalCard = CreateResponsiveCard(scroll, out TableLayoutPanel genTable, 1);
        genTable.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

        int gr = 0;
        var genTitle = new Label { Text = "General and Appearance", Font = _sectionTitleFont, AutoSize = true, Margin = new Padding(0, 0, 0, 10) };
        genTable.Controls.Add(genTitle, 0, gr++);

        AddSettingFieldHeader(genTable, ref gr, "Color theme", addTopSpacing: false);
        var themeCombo = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 280, Margin = new Padding(0, 0, 0, 4) };
        themeCombo.Items.AddRange(["Follow Windows theme *", "Dark (VirusTotal style)", "Light"]);
        themeCombo.SelectedIndexChanged += (_, _) => UpdateRecommendedStarIndicators();
        genTable.Controls.Add(WrapWithRecommendedStar(
            themeCombo,
            "Follow Windows theme",
            () => themeCombo.SelectedIndex == (int)AppThemeMode.System), 0, gr++);

        AddSectionDivider(genTable, ref gr);

        AddSettingFieldHeader(genTable, ref gr, "Windows startup", addTopSpacing: false);
        var startupCheck = new CheckBox
        {
            Text = "Start automatically minimized to system tray when Windows starts",
            AutoSize = true,
            Margin = new Padding(0, 2, 0, 4)
        };
        startupCheck.CheckedChanged += (_, _) => UpdateRecommendedStarIndicators();
        genTable.Controls.Add(WrapWithRecommendedStar(
            startupCheck,
            "Enabled",
            () => startupCheck.Checked), 0, gr++);

        AddSectionDivider(genTable, ref gr);

        AddSettingFieldHeader(genTable, ref gr, "Setup and Help", addTopSpacing: false);
        var helpButtonsRow = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0, 2, 0, 2) };
        var runWizardBtn = MakeButton("Run Setup Wizard", ModernButtonVariant.Secondary);
        runWizardBtn.Click += (_, _) => ShowOnboardingWizard();
        var startTourBtn = MakeButton("Start UI Tour", ModernButtonVariant.Secondary);
        startTourBtn.Click += (_, _) => StartUiTutorial();
        helpButtonsRow.Controls.AddRange([runWizardBtn, startTourBtn]);
        genTable.Controls.Add(helpButtonsRow, 0, gr++);

        // Card 2: Updates
        var updatesCard = CreateResponsiveCard(scroll, out TableLayoutPanel updTable, 1);
        updTable.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

        int ur = 0;
        var updTitle = new Label { Text = "Updates", Font = _sectionTitleFont, AutoSize = true, Margin = new Padding(0, 0, 0, 10) };
        updTable.Controls.Add(updTitle, 0, ur++);

        AddSettingFieldHeader(updTable, ref ur, "Installed version", addTopSpacing: false);
        var installedVersionLabel = new Label
        {
            Text = $"v{_updateService.CurrentVersion.ToString(3)}",
            AutoSize = true,
            Font = _boldFont,
            Margin = new Padding(0, 0, 0, 4)
        };
        updTable.Controls.Add(installedVersionLabel, 0, ur++);

        AddSectionDivider(updTable, ref ur);

        AddSettingFieldHeader(updTable, ref ur, "Update status", addTopSpacing: false);
        var statusRow = new FlowLayoutPanel { AutoSize = true, WrapContents = true, Margin = new Padding(0, 0, 0, 4) };
        var updateStatusLabel = new Label
        {
            Text = "Click Check for Updates to query GitHub for new releases.",
            AutoSize = true,
            MaximumSize = new Size(680, 0),
            Margin = new Padding(0, 2, 12, 0)
        };
        var updateReleaseLink = new LinkLabel { Text = "View release notes", AutoSize = true, Font = _smallFont, Visible = false, Margin = new Padding(0, 2, 0, 0) };
        updateReleaseLink.LinkClicked += (_, _) =>
        {
            if (!string.IsNullOrWhiteSpace(_latestReleaseUrl))
            {
                OpenUrl(_latestReleaseUrl);
            }
        };
        _allLinks.Add(updateReleaseLink);
        statusRow.Controls.AddRange([updateStatusLabel, updateReleaseLink]);
        updTable.Controls.Add(statusRow, 0, ur++);

        var updateProgressBar = MakeProgressBar();
        updateProgressBar.Dock = DockStyle.None;
        updateProgressBar.Width = 460;
        updateProgressBar.Height = 12;
        updateProgressBar.Maximum = 100;
        updateProgressBar.Value = 0;
        updateProgressBar.Visible = false;
        updateProgressBar.Margin = new Padding(0, 2, 0, 6);
        updTable.Controls.Add(updateProgressBar, 0, ur++);

        var updBtnRow = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0, 2, 0, 4) };
        var checkUpdatesBtn = MakeButton("Check for Updates", ModernButtonVariant.Secondary);
        checkUpdatesBtn.Click += async (_, _) => await CheckForUpdatesAsync();
        var installUpdateBtn = MakeButton("Download and Install Update", ModernButtonVariant.Primary);
        installUpdateBtn.Enabled = false;
        installUpdateBtn.Click += async (_, _) => await InstallUpdateAsync();
        updBtnRow.Controls.AddRange([checkUpdatesBtn, installUpdateBtn]);
        updTable.Controls.Add(updBtnRow, 0, ur++);

        AddSectionDivider(updTable, ref ur);

        AddSettingFieldHeader(updTable, ref ur, "Automatic updates", addTopSpacing: false);
        var autoUpdateModeCombo = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 280, Margin = new Padding(0, 0, 0, 4) };
        autoUpdateModeCombo.Items.AddRange(
        [
            "Off (manual checks only)",
            "Critical updates only *",
            "On (all releases)"
        ]);
        autoUpdateModeCombo.SelectedIndexChanged += (_, _) =>
        {
            UpdateRecommendedStarIndicators();
            if (_autoUpdateModeCombo is not null && _updateService.LatestCheckResult is null)
            {
                RefreshUpdateUiFromLatest();
            }
        };
        updTable.Controls.Add(WrapWithRecommendedStar(
            autoUpdateModeCombo,
            "Critical updates only",
            () => autoUpdateModeCombo.SelectedIndex == 1), 0, ur++);

        var updateHelperLabel = new Label
        {
            Text = $"Critical updates are indicated by {UpdateService.CriticalReleaseMarker} on the first line of the GitHub release notes. Settings, directories, and scan history are backed up and preserved during updates.",
            AutoSize = true,
            MaximumSize = new Size(680, 0),
            Font = _smallFont,
            Margin = new Padding(0, 4, 0, 2)
        };
        updTable.Controls.Add(updateHelperLabel, 0, ur++);

        // Card 3: VirusTotal Configuration
        var vtCard = CreateResponsiveCard(scroll, out TableLayoutPanel vtTable, 1);
        vtTable.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

        int vr = 0;
        var vtTitle = new Label { Text = "VirusTotal Configuration", Font = _sectionTitleFont, AutoSize = true, Margin = new Padding(0, 0, 0, 10) };
        vtTable.Controls.Add(vtTitle, 0, vr++);

        AddSettingFieldHeader(vtTable, ref vr, "VirusTotal API Key", addTopSpacing: false);
        var keyRow = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0) };
        var apiKeyBox = new TextBox { Width = 360, UseSystemPasswordChar = true };
        var toggleKeyBtn = MakeButton("Show", ModernButtonVariant.Secondary);
        toggleKeyBtn.Click += (_, _) =>
        {
            apiKeyBox.UseSystemPasswordChar = !apiKeyBox.UseSystemPasswordChar;
            toggleKeyBtn.Text = apiKeyBox.UseSystemPasswordChar ? "Show" : "Hide";
        };
        var testKeyBtn = MakeButton("Test Key", ModernButtonVariant.Secondary);
        testKeyBtn.Click += async (_, _) => await TestVirusTotalKeyAsync();
        keyRow.Controls.AddRange([apiKeyBox, toggleKeyBtn, testKeyBtn]);
        vtTable.Controls.Add(keyRow, 0, vr++);

        var keyInfoRow = new FlowLayoutPanel { AutoSize = true, Margin = new Padding(0, 4, 0, 4) };
        var vtLink = MakeLink("Get free API key at virustotal.com", "https://www.virustotal.com/gui/my-apikey");
        vtLink.Margin = new Padding(0, 2, 16, 0);
        var keyStatusLabel = new Label { AutoSize = true, Font = _smallFont, Margin = new Padding(0, 2, 0, 0) };
        keyInfoRow.Controls.AddRange([vtLink, keyStatusLabel]);
        vtTable.Controls.Add(keyInfoRow, 0, vr++);

        AddSectionDivider(vtTable, ref vr);

        AddSettingFieldHeader(vtTable, ref vr, "When VirusTotal has not seen a file", addTopSpacing: false);
        var uploadPolicyCombo = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 460 };
        uploadPolicyCombo.Items.AddRange(
        [
            "Auto-upload executables, scripts & installers *",
            "Hash lookup only (never upload files)",
            "Auto-upload all watched files"
        ]);
        uploadPolicyCombo.SelectedIndexChanged += (_, _) => UpdateRecommendedStarIndicators();
        vtTable.Controls.Add(WrapWithRecommendedStar(
            uploadPolicyCombo,
            "Auto-upload executables, scripts & installers",
            () => uploadPolicyCombo.SelectedIndex == (int)UploadPolicy.ExecutablesAndScriptsOnly), 0, vr++);

        AddSettingFieldHeader(vtTable, ref vr, "Watched file types");
        var filterModeCombo = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 460 };
        filterModeCombo.Items.AddRange(
        [
            "Executables, scripts, installers & archives *",
            "All file types (uses more API quota)"
        ]);
        filterModeCombo.SelectedIndexChanged += (_, _) => UpdateRecommendedStarIndicators();
        vtTable.Controls.Add(WrapWithRecommendedStar(
            filterModeCombo,
            "Executables, scripts, installers & archives",
            () => filterModeCombo.SelectedIndex == (int)FileFilterMode.ExecutablesScriptsAndArchives), 0, vr++);

        AddSettingFieldHeader(vtTable, ref vr, "Executable and script extensions");
        var uploadExtBox = new TextBox { Width = 540 };
        uploadExtBox.TextChanged += (_, _) => UpdateRecommendedStarIndicators();
        vtTable.Controls.Add(WrapWithRecommendedStar(
            uploadExtBox,
            "Default executable and script extensions",
            () => ExtensionsMatchDefaults(uploadExtBox.Text, AppSettings.DefaultUploadExtensions)), 0, vr++);

        AddSettingFieldHeader(vtTable, ref vr, "Archive and disk image extensions");
        var archPanel = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0) };
        var archiveExtBox = new TextBox { Width = 415 };
        archiveExtBox.TextChanged += (_, _) => UpdateRecommendedStarIndicators();
        var resetExtBtn = MakeButton("Reset Extensions", ModernButtonVariant.Secondary);
        resetExtBtn.Click += (_, _) =>
        {
            uploadExtBox.Text = string.Join(", ", AppSettings.DefaultUploadExtensions);
            archiveExtBox.Text = string.Join(", ", AppSettings.DefaultArchiveExtensions);
        };
        archPanel.Controls.AddRange([archiveExtBox, resetExtBtn]);
        vtTable.Controls.Add(WrapWithRecommendedStar(
            archPanel,
            "Default archive and disk image extensions",
            () => ExtensionsMatchDefaults(archiveExtBox.Text, AppSettings.DefaultArchiveExtensions)), 0, vr++);

        AddSectionDivider(vtTable, ref vr);

        AddSettingFieldHeader(vtTable, ref vr, "Unsafe alert threshold (vendors)", addTopSpacing: false);
        var thresholdContainer = new FlowLayoutPanel
        {
            FlowDirection = FlowDirection.TopDown,
            AutoSize = true,
            WrapContents = false,
            Margin = new Padding(0, 2, 0, 4)
        };
        var thresholdSlider = new ModernThresholdSlider
        {
            Width = 480,
            Height = 74,
            Margin = new Padding(0, 0, 0, 4)
        };
        var thresholdDescLabel = new Label
        {
            AutoSize = true,
            MaximumSize = new Size(680, 0),
            Font = _smallFont,
            Margin = new Padding(2, 0, 0, 0)
        };
        thresholdSlider.ValueChanged += val =>
        {
            UpdateThresholdDescriptionLabel(thresholdDescLabel, val);
            UpdateRecommendedStarIndicators();
        };
        thresholdContainer.Controls.Add(WrapWithRecommendedStar(
            thresholdSlider,
            "2+ vendors",
            () => thresholdSlider.Value == ModernThresholdSlider.RecommendedThreshold));
        thresholdContainer.Controls.Add(thresholdDescLabel);
        vtTable.Controls.Add(thresholdContainer, 0, vr++);

        AddSectionDivider(vtTable, ref vr);

        AddSettingFieldHeader(vtTable, ref vr, "API rate limit (requests / minute)", addTopSpacing: false);
        var rateLimitNum = new NumericUpDown { Minimum = 1, Maximum = 1000, Width = 110 };
        rateLimitNum.ValueChanged += (_, _) =>
        {
            UpdateVirusTotalLimitWarnings();
            UpdateRecommendedStarIndicators();
        };
        vtTable.Controls.Add(WrapWithRecommendedStar(
            rateLimitNum,
            "4 requests/minute (Free API limit)",
            () => (int)rateLimitNum.Value == 4), 0, vr++);
        Label rateLimitWarningLabel = AddSettingsHintOrWarningLabel(vtTable, ref vr);

        AddSettingFieldHeader(vtTable, ref vr, "Max file size to upload (MB)");
        var maxUploadNum = new NumericUpDown { Minimum = 1, Maximum = 650, Increment = 16, Width = 110 };
        maxUploadNum.ValueChanged += (_, _) =>
        {
            UpdateVirusTotalLimitWarnings();
            UpdateRecommendedStarIndicators();
        };
        vtTable.Controls.Add(WrapWithRecommendedStar(
            maxUploadNum,
            "32 MB (Free API direct upload limit)",
            () => (int)maxUploadNum.Value == 32), 0, vr++);
        Label maxUploadWarningLabel = AddSettingsHintOrWarningLabel(vtTable, ref vr);

        AddSettingFieldHeader(vtTable, ref vr, "Max file size to hash (MB, 0 = unlimited)");
        var maxHashNum = new NumericUpDown { Minimum = 0, Maximum = 50000, Increment = 128, Width = 110 };
        maxHashNum.ValueChanged += (_, _) =>
        {
            UpdateVirusTotalLimitWarnings();
            UpdateRecommendedStarIndicators();
        };
        vtTable.Controls.Add(WrapWithRecommendedStar(
            maxHashNum,
            "2048 MB",
            () => (int)maxHashNum.Value == 2048), 0, vr++);
        Label maxHashWarningLabel = AddSettingsHintOrWarningLabel(vtTable, ref vr);

        // Card 4: Secondary Hash Lookup Services
        var secCard = CreateResponsiveCard(scroll, out TableLayoutPanel secTable, 1);
        secTable.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

        int sr = 0;
        var secTitle = new Label { Text = "Secondary Hash Lookup Services", Font = _sectionTitleFont, AutoSize = true, Margin = new Padding(0, 0, 0, 10) };
        secTable.Controls.Add(secTitle, 0, sr++);

        AddSettingFieldHeader(secTable, ref sr, "Screening scope", addTopSpacing: false);
        var lowerRiskOnlyCheck = new CheckBox
        {
            Text = "Only use secondary services for lower-risk files (Low Risk and Likely Safe)",
            AutoSize = true,
            Margin = new Padding(0, 2, 0, 4)
        };
        lowerRiskOnlyCheck.CheckedChanged += (_, _) => UpdateRecommendedStarIndicators();
        secTable.Controls.Add(WrapWithRecommendedStar(
            lowerRiskOnlyCheck,
            "Unchecked (all risk levels)",
            () => !lowerRiskOnlyCheck.Checked), 0, sr++);

        AddSectionDivider(secTable, ref sr);

        AddSettingFieldHeader(secTable, ref sr, "CIRCL Hashlookup (NSRL)", addTopSpacing: false);
        var enableCirclCheck = new CheckBox
        {
            Text = "Enable CIRCL Hashlookup (free NIST NSRL known-good database, no API key required)",
            AutoSize = true,
            Margin = new Padding(0, 2, 0, 4)
        };
        enableCirclCheck.CheckedChanged += (_, _) => UpdateRecommendedStarIndicators();
        secTable.Controls.Add(WrapWithRecommendedStar(
            enableCirclCheck,
            "Enabled",
            () => enableCirclCheck.Checked), 0, sr++);

        AddSectionDivider(secTable, ref sr);

        // OPSWAT MetaDefender
        AddSettingFieldHeader(secTable, ref sr, "OPSWAT MetaDefender Cloud", addTopSpacing: false);
        var mdStack = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, AutoSize = true, WrapContents = false, Margin = new Padding(0, 2, 0, 4) };
        var enableMdCheck = new CheckBox { Text = "Enable MetaDefender hash lookup (requires free API key)", AutoSize = true };
        enableMdCheck.CheckedChanged += (_, _) => UpdateRecommendedStarIndicators();
        var mdKeyRow = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0, 6, 0, 2) };
        var mdKeyBox = new TextBox { Width = 360, UseSystemPasswordChar = true };
        var toggleMdBtn = MakeButton("Show", ModernButtonVariant.Secondary);
        toggleMdBtn.Click += (_, _) =>
        {
            mdKeyBox.UseSystemPasswordChar = !mdKeyBox.UseSystemPasswordChar;
            toggleMdBtn.Text = mdKeyBox.UseSystemPasswordChar ? "Show" : "Hide";
        };
        var testMdBtn = MakeButton("Test", ModernButtonVariant.Secondary);
        testMdBtn.Click += async (_, _) => await TestMetaDefenderKeyAsync();
        mdKeyRow.Controls.AddRange([mdKeyBox, toggleMdBtn, testMdBtn]);

        var mdInfoRow = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0, 2, 0, 0) };
        var mdLink = MakeLink("Get free key at metadefender.opswat.com", "https://metadefender.opswat.com/");
        mdLink.Margin = new Padding(0, 2, 16, 0);
        var mdStatusLabel = new Label { AutoSize = true, Font = _smallFont, Margin = new Padding(0, 2, 0, 0) };
        mdInfoRow.Controls.AddRange([mdLink, mdStatusLabel]);
        mdStack.Controls.Add(WrapWithRecommendedStar(
            enableMdCheck,
            "Disabled unless you have a free MetaDefender API key",
            () => !enableMdCheck.Checked));
        mdStack.Controls.Add(mdKeyRow);
        mdStack.Controls.Add(mdInfoRow);
        secTable.Controls.Add(mdStack, 0, sr++);

        AddSectionDivider(secTable, ref sr);

        // MalwareBazaar
        AddSettingFieldHeader(secTable, ref sr, "MalwareBazaar (abuse.ch)", addTopSpacing: false);
        var mbStack = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, AutoSize = true, WrapContents = false, Margin = new Padding(0, 2, 0, 2) };
        var enableMbCheck = new CheckBox { Text = "Enable MalwareBazaar threat lookup (requires free Auth-Key)", AutoSize = true };
        enableMbCheck.CheckedChanged += (_, _) => UpdateRecommendedStarIndicators();
        var mbKeyRow = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0, 6, 0, 2) };
        var mbKeyBox = new TextBox { Width = 360, UseSystemPasswordChar = true };
        var toggleMbBtn = MakeButton("Show", ModernButtonVariant.Secondary);
        toggleMbBtn.Click += (_, _) =>
        {
            mbKeyBox.UseSystemPasswordChar = !mbKeyBox.UseSystemPasswordChar;
            toggleMbBtn.Text = mbKeyBox.UseSystemPasswordChar ? "Show" : "Hide";
        };
        var testMbBtn = MakeButton("Test", ModernButtonVariant.Secondary);
        testMbBtn.Click += async (_, _) => await TestMalwareBazaarKeyAsync();
        mbKeyRow.Controls.AddRange([mbKeyBox, toggleMbBtn, testMbBtn]);

        var mbInfoRow = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0, 2, 0, 0) };
        var mbLink = MakeLink("Get free Auth-Key at auth.abuse.ch", "https://auth.abuse.ch/");
        mbLink.Margin = new Padding(0, 2, 16, 0);
        var mbStatusLabel = new Label { AutoSize = true, Font = _smallFont, Margin = new Padding(0, 2, 0, 0) };
        mbInfoRow.Controls.AddRange([mbLink, mbStatusLabel]);
        mbStack.Controls.Add(WrapWithRecommendedStar(
            enableMbCheck,
            "Disabled unless you have a free MalwareBazaar Auth-Key",
            () => !enableMbCheck.Checked));
        mbStack.Controls.Add(mbKeyRow);
        mbStack.Controls.Add(mbInfoRow);
        secTable.Controls.Add(mbStack, 0, sr);

        // Card 5: Reset Settings (at bottom of settings menu)
        var resetCard = CreateResponsiveCard(scroll, out TableLayoutPanel resetTable, 1);
        resetTable.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

        int rr = 0;
        var resetTitle = new Label { Text = "Reset Settings", Font = _sectionTitleFont, AutoSize = true, Margin = new Padding(0, 0, 0, 6) };
        resetTable.Controls.Add(resetTitle, 0, rr++);

        var resetDescLabel = new Label
        {
            Text = "Restore all settings above to their recommended defaults. Your saved API keys and watched directories will be kept.",
            AutoSize = true,
            MaximumSize = new Size(680, 0),
            Font = _smallFont,
            Margin = new Padding(0, 0, 0, 10)
        };
        _wrappingSettingsLabels.Add(resetDescLabel);
        resetTable.Controls.Add(resetDescLabel, 0, rr++);

        var resetDefaultsBtn = MakeButton("Reset Settings to Defaults", ModernButtonVariant.Secondary);
        resetDefaultsBtn.Click += (_, _) => ResetSettingsToDefaults();
        resetTable.Controls.Add(resetDefaultsBtn, 0, rr);

        scroll.SizeChanged += (_, _) => UpdateResponsiveCards(scroll);
        root.Controls.Add(scroll, 0, 0);

        // Save bar
        var saveBar = new Panel
        {
            Dock = DockStyle.Fill,
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            Padding = new Padding(4, 8, 4, 4)
        };
        var saveRow = new FlowLayoutPanel
        {
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            Dock = DockStyle.Left,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = false
        };
        var saveBtn = MakeButton("Save Settings", ModernButtonVariant.Primary);
        saveBtn.Click += (_, _) => SaveSettingsFromForm();
        var saveConfirmLabel = new Label { AutoSize = true, Font = _boldFont, Margin = new Padding(10, 8, 0, 0) };
        saveRow.Controls.AddRange([saveBtn, saveConfirmLabel]);
        saveBar.Controls.Add(saveRow);
        root.Controls.Add(saveBar, 0, 1);

        view.Controls.Add(root);
        return (view, scroll, generalCard, updatesCard, vtCard, secCard, resetCard, saveBar, legendLabel,
            themeCombo, startupCheck,
            installedVersionLabel, updateStatusLabel, updateReleaseLink, updateProgressBar,
            checkUpdatesBtn, installUpdateBtn, autoUpdateModeCombo, updateHelperLabel,
            apiKeyBox, toggleKeyBtn, testKeyBtn, keyStatusLabel, uploadPolicyCombo, filterModeCombo,
            uploadExtBox, archiveExtBox, resetExtBtn, thresholdContainer, thresholdSlider, thresholdDescLabel,
            rateLimitNum, maxUploadNum, maxHashNum, rateLimitWarningLabel, maxUploadWarningLabel, maxHashWarningLabel,
            lowerRiskOnlyCheck, enableCirclCheck, enableMdCheck, mdKeyBox, toggleMdBtn, testMdBtn, mdStatusLabel,
            enableMbCheck, mbKeyBox, toggleMbBtn, testMbBtn, mbStatusLabel, saveBtn, resetDefaultsBtn, saveConfirmLabel);
    }

    private FlowLayoutPanel WrapWithRecommendedStar(Control control, string recommendedDescription, Func<bool> isRecommended)
    {
        var originalMargin = control.Margin;
        control.Margin = new Padding(0);

        var row = new FlowLayoutPanel
        {
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = false,
            BackColor = Color.Transparent,
            Margin = originalMargin,
            Padding = new Padding(0)
        };

        int starTop = Math.Max(2, (control.PreferredSize.Height - 18) / 2);
        var star = new RecommendedStarIndicator
        {
            Margin = new Padding(8, starTop, 0, 0)
        };
        _settingsToolTip.SetToolTip(star, $"At recommended value: {recommendedDescription}");
        _recommendedIndicators.Add((star, isRecommended));

        row.Controls.Add(control);
        row.Controls.Add(star);
        return row;
    }

    private static bool ExtensionsMatchDefaults(string rawText, string[] defaults)
    {
        List<string> parsed = SettingsStore.NormalizeExtensions(
            rawText.Split([',', ';', ' '], StringSplitOptions.RemoveEmptyEntries));
        return parsed.SequenceEqual(defaults, StringComparer.OrdinalIgnoreCase);
    }

    private void AddSettingFieldHeader(
        TableLayoutPanel table,
        ref int row,
        string title,
        bool addTopSpacing = true)
    {
        var titleLabel = new Label
        {
            Text = title,
            AutoSize = true,
            Font = _boldFont,
            Anchor = AnchorStyles.Left,
            Margin = new Padding(0, addTopSpacing ? 10 : 2, 0, 3)
        };
        table.Controls.Add(titleLabel, 0, row++);
    }

    private void AddSectionDivider(TableLayoutPanel table, ref int row)
    {
        var divider = new Panel
        {
            Dock = DockStyle.Top,
            Height = 1,
            Margin = new Padding(0, 12, 0, 10),
            Tag = "Divider"
        };
        _sectionDividers.Add(divider);
        table.Controls.Add(divider, 0, row++);
    }

    private Label AddSettingsHintOrWarningLabel(TableLayoutPanel table, ref int row)
    {
        var label = new Label
        {
            AutoSize = true,
            MaximumSize = new Size(760, 0),
            Font = _smallFont,
            Visible = false,
            Margin = new Padding(0, 4, 0, 2),
            Tag = "LimitWarning"
        };
        _wrappingSettingsLabels.Add(label);
        table.Controls.Add(label, 0, row++);
        return label;
    }

    private ModernCardPanel CreateResponsiveCard(FlowLayoutPanel host, out TableLayoutPanel innerTable, int columnCount)
    {
        var card = MakeCard();
        card.AutoSize = true;
        card.AutoSizeMode = AutoSizeMode.GrowAndShrink;
        card.Margin = new Padding(0, 0, 0, 12);

        innerTable = new SmoothTableLayoutPanel
        {
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            ColumnCount = columnCount,
            Location = new Point(16, 16),
            BackColor = Color.Transparent,
            Width = 860
        };
        card.Controls.Add(innerTable);
        host.Controls.Add(card);
        _responsiveCards.Add((card, innerTable));
        return card;
    }

    private void UpdateResponsiveCards(FlowLayoutPanel host, bool force = false)
    {
        if (!force && !host.Visible)
        {
            return;
        }

        int cardWidth = Math.Max(520, host.ClientSize.Width - host.Padding.Horizontal - 20);
        if (!force && _lastCardWidthByHost.TryGetValue(host, out int prevWidth) && prevWidth == cardWidth)
        {
            return;
        }

        _lastCardWidthByHost[host] = cardWidth;
        host.SuspendLayout();
        try
        {
            foreach (var (card, inner) in _responsiveCards)
            {
                if (card.Parent != host)
                {
                    continue;
                }

                card.SuspendLayout();
                inner.SuspendLayout();
                try
                {
                    card.MinimumSize = new Size(cardWidth, 0);
                    card.MaximumSize = new Size(cardWidth, 0);
                    inner.MinimumSize = new Size(cardWidth - 32, 0);
                    inner.MaximumSize = new Size(cardWidth - 32, 0);
                    inner.Width = cardWidth - 32;
                }
                finally
                {
                    inner.ResumeLayout(false);
                    card.ResumeLayout(false);
                }
            }

            if (host == _settingsScrollPanel)
            {
                Size wrapMax = new(Math.Max(400, cardWidth - 48), 0);
                _updateHelperLabel.MaximumSize = wrapMax;
                _thresholdDescLabel.MaximumSize = wrapMax;
                _updateStatusLabel.MaximumSize = wrapMax;
                foreach (Label lbl in _wrappingSettingsLabels)
                {
                    lbl.MaximumSize = wrapMax;
                }
            }
        }
        finally
        {
            host.ResumeLayout(!_isResizing);
        }
    }

    private void ApplyTheme(ThemePalette palette)
    {
        _palette = palette;
        BackColor = palette.CanvasBg;
        ForeColor = palette.TextPrimary;

        _headerPanel.BackColor = palette.TopBarBg;
        _titleLabel.ForeColor = palette.TextPrimary;
        _subtitleLabel.ForeColor = palette.TextSecondary;
        _navBar.ApplyTheme(palette);
        _contentHost.BackColor = palette.CanvasBg;
        _footerPanel.BackColor = palette.TopBarBg;
        _footerLabel.ForeColor = palette.TextMuted;

        _historyFilterPanel.BackColor = palette.CanvasBg;
        _historyCountLabel.ForeColor = palette.TextSecondary;
        _detailFileLabel.ForeColor = palette.TextPrimary;
        _detailShaLabel.ForeColor = palette.TextSecondary;
        _detailMetaLabel.ForeColor = palette.TextSecondary;

        _queueInfoLabel.ForeColor = palette.TextSecondary;
        _queueCountSummaryLabel.ForeColor = palette.AccentBlue;

        _apiScrollPanel.BackColor = palette.CanvasBg;
        _settingsScrollPanel.BackColor = palette.CanvasBg;
        _settingsSaveBar.BackColor = palette.CanvasBg;

        _vtAccountLabel.ForeColor = palette.TextSecondary;
        _vtFetchedAtLabel.ForeColor = palette.TextMuted;
        _minuteQuotaValueLabel.ForeColor = palette.TextPrimary;
        _hourlyQuotaValueLabel.ForeColor = palette.TextPrimary;
        _dailyQuotaValueLabel.ForeColor = palette.TextPrimary;
        _monthlyQuotaValueLabel.ForeColor = palette.TextPrimary;
        _vtQuotaStatusLabel.ForeColor = palette.TextSecondary;
        _cacheCountValueLabel.ForeColor = palette.TextPrimary;
        _cacheHitsValueLabel.ForeColor = palette.SuccessGreen;
        _secondarySavedValueLabel.ForeColor = palette.AccentBlue;

        foreach (ModernButton btn in _allButtons)
        {
            btn.ApplyTheme(palette);
        }

        foreach (ModernCardPanel card in _allCards)
        {
            card.ApplyTheme(palette);
        }

        foreach (ModernProgressBar bar in _allProgressBars)
        {
            bar.ApplyTheme(palette);
        }

        foreach (LinkLabel link in _allLinks)
        {
            link.LinkColor = palette.AccentBlue;
            link.ActiveLinkColor = palette.AccentBlueHover;
            link.VisitedLinkColor = palette.AccentBlue;
        }

        _thresholdSlider.ApplyTheme(palette);
        _thresholdDescLabel.ForeColor = palette.TextSecondary;
        _settingsLegendLabel.ForeColor = palette.TextSecondary;
        _updateHelperLabel.ForeColor = palette.TextSecondary;
        _installedVersionLabel.ForeColor = palette.TextPrimary;

        foreach (var (indicator, _) in _recommendedIndicators)
        {
            indicator.ApplyTheme(palette);
        }

        foreach (Panel divider in _sectionDividers)
        {
            divider.BackColor = palette.Border;
        }

        ModernGridHelper.ConfigureGrid(_historyGrid, palette);
        ModernGridHelper.ConfigureGrid(_queueGrid, palette);
        ModernGridHelper.ConfigureGrid(_directoriesGrid, palette);
        ModernGridHelper.ConfigureGrid(_secondaryGrid, palette);

        ApplyStandardControlThemeRecursive(_contentHost, palette);
        ThemePalette.ApplyWindowTheme(this, palette);

        RefreshHeaderStatus();
        RefreshUpdateUiFromLatest();
        UpdateVirusTotalLimitWarnings();
        UpdateRecommendedStarIndicators();
        RefreshHistoryGrid();
        RefreshQueueGrid();
        RefreshDirectoriesGrid();
        RefreshApiTab();
        UpdateResponsiveCards(_apiScrollPanel, force: true);
        UpdateResponsiveCards(_settingsScrollPanel, force: true);
    }

    private static void ApplyStandardControlThemeRecursive(Control parent, ThemePalette palette)
    {
        foreach (Control ctrl in parent.Controls)
        {
            switch (ctrl)
            {
                case TextBox tb:
                    tb.BackColor = palette.InputBg;
                    tb.ForeColor = palette.TextPrimary;
                    tb.BorderStyle = BorderStyle.FixedSingle;
                    break;
                case ComboBox cb:
                    cb.BackColor = palette.InputBg;
                    cb.ForeColor = palette.TextPrimary;
                    cb.FlatStyle = FlatStyle.Flat;
                    break;
                case NumericUpDown num:
                    num.BackColor = palette.InputBg;
                    num.ForeColor = palette.TextPrimary;
                    break;
                case CheckBox chk:
                    chk.ForeColor = palette.TextPrimary;
                    chk.BackColor = Color.Transparent;
                    break;
                case Label lbl when lbl.Tag is null:
                    if (lbl.Name == string.Empty && lbl.ForeColor == SystemColors.ControlText)
                    {
                        lbl.ForeColor = palette.TextPrimary;
                    }
                    else if (lbl.Parent is TableLayoutPanel || lbl.Parent is FlowLayoutPanel)
                    {
                        if (lbl.ForeColor != palette.SuccessGreen
                            && lbl.ForeColor != palette.DangerRed
                            && lbl.ForeColor != palette.AccentBlue
                            && lbl.ForeColor != palette.WarningAmber
                            && lbl.ForeColor != palette.TextSecondary
                            && lbl.ForeColor != palette.TextMuted)
                        {
                            lbl.ForeColor = palette.TextPrimary;
                        }
                    }

                    break;
            }

            if (ctrl.HasChildren)
            {
                ApplyStandardControlThemeRecursive(ctrl, palette);
            }
        }
    }

    private void OnEngineChanged()
    {
        if (IsDisposed || !IsHandleCreated)
        {
            return;
        }

        BeginInvoke(() =>
        {
            if (!IsDisposed)
            {
                RefreshHeaderStatus();
                RefreshDirectoriesGrid();
                UpdateQueueBadge();
                if (_activeTabIndex == TabApi)
                {
                    RefreshApiTab();
                }
            }
        });
    }

    private void OnQueueChanged()
    {
        if (IsDisposed || !IsHandleCreated)
        {
            return;
        }

        BeginInvoke(() =>
        {
            if (!IsDisposed)
            {
                UpdateQueueBadge();
                RefreshHeaderStatus();
                if (_activeTabIndex == TabQueued)
                {
                    RefreshQueueGrid();
                }
            }
        });
    }

    private void OnScanCompleted(ScanRecord _)
    {
        if (IsDisposed || !IsHandleCreated)
        {
            return;
        }

        BeginInvoke(() =>
        {
            if (!IsDisposed)
            {
                RefreshHeaderStatus();
                RefreshHistoryGrid();
                UpdateQueueBadge();
                if (_activeTabIndex == TabQueued)
                {
                    RefreshQueueGrid();
                }
                else if (_activeTabIndex == TabApi)
                {
                    RefreshApiTab();
                }
            }
        });
    }

    private void RefreshAll()
    {
        RefreshHeaderStatus();
        UpdateQueueBadge();
        RefreshHistoryGrid();
        RefreshQueueGrid();
        RefreshDirectoriesGrid();
        RefreshApiTab();
    }

    private void RefreshHeaderStatus()
    {
        TrayStatus status = _engine.CurrentTrayStatus;
        bool paused = _engine.IsPaused;

        _headerPauseBtn.Text = paused ? "Resume" : "Pause";
        _acknowledgeBtn.Visible = status == TrayStatus.Unsafe;

        if (status == TrayStatus.Unsafe)
        {
            int count = _engine.UnacknowledgedUnsafeCount;
            _statusPillLabel.Text = count == 1 ? "UNSAFE FILE DETECTED" : $"{count} UNSAFE FILES";
            _statusPillLabel.BackColor = _palette.DangerBg;
            _statusPillLabel.ForeColor = _palette.DangerRed;
            _subtitleLabel.Text = _engine.LatestUnacknowledgedUnsafe?.FileName ?? "Review scan alerts below.";
        }
        else if (status == TrayStatus.NeedsSetup)
        {
            _statusPillLabel.Text = "SETUP NEEDED";
            _statusPillLabel.BackColor = _palette.WarningBg;
            _statusPillLabel.ForeColor = _palette.WarningAmber;
            _subtitleLabel.Text = "Open Settings and enter your free VirusTotal API key to begin scanning.";
        }
        else if (status == TrayStatus.Scanning)
        {
            int queued = _engine.QueuedCount;
            string active = _engine.ActiveFileName ?? "Queued file";
            string stage = string.IsNullOrWhiteSpace(_engine.ActiveStage) ? "Scanning..." : _engine.ActiveStage;
            _statusPillLabel.Text = queued > 0 ? $"SCANNING ({queued} QUEUED)" : "SCANNING";
            _statusPillLabel.BackColor = _palette.AccentBlueBg;
            _statusPillLabel.ForeColor = _palette.AccentBlue;
            _subtitleLabel.Text = $"{active}: {stage}";
        }
        else if (paused)
        {
            _statusPillLabel.Text = "PAUSED";
            _statusPillLabel.BackColor = _palette.NeutralBg;
            _statusPillLabel.ForeColor = _palette.NeutralSlate;
            _subtitleLabel.Text = "Folder monitoring is paused. Click Resume to monitor new downloads.";
        }
        else
        {
            int activeFolders = _engine.CurrentSettings.WatchedDirectories.Count(d => d.Enabled);
            _statusPillLabel.Text = "PROTECTED";
            _statusPillLabel.BackColor = _palette.SuccessBg;
            _statusPillLabel.ForeColor = _palette.SuccessGreen;
            _subtitleLabel.Text = $"Watching {activeFolders} active folder(s). Everything checked and safe.";
        }
    }

    private void UpdateQueueBadge()
    {
        int count = _engine.GetQueueSnapshot().Count;
        _navBar.SetBadge(TabQueued, count, alert: false);
    }

    private void RefreshHistoryGrid()
    {
        IReadOnlyList<ScanRecord> allRecords = _engine.GetHistory();
        string query = (_historySearchBox.Text ?? string.Empty).Trim();
        int verdictFilterIdx = _verdictFilterCombo.SelectedIndex;

        Guid? selectedId = GetSelectedScanRecord()?.Id;
        _displayedRecords.Clear();

        foreach (ScanRecord rec in allRecords)
        {
            bool matchesVerdict = verdictFilterIdx switch
            {
                1 => rec.Verdict == ScanVerdict.Unsafe,
                2 => rec.Verdict == ScanVerdict.LowRisk,
                3 => rec.Verdict == ScanVerdict.Clean,
                4 => rec.Verdict is ScanVerdict.Unknown or ScanVerdict.Error or ScanVerdict.Skipped,
                _ => true
            };

            if (!matchesVerdict)
            {
                continue;
            }

            if (!string.IsNullOrEmpty(query))
            {
                bool hit = rec.FileName.Contains(query, StringComparison.OrdinalIgnoreCase)
                    || rec.FilePath.Contains(query, StringComparison.OrdinalIgnoreCase)
                    || rec.Sha256.Contains(query, StringComparison.OrdinalIgnoreCase)
                    || rec.SignerName.Contains(query, StringComparison.OrdinalIgnoreCase)
                    || rec.SourceService.Contains(query, StringComparison.OrdinalIgnoreCase)
                    || rec.Summary.Contains(query, StringComparison.OrdinalIgnoreCase);
                if (!hit)
                {
                    continue;
                }
            }

            _displayedRecords.Add(rec);
        }

        _historyCountLabel.Text = $"Showing {_displayedRecords.Count} of {allRecords.Count} scans";

        _historyGrid.SuspendLayout();
        _historyGrid.Rows.Clear();

        int selectRow = -1;
        for (int i = 0; i < _displayedRecords.Count; i++)
        {
            ScanRecord rec = _displayedRecords[i];
            string localTime = rec.ScannedAtUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");
            string riskText = FileRiskClassifier.GetCategoryLabel(rec.RiskCategory);
            string verdictText = FormatVerdictLabel(rec.Verdict);
            string detectionsText = rec.TotalEngines > 0 ? $"{rec.MaliciousCount}/{rec.TotalEngines}" : "-";
            string sourceText = FormatSourceLabel(rec);
            string detailText = rec.DetectionNames.Count > 0
                ? string.Join("; ", rec.DetectionNames)
                : rec.Summary;

            int rowIdx = _historyGrid.Rows.Add(localTime, rec.FileName, riskText, verdictText, detectionsText, sourceText, detailText);
            if (selectedId.HasValue && rec.Id == selectedId.Value)
            {
                selectRow = rowIdx;
            }
        }

        if (selectRow >= 0 && selectRow < _historyGrid.Rows.Count)
        {
            _historyGrid.Rows[selectRow].Selected = true;
        }
        else if (_historyGrid.Rows.Count > 0)
        {
            _historyGrid.Rows[0].Selected = true;
        }

        _historyGrid.ResumeLayout();
        UpdateHistorySelectionDetails();
    }

    private void OnHistoryGridCellPainting(object? sender, DataGridViewCellPaintingEventArgs e)
    {
        if (e.RowIndex < 0 || e.RowIndex >= _displayedRecords.Count)
        {
            return;
        }

        ScanRecord rec = _displayedRecords[e.RowIndex];
        if (e.ColumnIndex == 2)
        {
            var (bg, fg) = _palette.GetRiskColors(rec.RiskCategory);
            ModernGridHelper.DrawPillCell(e, FileRiskClassifier.GetCategoryLabel(rec.RiskCategory), bg, fg, _pillFont, _palette);
        }
        else if (e.ColumnIndex == 3)
        {
            var (bg, fg) = _palette.GetVerdictColors(rec.Verdict);
            ModernGridHelper.DrawPillCell(e, FormatVerdictLabel(rec.Verdict), bg, fg, _pillFont, _palette);
        }
        else if (e.ColumnIndex == 4)
        {
            string text = rec.TotalEngines > 0 ? $"{rec.MaliciousCount}/{rec.TotalEngines}" : "-";
            Color bg = rec.MaliciousCount >= _engine.CurrentSettings.MaliciousThreshold
                ? _palette.DangerBg
                : rec.MaliciousCount > 0 || rec.SuspiciousCount > 0
                    ? _palette.WarningBg
                    : rec.TotalEngines > 0
                        ? _palette.SuccessBg
                        : _palette.NeutralBg;
            Color fg = rec.MaliciousCount >= _engine.CurrentSettings.MaliciousThreshold
                ? _palette.DangerRed
                : rec.MaliciousCount > 0 || rec.SuspiciousCount > 0
                    ? _palette.WarningAmber
                    : rec.TotalEngines > 0
                        ? _palette.SuccessGreen
                        : _palette.NeutralSlate;
            ModernGridHelper.DrawPillCell(e, text, bg, fg, _pillFont, _palette);
        }
    }

    private static string FormatVerdictLabel(ScanVerdict verdict) => verdict switch
    {
        ScanVerdict.Unsafe => "Unsafe",
        ScanVerdict.LowRisk => "Low Risk",
        ScanVerdict.Clean => "Clean",
        ScanVerdict.Unknown => "Unknown",
        ScanVerdict.Skipped => "Skipped",
        ScanVerdict.Error => "Error",
        _ => verdict.ToString()
    };

    private static string FormatSourceLabel(ScanRecord rec)
    {
        string svc = string.IsNullOrWhiteSpace(rec.SourceService) ? "VirusTotal" : rec.SourceService;
        if (rec.FromCache)
        {
            return $"Cache ({svc})";
        }

        return rec.Uploaded ? $"{svc} (Upload)" : svc;
    }

    private ScanRecord? GetSelectedScanRecord()
    {
        if (_historyGrid.SelectedRows.Count == 0)
        {
            return null;
        }

        int idx = _historyGrid.SelectedRows[0].Index;
        return idx >= 0 && idx < _displayedRecords.Count ? _displayedRecords[idx] : null;
    }

    private void UpdateHistorySelectionDetails()
    {
        ScanRecord? rec = GetSelectedScanRecord();
        if (rec is null)
        {
            _detailFileLabel.Text = "Select a scanned file above to inspect its hash, risk classification, and report options.";
            _detailShaLabel.Text = string.Empty;
            _detailMetaLabel.Text = string.Empty;
            _openReportBtn.Enabled = false;
            _openLocationBtn.Enabled = false;
            _scanOnVtBtn.Enabled = false;
            _uploadSelectedBtn.Enabled = false;
            return;
        }

        bool fileExists = !string.IsNullOrWhiteSpace(rec.FilePath) && File.Exists(rec.FilePath);
        _detailFileLabel.Text = $"File: {rec.FilePath}";
        _detailShaLabel.Text = string.IsNullOrWhiteSpace(rec.Sha256)
            ? "SHA-256: (not computed)"
            : $"SHA-256: {rec.Sha256}";

        string signerPart = string.IsNullOrWhiteSpace(rec.SignerName) ? "Unsigned" : $"Signed by {rec.SignerName}";
        string riskPart = string.IsNullOrWhiteSpace(rec.RiskReason)
            ? FileRiskClassifier.GetCategoryLabel(rec.RiskCategory)
            : $"{FileRiskClassifier.GetCategoryLabel(rec.RiskCategory)} ({rec.RiskReason})";
        _detailMetaLabel.Text = $"Risk: {riskPart}  |  Signature: {signerPart}  |  Size: {FormatBytes(rec.FileSizeBytes)}";

        _openReportBtn.Enabled = !string.IsNullOrWhiteSpace(rec.EffectiveReportUrl);
        _openLocationBtn.Enabled = fileExists;
        _scanOnVtBtn.Enabled = fileExists && _engine.HasApiKey;
        _uploadSelectedBtn.Enabled = fileExists && _engine.HasApiKey && rec.Verdict == ScanVerdict.Unknown;
    }

    private void RefreshQueueGrid()
    {
        IReadOnlyList<QueuedScanItem> snapshot = _engine.GetQueueSnapshot();
        string? selectedPath = GetSelectedQueueItem()?.FilePath;

        _displayedQueue.Clear();
        _displayedQueue.AddRange(snapshot);

        int scanningCount = snapshot.Count(i => i.State == "Scanning");
        int queuedCount = snapshot.Count(i => i.State == "Queued");
        int waitingCount = snapshot.Count(i => i.State == "Waiting for file");
        _queueCountSummaryLabel.Text = snapshot.Count == 0
            ? "Queue is empty"
            : $"{scanningCount} scanning, {queuedCount} queued, {waitingCount} stabilizing";

        _queueGrid.SuspendLayout();
        _queueGrid.Rows.Clear();

        int priorityPos = 1;
        int selectRow = -1;
        for (int i = 0; i < _displayedQueue.Count; i++)
        {
            QueuedScanItem item = _displayedQueue[i];
            string priorityText = item.State switch
            {
                "Scanning" => "Active",
                "Queued" => $"#{priorityPos++}",
                _ => "Pending"
            };

            string folder = Path.GetDirectoryName(item.FilePath) ?? item.FilePath;
            int rowIdx = _queueGrid.Rows.Add(
                priorityText,
                item.State,
                item.FileName,
                FileRiskClassifier.GetCategoryLabel(item.RiskCategory),
                item.RiskReason,
                FormatBytes(item.FileSizeBytes),
                folder);

            if (selectedPath is not null && string.Equals(item.FilePath, selectedPath, StringComparison.OrdinalIgnoreCase))
            {
                selectRow = rowIdx;
            }
        }

        if (selectRow >= 0 && selectRow < _queueGrid.Rows.Count)
        {
            _queueGrid.Rows[selectRow].Selected = true;
        }
        else if (_queueGrid.Rows.Count > 0)
        {
            _queueGrid.Rows[0].Selected = true;
        }

        _queueGrid.ResumeLayout();
        UpdateQueueButtons();
    }

    private void OnQueueGridCellPainting(object? sender, DataGridViewCellPaintingEventArgs e)
    {
        if (e.RowIndex < 0 || e.RowIndex >= _displayedQueue.Count)
        {
            return;
        }

        QueuedScanItem item = _displayedQueue[e.RowIndex];
        if (e.ColumnIndex == 1)
        {
            (Color bg, Color fg) = item.State switch
            {
                "Scanning" => (_palette.AccentBlueBg, _palette.AccentBlue),
                "Queued" => (_palette.NeutralBg, _palette.TextPrimary),
                _ => (_palette.WarningBg, _palette.WarningAmber)
            };
            ModernGridHelper.DrawPillCell(e, item.State, bg, fg, _pillFont, _palette);
        }
        else if (e.ColumnIndex == 3)
        {
            var (bg, fg) = _palette.GetRiskColors(item.RiskCategory);
            ModernGridHelper.DrawPillCell(e, FileRiskClassifier.GetCategoryLabel(item.RiskCategory), bg, fg, _pillFont, _palette);
        }
    }

    private QueuedScanItem? GetSelectedQueueItem()
    {
        if (_queueGrid.SelectedRows.Count == 0)
        {
            return null;
        }

        int idx = _queueGrid.SelectedRows[0].Index;
        return idx >= 0 && idx < _displayedQueue.Count ? _displayedQueue[idx] : null;
    }

    private void UpdateQueueButtons()
    {
        QueuedScanItem? item = GetSelectedQueueItem();
        bool canModifyItem = item is not null && item.State == "Queued";
        _promoteQueueBtn.Enabled = canModifyItem;
        _removeQueueBtn.Enabled = canModifyItem;
        _clearQueueBtn.Enabled = _engine.QueuedCount > 0;
    }

    private void RefreshDirectoriesGrid()
    {
        AppSettings settings = _engine.CurrentSettings;
        IReadOnlyDictionary<string, string> statuses = _engine.GetDirectoryStatuses();
        string? selectedPath = GetSelectedDirectory()?.Path;

        _displayedDirs.Clear();
        _displayedDirs.AddRange(settings.WatchedDirectories);

        _directoriesGrid.SuspendLayout();
        _directoriesGrid.Rows.Clear();

        int selectRow = -1;
        for (int i = 0; i < _displayedDirs.Count; i++)
        {
            WatchedDirectory dir = _displayedDirs[i];
            string status = statuses.TryGetValue(dir.Path, out string? st) ? st : "Unknown";
            int rowIdx = _directoriesGrid.Rows.Add(
                dir.Path,
                dir.IncludeSubdirectories ? "Yes" : "No",
                dir.Enabled ? "Yes" : "No",
                status);
            if (selectedPath is not null && string.Equals(dir.Path, selectedPath, StringComparison.OrdinalIgnoreCase))
            {
                selectRow = rowIdx;
            }
        }

        if (selectRow >= 0 && selectRow < _directoriesGrid.Rows.Count)
        {
            _directoriesGrid.Rows[selectRow].Selected = true;
        }
        else if (_directoriesGrid.Rows.Count > 0)
        {
            _directoriesGrid.Rows[0].Selected = true;
        }

        _directoriesGrid.ResumeLayout();
        UpdateDirectoryButtons();
    }

    private void OnDirectoryGridCellPainting(object? sender, DataGridViewCellPaintingEventArgs e)
    {
        if (e.RowIndex < 0 || e.RowIndex >= _displayedDirs.Count || e.ColumnIndex != 3)
        {
            return;
        }

        string status = _directoriesGrid.Rows[e.RowIndex].Cells[3].Value?.ToString() ?? "Unknown";
        (Color bg, Color fg) = status switch
        {
            "Watching" => (_palette.SuccessBg, _palette.SuccessGreen),
            "Folder not found" => (_palette.DangerBg, _palette.DangerRed),
            "Watcher error (retrying)" => (_palette.WarningBg, _palette.WarningAmber),
            _ => (_palette.NeutralBg, _palette.NeutralSlate)
        };

        ModernGridHelper.DrawPillCell(e, status, bg, fg, _pillFont, _palette);
    }

    private WatchedDirectory? GetSelectedDirectory()
    {
        if (_directoriesGrid.SelectedRows.Count == 0)
        {
            return null;
        }

        int idx = _directoriesGrid.SelectedRows[0].Index;
        return idx >= 0 && idx < _displayedDirs.Count ? _displayedDirs[idx] : null;
    }

    private void UpdateDirectoryButtons()
    {
        WatchedDirectory? dir = GetSelectedDirectory();
        bool hasSelection = dir is not null;
        _removeDirBtn.Enabled = hasSelection;
        _toggleSubfoldersBtn.Enabled = hasSelection;
        _toggleEnabledBtn.Enabled = hasSelection;
        _openDirBtn.Enabled = hasSelection && Directory.Exists(dir!.Path);
    }

    private void RefreshApiRateWindowOnly()
    {
        RateLimiterSnapshot snap = _engine.GetRateLimiterSnapshot();
        string note;
        if (snap.CooldownRemaining > TimeSpan.Zero)
        {
            note = $" (429 cooldown: {snap.CooldownRemaining.TotalSeconds:F0}s)";
        }
        else if (snap.NextSlotIn > TimeSpan.Zero)
        {
            note = $" (next slot in {snap.NextSlotIn.TotalSeconds:F0}s)";
        }
        else
        {
            note = " (ready)";
        }

        _minuteQuotaValueLabel.Text = $"{snap.RequestsInWindow} / {snap.MaxRequestsPerWindow} in {snap.WindowSeconds:F0}s{note}";
        _minuteQuotaBar.Maximum = Math.Max(1, snap.MaxRequestsPerWindow);
        _minuteQuotaBar.Value = snap.RequestsInWindow;
        _minuteQuotaBar.ForceNeutral = false;
    }

    private void RefreshApiTab()
    {
        RefreshApiRateWindowOnly();

        DailyUsageSnapshot daily = _engine.GetDailyUsageSnapshot();
        VtUserQuotaInfo? vtQuota = _engine.LastFetchedQuota;

        if (!_engine.HasApiKey)
        {
            _vtAccountLabel.Text = "Account: VirusTotal API key not configured";
            _vtFetchedAtLabel.Text = "Not fetched";
            _hourlyQuotaValueLabel.Text = "Not available";
            _hourlyQuotaBar.Maximum = 100;
            _hourlyQuotaBar.Value = 0;
            _hourlyQuotaBar.ForceNeutral = true;

            _dailyQuotaValueLabel.Text = $"{daily.DailyVtRequests} local requests today";
            _dailyQuotaBar.Maximum = 500;
            _dailyQuotaBar.Value = daily.DailyVtRequests;
            _dailyQuotaBar.ForceNeutral = true;

            _monthlyQuotaValueLabel.Text = "Not available";
            _monthlyQuotaBar.Maximum = 100;
            _monthlyQuotaBar.Value = 0;
            _monthlyQuotaBar.ForceNeutral = true;

            _vtQuotaStatusLabel.Text = "Add a VirusTotal API key in Settings to query live account quotas.";
            _vtQuotaStatusLabel.ForeColor = _palette.TextSecondary;
        }
        else if (vtQuota is not null && vtQuota.Success)
        {
            _vtAccountLabel.Text = string.IsNullOrWhiteSpace(vtQuota.UserId)
                ? "Account: Connected"
                : $"Account ID: {vtQuota.UserId}";
            _vtFetchedAtLabel.Text = $"Last refreshed: {vtQuota.FetchedAtUtc.ToLocalTime():HH:mm:ss}";

            SetQuotaDisplay(_hourlyQuotaValueLabel, _hourlyQuotaBar, vtQuota.Hourly);
            SetQuotaDisplay(_dailyQuotaValueLabel, _dailyQuotaBar, vtQuota.Daily);
            SetQuotaDisplay(_monthlyQuotaValueLabel, _monthlyQuotaBar, vtQuota.Monthly);

            _vtQuotaStatusLabel.Text = $"Local tracker today ({daily.QuotaDateUtc:yyyy-MM-dd}): {daily.DailyVtRequests} VirusTotal request(s) sent from this PC.";
            _vtQuotaStatusLabel.ForeColor = _palette.TextSecondary;
        }
        else
        {
            _vtAccountLabel.Text = "Account: API key configured";
            _vtFetchedAtLabel.Text = vtQuota is null ? "Not fetched yet" : $"Last attempt: {vtQuota.FetchedAtUtc.ToLocalTime():HH:mm:ss}";

            _hourlyQuotaValueLabel.Text = "Click Refresh from VirusTotal";
            _hourlyQuotaBar.Maximum = 100;
            _hourlyQuotaBar.Value = 0;
            _hourlyQuotaBar.ForceNeutral = true;

            _dailyQuotaValueLabel.Text = $"{daily.DailyVtRequests} / 500 (local count today)";
            _dailyQuotaBar.Maximum = 500;
            _dailyQuotaBar.Value = daily.DailyVtRequests;
            _dailyQuotaBar.ForceNeutral = false;

            _monthlyQuotaValueLabel.Text = "Click Refresh from VirusTotal";
            _monthlyQuotaBar.Maximum = 100;
            _monthlyQuotaBar.Value = 0;
            _monthlyQuotaBar.ForceNeutral = true;

            if (vtQuota is not null && !string.IsNullOrWhiteSpace(vtQuota.ErrorMessage))
            {
                _vtQuotaStatusLabel.Text = vtQuota.ErrorMessage;
                _vtQuotaStatusLabel.ForeColor = _palette.WarningAmber;
            }
            else
            {
                _vtQuotaStatusLabel.Text = "Click Refresh from VirusTotal to load hourly, daily, and monthly account quotas.";
                _vtQuotaStatusLabel.ForeColor = _palette.TextSecondary;
            }
        }

        _cacheCountValueLabel.Text = _engine.GetCacheCount().ToString("N0");
        _cacheHitsValueLabel.Text = daily.DailyCacheHits.ToString("N0");
        _secondarySavedValueLabel.Text = daily.DailySecondarySavedCalls.ToString("N0");

        IReadOnlyList<SecondaryServiceStats> services = _engine.GetSecondaryServiceStatuses();
        _secondaryGrid.SuspendLayout();
        _secondaryGrid.Rows.Clear();
        foreach (SecondaryServiceStats svc in services)
        {
            string enabledText = svc.Enabled ? "Enabled" : "Disabled";
            string keyText = !svc.RequiresApiKey
                ? "Not required"
                : svc.HasApiKey
                    ? "Configured"
                    : "Missing";
            _secondaryGrid.Rows.Add(
                svc.Name,
                enabledText,
                keyText,
                svc.RequestsToday.ToString("N0"),
                svc.HitsToday.ToString("N0"),
                svc.LastStatus);
        }

        _secondaryGrid.ResumeLayout();
    }

    private static void SetQuotaDisplay(Label valueLabel, ModernProgressBar bar, VtQuotaBucket bucket)
    {
        if (bucket.Allowed <= 0)
        {
            valueLabel.Text = $"{bucket.Used:N0} used (no limit reported)";
            bar.Maximum = 100;
            bar.Value = 0;
            bar.ForceNeutral = true;
            return;
        }

        long remaining = Math.Max(0, bucket.Allowed - bucket.Used);
        double pct = (double)bucket.Used * 100.0 / bucket.Allowed;
        valueLabel.Text = $"{bucket.Used:N0} / {bucket.Allowed:N0} ({pct:F1}%, {remaining:N0} left)";
        bar.Maximum = bucket.Allowed;
        bar.Value = bucket.Used;
        bar.ForceNeutral = false;
    }

    private void MaybeAutoFetchQuota()
    {
        if (_quotaFetchInFlight || !_engine.HasApiKey)
        {
            return;
        }

        VtUserQuotaInfo? last = _engine.LastFetchedQuota;
        if (last is null || !last.Success || (DateTimeOffset.UtcNow - last.FetchedAtUtc) > TimeSpan.FromMinutes(5))
        {
            _ = RefreshVirusTotalQuotaAsync();
        }
    }

    private async Task RefreshVirusTotalQuotaAsync()
    {
        if (_quotaFetchInFlight)
        {
            return;
        }

        _quotaFetchInFlight = true;
        _refreshQuotaBtn.Enabled = false;
        _refreshQuotaBtn.Text = "Refreshing...";
        _vtQuotaStatusLabel.Text = "Querying VirusTotal user quota endpoint...";
        _vtQuotaStatusLabel.ForeColor = _palette.TextSecondary;

        try
        {
            _ = await _engine.FetchVirusTotalQuotaAsync();
        }
        finally
        {
            _quotaFetchInFlight = false;
            if (!IsDisposed)
            {
                _refreshQuotaBtn.Enabled = true;
                _refreshQuotaBtn.Text = "Refresh from VirusTotal";
                RefreshApiTab();
            }
        }
    }

    private void OpenSelectedReport()
    {
        ScanRecord? rec = GetSelectedScanRecord();
        string? url = rec?.EffectiveReportUrl;
        if (!string.IsNullOrWhiteSpace(url))
        {
            OpenUrl(url);
        }
    }

    private void OpenSelectedFileLocation()
    {
        ScanRecord? rec = GetSelectedScanRecord();
        if (rec is null || !File.Exists(rec.FilePath))
        {
            return;
        }

        try
        {
            Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{rec.FilePath}\"")
            {
                UseShellExecute = true
            });
        }
        catch (Exception ex)
        {
            _logger.Warn($"Failed to open file location: {ex.Message}");
        }
    }

    private void RescanSelectedOnVirusTotal()
    {
        ScanRecord? rec = GetSelectedScanRecord();
        if (rec is not null && File.Exists(rec.FilePath))
        {
            _engine.RescanOnVirusTotal(rec);
        }
    }

    private void UploadSelectedRecord()
    {
        ScanRecord? rec = GetSelectedScanRecord();
        if (rec is not null && File.Exists(rec.FilePath))
        {
            _engine.ManualUploadRecord(rec);
        }
    }

    private void PromptManualFileScan()
    {
        using var dialog = new OpenFileDialog
        {
            Title = "Select a file to scan",
            CheckFileExists = true
        };
        if (dialog.ShowDialog(this) == DialogResult.OK)
        {
            _engine.EnqueueFile(dialog.FileName, manual: true);
        }
    }

    private void AddWatchedFolder()
    {
        using var dialog = new FolderBrowserDialog
        {
            Description = "Select a directory to monitor automatically",
            ShowNewFolderButton = true
        };

        if (dialog.ShowDialog(this) != DialogResult.OK || string.IsNullOrWhiteSpace(dialog.SelectedPath))
        {
            return;
        }

        AppSettings settings = _engine.CurrentSettings;
        if (settings.WatchedDirectories.Any(d => string.Equals(d.Path, dialog.SelectedPath, StringComparison.OrdinalIgnoreCase)))
        {
            MessageBox.Show(this, "That directory is already in the watched list.", "Already Watched",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        settings.WatchedDirectories.Add(new WatchedDirectory
        {
            Path = dialog.SelectedPath,
            IncludeSubdirectories = true,
            Enabled = true
        });
        _engine.ApplySettings(settings);
        RefreshDirectoriesGrid();
    }

    private void RemoveSelectedFolder()
    {
        WatchedDirectory? dir = GetSelectedDirectory();
        if (dir is null)
        {
            return;
        }

        AppSettings settings = _engine.CurrentSettings;
        settings.WatchedDirectories.RemoveAll(d => string.Equals(d.Path, dir.Path, StringComparison.OrdinalIgnoreCase));
        _engine.ApplySettings(settings);
        RefreshDirectoriesGrid();
    }

    private void ToggleSelectedDirectorySubfolders()
    {
        WatchedDirectory? dir = GetSelectedDirectory();
        if (dir is null)
        {
            return;
        }

        AppSettings settings = _engine.CurrentSettings;
        WatchedDirectory? match = settings.WatchedDirectories.FirstOrDefault(d =>
            string.Equals(d.Path, dir.Path, StringComparison.OrdinalIgnoreCase));
        if (match is not null)
        {
            match.IncludeSubdirectories = !match.IncludeSubdirectories;
            _engine.ApplySettings(settings);
            RefreshDirectoriesGrid();
        }
    }

    private void ToggleSelectedDirectoryEnabled()
    {
        WatchedDirectory? dir = GetSelectedDirectory();
        if (dir is null)
        {
            return;
        }

        AppSettings settings = _engine.CurrentSettings;
        WatchedDirectory? match = settings.WatchedDirectories.FirstOrDefault(d =>
            string.Equals(d.Path, dir.Path, StringComparison.OrdinalIgnoreCase));
        if (match is not null)
        {
            match.Enabled = !match.Enabled;
            _engine.ApplySettings(settings);
            RefreshDirectoriesGrid();
        }
    }

    private void OpenSelectedDirectoryInExplorer()
    {
        WatchedDirectory? dir = GetSelectedDirectory();
        if (dir is not null && Directory.Exists(dir.Path))
        {
            OpenFolder(dir.Path);
        }
    }

    private void LoadSettingsIntoControls()
    {
        AppSettings s = _engine.CurrentSettings;
        _themeCombo.SelectedIndex = Math.Clamp((int)s.ThemeMode, 0, _themeCombo.Items.Count - 1);
        _startupCheckBox.Checked = StartupManager.IsStartupEnabled() || s.StartWithWindows;

        _apiKeyTextBox.Text = SettingsStore.GetDecryptedApiKey(s);
        _uploadPolicyCombo.SelectedIndex = Math.Clamp((int)s.UploadPolicy, 0, _uploadPolicyCombo.Items.Count - 1);
        _filterModeCombo.SelectedIndex = Math.Clamp((int)s.FilterMode, 0, _filterModeCombo.Items.Count - 1);
        _uploadExtTextBox.Text = string.Join(", ", s.UploadExtensions);
        _archiveExtTextBox.Text = string.Join(", ", s.ArchiveExtensions);
        _thresholdSlider.Value = Math.Clamp(s.MaliciousThreshold, ModernThresholdSlider.MinThreshold, ModernThresholdSlider.MaxThreshold);
        UpdateThresholdDescriptionLabel(_thresholdDescLabel, _thresholdSlider.Value);
        _rateLimitNumeric.Value = Math.Clamp(s.MaxRequestsPerMinute, (int)_rateLimitNumeric.Minimum, (int)_rateLimitNumeric.Maximum);
        _maxUploadMbNumeric.Value = Math.Clamp(s.MaxUploadSizeMb, (int)_maxUploadMbNumeric.Minimum, (int)_maxUploadMbNumeric.Maximum);
        _maxHashMbNumeric.Value = Math.Clamp(s.MaxHashSizeMb, (int)_maxHashMbNumeric.Minimum, (int)_maxHashMbNumeric.Maximum);
        UpdateVirusTotalLimitWarnings();

        _secondaryLowerRiskOnlyCheckBox.Checked = s.SecondaryLookupsLowerRiskOnly;
        _enableCirclCheckBox.Checked = s.EnableCirclHashlookup;
        _enableMetaDefenderCheckBox.Checked = s.EnableMetaDefender;
        _metaDefenderKeyBox.Text = SettingsStore.GetDecryptedMetaDefenderApiKey(s);
        _enableMalwareBazaarCheckBox.Checked = s.EnableMalwareBazaar;
        _malwareBazaarKeyBox.Text = SettingsStore.GetDecryptedMalwareBazaarApiKey(s);

        _autoUpdateModeCombo.SelectedIndex = !s.AutoUpdateEnabled
            ? 0
            : s.AutoUpdateCriticalOnly
                ? 1
                : 2;
        UpdateRecommendedStarIndicators();
        RefreshUpdateUiFromLatest();
    }

    private void SaveSettingsFromForm()
    {
        AppSettings settings = _engine.CurrentSettings;
        settings.ThemeMode = (AppThemeMode)Math.Clamp(_themeCombo.SelectedIndex, 0, 2);
        settings.StartWithWindows = _startupCheckBox.Checked;
        switch (_autoUpdateModeCombo.SelectedIndex)
        {
            case 0:
                settings.AutoUpdateEnabled = false;
                settings.AutoUpdateCriticalOnly = false;
                break;
            case 2:
                settings.AutoUpdateEnabled = true;
                settings.AutoUpdateCriticalOnly = false;
                break;
            default:
                settings.AutoUpdateEnabled = true;
                settings.AutoUpdateCriticalOnly = true;
                break;
        }

        SettingsStore.SetApiKey(settings, _apiKeyTextBox.Text);
        settings.UploadPolicy = (UploadPolicy)Math.Clamp(_uploadPolicyCombo.SelectedIndex, 0, 2);
        settings.FilterMode = (FileFilterMode)Math.Clamp(_filterModeCombo.SelectedIndex, 0, 1);
        settings.UploadExtensions = SettingsStore.NormalizeExtensions(
            _uploadExtTextBox.Text.Split([',', ';', ' '], StringSplitOptions.RemoveEmptyEntries));
        settings.ArchiveExtensions = SettingsStore.NormalizeExtensions(
            _archiveExtTextBox.Text.Split([',', ';', ' '], StringSplitOptions.RemoveEmptyEntries));
        settings.MaliciousThreshold = _thresholdSlider.Value;
        settings.MaxRequestsPerMinute = (int)_rateLimitNumeric.Value;
        settings.MaxUploadSizeMb = (int)_maxUploadMbNumeric.Value;
        settings.MaxHashSizeMb = (int)_maxHashMbNumeric.Value;

        settings.SecondaryLookupsLowerRiskOnly = _secondaryLowerRiskOnlyCheckBox.Checked;
        settings.EnableCirclHashlookup = _enableCirclCheckBox.Checked;
        settings.EnableMetaDefender = _enableMetaDefenderCheckBox.Checked;
        SettingsStore.SetMetaDefenderApiKey(settings, _metaDefenderKeyBox.Text);
        settings.EnableMalwareBazaar = _enableMalwareBazaarCheckBox.Checked;
        SettingsStore.SetMalwareBazaarApiKey(settings, _malwareBazaarKeyBox.Text);

        _engine.ApplySettings(settings);

        try
        {
            StartupManager.SetStartupEnabled(settings.StartWithWindows);
        }
        catch (Exception ex)
        {
            _logger.Warn($"Failed updating Windows startup entry: {ex.Message}");
        }

        ThemePalette resolved = ThemePalette.Resolve(settings.ThemeMode);
        ApplyTheme(resolved);

        _saveConfirmLabel.ForeColor = resolved.SuccessGreen;
        _saveConfirmLabel.Text = "Settings saved.";
    }

    private void ResetSettingsToDefaults()
    {
        DialogResult confirm = MessageBox.Show(
            this,
            "Reset all settings on this page to their recommended default values? Your saved API keys and watched directories will be kept.",
            "Reset Settings to Defaults",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Question,
            MessageBoxDefaultButton.Button2);

        if (confirm != DialogResult.Yes)
        {
            return;
        }

        AppSettings settings = _engine.CurrentSettings;
        settings.ResetPreferencesToDefaults();
        _engine.ApplySettings(settings);

        try
        {
            StartupManager.SetStartupEnabled(settings.StartWithWindows);
        }
        catch (Exception ex)
        {
            _logger.Warn($"Failed resetting Windows startup entry: {ex.Message}");
        }

        LoadSettingsIntoControls();
        ThemePalette resolved = ThemePalette.Resolve(settings.ThemeMode);
        ApplyTheme(resolved);

        _saveConfirmLabel.ForeColor = resolved.SuccessGreen;
        _saveConfirmLabel.Text = "Settings reset to recommended defaults.";
    }

    public static (string RateLimitWarning, string MaxUploadWarning, string MaxHashWarning, bool MaxHashIsWarning)
        EvaluateVirusTotalLimitWarnings(int rateLimitPerMinute, int maxUploadSizeMb, int maxHashSizeMb)
    {
        string rateLimitWarning = rateLimitPerMinute > 4
            ? "Warning: Exceeds the free VirusTotal API limit (4 requests/minute). Higher values require a paid API key and may cause HTTP 429 rate-limit errors."
            : string.Empty;

        string maxUploadWarning = maxUploadSizeMb > 32
            ? "Warning: Exceeds VirusTotal's standard 32 MB direct upload limit. Larger uploads (up to 650 MB) require an extra upload URL request, use more free API quota, and may fail or time out."
            : string.Empty;

        string maxHashWarning = string.Empty;
        bool maxHashIsWarning = false;
        if (maxHashSizeMb == 0 || maxHashSizeMb > 2048)
        {
            maxHashIsWarning = true;
            maxHashWarning = "Warning: Hashing files above 2048 MB (or unlimited) can cause heavy disk and CPU usage. VirusTotal also cannot accept file uploads over 32 MB directly (650 MB max); larger files are checked by hash only.";
        }
        else if (maxHashSizeMb > 650)
        {
            maxHashIsWarning = false;
            maxHashWarning = "Files larger than your upload limit are checked by local SHA-256 hash only (VirusTotal caps file uploads at 32 MB direct / 650 MB max).";
        }

        return (rateLimitWarning, maxUploadWarning, maxHashWarning, maxHashIsWarning);
    }

    private void UpdateVirusTotalLimitWarnings()
    {
        var (rateWarning, uploadWarning, hashWarning, hashIsWarning) = EvaluateVirusTotalLimitWarnings(
            (int)_rateLimitNumeric.Value,
            (int)_maxUploadMbNumeric.Value,
            (int)_maxHashMbNumeric.Value);

        ApplyLimitNotice(_rateLimitWarningLabel, rateWarning, isWarning: true);
        ApplyLimitNotice(_maxUploadWarningLabel, uploadWarning, isWarning: true);
        ApplyLimitNotice(_maxHashWarningLabel, hashWarning, isWarning: hashIsWarning);
    }

    private void ApplyLimitNotice(Label label, string text, bool isWarning)
    {
        bool hasText = !string.IsNullOrWhiteSpace(text);
        label.Visible = hasText;
        label.Text = text;
        if (hasText)
        {
            label.ForeColor = isWarning ? _palette.WarningAmber : _palette.TextSecondary;
        }
    }

    private void UpdateRecommendedStarIndicators()
    {
        foreach (var (indicator, isRecommended) in _recommendedIndicators)
        {
            indicator.IsAtRecommended = isRecommended();
        }
    }

    public (int HeaderBottom, int NavTop, int SubtitleBottom, int HeaderHeight, int ScanBtnBottom) GetHeaderLayoutMetricsForTest()
    {
        static int BottomRelativeTo(Control child, Control ancestor)
        {
            int y = child.Bottom;
            Control? current = child.Parent;
            while (current is not null && current != ancestor)
            {
                y += current.Top;
                current = current.Parent;
            }

            return y;
        }

        return (
            _headerPanel.Bottom,
            _navBar.Top,
            BottomRelativeTo(_subtitleLabel, _headerPanel),
            _headerPanel.Height,
            BottomRelativeTo(_headerScanBtn, _headerPanel));
    }

    private void OnUpdateStatusChanged(UpdateCheckResult result)
    {
        if (IsDisposed || !IsHandleCreated)
        {
            return;
        }

        BeginInvoke(() =>
        {
            if (!IsDisposed)
            {
                RefreshUpdateUiFromLatest();
            }
        });
    }

    private void RefreshUpdateUiFromLatest()
    {
        UpdateCheckResult? latest = _updateService.LatestCheckResult;
        if (latest is null)
        {
            _headerUpdateBtn.Visible = false;
            _installUpdateBtn.Enabled = false;
            _updateReleaseLink.Visible = false;
            _latestReleaseUrl = string.Empty;
            _updateStatusLabel.ForeColor = _palette.TextSecondary;
            _updateStatusLabel.Text = _autoUpdateModeCombo.SelectedIndex switch
            {
                0 => "Automatic updates are turned off (manual checks only). Click Check for Updates to query GitHub.",
                2 => "Automatic updates enabled for all releases. Click Check for Updates to check right now.",
                _ => "Critical automatic updates enabled. Click Check for Updates to check right now."
            };
            return;
        }

        _latestReleaseUrl = latest.ReleaseHtmlUrl;
        _updateReleaseLink.Visible = !string.IsNullOrWhiteSpace(_latestReleaseUrl);

        if (!latest.Success)
        {
            _headerUpdateBtn.Visible = false;
            _installUpdateBtn.Enabled = false;
            _updateStatusLabel.ForeColor = _palette.WarningAmber;
            _updateStatusLabel.Text = latest.ErrorMessage;
            return;
        }

        if (latest.UpdateAvailable)
        {
            string tag = string.IsNullOrWhiteSpace(latest.TagName)
                ? $"v{latest.LatestVersion?.ToString(3)}"
                : latest.TagName;
            string critTag = latest.IsCritical ? " [Critical]" : string.Empty;
            _headerUpdateBtn.Text = $"Update {tag}";
            _headerUpdateBtn.Visible = true;
            _installUpdateBtn.Enabled = !_updateActionInFlight;
            _updateStatusLabel.ForeColor = latest.IsCritical ? _palette.WarningAmber : _palette.SuccessGreen;
            _updateStatusLabel.Text = $"New version available: {tag}{critTag} ({latest.AssetName}). Your settings and history will be preserved.";
            return;
        }

        _headerUpdateBtn.Visible = false;
        _installUpdateBtn.Enabled = false;
        _updateStatusLabel.ForeColor = _palette.SuccessGreen;
        _updateStatusLabel.Text = $"Up to date (v{_updateService.CurrentVersion.ToString(3)} checked at {latest.CheckedAtUtc.ToLocalTime():HH:mm:ss}).";
    }

    private async Task CheckForUpdatesAsync()
    {
        if (_updateActionInFlight)
        {
            return;
        }

        _updateActionInFlight = true;
        _checkUpdatesBtn.Enabled = false;
        _installUpdateBtn.Enabled = false;
        _updateStatusLabel.ForeColor = _palette.TextSecondary;
        _updateStatusLabel.Text = "Checking GitHub for the latest release...";
        try
        {
            _ = await _updateService.CheckForUpdatesAsync(_engine.CurrentSettings);
        }
        finally
        {
            _updateActionInFlight = false;
            if (!IsDisposed)
            {
                _checkUpdatesBtn.Enabled = true;
                RefreshUpdateUiFromLatest();
            }
        }
    }

    private async Task InstallUpdateAsync()
    {
        UpdateCheckResult? latest = _updateService.LatestCheckResult;
        if (latest is null || !latest.Success || !latest.UpdateAvailable || _updateActionInFlight)
        {
            return;
        }

        _updateActionInFlight = true;
        _checkUpdatesBtn.Enabled = false;
        _installUpdateBtn.Enabled = false;
        _updateProgressBar.Value = 0;
        _updateProgressBar.Visible = true;
        _updateStatusLabel.ForeColor = _palette.TextSecondary;
        _updateStatusLabel.Text = "Preparing update...";

        try
        {
            var (started, message) = await _updateService.DownloadAndApplyUpdateAsync(
                latest,
                openDashboardAfterUpdate: true,
                (stage, pct) =>
                {
                    if (!IsDisposed && IsHandleCreated)
                    {
                        BeginInvoke(() =>
                        {
                            if (!IsDisposed)
                            {
                                _updateStatusLabel.Text = stage;
                                _updateProgressBar.Value = pct;
                            }
                        });
                    }
                },
                _requestShutdownForUpdate);

            if (!started && !IsDisposed)
            {
                _updateProgressBar.Visible = false;
                _updateStatusLabel.ForeColor = _palette.DangerRed;
                _updateStatusLabel.Text = message;
            }
        }
        finally
        {
            _updateActionInFlight = false;
            if (!IsDisposed)
            {
                _checkUpdatesBtn.Enabled = true;
                _installUpdateBtn.Enabled = _updateService.LatestCheckResult?.UpdateAvailable ?? false;
            }
        }
    }

    private async Task TestVirusTotalKeyAsync()
    {
        _testKeyBtn.Enabled = false;
        _keyStatusLabel.ForeColor = _palette.TextSecondary;
        _keyStatusLabel.Text = "Checking VirusTotal API key...";
        try
        {
            var (success, message) = await _engine.TestApiKeyAsync(_apiKeyTextBox.Text);
            _keyStatusLabel.ForeColor = success ? _palette.SuccessGreen : _palette.DangerRed;
            _keyStatusLabel.Text = message;
        }
        finally
        {
            if (!IsDisposed)
            {
                _testKeyBtn.Enabled = true;
            }
        }
    }

    private async Task TestMetaDefenderKeyAsync()
    {
        _testMdKeyBtn.Enabled = false;
        _mdStatusLabel.ForeColor = _palette.TextSecondary;
        _mdStatusLabel.Text = "Checking MetaDefender key...";
        try
        {
            var (success, message) = await _engine.TestMetaDefenderKeyAsync(_metaDefenderKeyBox.Text);
            _mdStatusLabel.ForeColor = success ? _palette.SuccessGreen : _palette.DangerRed;
            _mdStatusLabel.Text = message;
        }
        finally
        {
            if (!IsDisposed)
            {
                _testMdKeyBtn.Enabled = true;
            }
        }
    }

    private async Task TestMalwareBazaarKeyAsync()
    {
        _testMbKeyBtn.Enabled = false;
        _mbStatusLabel.ForeColor = _palette.TextSecondary;
        _mbStatusLabel.Text = "Checking MalwareBazaar Auth-Key...";
        try
        {
            var (success, message) = await _engine.TestMalwareBazaarKeyAsync(_malwareBazaarKeyBox.Text);
            _mbStatusLabel.ForeColor = success ? _palette.SuccessGreen : _palette.DangerRed;
            _mbStatusLabel.Text = message;
        }
        finally
        {
            if (!IsDisposed)
            {
                _testMbKeyBtn.Enabled = true;
            }
        }
    }

    private static void UpdateThresholdDescriptionLabel(Label label, int value)
    {
        var (_, desc) = ModernThresholdSlider.GetThresholdGuidance(value);
        label.Text = desc;
    }

    private static string FormatBytes(long bytes)
    {
        if (bytes <= 0)
        {
            return "-";
        }

        if (bytes < 1024)
        {
            return $"{bytes} B";
        }

        double kb = bytes / 1024.0;
        if (kb < 1024)
        {
            return $"{kb:F1} KB";
        }

        double mb = kb / 1024.0;
        if (mb < 1024)
        {
            return $"{mb:F1} MB";
        }

        return $"{mb / 1024.0:F2} GB";
    }

    private void OpenUrl(string url)
    {
        try
        {
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            _logger.Warn($"Failed opening URL '{url}': {ex.Message}");
        }
    }

    private void OpenFolder(string path)
    {
        try
        {
            Process.Start(new ProcessStartInfo("explorer.exe", $"\"{path}\"") { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            _logger.Warn($"Failed opening folder '{path}': {ex.Message}");
        }
    }
}
