using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;
using VTDownloadGuard.Models;
using VTDownloadGuard.Services;

namespace VTDownloadGuard.UI;

public sealed class OnboardingDialog : Form
{
    private const int TotalSteps = 4;

    private readonly ScanEngine _engine;
    private readonly AppLogger _logger;
    private readonly AppSettings _workingSettings;
    private readonly ThemePalette _palette;

    private readonly Font _titleFont = new("Segoe UI Semibold", 13.0f);
    private readonly Font _sectionFont = new("Segoe UI Semibold", 10.0f);
    private readonly Font _boldFont = new("Segoe UI Semibold", 9.0f);
    private readonly Font _bodyFont = new("Segoe UI", 9.0f);
    private readonly Font _smallFont = new("Segoe UI", 8.5f);
    private readonly Font _pillFont = new("Segoe UI Semibold", 8.2f);

    private readonly Panel _headerPanel;
    private readonly PictureBox _iconBox;
    private readonly Label _headerTitleLabel;
    private readonly Label _stepPillLabel;
    private readonly ModernProgressBar _stepProgressBar;
    private readonly Panel _bodyHost;
    private readonly Panel _footerPanel;

    private readonly ModernButton _skipBtn;
    private readonly ModernButton _backBtn;
    private readonly ModernButton _nextBtn;
    private readonly ModernButton _finishWithoutTourBtn;

    private readonly Panel[] _stepPanels = new Panel[TotalSteps];

    // Step 2: Directories
    private readonly DataGridView _dirsGrid;
    private readonly ModernButton _addDirBtn;
    private readonly ModernButton _removeDirBtn;
    private readonly FlowLayoutPanel _suggestedGamesPanel;
    private readonly List<CheckBox> _gameCheckBoxes = [];

    // Step 3: API Keys
    private readonly TextBox _vtKeyBox;
    private readonly ModernButton _toggleVtKeyBtn;
    private readonly ModernButton _testVtKeyBtn;
    private readonly Label _vtStatusLabel;
    private readonly CheckBox _enableCirclCheck;
    private readonly CheckBox _lowerRiskOnlyCheck;
    private readonly CheckBox _enableMdCheck;
    private readonly TextBox _mdKeyBox;
    private readonly ModernButton _toggleMdKeyBtn;
    private readonly ModernButton _testMdKeyBtn;
    private readonly Label _mdStatusLabel;
    private readonly CheckBox _enableMbCheck;
    private readonly TextBox _mbKeyBox;
    private readonly ModernButton _toggleMbKeyBtn;
    private readonly ModernButton _testMbKeyBtn;
    private readonly Label _mbStatusLabel;

    // Step 4: Summary & Finish
    private readonly Label _summaryDirsLabel;
    private readonly Label _summaryVtLabel;
    private readonly Label _summarySecLabel;
    private readonly CheckBox _startupCheckBox;

    private readonly List<ModernButton> _allButtons = [];
    private readonly List<ModernCardPanel> _allCards = [];
    private readonly List<LinkLabel> _allLinks = [];

    private int _currentStep;

    public bool CompletedSetup { get; private set; }
    public bool StartUiTourRequested { get; private set; }

    public OnboardingDialog(ScanEngine engine, AppLogger logger, Icon appIcon)
    {
        _engine = engine;
        _logger = logger;
        _workingSettings = engine.CurrentSettings.Clone();
        SettingsStore.EnsureDefaultDownloadsIncluded(_workingSettings);
        _palette = ThemePalette.Resolve(_workingSettings.ThemeMode);

        Text = "VTDownloadGuard Setup";
        Icon = appIcon;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        StartPosition = FormStartPosition.CenterParent;
        Size = new Size(740, 610);
        Font = _bodyFont;

        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 4,
            Margin = new Padding(0),
            Padding = new Padding(0)
        };
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 66));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 10));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 58));
        Controls.Add(root);

        // Header
        _headerPanel = new Panel { Dock = DockStyle.Fill, Padding = new Padding(20, 12, 20, 8) };
        var headerRow = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3, RowCount = 1 };
        headerRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 42));
        headerRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        headerRow.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));

        _iconBox = new PictureBox
        {
            Size = new Size(32, 32),
            SizeMode = PictureBoxSizeMode.Zoom,
            Image = new Icon(appIcon, 48, 48).ToBitmap(),
            Margin = new Padding(0, 4, 8, 0)
        };
        _headerTitleLabel = new Label
        {
            AutoSize = true,
            Font = _titleFont,
            Anchor = AnchorStyles.Left,
            Margin = new Padding(0, 4, 0, 0)
        };
        _stepPillLabel = new Label
        {
            AutoSize = true,
            Font = _pillFont,
            Padding = new Padding(10, 4, 10, 4),
            Anchor = AnchorStyles.Right,
            Margin = new Padding(0, 8, 0, 0)
        };

        headerRow.Controls.Add(_iconBox, 0, 0);
        headerRow.Controls.Add(_headerTitleLabel, 1, 0);
        headerRow.Controls.Add(_stepPillLabel, 2, 0);
        _headerPanel.Controls.Add(headerRow);
        root.Controls.Add(_headerPanel, 0, 0);

        // Progress strip
        var progContainer = new Panel { Dock = DockStyle.Fill, Padding = new Padding(20, 0, 20, 0) };
        _stepProgressBar = new ModernProgressBar { Dock = DockStyle.Fill, Maximum = TotalSteps, Value = 1 };
        progContainer.Controls.Add(_stepProgressBar);
        root.Controls.Add(progContainer, 0, 1);

        // Body host
        _bodyHost = new Panel { Dock = DockStyle.Fill, Padding = new Padding(20, 12, 20, 8) };
        root.Controls.Add(_bodyHost, 0, 2);

        _stepPanels[0] = BuildWelcomeStep();
        (_stepPanels[1], _dirsGrid, _addDirBtn, _removeDirBtn, _suggestedGamesPanel) = BuildDirectoriesStep();
        (_stepPanels[2], _vtKeyBox, _toggleVtKeyBtn, _testVtKeyBtn, _vtStatusLabel,
            _enableCirclCheck, _lowerRiskOnlyCheck,
            _enableMdCheck, _mdKeyBox, _toggleMdKeyBtn, _testMdKeyBtn, _mdStatusLabel,
            _enableMbCheck, _mbKeyBox, _toggleMbKeyBtn, _testMbKeyBtn, _mbStatusLabel) = BuildApiKeysStep();
        (_stepPanels[3], _summaryDirsLabel, _summaryVtLabel, _summarySecLabel, _startupCheckBox) = BuildFinishStep();

        foreach (Panel p in _stepPanels)
        {
            p.Dock = DockStyle.Fill;
            p.Visible = false;
            _bodyHost.Controls.Add(p);
        }

        // Footer bar
        _footerPanel = new Panel { Dock = DockStyle.Fill, Padding = new Padding(20, 12, 20, 12) };
        var footerLayout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1 };
        footerLayout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        footerLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

        _skipBtn = MakeButton("Skip Setup", ModernButtonVariant.Ghost);
        _skipBtn.Click += (_, _) => SkipOnboarding();
        footerLayout.Controls.Add(_skipBtn, 0, 0);

        var navRight = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.RightToLeft,
            WrapContents = false,
            Margin = new Padding(0)
        };
        _nextBtn = MakeButton("Next", ModernButtonVariant.Primary);
        _nextBtn.Click += (_, _) => OnNextClicked();

        _finishWithoutTourBtn = MakeButton("Finish Without Tour", ModernButtonVariant.Secondary);
        _finishWithoutTourBtn.Visible = false;
        _finishWithoutTourBtn.Click += (_, _) => FinishOnboarding(startTour: false);

        _backBtn = MakeButton("Back", ModernButtonVariant.Secondary);
        _backBtn.Click += (_, _) => ShowStep(_currentStep - 1);

        navRight.Controls.AddRange([_nextBtn, _finishWithoutTourBtn, _backBtn]);
        footerLayout.Controls.Add(navRight, 1, 0);
        _footerPanel.Controls.Add(footerLayout);
        root.Controls.Add(_footerPanel, 0, 3);

        ApplyTheme(_palette);
        RefreshDirectoriesStep();
        ShowStep(0);
    }

    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        ThemePalette.ApplyWindowTheme(this, _palette);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _titleFont.Dispose();
            _sectionFont.Dispose();
            _boldFont.Dispose();
            _bodyFont.Dispose();
            _smallFont.Dispose();
            _pillFont.Dispose();
            _iconBox.Image?.Dispose();
        }

        base.Dispose(disposing);
    }

    public int CurrentStepIndex => _currentStep;

    public void ShowStep(int index)
    {
        _currentStep = Math.Clamp(index, 0, TotalSteps - 1);
        for (int i = 0; i < _stepPanels.Length; i++)
        {
            _stepPanels[i].Visible = i == _currentStep;
        }

        _stepProgressBar.Value = _currentStep + 1;
        _stepPillLabel.Text = $"Step {_currentStep + 1} of {TotalSteps}";
        _headerTitleLabel.Text = _currentStep switch
        {
            0 => "Welcome to VTDownloadGuard",
            1 => "Configure Watched Directories",
            2 => "Connect Your VirusTotal API Key",
            _ => "Ready to Protect Your PC"
        };

        _backBtn.Enabled = _currentStep > 0;
        _backBtn.Visible = _currentStep > 0;

        if (_currentStep == TotalSteps - 1)
        {
            RefreshFinishSummary();
            _nextBtn.Text = "Finish and Start UI Tour";
            _finishWithoutTourBtn.Visible = true;
        }
        else
        {
            _nextBtn.Text = "Next";
            _finishWithoutTourBtn.Visible = false;
        }
    }

    private void OnNextClicked()
    {
        if (_currentStep < TotalSteps - 1)
        {
            if (_currentStep == 2)
            {
                CaptureApiStepIntoWorkingSettings();
            }

            ShowStep(_currentStep + 1);
        }
        else
        {
            FinishOnboarding(startTour: true);
        }
    }

    private ModernButton MakeButton(string text, ModernButtonVariant variant)
    {
        var btn = new ModernButton
        {
            Text = text,
            Variant = variant,
            AutoSize = true,
            Margin = new Padding(6, 0, 0, 0)
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

    private LinkLabel MakeLink(string text, string url)
    {
        var link = new LinkLabel { Text = text, AutoSize = true, Font = _smallFont };
        link.LinkClicked += (_, _) => OpenUrl(url);
        _allLinks.Add(link);
        return link;
    }

    private Panel BuildWelcomeStep()
    {
        var panel = new Panel { Dock = DockStyle.Fill };
        var stack = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.TopDown,
            WrapContents = false,
            AutoScroll = true
        };

        var card = MakeCard();
        card.Width = 676;
        card.AutoSize = true;
        card.AutoSizeMode = AutoSizeMode.GrowAndShrink;
        card.Margin = new Padding(0, 0, 0, 12);

        var inner = new FlowLayoutPanel
        {
            FlowDirection = FlowDirection.TopDown,
            AutoSize = true,
            WrapContents = false,
            Location = new Point(16, 16),
            MaximumSize = new Size(644, 0),
            BackColor = Color.Transparent
        };

        var headline = new Label
        {
            Text = "Lightweight automatic screening for new downloads and game files",
            Font = _sectionFont,
            AutoSize = true,
            MaximumSize = new Size(640, 0),
            Margin = new Padding(0, 0, 0, 10)
        };
        inner.Controls.Add(headline);

        string[] bullets =
        [
            "1. Monitors your Downloads and chosen folders quietly in the Windows system tray.",
            "2. Ranks incoming files locally by risk so suspicious scripts and unsigned installers are checked first.",
            "3. Checks SHA-256 hashes against local cache and optional trusted hash databases before spending VirusTotal quota.",
            "4. Notifies you right away when a file crosses your detection threshold and opens the full report on click."
        ];
        foreach (string line in bullets)
        {
            inner.Controls.Add(new Label
            {
                Text = line,
                AutoSize = true,
                MaximumSize = new Size(636, 0),
                Margin = new Padding(0, 0, 0, 8)
            });
        }

        card.Controls.Add(inner);
        stack.Controls.Add(card);

        var noteCard = MakeCard();
        noteCard.Width = 676;
        noteCard.AutoSize = true;
        noteCard.AutoSizeMode = AutoSizeMode.GrowAndShrink;

        var noteLabel = new Label
        {
            Text = "This setup takes under a minute: confirm which folders to watch, add your free VirusTotal API key, and optionally take a short guided tour of the dashboard.",
            Location = new Point(16, 14),
            AutoSize = true,
            MaximumSize = new Size(640, 0),
            Margin = new Padding(0, 0, 0, 8)
        };
        noteCard.Controls.Add(noteLabel);
        stack.Controls.Add(noteCard);

        panel.Controls.Add(stack);
        return panel;
    }

    private (
        Panel Panel,
        DataGridView Grid,
        ModernButton AddBtn,
        ModernButton RemoveBtn,
        FlowLayoutPanel SuggestedPanel) BuildDirectoriesStep()
    {
        var panel = new Panel { Dock = DockStyle.Fill };
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 4 };
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 58));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 42));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 42));

        var introLabel = new Label
        {
            Text = "Your Windows Downloads folder was added automatically. Add any extra download folders or select detected game folders below.",
            AutoSize = true,
            MaximumSize = new Size(680, 0),
            Margin = new Padding(0, 0, 0, 8)
        };
        layout.Controls.Add(introLabel, 0, 0);

        var gridCard = MakeCard();
        gridCard.Dock = DockStyle.Fill;
        gridCard.Padding = new Padding(1);
        var grid = new DataGridView { Dock = DockStyle.Fill };
        grid.Columns.Add(new DataGridViewTextBoxColumn
        {
            Name = "Path",
            HeaderText = "Watched Directory",
            AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill
        });
        grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "Subfolders", HeaderText = "Subfolders", Width = 100 });
        gridCard.Controls.Add(grid);
        layout.Controls.Add(gridCard, 0, 1);

        var btnRow = new FlowLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(0, 6, 0, 0) };
        var addBtn = MakeButton("Add Folder...", ModernButtonVariant.Secondary);
        addBtn.Click += (_, _) => AddOnboardingFolder();

        var removeBtn = MakeButton("Remove Selected", ModernButtonVariant.Ghost);
        removeBtn.Enabled = false;
        removeBtn.Click += (_, _) => RemoveSelectedOnboardingFolder();

        grid.SelectionChanged += (_, _) => removeBtn.Enabled = grid.SelectedRows.Count > 0;
        btnRow.Controls.AddRange([addBtn, removeBtn]);
        layout.Controls.Add(btnRow, 0, 2);

        var gamesCard = MakeCard();
        gamesCard.Dock = DockStyle.Fill;
        gamesCard.Padding = new Padding(12);
        var gamesLayout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2 };
        gamesLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        gamesLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

        gamesLayout.Controls.Add(new Label
        {
            Text = "Detected Game Folders (optional)",
            Font = _boldFont,
            AutoSize = true,
            Margin = new Padding(0, 0, 0, 6)
        }, 0, 0);

        var suggestedPanel = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.TopDown,
            WrapContents = false,
            AutoScroll = true
        };
        gamesLayout.Controls.Add(suggestedPanel, 0, 1);
        gamesCard.Controls.Add(gamesLayout);
        layout.Controls.Add(gamesCard, 0, 3);

        panel.Controls.Add(layout);
        return (panel, grid, addBtn, removeBtn, suggestedPanel);
    }

    private (
        Panel Panel,
        TextBox VtKeyBox,
        ModernButton ToggleVtBtn,
        ModernButton TestVtBtn,
        Label VtStatusLabel,
        CheckBox CirclCheck,
        CheckBox LowerRiskCheck,
        CheckBox MdCheck,
        TextBox MdKeyBox,
        ModernButton ToggleMdBtn,
        ModernButton TestMdBtn,
        Label MdStatusLabel,
        CheckBox MbCheck,
        TextBox MbKeyBox,
        ModernButton ToggleMbBtn,
        ModernButton TestMbBtn,
        Label MbStatusLabel) BuildApiKeysStep()
    {
        var panel = new Panel { Dock = DockStyle.Fill };
        var scroll = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.TopDown,
            WrapContents = false,
            AutoScroll = true
        };

        // VirusTotal Card
        var vtCard = MakeCard();
        vtCard.Width = 668;
        vtCard.AutoSize = true;
        vtCard.AutoSizeMode = AutoSizeMode.GrowAndShrink;
        vtCard.Margin = new Padding(0, 0, 0, 12);

        var vtStack = new FlowLayoutPanel
        {
            FlowDirection = FlowDirection.TopDown,
            AutoSize = true,
            WrapContents = false,
            Location = new Point(16, 16),
            MaximumSize = new Size(636, 0)
        };
        vtStack.Controls.Add(new Label
        {
            Text = "VirusTotal API Key (Required for VirusTotal scanning)",
            Font = _sectionFont,
            AutoSize = true,
            Margin = new Padding(0, 0, 0, 6)
        });
        vtStack.Controls.Add(new Label
        {
            Text = "Create a free VirusTotal account, copy your personal API key, and paste it here. Keys are encrypted locally using Windows DPAPI.",
            AutoSize = true,
            MaximumSize = new Size(632, 0),
            Margin = new Padding(0, 0, 0, 8)
        });

        var vtRow = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0, 0, 0, 4) };
        var vtKeyBox = new TextBox
        {
            Width = 370,
            UseSystemPasswordChar = true,
            Text = SettingsStore.GetDecryptedApiKey(_workingSettings)
        };
        var toggleVtBtn = MakeButton("Show", ModernButtonVariant.Secondary);
        toggleVtBtn.Click += (_, _) =>
        {
            vtKeyBox.UseSystemPasswordChar = !vtKeyBox.UseSystemPasswordChar;
            toggleVtBtn.Text = vtKeyBox.UseSystemPasswordChar ? "Show" : "Hide";
        };
        var testVtBtn = MakeButton("Test Key", ModernButtonVariant.Secondary);
        vtRow.Controls.AddRange([vtKeyBox, toggleVtBtn, testVtBtn]);

        var vtInfoRow = new FlowLayoutPanel { AutoSize = true, WrapContents = false };
        var vtLink = MakeLink("Get free API key at virustotal.com", "https://www.virustotal.com/gui/my-apikey");
        vtLink.Margin = new Padding(0, 2, 14, 0);
        var vtStatus = new Label { AutoSize = true, Font = _smallFont, Margin = new Padding(0, 2, 0, 0) };
        vtInfoRow.Controls.AddRange([vtLink, vtStatus]);

        testVtBtn.Click += async (_, _) => await TestKeyAsync(
            testVtBtn,
            vtStatus,
            () => _engine.TestApiKeyAsync(vtKeyBox.Text),
            "Checking VirusTotal key...");

        vtStack.Controls.AddRange([vtRow, vtInfoRow]);
        vtCard.Controls.Add(vtStack);
        scroll.Controls.Add(vtCard);

        // Secondary Services Card
        var secCard = MakeCard();
        secCard.Width = 668;
        secCard.AutoSize = true;
        secCard.AutoSizeMode = AutoSizeMode.GrowAndShrink;

        var secStack = new FlowLayoutPanel
        {
            FlowDirection = FlowDirection.TopDown,
            AutoSize = true,
            WrapContents = false,
            Location = new Point(16, 16),
            MaximumSize = new Size(636, 0)
        };
        secStack.Controls.Add(new Label
        {
            Text = "Optional Secondary Hash Services (Saves VirusTotal Quota)",
            Font = _sectionFont,
            AutoSize = true,
            Margin = new Padding(0, 0, 0, 6)
        });

        var circlCheck = new CheckBox
        {
            Text = "Enable CIRCL Hashlookup (free NIST NSRL database, no API key required)",
            AutoSize = true,
            Checked = _workingSettings.EnableCirclHashlookup,
            Margin = new Padding(0, 0, 0, 4)
        };
        var lowerRiskCheck = new CheckBox
        {
            Text = "Only use secondary services for lower-risk files (Low Risk and Likely Safe)",
            AutoSize = true,
            Checked = _workingSettings.SecondaryLookupsLowerRiskOnly,
            Margin = new Padding(0, 0, 0, 10)
        };
        secStack.Controls.AddRange([circlCheck, lowerRiskCheck]);

        // MetaDefender
        var mdCheck = new CheckBox
        {
            Text = "Enable OPSWAT MetaDefender Cloud (optional, requires free API key)",
            AutoSize = true,
            Checked = _workingSettings.EnableMetaDefender,
            Margin = new Padding(0, 0, 0, 4)
        };
        var mdRow = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(18, 0, 0, 2) };
        var mdKeyBox = new TextBox
        {
            Width = 340,
            UseSystemPasswordChar = true,
            Text = SettingsStore.GetDecryptedMetaDefenderApiKey(_workingSettings)
        };
        var toggleMdBtn = MakeButton("Show", ModernButtonVariant.Secondary);
        toggleMdBtn.Click += (_, _) =>
        {
            mdKeyBox.UseSystemPasswordChar = !mdKeyBox.UseSystemPasswordChar;
            toggleMdBtn.Text = mdKeyBox.UseSystemPasswordChar ? "Show" : "Hide";
        };
        var testMdBtn = MakeButton("Test", ModernButtonVariant.Secondary);
        mdRow.Controls.AddRange([mdKeyBox, toggleMdBtn, testMdBtn]);

        var mdInfoRow = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(18, 0, 0, 10) };
        var mdLink = MakeLink("Get free key at metadefender.opswat.com", "https://metadefender.opswat.com/");
        mdLink.Margin = new Padding(0, 2, 12, 0);
        var mdStatus = new Label { AutoSize = true, Font = _smallFont, Margin = new Padding(0, 2, 0, 0) };
        mdInfoRow.Controls.AddRange([mdLink, mdStatus]);
        testMdBtn.Click += async (_, _) => await TestKeyAsync(
            testMdBtn,
            mdStatus,
            () => _engine.TestMetaDefenderKeyAsync(mdKeyBox.Text),
            "Checking MetaDefender key...");
        secStack.Controls.AddRange([mdCheck, mdRow, mdInfoRow]);

        // MalwareBazaar
        var mbCheck = new CheckBox
        {
            Text = "Enable MalwareBazaar by abuse.ch (optional, requires free Auth-Key)",
            AutoSize = true,
            Checked = _workingSettings.EnableMalwareBazaar,
            Margin = new Padding(0, 0, 0, 4)
        };
        var mbRow = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(18, 0, 0, 2) };
        var mbKeyBox = new TextBox
        {
            Width = 340,
            UseSystemPasswordChar = true,
            Text = SettingsStore.GetDecryptedMalwareBazaarApiKey(_workingSettings)
        };
        var toggleMbBtn = MakeButton("Show", ModernButtonVariant.Secondary);
        toggleMbBtn.Click += (_, _) =>
        {
            mbKeyBox.UseSystemPasswordChar = !mbKeyBox.UseSystemPasswordChar;
            toggleMbBtn.Text = mbKeyBox.UseSystemPasswordChar ? "Show" : "Hide";
        };
        var testMbBtn = MakeButton("Test", ModernButtonVariant.Secondary);
        mbRow.Controls.AddRange([mbKeyBox, toggleMbBtn, testMbBtn]);

        var mbInfoRow = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(18, 0, 0, 0) };
        var mbLink = MakeLink("Get free Auth-Key at auth.abuse.ch", "https://auth.abuse.ch/");
        mbLink.Margin = new Padding(0, 2, 12, 0);
        var mbStatus = new Label { AutoSize = true, Font = _smallFont, Margin = new Padding(0, 2, 0, 0) };
        mbInfoRow.Controls.AddRange([mbLink, mbStatus]);
        testMbBtn.Click += async (_, _) => await TestKeyAsync(
            testMbBtn,
            mbStatus,
            () => _engine.TestMalwareBazaarKeyAsync(mbKeyBox.Text),
            "Checking MalwareBazaar key...");
        secStack.Controls.AddRange([mbCheck, mbRow, mbInfoRow]);

        secCard.Controls.Add(secStack);
        scroll.Controls.Add(secCard);

        panel.Controls.Add(scroll);
        return (panel, vtKeyBox, toggleVtBtn, testVtBtn, vtStatus, circlCheck, lowerRiskCheck,
            mdCheck, mdKeyBox, toggleMdBtn, testMdBtn, mdStatus, mbCheck, mbKeyBox, toggleMbBtn, testMbBtn, mbStatus);
    }

    private (
        Panel Panel,
        Label SummaryDirs,
        Label SummaryVt,
        Label SummarySec,
        CheckBox StartupCheck) BuildFinishStep()
    {
        var panel = new Panel { Dock = DockStyle.Fill };
        var stack = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.TopDown,
            WrapContents = false,
            AutoScroll = true
        };

        var card = MakeCard();
        card.Width = 676;
        card.AutoSize = true;
        card.AutoSizeMode = AutoSizeMode.GrowAndShrink;
        card.Margin = new Padding(0, 0, 0, 12);

        var inner = new FlowLayoutPanel
        {
            FlowDirection = FlowDirection.TopDown,
            AutoSize = true,
            WrapContents = false,
            Location = new Point(16, 16),
            MaximumSize = new Size(644, 0)
        };
        inner.Controls.Add(new Label
        {
            Text = "Setup Summary",
            Font = _sectionFont,
            AutoSize = true,
            Margin = new Padding(0, 0, 0, 10)
        });

        var sumDirs = new Label { AutoSize = true, MaximumSize = new Size(636, 0), Margin = new Padding(0, 0, 0, 8) };
        var sumVt = new Label { AutoSize = true, MaximumSize = new Size(636, 0), Margin = new Padding(0, 0, 0, 8) };
        var sumSec = new Label { AutoSize = true, MaximumSize = new Size(636, 0), Margin = new Padding(0, 0, 0, 10) };

        var startupCheck = new CheckBox
        {
            Text = "Start automatically minimized to the system tray when Windows starts",
            AutoSize = true,
            Checked = _workingSettings.StartWithWindows,
            Margin = new Padding(0, 4, 0, 0)
        };

        inner.Controls.AddRange([sumDirs, sumVt, sumSec, startupCheck]);
        card.Controls.Add(inner);
        stack.Controls.Add(card);

        var tourCard = MakeCard();
        tourCard.Width = 676;
        tourCard.AutoSize = true;
        tourCard.AutoSizeMode = AutoSizeMode.GrowAndShrink;
        var tourLabel = new Label
        {
            Text = "Optional Interface Tour: Click 'Finish and Start UI Tour' below if you would like a quick spotlight walkthrough highlighting each tab and control.",
            Location = new Point(16, 14),
            AutoSize = true,
            MaximumSize = new Size(640, 0),
            Margin = new Padding(0, 0, 0, 8)
        };
        tourCard.Controls.Add(tourLabel);
        stack.Controls.Add(tourCard);

        panel.Controls.Add(stack);
        return (panel, sumDirs, sumVt, sumSec, startupCheck);
    }

    private void RefreshDirectoriesStep()
    {
        _dirsGrid.SuspendLayout();
        _dirsGrid.Rows.Clear();
        foreach (WatchedDirectory dir in _workingSettings.WatchedDirectories)
        {
            _dirsGrid.Rows.Add(dir.Path, dir.IncludeSubdirectories ? "Yes" : "No");
        }

        _dirsGrid.ResumeLayout();

        _suggestedGamesPanel.Controls.Clear();
        _gameCheckBoxes.Clear();

        List<string> suggested = AppSettings.GetSuggestedGameDirectories();
        if (suggested.Count == 0)
        {
            _suggestedGamesPanel.Controls.Add(new Label
            {
                Text = "No common Steam, Epic, GOG, Xbox, or Games folders were found automatically. You can add custom folders above.",
                AutoSize = true,
                MaximumSize = new Size(620, 0),
                ForeColor = _palette.TextSecondary
            });
            return;
        }

        foreach (string gamePath in suggested)
        {
            bool isChecked = _workingSettings.WatchedDirectories.Any(d =>
                string.Equals(d.Path, gamePath, StringComparison.OrdinalIgnoreCase));
            var chk = new CheckBox
            {
                Text = gamePath,
                AutoSize = true,
                Checked = isChecked,
                ForeColor = _palette.TextPrimary,
                Margin = new Padding(0, 2, 0, 2)
            };
            chk.CheckedChanged += (_, _) => OnSuggestedGameCheckedChanged(gamePath, chk.Checked);
            _gameCheckBoxes.Add(chk);
            _suggestedGamesPanel.Controls.Add(chk);
        }
    }

    private void OnSuggestedGameCheckedChanged(string path, bool enabled)
    {
        if (enabled)
        {
            if (!_workingSettings.WatchedDirectories.Any(d => string.Equals(d.Path, path, StringComparison.OrdinalIgnoreCase)))
            {
                _workingSettings.WatchedDirectories.Add(new WatchedDirectory
                {
                    Path = path,
                    IncludeSubdirectories = true,
                    Enabled = true
                });
            }
        }
        else
        {
            _workingSettings.WatchedDirectories.RemoveAll(d =>
                string.Equals(d.Path, path, StringComparison.OrdinalIgnoreCase));
        }

        _dirsGrid.SuspendLayout();
        _dirsGrid.Rows.Clear();
        foreach (WatchedDirectory dir in _workingSettings.WatchedDirectories)
        {
            _dirsGrid.Rows.Add(dir.Path, dir.IncludeSubdirectories ? "Yes" : "No");
        }

        _dirsGrid.ResumeLayout();
    }

    private void AddOnboardingFolder()
    {
        using var dialog = new FolderBrowserDialog
        {
            Description = "Select a folder to watch automatically",
            ShowNewFolderButton = true
        };
        if (dialog.ShowDialog(this) != DialogResult.OK || string.IsNullOrWhiteSpace(dialog.SelectedPath))
        {
            return;
        }

        if (_workingSettings.WatchedDirectories.Any(d =>
            string.Equals(d.Path, dialog.SelectedPath, StringComparison.OrdinalIgnoreCase)))
        {
            return;
        }

        _workingSettings.WatchedDirectories.Add(new WatchedDirectory
        {
            Path = dialog.SelectedPath,
            IncludeSubdirectories = true,
            Enabled = true
        });
        RefreshDirectoriesStep();
    }

    private void RemoveSelectedOnboardingFolder()
    {
        if (_dirsGrid.SelectedRows.Count == 0)
        {
            return;
        }

        int idx = _dirsGrid.SelectedRows[0].Index;
        if (idx >= 0 && idx < _workingSettings.WatchedDirectories.Count)
        {
            _workingSettings.WatchedDirectories.RemoveAt(idx);
            RefreshDirectoriesStep();
        }
    }

    private void CaptureApiStepIntoWorkingSettings()
    {
        SettingsStore.SetApiKey(_workingSettings, _vtKeyBox.Text);
        _workingSettings.EnableCirclHashlookup = _enableCirclCheck.Checked;
        _workingSettings.SecondaryLookupsLowerRiskOnly = _lowerRiskOnlyCheck.Checked;
        _workingSettings.EnableMetaDefender = _enableMdCheck.Checked;
        SettingsStore.SetMetaDefenderApiKey(_workingSettings, _mdKeyBox.Text);
        _workingSettings.EnableMalwareBazaar = _enableMbCheck.Checked;
        SettingsStore.SetMalwareBazaarApiKey(_workingSettings, _mbKeyBox.Text);
    }

    private void RefreshFinishSummary()
    {
        int dirCount = _workingSettings.WatchedDirectories.Count;
        string dirPreview = string.Join(", ", _workingSettings.WatchedDirectories.Take(3).Select(d => d.Path));
        if (dirCount > 3)
        {
            dirPreview += $", and {dirCount - 3} more";
        }

        _summaryDirsLabel.Text = dirCount > 0
            ? $"Watched Directories ({dirCount}): {dirPreview}"
            : "Watched Directories: None selected (you can add folders anytime in the Directories tab).";

        bool hasVtKey = !string.IsNullOrWhiteSpace(SettingsStore.GetDecryptedApiKey(_workingSettings));
        _summaryVtLabel.Text = hasVtKey
            ? "VirusTotal API Key: Configured and encrypted locally."
            : "VirusTotal API Key: Not added yet (add it anytime in Settings to start VirusTotal checks).";

        var activeSecondary = new List<string>();
        if (_workingSettings.EnableCirclHashlookup)
        {
            activeSecondary.Add("CIRCL Hashlookup");
        }

        if (_workingSettings.EnableMetaDefender && !string.IsNullOrWhiteSpace(SettingsStore.GetDecryptedMetaDefenderApiKey(_workingSettings)))
        {
            activeSecondary.Add("OPSWAT MetaDefender");
        }

        if (_workingSettings.EnableMalwareBazaar && !string.IsNullOrWhiteSpace(SettingsStore.GetDecryptedMalwareBazaarApiKey(_workingSettings)))
        {
            activeSecondary.Add("MalwareBazaar");
        }

        _summarySecLabel.Text = activeSecondary.Count > 0
            ? $"Secondary Hash Services: {string.Join(", ", activeSecondary)}"
            : "Secondary Hash Services: Disabled";
    }

    private void FinishOnboarding(bool startTour)
    {
        CaptureApiStepIntoWorkingSettings();
        SettingsStore.EnsureDefaultDownloadsIncluded(_workingSettings);
        _workingSettings.StartWithWindows = _startupCheckBox.Checked;
        _workingSettings.OnboardingCompleted = true;

        _engine.ApplySettings(_workingSettings);
        try
        {
            StartupManager.SetStartupEnabled(_workingSettings.StartWithWindows);
        }
        catch (Exception ex)
        {
            _logger.Warn($"Failed updating startup registration after onboarding: {ex.Message}");
        }

        CompletedSetup = true;
        StartUiTourRequested = startTour;
        DialogResult = DialogResult.OK;
        Close();
    }

    private void SkipOnboarding()
    {
        AppSettings updated = _engine.CurrentSettings;
        SettingsStore.EnsureDefaultDownloadsIncluded(updated);
        updated.OnboardingCompleted = true;
        _engine.ApplySettings(updated);

        CompletedSetup = true;
        StartUiTourRequested = false;
        DialogResult = DialogResult.Cancel;
        Close();
    }

    private async Task TestKeyAsync(
        ModernButton button,
        Label statusLabel,
        Func<Task<(bool Success, string Message)>> testCall,
        string pendingText)
    {
        button.Enabled = false;
        statusLabel.ForeColor = _palette.TextSecondary;
        statusLabel.Text = pendingText;
        try
        {
            var (success, message) = await testCall();
            statusLabel.ForeColor = success ? _palette.SuccessGreen : _palette.DangerRed;
            statusLabel.Text = message;
        }
        finally
        {
            if (!IsDisposed)
            {
                button.Enabled = true;
            }
        }
    }

    private void ApplyTheme(ThemePalette palette)
    {
        BackColor = palette.CanvasBg;
        ForeColor = palette.TextPrimary;
        _headerPanel.BackColor = palette.TopBarBg;
        _footerPanel.BackColor = palette.TopBarBg;
        _headerTitleLabel.ForeColor = palette.TextPrimary;
        _stepPillLabel.BackColor = palette.AccentBlueBg;
        _stepPillLabel.ForeColor = palette.AccentBlue;
        _stepProgressBar.ApplyTheme(palette);

        foreach (ModernButton btn in _allButtons)
        {
            btn.ApplyTheme(palette);
        }

        foreach (ModernCardPanel card in _allCards)
        {
            card.ApplyTheme(palette);
        }

        foreach (LinkLabel link in _allLinks)
        {
            link.LinkColor = palette.AccentBlue;
            link.ActiveLinkColor = palette.AccentBlueHover;
            link.VisitedLinkColor = palette.AccentBlue;
        }

        ModernGridHelper.ConfigureGrid(_dirsGrid, palette);
        ApplyRecursiveTheme(_bodyHost, palette);
        ThemePalette.ApplyWindowTheme(this, palette);
    }

    private static void ApplyRecursiveTheme(Control parent, ThemePalette palette)
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
                case CheckBox chk:
                    chk.ForeColor = palette.TextPrimary;
                    chk.BackColor = Color.Transparent;
                    break;
                case Label lbl when lbl is not LinkLabel:
                    if (lbl.ForeColor != palette.SuccessGreen && lbl.ForeColor != palette.DangerRed)
                    {
                        lbl.ForeColor = palette.TextPrimary;
                    }

                    break;
            }

            if (ctrl.HasChildren)
            {
                ApplyRecursiveTheme(ctrl, palette);
            }
        }
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
}
