using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Windows.Forms;
using VTDownloadGuard.Models;
using VTDownloadGuard.Services;

namespace VTDownloadGuard.UI;

public enum ManualUploadAssistAction
{
    Cancel = 0,
    UploadViaApi = 1,
    OpenBrowserAndRevealFile = 2,
    OpenHashReport = 3,
    OpenSettings = 4
}

public sealed class ManualUploadAssistDialog : Form
{
    private readonly ThemePalette _palette;
    private readonly Font _titleFont = new("Segoe UI Semibold", 11.5f);
    private readonly Font _sectionFont = new("Segoe UI Semibold", 9.5f);
    private readonly Font _boldFont = new("Segoe UI Semibold", 9.0f);
    private readonly Font _bodyFont = new("Segoe UI", 9.0f);
    private readonly Font _smallFont = new("Segoe UI", 8.5f);
    private readonly Font _monoFont = new("Consolas", 8.8f);
    private readonly PictureBox _iconBox;
    private readonly List<ModernButton> _buttons = [];
    private readonly List<ModernCardPanel> _cards = [];
    private readonly Label _inlineStatusLabel;

    public ManualUploadAssistAction SelectedAction { get; private set; } = ManualUploadAssistAction.Cancel;

    public ManualUploadAssistDialog(
        ScanRecord record,
        long actualFileSizeBytes,
        ManualUploadStrategy strategy,
        ThemePalette palette,
        Icon appIcon)
    {
        ArgumentNullException.ThrowIfNull(record);
        _palette = palette;

        Text = strategy switch
        {
            ManualUploadStrategy.LargeApiUpload => "Large File Upload - VTDownloadGuard",
            ManualUploadStrategy.ManualBrowserOnlyNoKey => "VirusTotal Upload Options - VTDownloadGuard",
            _ => "File Exceeds VirusTotal Upload Limit - VTDownloadGuard"
        };
        Icon = appIcon;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        StartPosition = FormStartPosition.CenterParent;
        AutoScaleMode = AutoScaleMode.Dpi;
        DoubleBuffered = true;
        ClientSize = new Size(680, 440);
        MinimumSize = new Size(660, 420);
        Font = _bodyFont;
        BackColor = palette.CanvasBg;
        ForeColor = palette.TextPrimary;

        var root = new SmoothTableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 3,
            Padding = new Padding(16),
            Margin = new Padding(0)
        };
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        Controls.Add(root);

        // Card 1: File summary
        var fileCard = CreateCard();
        fileCard.Dock = DockStyle.Fill;
        fileCard.Margin = new Padding(0, 0, 0, 12);
        var fileTable = new SmoothTableLayoutPanel
        {
            Dock = DockStyle.Fill,
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            ColumnCount = 2,
            BackColor = Color.Transparent
        };
        fileTable.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 42));
        fileTable.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

        _iconBox = new PictureBox
        {
            Size = new Size(32, 32),
            SizeMode = PictureBoxSizeMode.Zoom,
            Image = new Icon(appIcon, 48, 48).ToBitmap(),
            Margin = new Padding(0, 2, 10, 0),
            BackColor = Color.Transparent
        };

        string headerText = strategy switch
        {
            ManualUploadStrategy.LargeApiUpload => "Large File VirusTotal Upload",
            ManualUploadStrategy.ManualBrowserOnlyNoKey => "Manual VirusTotal Upload",
            _ => "Cannot Upload Directly (Over 650 MB)"
        };

        var headerLabel = new Label
        {
            Text = headerText,
            AutoSize = true,
            Font = _titleFont,
            ForeColor = palette.TextPrimary,
            Margin = new Padding(0, 4, 0, 6)
        };

        fileTable.Controls.Add(_iconBox, 0, 0);
        fileTable.Controls.Add(headerLabel, 1, 0);

        string displayName = string.IsNullOrWhiteSpace(record.FileName)
            ? Path.GetFileName(record.FilePath)
            : record.FileName;
        var nameLabel = new Label
        {
            Text = $"File: {displayName} ({FormatBytes(actualFileSizeBytes)})",
            AutoSize = true,
            MaximumSize = new Size(600, 0),
            Font = _boldFont,
            ForeColor = palette.TextPrimary,
            Margin = new Padding(0, 4, 0, 2)
        };
        fileTable.SetColumnSpan(nameLabel, 2);
        fileTable.Controls.Add(nameLabel, 0, 1);

        var pathLabel = new Label
        {
            Text = $"Path: {record.FilePath}",
            AutoSize = true,
            MaximumSize = new Size(600, 0),
            Font = _smallFont,
            ForeColor = palette.TextSecondary,
            Margin = new Padding(0, 0, 0, 2)
        };
        fileTable.SetColumnSpan(pathLabel, 2);
        fileTable.Controls.Add(pathLabel, 0, 2);

        bool hasHash = !string.IsNullOrWhiteSpace(record.Sha256);
        var shaLabel = new Label
        {
            Text = hasHash ? $"SHA-256: {record.Sha256}" : "SHA-256: (not computed yet)",
            AutoSize = true,
            MaximumSize = new Size(600, 0),
            Font = _monoFont,
            ForeColor = palette.TextSecondary,
            Margin = new Padding(0, 2, 0, 0)
        };
        fileTable.SetColumnSpan(shaLabel, 2);
        fileTable.Controls.Add(shaLabel, 0, 3);

        fileCard.Controls.Add(fileTable);
        root.Controls.Add(fileCard, 0, 0);

        // Card 2: Guidance
        var guideCard = CreateCard();
        guideCard.Dock = DockStyle.Fill;
        guideCard.Margin = new Padding(0, 0, 0, 12);

        var guideStack = new SmoothTableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 3,
            BackColor = Color.Transparent
        };
        guideStack.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        guideStack.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        guideStack.RowStyles.Add(new RowStyle(SizeType.AutoSize));

        var (guideTitle, guideBody) = BuildGuidanceText(actualFileSizeBytes, strategy);

        var guideTitleLabel = new Label
        {
            Text = guideTitle,
            AutoSize = true,
            Font = _sectionFont,
            ForeColor = strategy == ManualUploadStrategy.ExceedsVirusTotalLimit
                ? palette.WarningAmber
                : palette.AccentBlue,
            Margin = new Padding(0, 0, 0, 8)
        };

        var guideBodyLabel = new Label
        {
            Text = guideBody,
            AutoSize = true,
            MaximumSize = new Size(600, 0),
            Font = _bodyFont,
            ForeColor = palette.TextPrimary,
            Margin = new Padding(0, 0, 0, 8)
        };

        _inlineStatusLabel = new Label
        {
            Text = string.Empty,
            AutoSize = true,
            Font = _smallFont,
            ForeColor = palette.SuccessGreen,
            Visible = false,
            Margin = new Padding(0, 2, 0, 0)
        };

        guideStack.Controls.Add(guideTitleLabel, 0, 0);
        guideStack.Controls.Add(guideBodyLabel, 0, 1);
        guideStack.Controls.Add(_inlineStatusLabel, 0, 2);
        guideCard.Controls.Add(guideStack);
        root.Controls.Add(guideCard, 0, 1);

        // Action Bar
        var actionsBar = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = true,
            BackColor = Color.Transparent,
            Margin = new Padding(0),
            Padding = new Padding(0, 2, 0, 0)
        };

        BuildActionButtons(actionsBar, record, strategy, hasHash);
        root.Controls.Add(actionsBar, 0, 2);
    }

    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        ThemePalette.ApplyWindowTheme(this, _palette);
    }

    private void BuildActionButtons(
        FlowLayoutPanel bar,
        ScanRecord record,
        ManualUploadStrategy strategy,
        bool hasHash)
    {
        if (strategy == ManualUploadStrategy.LargeApiUpload)
        {
            var autoBtn = MakeButton("Upload Automatically Now", ModernButtonVariant.Primary);
            autoBtn.Click += (_, _) => FinishWithAction(ManualUploadAssistAction.UploadViaApi, DialogResult.OK);
            AcceptButton = autoBtn;

            var browserBtn = MakeButton("Upload Manually in Browser", ModernButtonVariant.Secondary);
            browserBtn.Click += (_, _) => FinishWithAction(ManualUploadAssistAction.OpenBrowserAndRevealFile, DialogResult.OK);

            var cancelBtn = MakeButton("Cancel", ModernButtonVariant.Ghost);
            cancelBtn.Click += (_, _) => FinishWithAction(ManualUploadAssistAction.Cancel, DialogResult.Cancel);
            CancelButton = cancelBtn;

            bar.Controls.AddRange([autoBtn, browserBtn, cancelBtn]);
        }
        else if (strategy == ManualUploadStrategy.ManualBrowserOnlyNoKey)
        {
            var browserBtn = MakeButton("Open VirusTotal + Reveal File", ModernButtonVariant.Primary);
            browserBtn.Click += (_, _) => FinishWithAction(ManualUploadAssistAction.OpenBrowserAndRevealFile, DialogResult.OK);
            AcceptButton = browserBtn;

            var settingsBtn = MakeButton("Open Settings", ModernButtonVariant.Secondary);
            settingsBtn.Click += (_, _) => FinishWithAction(ManualUploadAssistAction.OpenSettings, DialogResult.OK);

            var cancelBtn = MakeButton("Cancel", ModernButtonVariant.Ghost);
            cancelBtn.Click += (_, _) => FinishWithAction(ManualUploadAssistAction.Cancel, DialogResult.Cancel);
            CancelButton = cancelBtn;

            bar.Controls.AddRange([browserBtn, settingsBtn, cancelBtn]);
        }
        else
        {
            var hashBtn = MakeButton("Open Hash on VirusTotal", ModernButtonVariant.Primary);
            hashBtn.Enabled = hasHash;
            hashBtn.Click += (_, _) => FinishWithAction(ManualUploadAssistAction.OpenHashReport, DialogResult.OK);
            if (hasHash)
            {
                AcceptButton = hashBtn;
            }

            var copyBtn = MakeButton("Copy SHA-256", ModernButtonVariant.Secondary);
            copyBtn.Enabled = hasHash;
            copyBtn.Click += (_, _) =>
            {
                if (!hasHash)
                {
                    return;
                }

                try
                {
                    Clipboard.SetText(record.Sha256);
                    _inlineStatusLabel.ForeColor = _palette.SuccessGreen;
                    _inlineStatusLabel.Text = "SHA-256 copied to clipboard.";
                    _inlineStatusLabel.Visible = true;
                }
                catch (Exception ex)
                {
                    _inlineStatusLabel.ForeColor = _palette.WarningAmber;
                    _inlineStatusLabel.Text = $"Could not copy hash: {ex.Message}";
                    _inlineStatusLabel.Visible = true;
                }
            };

            var revealBtn = MakeButton("Reveal File in Explorer", ModernButtonVariant.Secondary);
            revealBtn.Enabled = File.Exists(record.FilePath);
            revealBtn.Click += (_, _) =>
            {
                try
                {
                    Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{record.FilePath}\"")
                    {
                        UseShellExecute = true
                    });
                }
                catch (Exception ex)
                {
                    _inlineStatusLabel.ForeColor = _palette.WarningAmber;
                    _inlineStatusLabel.Text = $"Could not open Explorer: {ex.Message}";
                    _inlineStatusLabel.Visible = true;
                }
            };

            var webBtn = MakeButton("Open VirusTotal Website", ModernButtonVariant.Secondary);
            webBtn.Click += (_, _) =>
            {
                try
                {
                    Process.Start(new ProcessStartInfo(VirusTotalClient.GuiUploadUrl)
                    {
                        UseShellExecute = true
                    });
                }
                catch
                {
                    // Ignore shell launch error in dialog.
                }
            };

            var closeBtn = MakeButton("Close", ModernButtonVariant.Ghost);
            closeBtn.Click += (_, _) => FinishWithAction(ManualUploadAssistAction.Cancel, DialogResult.Cancel);
            CancelButton = closeBtn;

            bar.Controls.AddRange([hashBtn, copyBtn, revealBtn, webBtn, closeBtn]);
        }
    }

    private void FinishWithAction(ManualUploadAssistAction action, DialogResult dialogResult)
    {
        SelectedAction = action;
        DialogResult = dialogResult;
        Close();
    }

    private ModernCardPanel CreateCard()
    {
        var card = new ModernCardPanel { Padding = new Padding(14) };
        card.ApplyTheme(_palette);
        _cards.Add(card);
        return card;
    }

    private ModernButton MakeButton(string text, ModernButtonVariant variant)
    {
        var btn = new ModernButton
        {
            Text = text,
            Variant = variant,
            AutoSize = true,
            Margin = new Padding(0, 0, 8, 6)
        };
        btn.ApplyTheme(_palette);
        _buttons.Add(btn);
        return btn;
    }

    private static (string Title, string Body) BuildGuidanceText(long sizeBytes, ManualUploadStrategy strategy)
    {
        string sizeText = FormatBytes(sizeBytes);
        return strategy switch
        {
            ManualUploadStrategy.LargeApiUpload => (
                "File exceeds the automatic upload size limit",
                $"This file is {sizeText}, which is larger than the 32 MB direct upload limit. VirusTotal still supports automatic uploads up to 650 MB through its large-file upload endpoint.\n\n" +
                "- Uses 1 extra VirusTotal API request to obtain a large-file upload URL.\n" +
                "- Depending on your upload speed, large uploads can take several minutes.\n" +
                "- Files uploaded to VirusTotal with a free API key are shared with the VirusTotal community."),

            ManualUploadStrategy.ManualBrowserOnlyNoKey => (
                "VirusTotal API key is not configured",
                $"Automatic uploads through VTDownloadGuard require a VirusTotal API key in Settings.\n\n" +
                $"You can either upload this {sizeText} file manually in your web browser (VTDownloadGuard will open the VirusTotal upload page and highlight the file in Explorer), or add your free API key in Settings first."),

            _ => (
                "VirusTotal limits all uploads to 650 MB",
                $"This file is {sizeText}. VirusTotal rejects both API uploads and browser uploads larger than 650 MB.\n\n" +
                "To inspect large installers, archives, or disk images:\n" +
                "- Check the file's SHA-256 hash on VirusTotal to see if it has already been analyzed.\n" +
                "- If it is an archive, installer, or extracted folder, unpack its contents and use Scan Folder... to scan the inner executables individually.")
        };
    }

    private static string FormatBytes(long bytes)
    {
        if (bytes <= 0)
        {
            return "0 B";
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

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _titleFont.Dispose();
            _sectionFont.Dispose();
            _boldFont.Dispose();
            _bodyFont.Dispose();
            _smallFont.Dispose();
            _monoFont.Dispose();
            _iconBox.Image?.Dispose();
        }

        base.Dispose(disposing);
    }
}
