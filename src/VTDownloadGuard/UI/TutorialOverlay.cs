using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace VTDownloadGuard.UI;

public sealed record TutorialStep(
    int TabIndex,
    Func<Control?> TargetProvider,
    string Title,
    string Description,
    Action? BeforeShow = null);

public sealed class TutorialSession : IDisposable
{
    private sealed class BackdropOverlayForm : Form
    {
        private readonly ThemePalette _palette;
        private Rectangle _spotlightRect;

        public BackdropOverlayForm(ThemePalette palette)
        {
            _palette = palette;
            DoubleBuffered = true;
            FormBorderStyle = FormBorderStyle.None;
            ShowInTaskbar = false;
            StartPosition = FormStartPosition.Manual;
            BackColor = Color.FromArgb(10, 12, 18);
            TransparencyKey = Color.Magenta;
            Opacity = 0.72;
            KeyPreview = true;
        }

        public void SetSpotlight(Rectangle rect)
        {
            _spotlightRect = rect;
            Invalidate();
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics;
            g.SmoothingMode = SmoothingMode.None;
            g.Clear(BackColor);

            if (_spotlightRect.Width > 0 && _spotlightRect.Height > 0)
            {
                using (var holeBrush = new SolidBrush(Color.Magenta))
                {
                    g.FillRectangle(holeBrush, _spotlightRect);
                }

                g.SmoothingMode = SmoothingMode.AntiAlias;
                var borderRect = Rectangle.Inflate(_spotlightRect, 1, 1);
                using var borderPen = new Pen(_palette.AccentBlue, 3f);
                g.DrawRectangle(borderPen, borderRect);
            }
        }
    }

    private sealed class CalloutCardForm : Form
    {
        private readonly ThemePalette _palette;
        private readonly Font _pillFont = new("Segoe UI Semibold", 8.2f);
        private readonly Font _titleFont = new("Segoe UI Semibold", 10.5f);
        private readonly Font _bodyFont = new("Segoe UI", 9.0f);

        private readonly Label _stepLabel;
        private readonly Label _titleLabel;
        private readonly Label _descLabel;
        private readonly ModernButton _skipBtn;
        private readonly ModernButton _backBtn;
        private readonly ModernButton _nextBtn;

        public event Action? SkipRequested;
        public event Action? BackRequested;
        public event Action? NextRequested;

        public CalloutCardForm(ThemePalette palette)
        {
            _palette = palette;
            DoubleBuffered = true;
            FormBorderStyle = FormBorderStyle.None;
            ShowInTaskbar = false;
            StartPosition = FormStartPosition.Manual;
            BackColor = palette.CardBg;
            ForeColor = palette.TextPrimary;
            Width = 380;
            KeyPreview = true;

            _stepLabel = new Label
            {
                AutoSize = true,
                Font = _pillFont,
                BackColor = palette.AccentBlueBg,
                ForeColor = palette.AccentBlue,
                Padding = new Padding(8, 3, 8, 3),
                Location = new Point(16, 14)
            };

            _titleLabel = new Label
            {
                AutoSize = true,
                MaximumSize = new Size(346, 0),
                Font = _titleFont,
                ForeColor = palette.TextPrimary,
                Location = new Point(16, 44)
            };

            _descLabel = new Label
            {
                AutoSize = true,
                MaximumSize = new Size(346, 0),
                Font = _bodyFont,
                ForeColor = palette.TextSecondary,
                Location = new Point(16, 72)
            };

            _skipBtn = new ModernButton { Text = "Skip Tour", Variant = ModernButtonVariant.Ghost, AutoSize = true };
            _skipBtn.ApplyTheme(palette);
            _skipBtn.Click += (_, _) => SkipRequested?.Invoke();

            _backBtn = new ModernButton { Text = "Back", Variant = ModernButtonVariant.Secondary, AutoSize = true };
            _backBtn.ApplyTheme(palette);
            _backBtn.Click += (_, _) => BackRequested?.Invoke();

            _nextBtn = new ModernButton { Text = "Next", Variant = ModernButtonVariant.Primary, AutoSize = true };
            _nextBtn.ApplyTheme(palette);
            _nextBtn.Click += (_, _) => NextRequested?.Invoke();

            Controls.AddRange([_stepLabel, _titleLabel, _descLabel, _skipBtn, _backBtn, _nextBtn]);
        }

        public void SetContent(int stepIndex, int totalSteps, string title, string description)
        {
            _stepLabel.Text = $"Step {stepIndex + 1} of {totalSteps}";
            _titleLabel.Text = title;

            int descY = _titleLabel.Bottom + 8;
            _descLabel.Location = new Point(16, descY);
            _descLabel.Text = description;

            int buttonY = _descLabel.Bottom + 16;
            _backBtn.Visible = stepIndex > 0;
            _nextBtn.Text = stepIndex == totalSteps - 1 ? "Finish" : "Next";

            _skipBtn.Location = new Point(12, buttonY);
            _nextBtn.Location = new Point(Width - 16 - _nextBtn.Width, buttonY);
            _backBtn.Location = new Point(_nextBtn.Left - 8 - _backBtn.Width, buttonY);

            Height = _nextBtn.Bottom + 14;
            Invalidate();
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e);
            using var pen = new Pen(_palette.AccentBlue, 1.5f);
            e.Graphics.DrawRectangle(pen, 0, 0, Width - 1, Height - 1);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _pillFont.Dispose();
                _titleFont.Dispose();
                _bodyFont.Dispose();
            }

            base.Dispose(disposing);
        }
    }

    private readonly Form _dashboard;
    private readonly IReadOnlyList<TutorialStep> _steps;
    private readonly Action<int> _switchTab;
    private readonly ThemePalette _palette;

    private readonly BackdropOverlayForm _backdrop;
    private readonly CalloutCardForm _callout;

    private int _currentIndex;
    private Rectangle _spotlightScreenRect;
    private bool _disposed;

    public event Action? Closed;

    public TutorialSession(
        Form dashboard,
        IReadOnlyList<TutorialStep> steps,
        Action<int> switchTab,
        ThemePalette palette)
    {
        _dashboard = dashboard;
        _steps = steps;
        _switchTab = switchTab;
        _palette = palette;

        _backdrop = new BackdropOverlayForm(palette);
        _callout = new CalloutCardForm(palette);

        _callout.SkipRequested += Dispose;
        _callout.BackRequested += PreviousStep;
        _callout.NextRequested += NextStep;

        _backdrop.KeyDown += OnOverlayKeyDown;
        _callout.KeyDown += OnOverlayKeyDown;

        _dashboard.LocationChanged += OnDashboardMovedOrResized;
        _dashboard.SizeChanged += OnDashboardMovedOrResized;
        _dashboard.FormClosed += OnDashboardClosed;
    }

    public int CurrentStepIndex => _currentIndex;

    public void Start()
    {
        if (_disposed || _steps.Count == 0)
        {
            return;
        }

        ShowStep(0);
        if (_dashboard.Visible && _dashboard.IsHandleCreated)
        {
            _backdrop.Show(_dashboard);
            _callout.Show(_backdrop);
            _callout.Focus();
        }
    }

    public void NextStep()
    {
        if (_disposed)
        {
            return;
        }

        if (_currentIndex + 1 >= _steps.Count)
        {
            Dispose();
            return;
        }

        ShowStep(_currentIndex + 1);
    }

    public void PreviousStep()
    {
        if (_disposed || _currentIndex <= 0)
        {
            return;
        }

        ShowStep(_currentIndex - 1);
    }

    public void ShowStep(int index)
    {
        if (_disposed || _steps.Count == 0)
        {
            return;
        }

        _currentIndex = Math.Clamp(index, 0, _steps.Count - 1);
        TutorialStep step = _steps[_currentIndex];

        _switchTab(step.TabIndex);
        _dashboard.PerformLayout();
        step.BeforeShow?.Invoke();
        _dashboard.PerformLayout();

        UpdateOverlayPositions();
        _callout.SetContent(_currentIndex, _steps.Count, step.Title, step.Description);
        PositionCallout();
    }

    private void OnOverlayKeyDown(object? sender, KeyEventArgs e)
    {
        switch (e.KeyCode)
        {
            case Keys.Escape:
                Dispose();
                e.Handled = true;
                break;
            case Keys.Right:
            case Keys.Enter:
                NextStep();
                e.Handled = true;
                break;
            case Keys.Left:
                PreviousStep();
                e.Handled = true;
                break;
        }
    }

    private void OnDashboardMovedOrResized(object? sender, EventArgs e)
    {
        if (_disposed)
        {
            return;
        }

        UpdateOverlayPositions();
        PositionCallout();
    }

    private void OnDashboardClosed(object? sender, FormClosedEventArgs e)
    {
        Dispose();
    }

    private void UpdateOverlayPositions()
    {
        Rectangle clientScreen = _dashboard.RectangleToScreen(_dashboard.ClientRectangle);
        _backdrop.Bounds = clientScreen;

        TutorialStep step = _steps[_currentIndex];
        Control? target = step.TargetProvider();

        if (target is not null && target.Visible && target.Width > 0 && target.Height > 0 && target.IsHandleCreated)
        {
            Rectangle targetScreen = target.RectangleToScreen(new Rectangle(0, 0, target.Width, target.Height));
            Rectangle paddedScreen = Rectangle.Inflate(targetScreen, 6, 6);
            Rectangle clampedScreen = Rectangle.Intersect(paddedScreen, clientScreen);
            _spotlightScreenRect = clampedScreen;
            Rectangle localRect = _backdrop.RectangleToClient(clampedScreen);
            _backdrop.SetSpotlight(localRect);
        }
        else
        {
            _spotlightScreenRect = Rectangle.Empty;
            _backdrop.SetSpotlight(Rectangle.Empty);
        }
    }

    private void PositionCallout()
    {
        Rectangle workArea = Screen.FromControl(_dashboard).WorkingArea;
        if (_spotlightScreenRect.IsEmpty)
        {
            int cx = workArea.Left + (workArea.Width - _callout.Width) / 2;
            int cy = workArea.Top + (workArea.Height - _callout.Height) / 2;
            _callout.Location = new Point(cx, cy);
            return;
        }

        const int gap = 14;
        int clampedLeft = Math.Clamp(
            _spotlightScreenRect.Left,
            workArea.Left + 8,
            Math.Max(workArea.Left + 8, workArea.Right - _callout.Width - 8));

        // 1. Try below
        int belowY = _spotlightScreenRect.Bottom + gap;
        if (belowY + _callout.Height <= workArea.Bottom - 8)
        {
            _callout.Location = new Point(clampedLeft, belowY);
            return;
        }

        // 2. Try above
        int aboveY = _spotlightScreenRect.Top - _callout.Height - gap;
        if (aboveY >= workArea.Top + 8)
        {
            _callout.Location = new Point(clampedLeft, aboveY);
            return;
        }

        // 3. Try right
        int rightX = _spotlightScreenRect.Right + gap;
        int clampedTop = Math.Clamp(
            _spotlightScreenRect.Top,
            workArea.Top + 8,
            Math.Max(workArea.Top + 8, workArea.Bottom - _callout.Height - 8));
        if (rightX + _callout.Width <= workArea.Right - 8)
        {
            _callout.Location = new Point(rightX, clampedTop);
            return;
        }

        // 4. Try left
        int leftX = _spotlightScreenRect.Left - _callout.Width - gap;
        if (leftX >= workArea.Left + 8)
        {
            _callout.Location = new Point(leftX, clampedTop);
            return;
        }

        // Fallback: bottom-right inside work area
        _callout.Location = new Point(
            Math.Max(workArea.Left + 8, workArea.Right - _callout.Width - 16),
            Math.Max(workArea.Top + 8, workArea.Bottom - _callout.Height - 16));
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _dashboard.LocationChanged -= OnDashboardMovedOrResized;
        _dashboard.SizeChanged -= OnDashboardMovedOrResized;
        _dashboard.FormClosed -= OnDashboardClosed;

        _callout.Close();
        _callout.Dispose();
        _backdrop.Close();
        _backdrop.Dispose();

        Closed?.Invoke();
    }
}
