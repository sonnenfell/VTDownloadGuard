using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Reflection;
using System.Windows.Forms;

namespace VTDownloadGuard.UI;

public enum ModernButtonVariant
{
    Primary = 0,
    Secondary = 1,
    Danger = 2,
    Ghost = 3
}

public sealed class ModernButton : Button
{
    private ModernButtonVariant _variant = ModernButtonVariant.Secondary;
    private ThemePalette _palette = ThemePalette.Dark;
    private bool _hovered;
    private bool _pressed;

    public ModernButton()
    {
        DoubleBuffered = true;
        FlatStyle = FlatStyle.Flat;
        FlatAppearance.BorderSize = 0;
        Cursor = Cursors.Hand;
        Height = 32;
        Padding = new Padding(12, 0, 12, 0);
        Font = new Font("Segoe UI Semibold", 9.0f);
    }

    [System.ComponentModel.DesignerSerializationVisibility(System.ComponentModel.DesignerSerializationVisibility.Hidden)]
    public ModernButtonVariant Variant
    {
        get => _variant;
        set
        {
            _variant = value;
            Invalidate();
        }
    }

    public void ApplyTheme(ThemePalette palette)
    {
        _palette = palette;
        Invalidate();
    }

    public override Size GetPreferredSize(Size proposedSize)
    {
        Size textSize = TextRenderer.MeasureText(Text, Font);
        return new Size(Math.Max(78, textSize.Width + 26), Math.Max(32, textSize.Height + 14));
    }

    protected override void OnMouseEnter(EventArgs e)
    {
        _hovered = true;
        Invalidate();
        base.OnMouseEnter(e);
    }

    protected override void OnMouseLeave(EventArgs e)
    {
        _hovered = false;
        _pressed = false;
        Invalidate();
        base.OnMouseLeave(e);
    }

    protected override void OnMouseDown(MouseEventArgs mevent)
    {
        if (mevent.Button == MouseButtons.Left)
        {
            _pressed = true;
            Invalidate();
        }

        base.OnMouseDown(mevent);
    }

    protected override void OnMouseUp(MouseEventArgs mevent)
    {
        _pressed = false;
        Invalidate();
        base.OnMouseUp(mevent);
    }

    protected override void OnPaint(PaintEventArgs pevent)
    {
        Graphics g = pevent.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.Clear(Parent?.BackColor ?? _palette.CanvasBg);

        var rect = new Rectangle(0, 0, Width - 1, Height - 1);
        var (bg, border, fg) = ResolveColors();

        using var path = ModernUiGeometry.CreateRoundedRect(rect, 6);
        using var bgBrush = new SolidBrush(bg);
        g.FillPath(bgBrush, path);

        if (border != Color.Transparent)
        {
            using var pen = new Pen(border, 1f);
            g.DrawPath(pen, path);
        }

        TextRenderer.DrawText(
            g,
            Text,
            Font,
            new Rectangle(2, 0, Width - 4, Height),
            fg,
            TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix);
    }

    private (Color Bg, Color Border, Color Fg) ResolveColors()
    {
        if (!Enabled)
        {
            return (_palette.CardAltBg, _palette.Border, _palette.TextMuted);
        }

        return _variant switch
        {
            ModernButtonVariant.Primary => (
                _pressed ? _palette.AccentBlue : (_hovered ? _palette.AccentBlueHover : _palette.AccentBlue),
                _palette.AccentBlue,
                Color.White),
            ModernButtonVariant.Danger => (
                _pressed ? _palette.DangerRed : (_hovered ? ControlPaint.Light(_palette.DangerRed, 0.12f) : _palette.DangerRed),
                _palette.DangerRed,
                Color.White),
            ModernButtonVariant.Ghost => (
                _pressed ? _palette.CardHoverBg : (_hovered ? _palette.CardAltBg : Color.Transparent),
                _hovered ? _palette.Border : Color.Transparent,
                _palette.TextSecondary),
            _ => (
                _pressed ? _palette.CardHoverBg : (_hovered ? _palette.CardHoverBg : _palette.CardBg),
                _palette.Border,
                _palette.TextPrimary)
        };
    }
}

public sealed class ModernNavBar : Control
{
    private sealed class NavTabItem
    {
        public string Title { get; init; } = string.Empty;
        public int BadgeCount { get; set; }
        public bool AlertBadge { get; set; }
        public Rectangle Bounds { get; set; }
    }

    private readonly List<NavTabItem> _tabs = [];
    private ThemePalette _palette = ThemePalette.Dark;
    private int _selectedIndex;
    private int _hoverIndex = -1;

    public event Action<int>? TabSelected;

    public ModernNavBar()
    {
        DoubleBuffered = true;
        Height = 44;
        Dock = DockStyle.Top;
        Font = new Font("Segoe UI Semibold", 9.5f);
        Cursor = Cursors.Hand;
    }

    [System.ComponentModel.DesignerSerializationVisibility(System.ComponentModel.DesignerSerializationVisibility.Hidden)]
    public int SelectedIndex
    {
        get => _selectedIndex;
        set
        {
            if (value >= 0 && value < _tabs.Count && _selectedIndex != value)
            {
                _selectedIndex = value;
                Invalidate();
            }
        }
    }

    public void SetTabs(params string[] titles)
    {
        _tabs.Clear();
        foreach (string title in titles)
        {
            _tabs.Add(new NavTabItem { Title = title });
        }

        if (_selectedIndex >= _tabs.Count)
        {
            _selectedIndex = 0;
        }

        RecalculateBounds();
        Invalidate();
    }

    public void SetBadge(int index, int count, bool alert = false)
    {
        if (index < 0 || index >= _tabs.Count)
        {
            return;
        }

        if (_tabs[index].BadgeCount == count && _tabs[index].AlertBadge == alert)
        {
            return;
        }

        _tabs[index].BadgeCount = count;
        _tabs[index].AlertBadge = alert;
        RecalculateBounds();
        Invalidate();
    }

    public void ApplyTheme(ThemePalette palette)
    {
        _palette = palette;
        BackColor = palette.TopBarBg;
        Invalidate();
    }

    public override Size GetPreferredSize(Size proposedSize)
    {
        int textHeight = TextRenderer.MeasureText("Settings", Font).Height;
        return new Size(Math.Max(200, proposedSize.Width), Math.Max(44, textHeight + 22));
    }

    protected override void OnResize(EventArgs e)
    {
        base.OnResize(e);
        RecalculateBounds();
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        int found = HitTest(e.Location);
        if (found != _hoverIndex)
        {
            _hoverIndex = found;
            Cursor = found >= 0 ? Cursors.Hand : Cursors.Default;
            Invalidate();
        }

        base.OnMouseMove(e);
    }

    protected override void OnMouseLeave(EventArgs e)
    {
        if (_hoverIndex != -1)
        {
            _hoverIndex = -1;
            Invalidate();
        }

        base.OnMouseLeave(e);
    }

    protected override void OnMouseDown(MouseEventArgs e)
    {
        if (e.Button == MouseButtons.Left)
        {
            int idx = HitTest(e.Location);
            if (idx >= 0 && idx < _tabs.Count)
            {
                _selectedIndex = idx;
                Invalidate();
                TabSelected?.Invoke(idx);
            }
        }

        base.OnMouseDown(e);
    }

    private int HitTest(Point pt)
    {
        for (int i = 0; i < _tabs.Count; i++)
        {
            if (_tabs[i].Bounds.Contains(pt))
            {
                return i;
            }
        }

        return -1;
    }

    private void RecalculateBounds()
    {
        int x = 16;
        using var badgeFont = new Font("Segoe UI Semibold", 8f);
        foreach (NavTabItem tab in _tabs)
        {
            Size titleSize = TextRenderer.MeasureText(tab.Title, Font);
            int width = titleSize.Width + 24;
            if (tab.BadgeCount > 0)
            {
                Size badgeSize = TextRenderer.MeasureText(tab.BadgeCount.ToString(), badgeFont);
                width += badgeSize.Width + 16;
            }

            tab.Bounds = new Rectangle(x, 2, width, Math.Max(36, Height - 4));
            x += width + 4;
        }
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        Graphics g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.Clear(_palette.TopBarBg);

        using var borderPen = new Pen(_palette.Border, 1f);
        g.DrawLine(borderPen, 0, Height - 1, Width, Height - 1);

        using var badgeFont = new Font("Segoe UI Semibold", 8f);
        for (int i = 0; i < _tabs.Count; i++)
        {
            NavTabItem tab = _tabs[i];
            bool selected = i == _selectedIndex;
            bool hovered = i == _hoverIndex;

            if (hovered && !selected)
            {
                using var hoverBrush = new SolidBrush(_palette.CardHoverBg);
                using var hoverPath = ModernUiGeometry.CreateRoundedRect(
                    new Rectangle(tab.Bounds.X, 5, tab.Bounds.Width, Height - 11), 6);
                g.FillPath(hoverBrush, hoverPath);
            }

            Color textColor = selected ? _palette.TextPrimary : _palette.TextSecondary;
            Size titleSize = TextRenderer.MeasureText(tab.Title, Font);
            int textX = tab.Bounds.X + 12;

            TextRenderer.DrawText(
                g,
                tab.Title,
                Font,
                new Rectangle(textX, 0, titleSize.Width + 4, Height - 2),
                textColor,
                TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPrefix);

            if (tab.BadgeCount > 0)
            {
                string badgeText = tab.BadgeCount.ToString();
                Size bSize = TextRenderer.MeasureText(badgeText, badgeFont);
                int badgeW = Math.Max(20, bSize.Width + 10);
                int badgeH = 18;
                int badgeX = textX + titleSize.Width + 4;
                int badgeY = (Height - badgeH) / 2 - 1;
                var badgeRect = new Rectangle(badgeX, badgeY, badgeW, badgeH);

                Color badgeBg = tab.AlertBadge ? _palette.DangerBg : _palette.AccentBlueBg;
                Color badgeFg = tab.AlertBadge ? _palette.DangerRed : _palette.AccentBlue;
                using var badgeBrush = new SolidBrush(badgeBg);
                using var badgePath = ModernUiGeometry.CreateRoundedRect(badgeRect, 9);
                g.FillPath(badgeBrush, badgePath);

                TextRenderer.DrawText(
                    g,
                    badgeText,
                    badgeFont,
                    badgeRect,
                    badgeFg,
                    TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPrefix);
            }

            if (selected)
            {
                using var indicatorBrush = new SolidBrush(_palette.AccentBlue);
                g.FillRectangle(indicatorBrush, tab.Bounds.X + 8, Height - 3, tab.Bounds.Width - 16, 3);
            }
        }
    }
}

public sealed class ModernCardPanel : Panel
{
    private ThemePalette _palette = ThemePalette.Dark;

    public ModernCardPanel()
    {
        DoubleBuffered = true;
        Padding = new Padding(16);
    }

    public void ApplyTheme(ThemePalette palette)
    {
        _palette = palette;
        BackColor = palette.CardBg;
        ForeColor = palette.TextPrimary;
        Invalidate();
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        Graphics g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.Clear(Parent?.BackColor ?? _palette.CanvasBg);

        var rect = new Rectangle(0, 0, Width - 1, Height - 1);
        using var path = ModernUiGeometry.CreateRoundedRect(rect, 8);
        using var bgBrush = new SolidBrush(_palette.CardBg);
        using var borderPen = new Pen(_palette.Border, 1f);
        g.FillPath(bgBrush, path);
        g.DrawPath(borderPen, path);
    }
}

public sealed class ModernProgressBar : Control
{
    private ThemePalette _palette = ThemePalette.Dark;
    private long _value;
    private long _maximum = 100;
    private bool _forceNeutral;

    public ModernProgressBar()
    {
        DoubleBuffered = true;
        Height = 10;
    }

    [System.ComponentModel.DesignerSerializationVisibility(System.ComponentModel.DesignerSerializationVisibility.Hidden)]
    public long Value
    {
        get => _value;
        set
        {
            _value = Math.Max(0, value);
            Invalidate();
        }
    }

    [System.ComponentModel.DesignerSerializationVisibility(System.ComponentModel.DesignerSerializationVisibility.Hidden)]
    public long Maximum
    {
        get => _maximum;
        set
        {
            _maximum = Math.Max(0, value);
            Invalidate();
        }
    }

    [System.ComponentModel.DesignerSerializationVisibility(System.ComponentModel.DesignerSerializationVisibility.Hidden)]
    public bool ForceNeutral
    {
        get => _forceNeutral;
        set
        {
            _forceNeutral = value;
            Invalidate();
        }
    }

    public void ApplyTheme(ThemePalette palette)
    {
        _palette = palette;
        Invalidate();
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        Graphics g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.Clear(Parent?.BackColor ?? _palette.CardBg);

        int barH = Math.Min(Height, 10);
        int barY = (Height - barH) / 2;
        var trackRect = new Rectangle(0, barY, Math.Max(10, Width - 1), barH);

        using var trackPath = ModernUiGeometry.CreateRoundedRect(trackRect, barH / 2);
        using var trackBrush = new SolidBrush(_palette.InputBg);
        using var trackBorder = new Pen(_palette.Border, 1f);
        g.FillPath(trackBrush, trackPath);
        g.DrawPath(trackBorder, trackPath);

        if (_maximum <= 0 || _value <= 0)
        {
            return;
        }

        double ratio = Math.Clamp((double)_value / _maximum, 0.0, 1.0);
        int fillW = Math.Max(barH, (int)Math.Round(trackRect.Width * ratio));
        var fillRect = new Rectangle(0, barY, Math.Min(trackRect.Width, fillW), barH);

        Color fillColor = _forceNeutral
            ? _palette.NeutralSlate
            : ratio >= 0.92
                ? _palette.DangerRed
                : ratio >= 0.75
                    ? _palette.WarningAmber
                    : _palette.AccentBlue;

        using var fillPath = ModernUiGeometry.CreateRoundedRect(fillRect, barH / 2);
        using var fillBrush = new SolidBrush(fillColor);
        g.FillPath(fillBrush, fillPath);
    }
}

public sealed class ModernThresholdSlider : Control
{
    public const int MinThreshold = 1;
    public const int MaxThreshold = 10;
    public const int RecommendedThreshold = 2;

    private ThemePalette _palette = ThemePalette.Dark;
    private int _value = RecommendedThreshold;
    private bool _dragging;

    public event Action<int>? ValueChanged;

    public ModernThresholdSlider()
    {
        DoubleBuffered = true;
        SetStyle(ControlStyles.Selectable | ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint, true);
        Size = new Size(460, 74);
        Cursor = Cursors.Hand;
        TabStop = true;
    }

    [System.ComponentModel.DesignerSerializationVisibility(System.ComponentModel.DesignerSerializationVisibility.Hidden)]
    public int Value
    {
        get => _value;
        set
        {
            int clamped = Math.Clamp(value, MinThreshold, MaxThreshold);
            if (_value != clamped)
            {
                _value = clamped;
                Invalidate();
                ValueChanged?.Invoke(_value);
            }
        }
    }

    public void ApplyTheme(ThemePalette palette)
    {
        _palette = palette;
        Invalidate();
    }

    public static Color GetThresholdColor(int value, ThemePalette palette)
    {
        bool dark = palette.IsDark;
        return Math.Clamp(value, MinThreshold, MaxThreshold) switch
        {
            1 => dark ? Color.FromArgb(129, 140, 248) : Color.FromArgb(79, 70, 229),
            2 => dark ? Color.FromArgb(34, 197, 94) : Color.FromArgb(22, 163, 74),
            3 => dark ? Color.FromArgb(20, 184, 166) : Color.FromArgb(13, 148, 136),
            4 or 5 => dark ? Color.FromArgb(245, 158, 11) : Color.FromArgb(217, 119, 6),
            6 or 7 => dark ? Color.FromArgb(249, 115, 22) : Color.FromArgb(234, 88, 12),
            _ => dark ? Color.FromArgb(239, 68, 68) : Color.FromArgb(220, 38, 38)
        };
    }

    public static (string Title, string Description) GetThresholdGuidance(int value)
    {
        int v = Math.Clamp(value, MinThreshold, MaxThreshold);
        return v switch
        {
            1 => (
                "1+ vendor (Very strict)",
                "Very strict. Theoretically the safest option, but realistically causes frequent false detections on indie games, mods, and fresh software updates without any real security benefit."),
            2 => (
                "2+ vendors (Recommended)",
                "Recommended default. Filters out most single-engine false alarms while still alerting you promptly on real threats."),
            3 => (
                "3+ vendors (Balanced)",
                "Balanced. Reduces occasional false positives on unsigned utilities and mods, with a slight chance of missing brand-new threats."),
            4 => (
                "4+ vendors (Moderate)",
                "Moderate. Fewer alerts from aggressive heuristic engines, though newer malware detected by only a few vendors will be logged as Low Risk instead of Unsafe."),
            5 => (
                "5+ vendors (Relaxed)",
                "Relaxed. Only alerts when several antivirus vendors agree. Very few false positives, but newly released or niche malware can slip through."),
            6 or 7 => (
                $"{v}+ vendors (Permissive)",
                "Permissive. Ignores low-consensus warnings. Only recommended if you frequently run unsigned tools and accept a higher risk of missed detections."),
            _ => (
                $"{v}+ vendors (Very permissive)",
                $"Very permissive. Only alerts on widely recognized malware. Risky for everyday downloads, because many active threats are flagged by fewer than {v} vendors at first.")
        };
    }

    protected override bool IsInputKey(Keys keyData) =>
        keyData is Keys.Left or Keys.Right or Keys.Up or Keys.Down or Keys.Home or Keys.End
        || base.IsInputKey(keyData);

    protected override void OnKeyDown(KeyEventArgs e)
    {
        switch (e.KeyCode)
        {
            case Keys.Left:
            case Keys.Down:
                Value--;
                e.Handled = true;
                break;
            case Keys.Right:
            case Keys.Up:
                Value++;
                e.Handled = true;
                break;
            case Keys.Home:
                Value = MinThreshold;
                e.Handled = true;
                break;
            case Keys.End:
                Value = MaxThreshold;
                e.Handled = true;
                break;
        }

        base.OnKeyDown(e);
    }

    protected override void OnGotFocus(EventArgs e)
    {
        Invalidate();
        base.OnGotFocus(e);
    }

    protected override void OnLostFocus(EventArgs e)
    {
        Invalidate();
        base.OnLostFocus(e);
    }

    protected override void OnMouseDown(MouseEventArgs e)
    {
        if (e.Button == MouseButtons.Left)
        {
            Focus();
            _dragging = true;
            UpdateValueFromMouseX(e.X);
        }

        base.OnMouseDown(e);
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        if (_dragging)
        {
            UpdateValueFromMouseX(e.X);
        }

        base.OnMouseMove(e);
    }

    protected override void OnMouseUp(MouseEventArgs e)
    {
        _dragging = false;
        base.OnMouseUp(e);
    }

    private void UpdateValueFromMouseX(int mouseX)
    {
        const float padX = 18f;
        float trackW = Math.Max(40f, Width - padX * 2f);
        float step = trackW / (MaxThreshold - MinThreshold);
        int idx = (int)Math.Round((mouseX - padX) / step);
        Value = Math.Clamp(MinThreshold + idx, MinThreshold, MaxThreshold);
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        Graphics g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.Clear(Parent?.BackColor ?? _palette.CardBg);

        Color activeColor = GetThresholdColor(_value, _palette);
        var (title, _) = GetThresholdGuidance(_value);

        using var badgeFont = new Font("Segoe UI Semibold", 8.6f);
        Size titleSize = TextRenderer.MeasureText(title, badgeFont);
        var pillRect = new Rectangle(0, 2, Math.Min(Width - 4, titleSize.Width + 18), 22);
        using (var pillPath = ModernUiGeometry.CreateRoundedRect(pillRect, 11))
        using (var pillBrush = new SolidBrush(Color.FromArgb(_palette.IsDark ? 42 : 28, activeColor)))
        {
            g.FillPath(pillBrush, pillPath);
        }

        TextRenderer.DrawText(
            g,
            title,
            badgeFont,
            pillRect,
            activeColor,
            TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPrefix);

        const float padX = 18f;
        float trackW = Math.Max(40f, Width - padX * 2f);
        float step = trackW / (MaxThreshold - MinThreshold);
        const int trackY = 36;
        const int trackH = 8;

        var trackRect = new Rectangle((int)padX - 4, trackY, (int)trackW + 8, trackH);
        using (var trackPath = ModernUiGeometry.CreateRoundedRect(trackRect, trackH / 2))
        using (var trackBrush = new SolidBrush(_palette.InputBg))
        using (var trackBorder = new Pen(_palette.Border, 1f))
        {
            g.FillPath(trackBrush, trackPath);
            g.DrawPath(trackBorder, trackPath);
        }

        float thumbX = padX + (_value - MinThreshold) * step;
        int fillW = Math.Max(trackH, (int)Math.Round(thumbX - (padX - 4)));
        var fillRect = new Rectangle((int)padX - 4, trackY, Math.Min(trackRect.Width, fillW), trackH);
        using (var fillPath = ModernUiGeometry.CreateRoundedRect(fillRect, trackH / 2))
        using (var fillBrush = new SolidBrush(activeColor))
        {
            g.FillPath(fillBrush, fillPath);
        }

        using var labelFont = new Font("Segoe UI", 8.2f);
        using var activeLabelFont = new Font("Segoe UI Semibold", 8.5f);

        for (int i = MinThreshold; i <= MaxThreshold; i++)
        {
            float cx = padX + (i - MinThreshold) * step;
            bool isSelected = i == _value;
            bool isPassed = i < _value;

            if (!isSelected)
            {
                Color dotColor = isPassed ? Color.FromArgb(215, 255, 255, 255) : _palette.TextMuted;
                using var dotBrush = new SolidBrush(dotColor);
                g.FillEllipse(dotBrush, cx - 2.2f, trackY + trackH / 2f - 2.2f, 4.4f, 4.4f);
            }

            var numRect = new Rectangle((int)Math.Round(cx - 12), 51, 24, 18);
            Color numColor = isSelected ? activeColor : _palette.TextSecondary;
            TextRenderer.DrawText(
                g,
                i.ToString(),
                isSelected ? activeLabelFont : labelFont,
                numRect,
                numColor,
                TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPrefix);

            if (i == RecommendedThreshold && !isSelected)
            {
                using var recBrush = new SolidBrush(GetThresholdColor(RecommendedThreshold, _palette));
                g.FillEllipse(recBrush, cx - 2f, 69f, 4f, 4f);
            }
        }

        const float thumbRadius = 8.5f;
        float thumbCenterY = trackY + trackH / 2f;
        if (Focused)
        {
            using var focusPen = new Pen(Color.FromArgb(110, activeColor), 2f);
            g.DrawEllipse(focusPen, thumbX - thumbRadius - 3, thumbCenterY - thumbRadius - 3, (thumbRadius + 3) * 2, (thumbRadius + 3) * 2);
        }

        using (var outerBrush = new SolidBrush(activeColor))
        using (var innerBrush = new SolidBrush(Color.White))
        {
            g.FillEllipse(outerBrush, thumbX - thumbRadius, thumbCenterY - thumbRadius, thumbRadius * 2, thumbRadius * 2);
            g.FillEllipse(innerBrush, thumbX - 3.5f, thumbCenterY - 3.5f, 7f, 7f);
        }
    }
}

public static class ModernGridHelper
{
    public static void ConfigureGrid(DataGridView grid, ThemePalette palette)
    {
        typeof(DataGridView)
            .GetProperty("DoubleBuffered", BindingFlags.Instance | BindingFlags.NonPublic)
            ?.SetValue(grid, true);

        grid.BorderStyle = BorderStyle.None;
        grid.CellBorderStyle = DataGridViewCellBorderStyle.SingleHorizontal;
        grid.GridColor = palette.Border;
        grid.BackgroundColor = palette.CardBg;
        grid.RowHeadersVisible = false;
        grid.AllowUserToAddRows = false;
        grid.AllowUserToDeleteRows = false;
        grid.AllowUserToResizeRows = false;
        grid.ReadOnly = true;
        grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
        grid.MultiSelect = false;
        grid.EnableHeadersVisualStyles = false;
        grid.ColumnHeadersBorderStyle = DataGridViewHeaderBorderStyle.Single;
        grid.ColumnHeadersHeight = 36;
        grid.ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.DisableResizing;
        grid.RowTemplate.Height = 38;
        grid.AutoSizeRowsMode = DataGridViewAutoSizeRowsMode.None;
        grid.ShowCellToolTips = true;

        grid.ColumnHeadersDefaultCellStyle = new DataGridViewCellStyle
        {
            BackColor = palette.CardAltBg,
            ForeColor = palette.TextSecondary,
            SelectionBackColor = palette.CardAltBg,
            SelectionForeColor = palette.TextSecondary,
            Font = new Font("Segoe UI Semibold", 8.8f),
            Padding = new Padding(8, 0, 8, 0),
            Alignment = DataGridViewContentAlignment.MiddleLeft
        };

        grid.DefaultCellStyle = new DataGridViewCellStyle
        {
            BackColor = palette.CardBg,
            ForeColor = palette.TextPrimary,
            SelectionBackColor = palette.CardHoverBg,
            SelectionForeColor = palette.TextPrimary,
            Font = new Font("Segoe UI", 9.0f),
            Padding = new Padding(8, 0, 8, 0),
            Alignment = DataGridViewContentAlignment.MiddleLeft
        };

        grid.AlternatingRowsDefaultCellStyle = new DataGridViewCellStyle
        {
            BackColor = palette.CardAltBg,
            ForeColor = palette.TextPrimary,
            SelectionBackColor = palette.CardHoverBg,
            SelectionForeColor = palette.TextPrimary,
            Font = new Font("Segoe UI", 9.0f),
            Padding = new Padding(8, 0, 8, 0),
            Alignment = DataGridViewContentAlignment.MiddleLeft
        };
    }

    public static void DrawPillCell(
        DataGridViewCellPaintingEventArgs e,
        string text,
        Color pillBg,
        Color pillFg,
        Font pillFont,
        ThemePalette palette)
    {
        if (e.Graphics is null)
        {
            return;
        }

        bool selected = (e.State & DataGridViewElementStates.Selected) != 0;
        Color cellBg = selected
            ? palette.CardHoverBg
            : (e.RowIndex % 2 == 1 ? palette.CardAltBg : palette.CardBg);

        using (var bgBrush = new SolidBrush(cellBg))
        {
            e.Graphics.FillRectangle(bgBrush, e.CellBounds);
        }

        using (var borderPen = new Pen(palette.Border, 1f))
        {
            e.Graphics.DrawLine(
                borderPen,
                e.CellBounds.Left,
                e.CellBounds.Bottom - 1,
                e.CellBounds.Right,
                e.CellBounds.Bottom - 1);
        }

        e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;

        Size textSize = TextRenderer.MeasureText(text, pillFont);
        int pillW = Math.Min(e.CellBounds.Width - 12, textSize.Width + 16);
        int pillH = 22;
        int pillX = e.CellBounds.X + 8;
        int pillY = e.CellBounds.Y + (e.CellBounds.Height - pillH) / 2;
        var pillRect = new Rectangle(pillX, pillY, Math.Max(24, pillW), pillH);

        using var path = ModernUiGeometry.CreateRoundedRect(pillRect, 11);
        using var pillBrush = new SolidBrush(pillBg);
        e.Graphics.FillPath(pillBrush, path);

        TextRenderer.DrawText(
            e.Graphics,
            text,
            pillFont,
            pillRect,
            pillFg,
            TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix);

        e.Handled = true;
    }
}

internal static class ModernUiGeometry
{
    public static GraphicsPath CreateRoundedRect(Rectangle rect, int radius)
    {
        var path = new GraphicsPath();
        int r = Math.Max(1, Math.Min(radius, Math.Min(rect.Width, rect.Height) / 2));
        int d = r * 2;
        path.AddArc(rect.X, rect.Y, d, d, 180, 90);
        path.AddArc(rect.Right - d, rect.Y, d, d, 270, 90);
        path.AddArc(rect.Right - d, rect.Bottom - d, d, d, 0, 90);
        path.AddArc(rect.X, rect.Bottom - d, d, d, 90, 90);
        path.CloseFigure();
        return path;
    }
}

public sealed class RecommendedStarIndicator : Control
{
    private ThemePalette _palette = ThemePalette.Dark;
    private bool _isAtRecommended;

    public RecommendedStarIndicator()
    {
        DoubleBuffered = true;
        Size = new Size(18, 18);
        Margin = new Padding(6, 4, 0, 0);
        TabStop = false;
    }

    [System.ComponentModel.DesignerSerializationVisibility(System.ComponentModel.DesignerSerializationVisibility.Hidden)]
    public bool IsAtRecommended
    {
        get => _isAtRecommended;
        set
        {
            if (_isAtRecommended != value)
            {
                _isAtRecommended = value;
                Invalidate();
            }
        }
    }

    public void ApplyTheme(ThemePalette palette)
    {
        _palette = palette;
        Invalidate();
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        Graphics g = e.Graphics;
        Color bg = Parent?.BackColor is { A: 255 } opaqueBg ? opaqueBg : _palette.CardBg;
        g.Clear(bg);

        if (!_isAtRecommended)
        {
            return;
        }

        g.SmoothingMode = SmoothingMode.AntiAlias;
        float cx = (Width - 1) / 2f;
        float cy = (Height - 1) / 2f;
        float outerR = Math.Min(Width, Height) * 0.42f;
        float innerR = outerR * 0.44f;

        var pts = new PointF[10];
        for (int i = 0; i < 10; i++)
        {
            double angle = -Math.PI / 2.0 + i * Math.PI / 5.0;
            float r = (i % 2 == 0) ? outerR : innerR;
            pts[i] = new PointF(
                cx + (float)(Math.Cos(angle) * r),
                cy + (float)(Math.Sin(angle) * r));
        }

        using var path = new GraphicsPath();
        path.AddPolygon(pts);

        Color fillColor = _palette.IsDark
            ? Color.FromArgb(196, 168, 92)
            : Color.FromArgb(182, 134, 34);
        Color strokeColor = _palette.IsDark
            ? Color.FromArgb(224, 198, 126)
            : Color.FromArgb(148, 106, 22);

        using var fillBrush = new SolidBrush(fillColor);
        using var strokePen = new Pen(strokeColor, 1f);
        g.FillPath(fillBrush, path);
        g.DrawPath(strokePen, path);
    }
}

public sealed class SmoothFlowLayoutPanel : FlowLayoutPanel
{
    public SmoothFlowLayoutPanel()
    {
        DoubleBuffered = true;
        SetStyle(ControlStyles.OptimizedDoubleBuffer | ControlStyles.AllPaintingInWmPaint, true);
    }
}

public sealed class SmoothTableLayoutPanel : TableLayoutPanel
{
    public SmoothTableLayoutPanel()
    {
        DoubleBuffered = true;
        SetStyle(ControlStyles.OptimizedDoubleBuffer | ControlStyles.AllPaintingInWmPaint, true);
    }
}
