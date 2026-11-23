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
