using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using Microsoft.Win32;
using VTDownloadGuard.Models;

namespace VTDownloadGuard.UI;

public sealed class ThemePalette
{
    private const int DwmwaUseImmersiveDarkMode = 20;

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int attrValue, int attrSize);

    [DllImport("uxtheme.dll", CharSet = CharSet.Unicode)]
    private static extern int SetWindowTheme(IntPtr hWnd, string pszSubAppName, string? pszSubIdList);

    public required bool IsDark { get; init; }
    public required Color CanvasBg { get; init; }
    public required Color TopBarBg { get; init; }
    public required Color CardBg { get; init; }
    public required Color CardAltBg { get; init; }
    public required Color CardHoverBg { get; init; }
    public required Color InputBg { get; init; }
    public required Color Border { get; init; }
    public required Color TextPrimary { get; init; }
    public required Color TextSecondary { get; init; }
    public required Color TextMuted { get; init; }
    public required Color AccentBlue { get; init; }
    public required Color AccentBlueHover { get; init; }
    public required Color AccentBlueBg { get; init; }
    public required Color SuccessGreen { get; init; }
    public required Color SuccessBg { get; init; }
    public required Color WarningAmber { get; init; }
    public required Color WarningBg { get; init; }
    public required Color DangerRed { get; init; }
    public required Color DangerBg { get; init; }
    public required Color NeutralSlate { get; init; }
    public required Color NeutralBg { get; init; }

    public static ThemePalette Dark { get; } = new()
    {
        IsDark = true,
        CanvasBg = Color.FromArgb(17, 19, 24),
        TopBarBg = Color.FromArgb(22, 25, 34),
        CardBg = Color.FromArgb(28, 32, 41),
        CardAltBg = Color.FromArgb(34, 39, 51),
        CardHoverBg = Color.FromArgb(40, 46, 61),
        InputBg = Color.FromArgb(20, 23, 31),
        Border = Color.FromArgb(46, 53, 68),
        TextPrimary = Color.FromArgb(230, 232, 239),
        TextSecondary = Color.FromArgb(148, 163, 184),
        TextMuted = Color.FromArgb(100, 116, 139),
        AccentBlue = Color.FromArgb(79, 107, 255),
        AccentBlueHover = Color.FromArgb(99, 125, 255),
        AccentBlueBg = Color.FromArgb(30, 41, 77),
        SuccessGreen = Color.FromArgb(34, 197, 94),
        SuccessBg = Color.FromArgb(18, 45, 33),
        WarningAmber = Color.FromArgb(245, 158, 11),
        WarningBg = Color.FromArgb(48, 35, 18),
        DangerRed = Color.FromArgb(239, 68, 68),
        DangerBg = Color.FromArgb(52, 21, 26),
        NeutralSlate = Color.FromArgb(148, 163, 184),
        NeutralBg = Color.FromArgb(38, 44, 58)
    };

    public static ThemePalette Light { get; } = new()
    {
        IsDark = false,
        CanvasBg = Color.FromArgb(243, 245, 249),
        TopBarBg = Color.FromArgb(255, 255, 255),
        CardBg = Color.FromArgb(255, 255, 255),
        CardAltBg = Color.FromArgb(248, 250, 252),
        CardHoverBg = Color.FromArgb(238, 242, 248),
        InputBg = Color.FromArgb(255, 255, 255),
        Border = Color.FromArgb(221, 227, 237),
        TextPrimary = Color.FromArgb(17, 24, 39),
        TextSecondary = Color.FromArgb(75, 85, 99),
        TextMuted = Color.FromArgb(107, 114, 128),
        AccentBlue = Color.FromArgb(46, 82, 240),
        AccentBlueHover = Color.FromArgb(29, 78, 216),
        AccentBlueBg = Color.FromArgb(235, 240, 255),
        SuccessGreen = Color.FromArgb(21, 128, 61),
        SuccessBg = Color.FromArgb(220, 252, 231),
        WarningAmber = Color.FromArgb(180, 83, 9),
        WarningBg = Color.FromArgb(254, 243, 199),
        DangerRed = Color.FromArgb(185, 28, 28),
        DangerBg = Color.FromArgb(254, 226, 226),
        NeutralSlate = Color.FromArgb(71, 85, 105),
        NeutralBg = Color.FromArgb(226, 232, 240)
    };

    public static bool IsWindowsDarkMode()
    {
        try
        {
            using RegistryKey? key = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
                writable: false);
            object? val = key?.GetValue("AppsUseLightTheme");
            return val is int i && i == 0;
        }
        catch
        {
            return true;
        }
    }

    public static ThemePalette Resolve(AppThemeMode mode) => mode switch
    {
        AppThemeMode.Dark => Dark,
        AppThemeMode.Light => Light,
        _ => IsWindowsDarkMode() ? Dark : Light
    };

    public static void ApplyWindowTheme(Form form, ThemePalette palette)
    {
        if (form.IsDisposed || !form.IsHandleCreated)
        {
            return;
        }

        try
        {
            int useDark = palette.IsDark ? 1 : 0;
            _ = DwmSetWindowAttribute(form.Handle, DwmwaUseImmersiveDarkMode, ref useDark, sizeof(int));
        }
        catch
        {
            // Ignore on older Windows versions.
        }

        ApplyScrollThemeRecursive(form, palette.IsDark ? "DarkMode_Explorer" : "Explorer");
    }

    private static void ApplyScrollThemeRecursive(Control parent, string themeName)
    {
        if (parent.IsHandleCreated && (parent is ScrollableControl || parent is DataGridView || parent is ComboBox))
        {
            try
            {
                _ = SetWindowTheme(parent.Handle, themeName, null);
            }
            catch
            {
                // Ignore unsupported controls.
            }
        }

        foreach (Control child in parent.Controls)
        {
            ApplyScrollThemeRecursive(child, themeName);
        }
    }

    public (Color Bg, Color Fg) GetVerdictColors(ScanVerdict verdict) => verdict switch
    {
        ScanVerdict.Unsafe => (DangerBg, DangerRed),
        ScanVerdict.LowRisk => (WarningBg, WarningAmber),
        ScanVerdict.Clean => (SuccessBg, SuccessGreen),
        ScanVerdict.Error => (DangerBg, DangerRed),
        _ => (NeutralBg, NeutralSlate)
    };

    public (Color Bg, Color Fg) GetRiskColors(FileRiskCategory risk) => risk switch
    {
        FileRiskCategory.Critical => (DangerBg, DangerRed),
        FileRiskCategory.High => (WarningBg, WarningAmber),
        FileRiskCategory.Medium => (AccentBlueBg, AccentBlue),
        FileRiskCategory.Low => (SuccessBg, SuccessGreen),
        FileRiskCategory.Trusted => (SuccessBg, SuccessGreen),
        _ => (NeutralBg, NeutralSlate)
    };
}

public sealed class ThemedToolStripRenderer : ToolStripProfessionalRenderer
{
    private readonly ThemePalette _palette;

    public ThemedToolStripRenderer(ThemePalette palette)
        : base(new ThemedColorTable(palette))
    {
        _palette = palette;
        RoundedEdges = true;
    }

    protected override void OnRenderItemText(ToolStripItemTextRenderEventArgs e)
    {
        e.TextColor = e.Item.Enabled ? _palette.TextPrimary : _palette.TextMuted;
        base.OnRenderItemText(e);
    }

    protected override void OnRenderToolStripBorder(ToolStripRenderEventArgs e)
    {
        using var pen = new Pen(_palette.Border);
        var rect = new Rectangle(0, 0, e.AffectedBounds.Width - 1, e.AffectedBounds.Height - 1);
        e.Graphics.DrawRectangle(pen, rect);
    }

    protected override void OnRenderSeparator(ToolStripSeparatorRenderEventArgs e)
    {
        int y = e.Item.ContentRectangle.Height / 2;
        using var pen = new Pen(_palette.Border);
        e.Graphics.DrawLine(pen, 8, y, e.Item.Width - 8, y);
    }

    protected override void OnRenderMenuItemBackground(ToolStripItemRenderEventArgs e)
    {
        if (!e.Item.Enabled)
        {
            return;
        }

        var rect = new Rectangle(4, 2, e.Item.Width - 8, e.Item.Height - 4);
        if (e.Item.Selected)
        {
            e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            using var brush = new SolidBrush(_palette.CardHoverBg);
            using var path = CreateRoundedPath(rect, 5);
            e.Graphics.FillPath(brush, path);
        }
    }

    private static GraphicsPath CreateRoundedPath(Rectangle rect, int radius)
    {
        var path = new GraphicsPath();
        int d = radius * 2;
        path.AddArc(rect.X, rect.Y, d, d, 180, 90);
        path.AddArc(rect.Right - d, rect.Y, d, d, 270, 90);
        path.AddArc(rect.Right - d, rect.Bottom - d, d, d, 0, 90);
        path.AddArc(rect.X, rect.Bottom - d, d, d, 90, 90);
        path.CloseFigure();
        return path;
    }

    private sealed class ThemedColorTable(ThemePalette palette) : ProfessionalColorTable
    {
        public override Color ToolStripDropDownBackground => palette.CardBg;
        public override Color MenuItemSelected => palette.CardHoverBg;
        public override Color MenuItemSelectedGradientBegin => palette.CardHoverBg;
        public override Color MenuItemSelectedGradientEnd => palette.CardHoverBg;
        public override Color MenuItemBorder => palette.Border;
        public override Color MenuBorder => palette.Border;
        public override Color ImageMarginGradientBegin => palette.CardBg;
        public override Color ImageMarginGradientMiddle => palette.CardBg;
        public override Color ImageMarginGradientEnd => palette.CardBg;
        public override Color SeparatorDark => palette.Border;
        public override Color SeparatorLight => palette.Border;
    }
}
