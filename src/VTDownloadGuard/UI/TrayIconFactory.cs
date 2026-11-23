using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using VTDownloadGuard.Models;

namespace VTDownloadGuard.UI;

/// <summary>
/// Loads the embedded multi-resolution application icon and renders crisp
/// status tray icons for each monitor state.
/// </summary>
public sealed class TrayIconFactory : IDisposable
{
    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DestroyIcon(IntPtr hIcon);

    private readonly Icon _appIcon;
    private readonly Icon _safeIcon;
    private readonly Icon _scanningFrame0;
    private readonly Icon _scanningFrame1;
    private readonly Icon _unsafeIcon;
    private readonly Icon _needsSetupIcon;
    private bool _disposed;

    public TrayIconFactory()
    {
        _safeIcon = CreateSafeIcon();
        _scanningFrame0 = CreateScanningIcon(frame: 0);
        _scanningFrame1 = CreateScanningIcon(frame: 1);
        _unsafeIcon = CreateUnsafeIcon();
        _needsSetupIcon = CreateNeedsSetupIcon();
        _appIcon = LoadEmbeddedAppIcon() ?? (Icon)_safeIcon.Clone();
    }

    public Icon AppIcon => _appIcon;

    public Icon GetIcon(TrayStatus status, int animationFrame = 0) => status switch
    {
        TrayStatus.Safe => _safeIcon,
        TrayStatus.Scanning => (animationFrame & 1) == 0 ? _scanningFrame0 : _scanningFrame1,
        TrayStatus.Unsafe => _unsafeIcon,
        TrayStatus.NeedsSetup => _needsSetupIcon,
        _ => _safeIcon
    };

    private static Icon? LoadEmbeddedAppIcon()
    {
        try
        {
            using Stream? stream = Assembly.GetExecutingAssembly()
                .GetManifestResourceStream("VTDownloadGuard.app.ico");
            return stream is not null ? new Icon(stream) : null;
        }
        catch
        {
            return null;
        }
    }

    private static Icon CreateSafeIcon() => RenderShieldIcon(
        Color.FromArgb(34, 197, 94),
        Color.FromArgb(21, 128, 61),
        g =>
        {
            using var pen = new Pen(Color.White, 3.2f)
            {
                StartCap = LineCap.Round,
                EndCap = LineCap.Round,
                LineJoin = LineJoin.Round
            };
            g.DrawLines(pen,
            [
                new PointF(10.0f, 16.5f),
                new PointF(14.2f, 20.8f),
                new PointF(22.2f, 11.8f)
            ]);
        });

    private static Icon CreateScanningIcon(int frame) => RenderShieldIcon(
        Color.FromArgb(79, 107, 255),
        Color.FromArgb(30, 58, 138),
        g =>
        {
            float startAngle = frame == 0 ? -50f : 130f;
            using var arcPen = new Pen(Color.White, 2.8f)
            {
                StartCap = LineCap.Round,
                EndCap = LineCap.Round
            };
            g.DrawArc(arcPen, 10.5f, 10.5f, 11f, 11f, startAngle, 220f);

            using var dotBrush = new SolidBrush(Color.FromArgb(191, 219, 254));
            g.FillEllipse(dotBrush, 14.3f, 14.3f, 3.4f, 3.4f);
        });

    private static Icon CreateUnsafeIcon() => RenderShieldIcon(
        Color.FromArgb(239, 68, 68),
        Color.FromArgb(153, 27, 27),
        g =>
        {
            using var barPen = new Pen(Color.White, 3.2f)
            {
                StartCap = LineCap.Round,
                EndCap = LineCap.Round
            };
            g.DrawLine(barPen, 16.0f, 9.8f, 16.0f, 17.5f);

            using var dotBrush = new SolidBrush(Color.White);
            g.FillEllipse(dotBrush, 14.2f, 20.2f, 3.6f, 3.6f);
        });

    private static Icon CreateNeedsSetupIcon() => RenderShieldIcon(
        Color.FromArgb(100, 116, 139),
        Color.FromArgb(51, 65, 85),
        g =>
        {
            using var qPen = new Pen(Color.White, 2.6f)
            {
                StartCap = LineCap.Round,
                EndCap = LineCap.Round
            };
            g.DrawArc(qPen, 12.2f, 9.5f, 7.6f, 6.8f, 185f, 235f);
            g.DrawLine(qPen, 16.0f, 16.3f, 16.0f, 18.0f);

            using var dotBrush = new SolidBrush(Color.FromArgb(253, 224, 71));
            g.FillEllipse(dotBrush, 14.3f, 20.4f, 3.4f, 3.4f);
        });

    private static Icon RenderShieldIcon(Color fillColor, Color borderColor, Action<Graphics> drawGlyph)
    {
        using var bmp = new Bitmap(32, 32);
        using (var g = Graphics.FromImage(bmp))
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.PixelOffsetMode = PixelOffsetMode.HighQuality;
            g.Clear(Color.Transparent);

            using var shieldPath = CreateShieldPath();
            using var fillBrush = new SolidBrush(fillColor);
            using var borderPen = new Pen(borderColor, 1.8f) { LineJoin = LineJoin.Round };

            g.FillPath(fillBrush, shieldPath);
            g.DrawPath(borderPen, shieldPath);
            drawGlyph(g);
        }

        IntPtr hIcon = bmp.GetHicon();
        try
        {
            using Icon managed = Icon.FromHandle(hIcon);
            return (Icon)managed.Clone();
        }
        finally
        {
            DestroyIcon(hIcon);
        }
    }

    private static GraphicsPath CreateShieldPath()
    {
        var path = new GraphicsPath();
        path.AddLines(
        [
            new PointF(16.0f, 2.0f),
            new PointF(28.5f, 6.2f),
            new PointF(27.5f, 16.8f),
            new PointF(22.6f, 24.8f),
            new PointF(16.0f, 30.0f),
            new PointF(9.4f, 24.8f),
            new PointF(4.5f, 16.8f),
            new PointF(3.5f, 6.2f)
        ]);
        path.CloseFigure();
        return path;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _appIcon.Dispose();
        _safeIcon.Dispose();
        _scanningFrame0.Dispose();
        _scanningFrame1.Dispose();
        _unsafeIcon.Dispose();
        _needsSetupIcon.Dispose();
    }
}
