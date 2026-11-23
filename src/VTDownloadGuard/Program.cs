using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows.Forms;
using VTDownloadGuard.Services;
using VTDownloadGuard.UI;

namespace VTDownloadGuard;

internal static class Program
{
    private const string SingleInstanceMutexName = @"Local\VTDownloadGuard_SingleInstance_v1";
    private const string ShowDashboardMessageName = "VTDownloadGuard_ShowDashboard_v1";
    private static readonly IntPtr HwndBroadcast = new(0xffff);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint RegisterWindowMessageW(string lpString);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool PostMessageW(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

    [STAThread]
    private static void Main(string[] args)
    {
        ApplicationConfiguration.Initialize();
        Application.SetColorMode(SystemColorMode.System);

        uint showDashboardMsg = RegisterWindowMessageW(ShowDashboardMessageName);

        using var mutex = new Mutex(initiallyOwned: true, SingleInstanceMutexName, out bool createdNew);
        if (!createdNew)
        {
            if (showDashboardMsg != 0)
            {
                PostMessageW(HwndBroadcast, showDashboardMsg, IntPtr.Zero, IntPtr.Zero);
            }

            return;
        }

        var paths = new AppPaths();
        var logger = new AppLogger(paths);
        logger.Info("VTDownloadGuard starting...");

        var settingsStore = new SettingsStore(paths, logger);
        var historyStore = new HistoryAndCacheStore(paths, logger);
        var initialSettings = settingsStore.Load();
        var rateLimiter = new RateLimiter(initialSettings.MaxRequestsPerMinute);
        var vtClient = new VirusTotalClient(rateLimiter, logger);
        var scanEngine = new ScanEngine(settingsStore, historyStore, rateLimiter, vtClient, logger);

        bool openDashboardOnStart = args.Any(a => string.Equals(a, "--open", StringComparison.OrdinalIgnoreCase));

        using var context = new TrayApplicationContext(
            scanEngine,
            vtClient,
            paths,
            logger,
            showDashboardMsg,
            openDashboardOnStart);

        Application.Run(context);
        logger.Info("VTDownloadGuard exited cleanly.");
    }
}
