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
        if (args.Any(a => string.Equals(a, "--apply-update", StringComparison.OrdinalIgnoreCase)))
        {
            Environment.ExitCode = SelfUpdateApplier.Run(args);
            return;
        }

        string? cleanupPath = GetArgValue(args, "--cleanup-update");
        if (!string.IsNullOrWhiteSpace(cleanupPath))
        {
            SelfUpdateApplier.ScheduleStagingCleanup(cleanupPath);
        }

        ApplicationConfiguration.Initialize();
        Application.SetColorMode(SystemColorMode.System);

        uint showDashboardMsg = RegisterWindowMessageW(ShowDashboardMessageName);
        bool afterUpdate = args.Any(a => string.Equals(a, "--after-update", StringComparison.OrdinalIgnoreCase));

        Mutex? mutex = AcquireSingleInstanceMutex(afterUpdate, out bool createdNew);
        if (!createdNew || mutex is null)
        {
            mutex?.Dispose();
            if (showDashboardMsg != 0)
            {
                PostMessageW(HwndBroadcast, showDashboardMsg, IntPtr.Zero, IntPtr.Zero);
            }

            return;
        }

        using (mutex)
        {
            var paths = new AppPaths();
            var logger = new AppLogger(paths);
            logger.Info("VTDownloadGuard starting...");

            var settingsStore = new SettingsStore(paths, logger);
            var historyStore = new HistoryAndCacheStore(paths, logger);
            var initialSettings = settingsStore.Load();
            var rateLimiter = new RateLimiter(initialSettings.MaxRequestsPerMinute);
            var vtClient = new VirusTotalClient(rateLimiter, logger);
            var scanEngine = new ScanEngine(settingsStore, historyStore, rateLimiter, vtClient, logger);
            var updateService = new UpdateService(paths, logger);

            bool openDashboardOnStart = args.Any(a => string.Equals(a, "--open", StringComparison.OrdinalIgnoreCase));

            using var context = new TrayApplicationContext(
                scanEngine,
                vtClient,
                updateService,
                paths,
                logger,
                showDashboardMsg,
                openDashboardOnStart);

            Application.Run(context);
            logger.Info("VTDownloadGuard exited cleanly.");
        }
    }

    private static Mutex? AcquireSingleInstanceMutex(bool waitAfterUpdate, out bool createdNew)
    {
        int maxAttempts = waitAfterUpdate ? 12 : 1;
        for (int attempt = 1; attempt <= maxAttempts; attempt++)
        {
            var m = new Mutex(initiallyOwned: true, SingleInstanceMutexName, out createdNew);
            if (createdNew)
            {
                return m;
            }

            m.Dispose();
            if (attempt < maxAttempts)
            {
                Thread.Sleep(250);
            }
        }

        createdNew = false;
        return null;
    }

    private static string? GetArgValue(string[] args, string flag)
    {
        for (int i = 0; i < args.Length - 1; i++)
        {
            if (string.Equals(args[i], flag, StringComparison.OrdinalIgnoreCase))
            {
                return args[i + 1];
            }
        }

        return null;
    }
}
