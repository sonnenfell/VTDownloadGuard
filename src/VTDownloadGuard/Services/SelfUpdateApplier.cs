using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace VTDownloadGuard.Services;

/// <summary>
/// Applies staged portable updates out-of-process once the running instance exits,
/// preserving all user data stored in AppData.
/// </summary>
public static class SelfUpdateApplier
{
    public static int Run(string[] args)
    {
        int parentPid = 0;
        string sourceDir = string.Empty;
        string targetDir = string.Empty;
        string relaunchArg = "--minimized";
        string stagingRoot = string.Empty;

        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];
            if (arg.Equals("--pid", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                _ = int.TryParse(args[++i], out parentPid);
            }
            else if (arg.Equals("--source", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                sourceDir = args[++i];
            }
            else if (arg.Equals("--target", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                targetDir = args[++i];
            }
            else if (arg.Equals("--relaunch-arg", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                relaunchArg = args[++i];
            }
            else if (arg.Equals("--staging-root", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                stagingRoot = args[++i];
            }
        }

        if (string.IsNullOrWhiteSpace(sourceDir) || string.IsNullOrWhiteSpace(targetDir) || !Directory.Exists(sourceDir))
        {
            return 1;
        }

        if (parentPid > 0)
        {
            WaitForProcessExit(parentPid, TimeSpan.FromSeconds(20));
        }

        try
        {
            ApplyDirectoryCopy(sourceDir, targetDir);
        }
        catch
        {
            return 2;
        }

        string exePath = Path.Combine(targetDir, "VTDownloadGuard.exe");
        if (!File.Exists(exePath))
        {
            return 3;
        }

        try
        {
            var psi = new ProcessStartInfo(exePath)
            {
                WorkingDirectory = targetDir,
                UseShellExecute = false
            };

            if (!string.IsNullOrWhiteSpace(relaunchArg))
            {
                psi.ArgumentList.Add(relaunchArg);
            }

            psi.ArgumentList.Add("--after-update");
            if (!string.IsNullOrWhiteSpace(stagingRoot))
            {
                psi.ArgumentList.Add("--cleanup-update");
                psi.ArgumentList.Add(stagingRoot);
            }

            Process.Start(psi);
            return 0;
        }
        catch
        {
            return 4;
        }
    }

    public static void ApplyDirectoryCopy(string sourceDir, string targetDir)
    {
        if (string.IsNullOrWhiteSpace(sourceDir))
        {
            throw new ArgumentException("Source directory is required.", nameof(sourceDir));
        }

        if (string.IsNullOrWhiteSpace(targetDir))
        {
            throw new ArgumentException("Target directory is required.", nameof(targetDir));
        }

        string fullSource = Path.GetFullPath(sourceDir);
        string fullTarget = Path.GetFullPath(targetDir);
        Directory.CreateDirectory(fullTarget);

        foreach (string dir in Directory.GetDirectories(fullSource, "*", SearchOption.AllDirectories))
        {
            string rel = Path.GetRelativePath(fullSource, dir);
            Directory.CreateDirectory(Path.Combine(fullTarget, rel));
        }

        foreach (string srcFile in Directory.GetFiles(fullSource, "*", SearchOption.AllDirectories))
        {
            string rel = Path.GetRelativePath(fullSource, srcFile);
            string dstFile = Path.Combine(fullTarget, rel);
            string? dstParent = Path.GetDirectoryName(dstFile);
            if (!string.IsNullOrEmpty(dstParent))
            {
                Directory.CreateDirectory(dstParent);
            }

            CopyFileWithRetries(srcFile, dstFile);
        }
    }

    public static void ScheduleStagingCleanup(string? stagingPath)
    {
        if (string.IsNullOrWhiteSpace(stagingPath))
        {
            return;
        }

        string fullStaging;
        string fullTemp;
        try
        {
            fullStaging = Path.GetFullPath(stagingPath);
            fullTemp = Path.GetFullPath(Path.GetTempPath());
        }
        catch
        {
            return;
        }

        if (!fullStaging.StartsWith(fullTemp, StringComparison.OrdinalIgnoreCase)
            || string.Equals(fullStaging.TrimEnd('\\'), fullTemp.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        _ = Task.Run(async () =>
        {
            await Task.Delay(TimeSpan.FromSeconds(2.5)).ConfigureAwait(false);
            for (int attempt = 0; attempt < 5; attempt++)
            {
                try
                {
                    if (Directory.Exists(fullStaging))
                    {
                        Directory.Delete(fullStaging, recursive: true);
                    }

                    return;
                }
                catch
                {
                    await Task.Delay(TimeSpan.FromSeconds(1)).ConfigureAwait(false);
                }
            }
        });
    }

    private static void WaitForProcessExit(int pid, TimeSpan timeout)
    {
        try
        {
            using Process proc = Process.GetProcessById(pid);
            if (!proc.HasExited)
            {
                _ = proc.WaitForExit((int)timeout.TotalMilliseconds);
            }
        }
        catch
        {
            // Process already exited.
        }
    }

    private static void CopyFileWithRetries(string srcFile, string dstFile)
    {
        const int maxAttempts = 10;
        for (int attempt = 1; attempt <= maxAttempts; attempt++)
        {
            try
            {
                File.Copy(srcFile, dstFile, overwrite: true);
                return;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                if (attempt == maxAttempts)
                {
                    throw;
                }

                Thread.Sleep(350);
            }
        }
    }
}
