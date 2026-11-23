using System;
using System.IO;
using System.Text;

namespace VTDownloadGuard.Services;

public sealed class AppLogger
{
    private const long MaxLogBytes = 512 * 1024;
    private readonly string _logPath;
    private readonly Lock _sync = new();

    public AppLogger(AppPaths paths)
    {
        _logPath = paths.LogPath;
    }

    public void Info(string message) => Write("INFO", message);

    public void Warn(string message) => Write("WARN", message);

    public void Error(string message, Exception? ex = null)
    {
        var full = ex is null ? message : $"{message}: {ex.GetType().Name}: {ex.Message}";
        Write("ERROR", full);
    }

    private void Write(string level, string message)
    {
        try
        {
            lock (_sync)
            {
                var dir = Path.GetDirectoryName(_logPath);
                if (!string.IsNullOrEmpty(dir))
                {
                    Directory.CreateDirectory(dir);
                }

                if (File.Exists(_logPath))
                {
                    var info = new FileInfo(_logPath);
                    if (info.Length > MaxLogBytes)
                    {
                        var archivePath = _logPath + ".old";
                        File.Move(_logPath, archivePath, overwrite: true);
                    }
                }

                var line = $"{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss.fff} [{level}] {message}{Environment.NewLine}";
                File.AppendAllText(_logPath, line, Encoding.UTF8);
            }
        }
        catch
        {
            // Logging failures must never crash the tray monitor.
        }
    }
}
