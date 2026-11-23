using System;
using System.IO;

namespace VTDownloadGuard.Services;

public sealed class AppPaths
{
    public AppPaths(string? dataDirectory = null)
    {
        DataDirectory = string.IsNullOrWhiteSpace(dataDirectory)
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "VTDownloadGuard")
            : Path.GetFullPath(dataDirectory);

        SettingsPath = Path.Combine(DataDirectory, "settings.json");
        HistoryPath = Path.Combine(DataDirectory, "history.json");
        HashCachePath = Path.Combine(DataDirectory, "hash-cache.json");
        LogPath = Path.Combine(DataDirectory, "app.log");
    }

    public string DataDirectory { get; }
    public string SettingsPath { get; }
    public string HistoryPath { get; }
    public string HashCachePath { get; }
    public string LogPath { get; }

    public void EnsureDataDirectoryExists()
    {
        Directory.CreateDirectory(DataDirectory);
    }
}
