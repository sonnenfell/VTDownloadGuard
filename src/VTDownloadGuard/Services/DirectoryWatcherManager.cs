using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using VTDownloadGuard.Models;

namespace VTDownloadGuard.Services;

public sealed class DirectoryWatcherManager : IDisposable
{
    private sealed class WatcherEntry
    {
        public WatchedDirectory Config { get; init; } = new();
        public FileSystemWatcher? Watcher { get; set; }
        public string Status { get; set; } = "Watching";
    }

    private readonly AppLogger _logger;
    private readonly FileStabilizer _stabilizer;
    private readonly Lock _sync = new();

    private readonly List<WatcherEntry> _entries = [];
    private AppSettings _settings = AppSettings.CreateDefault();
    private System.Threading.Timer? _recoveryTimer;
    private bool _isPaused;
    private bool _disposed;

    public DirectoryWatcherManager(AppLogger logger, FileStabilizer stabilizer)
    {
        _logger = logger;
        _stabilizer = stabilizer;
    }

    public bool IsPaused
    {
        get
        {
            lock (_sync)
            {
                return _isPaused;
            }
        }
    }

    public void Reload(AppSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        lock (_sync)
        {
            if (_disposed)
            {
                return;
            }

            _settings = settings.Clone();
            DisposeWatchersLocked();
            _entries.Clear();

            foreach (var dir in _settings.WatchedDirectories)
            {
                _entries.Add(new WatcherEntry { Config = dir.Clone() });
            }

            AttachMissingOrErroredWatchersLocked();
        }
    }

    public void SetPaused(bool paused)
    {
        lock (_sync)
        {
            if (_disposed || _isPaused == paused)
            {
                return;
            }

            _isPaused = paused;
            foreach (var entry in _entries)
            {
                if (entry.Watcher is not null)
                {
                    try
                    {
                        entry.Watcher.EnableRaisingEvents = !paused;
                        entry.Status = paused ? "Paused" : "Watching";
                    }
                    catch (Exception ex)
                    {
                        entry.Status = "Watcher error (retrying)";
                        _logger.Warn($"Failed toggling watcher for '{entry.Config.Path}': {ex.Message}");
                    }
                }
                else if (entry.Config.Enabled && paused)
                {
                    entry.Status = "Paused";
                }
            }

            if (!paused)
            {
                AttachMissingOrErroredWatchersLocked();
            }
            else
            {
                StopRecoveryTimerLocked();
            }
        }
    }

    public IReadOnlyDictionary<string, string> GetDirectoryStatuses()
    {
        lock (_sync)
        {
            var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var entry in _entries)
            {
                string status;
                if (!entry.Config.Enabled)
                {
                    status = "Disabled";
                }
                else if (_isPaused)
                {
                    status = "Paused";
                }
                else if (!Directory.Exists(entry.Config.Path))
                {
                    status = "Folder not found";
                }
                else
                {
                    status = entry.Status;
                }

                dict[entry.Config.Path] = status;
            }

            return dict;
        }
    }

    private void AttachMissingOrErroredWatchersLocked()
    {
        bool needsRecovery = false;

        foreach (var entry in _entries)
        {
            if (!entry.Config.Enabled)
            {
                entry.Status = "Disabled";
                continue;
            }

            if (entry.Watcher is not null)
            {
                entry.Status = _isPaused ? "Paused" : "Watching";
                continue;
            }

            if (!Directory.Exists(entry.Config.Path))
            {
                entry.Status = "Folder not found";
                needsRecovery = true;
                continue;
            }

            try
            {
                var fsw = new FileSystemWatcher(entry.Config.Path)
                {
                    IncludeSubdirectories = entry.Config.IncludeSubdirectories,
                    InternalBufferSize = 65536,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.CreationTime
                };

                fsw.Created += OnFileCreated;
                fsw.Renamed += OnFileRenamed;
                fsw.Error += (_, args) => OnWatcherError(entry, args);
                fsw.EnableRaisingEvents = !_isPaused;

                entry.Watcher = fsw;
                entry.Status = _isPaused ? "Paused" : "Watching";
            }
            catch (Exception ex)
            {
                entry.Status = "Watcher error (retrying)";
                needsRecovery = true;
                _logger.Error($"Failed to start FileSystemWatcher on '{entry.Config.Path}'", ex);
            }
        }

        if (needsRecovery && !_isPaused)
        {
            EnsureRecoveryTimerRunningLocked();
        }
        else
        {
            StopRecoveryTimerLocked();
        }
    }

    private void OnFileCreated(object sender, FileSystemEventArgs e)
    {
        HandleCandidatePath(e.FullPath);
    }

    private void OnFileRenamed(object sender, RenamedEventArgs e)
    {
        HandleCandidatePath(e.FullPath);
    }

    private void HandleCandidatePath(string fullPath)
    {
        AppSettings settingsSnapshot;
        lock (_sync)
        {
            if (_disposed || _isPaused)
            {
                return;
            }

            settingsSnapshot = _settings;
        }

        if (string.IsNullOrWhiteSpace(fullPath) || Directory.Exists(fullPath))
        {
            return;
        }

        if (!SettingsStore.ShouldScanFile(settingsSnapshot, fullPath))
        {
            return;
        }

        _stabilizer.Enqueue(fullPath);
    }

    private void OnWatcherError(WatcherEntry entry, ErrorEventArgs e)
    {
        _logger.Warn($"FileSystemWatcher error on '{entry.Config.Path}': {e.GetException().Message}");
        lock (_sync)
        {
            if (_disposed)
            {
                return;
            }

            try
            {
                entry.Watcher?.Dispose();
            }
            catch
            {
                // Ignore dispose error.
            }

            entry.Watcher = null;
            entry.Status = "Watcher error (retrying)";
            if (!_isPaused)
            {
                EnsureRecoveryTimerRunningLocked();
            }
        }
    }

    private void EnsureRecoveryTimerRunningLocked()
    {
        _recoveryTimer ??= new System.Threading.Timer(_ =>
        {
            lock (_sync)
            {
                if (_disposed || _isPaused)
                {
                    return;
                }

                AttachMissingOrErroredWatchersLocked();
            }
        }, null, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));
    }

    private void StopRecoveryTimerLocked()
    {
        _recoveryTimer?.Dispose();
        _recoveryTimer = null;
    }

    private void DisposeWatchersLocked()
    {
        foreach (var entry in _entries)
        {
            if (entry.Watcher is not null)
            {
                try
                {
                    entry.Watcher.EnableRaisingEvents = false;
                    entry.Watcher.Dispose();
                }
                catch
                {
                    // Ignore dispose exception.
                }

                entry.Watcher = null;
            }
        }
    }

    public void Dispose()
    {
        lock (_sync)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            StopRecoveryTimerLocked();
            DisposeWatchersLocked();
            _entries.Clear();
        }
    }
}
