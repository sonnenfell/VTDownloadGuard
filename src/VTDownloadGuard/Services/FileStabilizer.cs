using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace VTDownloadGuard.Services;

/// <summary>
/// Waits until newly created or renamed files are unlocked and stop changing size/timestamp
/// before triggering SHA-256 hashing. Uses zero background timers or polling when idle.
/// </summary>
public sealed class FileStabilizer : IDisposable
{
    private sealed class PendingFile
    {
        public string Path { get; init; } = string.Empty;
        public DateTimeOffset FirstSeenUtc { get; init; }
        public long LastLength { get; set; } = -1;
        public DateTime LastWriteUtc { get; set; }
        public DateTimeOffset LastObservedUtc { get; set; }
    }

    private readonly AppLogger _logger;
    private readonly TimeSpan _stabilityInterval;
    private readonly TimeSpan _checkInterval;
    private readonly TimeSpan _zeroByteGrace;
    private readonly TimeSpan _maxWait;
    private readonly ConcurrentDictionary<string, PendingFile> _pending = new(StringComparer.OrdinalIgnoreCase);
    private readonly CancellationTokenSource _cts = new();
    private readonly Lock _loopSync = new();

    private Task? _loopTask;
    private bool _disposed;

    public event Action<string>? FileReady;
    public event Action? PendingChanged;

    public FileStabilizer(
        AppLogger logger,
        TimeSpan? stabilityInterval = null,
        TimeSpan? checkInterval = null,
        TimeSpan? zeroByteGrace = null,
        TimeSpan? maxWait = null)
    {
        _logger = logger;
        _stabilityInterval = stabilityInterval ?? TimeSpan.FromMilliseconds(1500);
        _checkInterval = checkInterval ?? TimeSpan.FromMilliseconds(750);
        _zeroByteGrace = zeroByteGrace ?? TimeSpan.FromSeconds(15);
        _maxWait = maxWait ?? TimeSpan.FromHours(2);
    }

    public int PendingCount => _pending.Count;

    public IReadOnlyList<string> GetPendingPaths() =>
        _pending.Keys.OrderBy(p => p, StringComparer.OrdinalIgnoreCase).ToList();

    public void Enqueue(string filePath)
    {
        if (_disposed || string.IsNullOrWhiteSpace(filePath))
        {
            return;
        }

        string normalized;
        try
        {
            normalized = Path.GetFullPath(filePath);
        }
        catch
        {
            return;
        }

        var now = DateTimeOffset.UtcNow;
        bool added = false;
        _pending.AddOrUpdate(
            normalized,
            _ =>
            {
                added = true;
                return new PendingFile { Path = normalized, FirstSeenUtc = now };
            },
            (_, existing) =>
            {
                existing.LastLength = -1;
                return existing;
            });

        lock (_loopSync)
        {
            if (!_disposed && (_loopTask is null || _loopTask.IsCompleted))
            {
                _loopTask = Task.Run(() => ProcessLoopAsync(_cts.Token));
            }
        }

        if (added)
        {
            RaisePendingChanged();
        }
    }

    private async Task ProcessLoopAsync(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                await Task.Delay(_checkInterval, ct).ConfigureAwait(false);

                DateTimeOffset now = DateTimeOffset.UtcNow;
                foreach (var kvp in _pending)
                {
                    if (ct.IsCancellationRequested)
                    {
                        return;
                    }

                    string path = kvp.Key;
                    PendingFile item = kvp.Value;

                    if (Directory.Exists(path) || !File.Exists(path))
                    {
                        if (_pending.TryRemove(path, out _))
                        {
                            RaisePendingChanged();
                        }

                        continue;
                    }

                    if (now - item.FirstSeenUtc > _maxWait)
                    {
                        if (_pending.TryRemove(path, out _))
                        {
                            RaisePendingChanged();
                        }

                        _logger.Warn($"Stopped waiting for locked/changing file after max timeout: {path}");
                        continue;
                    }

                    long currentLength;
                    DateTime currentWriteUtc;
                    try
                    {
                        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
                        currentLength = fs.Length;
                        currentWriteUtc = File.GetLastWriteTimeUtc(path);
                    }
                    catch (IOException)
                    {
                        // Still exclusively locked by browser/installer/extractor.
                        item.LastLength = -1;
                        continue;
                    }
                    catch (UnauthorizedAccessException)
                    {
                        item.LastLength = -1;
                        continue;
                    }
                    catch (Exception ex)
                    {
                        if (_pending.TryRemove(path, out _))
                        {
                            RaisePendingChanged();
                        }

                        _logger.Warn($"Skipped inaccessible file '{path}': {ex.Message}");
                        continue;
                    }

                    if (currentLength == 0)
                    {
                        if (now - item.FirstSeenUtc >= _zeroByteGrace)
                        {
                            if (_pending.TryRemove(path, out _))
                            {
                                RaisePendingChanged();
                            }
                        }

                        continue;
                    }

                    if (item.LastLength == currentLength && item.LastWriteUtc == currentWriteUtc)
                    {
                        if (now - item.LastObservedUtc >= _stabilityInterval)
                        {
                            if (_pending.TryRemove(path, out _))
                            {
                                RaisePendingChanged();
                                try
                                {
                                    FileReady?.Invoke(path);
                                }
                                catch (Exception ex)
                                {
                                    _logger.Error($"FileReady handler threw for '{path}'", ex);
                                }
                            }
                        }
                    }
                    else
                    {
                        item.LastLength = currentLength;
                        item.LastWriteUtc = currentWriteUtc;
                        item.LastObservedUtc = now;
                    }
                }

                lock (_loopSync)
                {
                    if (_pending.IsEmpty)
                    {
                        _loopTask = null;
                        return;
                    }
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Clean shutdown.
        }
        catch (Exception ex)
        {
            _logger.Error("Unexpected exception in FileStabilizer loop", ex);
            lock (_loopSync)
            {
                _loopTask = null;
            }
        }
    }

    private void RaisePendingChanged()
    {
        try
        {
            PendingChanged?.Invoke();
        }
        catch (Exception ex)
        {
            _logger.Warn($"PendingChanged handler error: {ex.Message}");
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _cts.Cancel();
        _pending.Clear();
        _cts.Dispose();
    }
}
