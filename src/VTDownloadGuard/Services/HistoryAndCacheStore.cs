using System;
using System.Collections.Generic;
using System.Linq;
using VTDownloadGuard.Models;

namespace VTDownloadGuard.Services;

public sealed class HistoryAndCacheStore
{
    private const int MaxHistoryRecords = 500;
    private const int MaxCacheEntries = 5000;
    private static readonly TimeSpan FoundCacheTtl = TimeSpan.FromDays(30);
    private static readonly TimeSpan NotFoundCacheTtl = TimeSpan.FromDays(1);

    private readonly AppPaths _paths;
    private readonly AppLogger _logger;
    private readonly Func<DateTimeOffset> _utcNow;
    private readonly Lock _sync = new();

    private List<ScanRecord> _history = [];
    private HashCacheFileData _cacheData = new();
    private Dictionary<string, HashCacheEntry> _cacheByHash = new(StringComparer.OrdinalIgnoreCase);

    public HistoryAndCacheStore(AppPaths paths, AppLogger logger, Func<DateTimeOffset>? utcNow = null)
    {
        _paths = paths;
        _logger = logger;
        _utcNow = utcNow ?? (() => DateTimeOffset.UtcNow);
        Load();
    }

    public void Load()
    {
        lock (_sync)
        {
            _paths.EnsureDataDirectoryExists();

            _history = AtomicJsonStorage.ReadOrDefault<List<ScanRecord>>(_paths.HistoryPath, _logger) ?? [];
            _history = _history
                .OrderByDescending(r => r.ScannedAtUtc)
                .Take(MaxHistoryRecords)
                .ToList();

            _cacheData = AtomicJsonStorage.ReadOrDefault<HashCacheFileData>(_paths.HashCachePath, _logger)
                ?? new HashCacheFileData { DailyQuotaDateUtc = DateOnly.FromDateTime(_utcNow().UtcDateTime) };
            _cacheData.Entries ??= [];

            _cacheByHash = new Dictionary<string, HashCacheEntry>(StringComparer.OrdinalIgnoreCase);
            foreach (var entry in _cacheData.Entries)
            {
                if (!string.IsNullOrWhiteSpace(entry.Sha256))
                {
                    _cacheByHash[entry.Sha256] = entry;
                }
            }

            ResetDailyQuotaIfNeededLocked();
        }
    }

    public IReadOnlyList<ScanRecord> GetHistory()
    {
        lock (_sync)
        {
            return _history.ToList();
        }
    }

    public int GetUnacknowledgedUnsafeCount()
    {
        lock (_sync)
        {
            return _history.Count(r => r.Verdict == ScanVerdict.Unsafe && !r.Acknowledged);
        }
    }

    public ScanRecord? GetLatestUnacknowledgedUnsafe()
    {
        lock (_sync)
        {
            return _history.FirstOrDefault(r => r.Verdict == ScanVerdict.Unsafe && !r.Acknowledged);
        }
    }

    public void AddOrUpdateScanRecord(ScanRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);
        lock (_sync)
        {
            int idx = _history.FindIndex(r => r.Id == record.Id);
            if (idx >= 0)
            {
                _history[idx] = record;
            }
            else
            {
                _history.Insert(0, record);
            }

            if (_history.Count > MaxHistoryRecords)
            {
                _history.RemoveRange(MaxHistoryRecords, _history.Count - MaxHistoryRecords);
            }

            AtomicJsonStorage.WriteAtomic(_paths.HistoryPath, _history, _logger);
        }
    }

    public int AcknowledgeAllUnsafe()
    {
        lock (_sync)
        {
            int count = 0;
            foreach (var rec in _history)
            {
                if (rec.Verdict == ScanVerdict.Unsafe && !rec.Acknowledged)
                {
                    rec.Acknowledged = true;
                    count++;
                }
            }

            if (count > 0)
            {
                AtomicJsonStorage.WriteAtomic(_paths.HistoryPath, _history, _logger);
            }

            return count;
        }
    }

    public void ClearHistory()
    {
        lock (_sync)
        {
            _history.Clear();
            AtomicJsonStorage.WriteAtomic(_paths.HistoryPath, _history, _logger);
        }
    }

    public bool TryGetCachedHash(string sha256, out HashCacheEntry? entry)
    {
        if (string.IsNullOrWhiteSpace(sha256))
        {
            entry = null;
            return false;
        }

        lock (_sync)
        {
            if (!_cacheByHash.TryGetValue(sha256, out var candidate))
            {
                entry = null;
                return false;
            }

            var ttl = candidate.WasFoundOnVirusTotal ? FoundCacheTtl : NotFoundCacheTtl;
            if (_utcNow() - candidate.CachedAtUtc > ttl)
            {
                _cacheByHash.Remove(sha256);
                SaveCacheLocked();
                entry = null;
                return false;
            }

            entry = candidate;
            return true;
        }
    }

    public void UpsertCacheEntry(HashCacheEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        if (string.IsNullOrWhiteSpace(entry.Sha256))
        {
            return;
        }

        lock (_sync)
        {
            _cacheByHash[entry.Sha256] = entry;
            if (_cacheByHash.Count > MaxCacheEntries)
            {
                var ordered = _cacheByHash.Values
                    .OrderByDescending(e => e.CachedAtUtc)
                    .Take(MaxCacheEntries)
                    .ToList();
                _cacheByHash = ordered.ToDictionary(e => e.Sha256, StringComparer.OrdinalIgnoreCase);
            }

            SaveCacheLocked();
        }
    }

    public int GetCacheCount()
    {
        lock (_sync)
        {
            return _cacheByHash.Count;
        }
    }

    public void ClearCache()
    {
        lock (_sync)
        {
            _cacheByHash.Clear();
            SaveCacheLocked();
        }
    }

    public int GetDailyApiRequests()
    {
        lock (_sync)
        {
            ResetDailyQuotaIfNeededLocked();
            return _cacheData.DailyApiRequests;
        }
    }

    public void RecordApiRequests(int count = 1)
    {
        if (count <= 0)
        {
            return;
        }

        lock (_sync)
        {
            ResetDailyQuotaIfNeededLocked();
            _cacheData.DailyApiRequests += count;
            SaveCacheLocked();
        }
    }

    public void RecordCacheHit()
    {
        lock (_sync)
        {
            ResetDailyQuotaIfNeededLocked();
            _cacheData.DailyCacheHits++;
            SaveCacheLocked();
        }
    }

    public void RecordSecondaryRequest(string serviceName, bool savedVtCall)
    {
        if (string.IsNullOrWhiteSpace(serviceName))
        {
            return;
        }

        lock (_sync)
        {
            ResetDailyQuotaIfNeededLocked();

            if (serviceName.Contains("CIRCL", StringComparison.OrdinalIgnoreCase))
            {
                _cacheData.DailyCirclRequests++;
                if (savedVtCall)
                {
                    _cacheData.DailyCirclHits++;
                }
            }
            else if (serviceName.Contains("MetaDefender", StringComparison.OrdinalIgnoreCase))
            {
                _cacheData.DailyMetaDefenderRequests++;
                if (savedVtCall)
                {
                    _cacheData.DailyMetaDefenderHits++;
                }
            }
            else if (serviceName.Contains("MalwareBazaar", StringComparison.OrdinalIgnoreCase))
            {
                _cacheData.DailyMalwareBazaarRequests++;
                if (savedVtCall)
                {
                    _cacheData.DailyMalwareBazaarHits++;
                }
            }

            if (savedVtCall)
            {
                _cacheData.DailySecondarySavedCalls++;
            }

            SaveCacheLocked();
        }
    }

    public DailyUsageSnapshot GetDailyUsageSnapshot()
    {
        lock (_sync)
        {
            ResetDailyQuotaIfNeededLocked();
            return new DailyUsageSnapshot(
                _cacheData.DailyApiRequests,
                _cacheData.DailyCacheHits,
                _cacheData.DailySecondarySavedCalls,
                _cacheData.DailyCirclRequests,
                _cacheData.DailyMetaDefenderRequests,
                _cacheData.DailyMalwareBazaarRequests,
                _cacheData.DailyCirclHits,
                _cacheData.DailyMetaDefenderHits,
                _cacheData.DailyMalwareBazaarHits,
                _cacheData.DailyQuotaDateUtc);
        }
    }

    private void ResetDailyQuotaIfNeededLocked()
    {
        var today = DateOnly.FromDateTime(_utcNow().UtcDateTime);
        if (_cacheData.DailyQuotaDateUtc != today)
        {
            _cacheData.DailyQuotaDateUtc = today;
            _cacheData.DailyApiRequests = 0;
            _cacheData.DailyCacheHits = 0;
            _cacheData.DailySecondarySavedCalls = 0;
            _cacheData.DailyCirclRequests = 0;
            _cacheData.DailyMetaDefenderRequests = 0;
            _cacheData.DailyMalwareBazaarRequests = 0;
            _cacheData.DailyCirclHits = 0;
            _cacheData.DailyMetaDefenderHits = 0;
            _cacheData.DailyMalwareBazaarHits = 0;
        }
    }

    private void SaveCacheLocked()
    {
        _cacheData.Entries = _cacheByHash.Values
            .OrderByDescending(e => e.CachedAtUtc)
            .ToList();
        AtomicJsonStorage.WriteAtomic(_paths.HashCachePath, _cacheData, _logger);
    }
}
