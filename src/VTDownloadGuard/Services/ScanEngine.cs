using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using VTDownloadGuard.Models;

namespace VTDownloadGuard.Services;

public sealed class ScanEngine : IDisposable
{
    private readonly SettingsStore _settingsStore;
    private readonly HistoryAndCacheStore _historyStore;
    private readonly RateLimiter _rateLimiter;
    private readonly VirusTotalClient _vtClient;
    private readonly AppLogger _logger;
    private readonly FileStabilizer _stabilizer;
    private readonly DirectoryWatcherManager _watcherManager;
    private readonly SecondaryHashLookupService _secondaryLookup;
    private readonly bool _ownsSecondaryLookup;
    private readonly FileRiskClassifier _riskClassifier;

    private readonly List<QueuedScanItem> _queuedItems = [];
    private readonly SemaphoreSlim _queueSignal = new(0);
    private readonly Lock _queueSync = new();
    private readonly CancellationTokenSource _cts = new();
    private readonly Lock _stateSync = new();

    private AppSettings _currentSettings;
    private Task? _workerTask;
    private QueuedScanItem? _activeItem;
    private string? _activeFileName;
    private string _activeStage = string.Empty;
    private VtUserQuotaInfo? _lastFetchedQuota;
    private long _promoteCounter;
    private bool _started;
    private bool _disposed;

    public event Action? StatusChanged;
    public event Action? QueueChanged;
    public event Action<ScanRecord>? ScanCompleted;
    public event Action<ScanRecord>? UnsafeFileDetected;
    public event Action<string>? ApiAuthFailed;

    public ScanEngine(
        SettingsStore settingsStore,
        HistoryAndCacheStore historyStore,
        RateLimiter rateLimiter,
        VirusTotalClient vtClient,
        AppLogger logger,
        TimeSpan? stabilityInterval = null,
        TimeSpan? stabilizerCheckInterval = null,
        TimeSpan? zeroByteGrace = null,
        SecondaryHashLookupService? secondaryLookup = null,
        FileRiskClassifier? riskClassifier = null)
    {
        _settingsStore = settingsStore;
        _historyStore = historyStore;
        _rateLimiter = rateLimiter;
        _vtClient = vtClient;
        _logger = logger;
        _ownsSecondaryLookup = secondaryLookup is null;
        _secondaryLookup = secondaryLookup ?? new SecondaryHashLookupService(historyStore, logger);
        _riskClassifier = riskClassifier ?? new FileRiskClassifier();

        _currentSettings = _settingsStore.Load();
        _rateLimiter.UpdateLimit(_currentSettings.MaxRequestsPerMinute);

        _stabilizer = new FileStabilizer(logger, stabilityInterval, stabilizerCheckInterval, zeroByteGrace);
        _watcherManager = new DirectoryWatcherManager(logger, _stabilizer);
        _stabilizer.FileReady += OnStabilizedFileReady;
        _stabilizer.PendingChanged += OnStabilizerPendingChanged;
    }

    public AppSettings CurrentSettings
    {
        get
        {
            lock (_stateSync)
            {
                return _currentSettings.Clone();
            }
        }
    }

    public bool HasApiKey
    {
        get
        {
            lock (_stateSync)
            {
                return !string.IsNullOrWhiteSpace(SettingsStore.GetDecryptedApiKey(_currentSettings));
            }
        }
    }

    public bool IsPaused => _watcherManager.IsPaused;

    public int QueuedCount
    {
        get
        {
            lock (_queueSync)
            {
                return _queuedItems.Count;
            }
        }
    }

    public string? ActiveFileName
    {
        get
        {
            lock (_stateSync)
            {
                return _activeFileName;
            }
        }
    }

    public string ActiveStage
    {
        get
        {
            lock (_stateSync)
            {
                return _activeStage;
            }
        }
    }

    public VtUserQuotaInfo? LastFetchedQuota
    {
        get
        {
            lock (_stateSync)
            {
                return _lastFetchedQuota;
            }
        }
    }

    public bool IsScanning => ActiveFileName is not null || QueuedCount > 0;

    public int UnacknowledgedUnsafeCount => _historyStore.GetUnacknowledgedUnsafeCount();

    public ScanRecord? LatestUnacknowledgedUnsafe => _historyStore.GetLatestUnacknowledgedUnsafe();

    public TrayStatus CurrentTrayStatus
    {
        get
        {
            if (!HasApiKey)
            {
                return TrayStatus.NeedsSetup;
            }

            if (UnacknowledgedUnsafeCount > 0)
            {
                return TrayStatus.Unsafe;
            }

            if (IsScanning)
            {
                return TrayStatus.Scanning;
            }

            return TrayStatus.Safe;
        }
    }

    public void Start()
    {
        lock (_stateSync)
        {
            if (_started || _disposed)
            {
                return;
            }

            _started = true;
            _watcherManager.Reload(_currentSettings);
            _workerTask = Task.Run(() => WorkerLoopAsync(_cts.Token));
        }

        RaiseStatusChanged();
    }

    public void ApplySettings(AppSettings updatedSettings)
    {
        ArgumentNullException.ThrowIfNull(updatedSettings);
        _settingsStore.Save(updatedSettings);

        lock (_stateSync)
        {
            _currentSettings = updatedSettings.Clone();
            _rateLimiter.UpdateLimit(_currentSettings.MaxRequestsPerMinute);
            _watcherManager.Reload(_currentSettings);
        }

        RaiseStatusChanged();
    }

    public void SetPaused(bool paused)
    {
        _watcherManager.SetPaused(paused);
        RaiseStatusChanged();
    }

    public IReadOnlyDictionary<string, string> GetDirectoryStatuses() => _watcherManager.GetDirectoryStatuses();

    public IReadOnlyList<ScanRecord> GetHistory() => _historyStore.GetHistory();

    public int GetDailyApiRequests() => _historyStore.GetDailyApiRequests();

    public DailyUsageSnapshot GetDailyUsageSnapshot() => _historyStore.GetDailyUsageSnapshot();

    public RateLimiterSnapshot GetRateLimiterSnapshot() => _rateLimiter.GetSnapshot();

    public IReadOnlyList<SecondaryServiceStats> GetSecondaryServiceStatuses() =>
        _secondaryLookup.GetServiceStatuses(CurrentSettings);

    public int GetCacheCount() => _historyStore.GetCacheCount();

    public void ClearHistory()
    {
        _historyStore.ClearHistory();
        RaiseStatusChanged();
    }

    public void ClearCache()
    {
        _historyStore.ClearCache();
        RaiseStatusChanged();
    }

    public Task<(bool Success, string Message)> TestApiKeyAsync(string apiKey, CancellationToken ct = default) =>
        _vtClient.TestApiKeyAsync(apiKey, ct);

    public Task<(bool Success, string Message)> TestMetaDefenderKeyAsync(string apiKey, CancellationToken ct = default) =>
        _secondaryLookup.TestMetaDefenderKeyAsync(apiKey, ct);

    public Task<(bool Success, string Message)> TestMalwareBazaarKeyAsync(string apiKey, CancellationToken ct = default) =>
        _secondaryLookup.TestMalwareBazaarKeyAsync(apiKey, ct);

    public async Task<VtUserQuotaInfo> FetchVirusTotalQuotaAsync(CancellationToken ct = default)
    {
        string apiKey = SettingsStore.GetDecryptedApiKey(CurrentSettings);
        if (string.IsNullOrWhiteSpace(apiKey))
        {
            var missing = new VtUserQuotaInfo
            {
                Success = false,
                ErrorMessage = "VirusTotal API key is not configured.",
                ApiCallsMade = 0
            };
            lock (_stateSync)
            {
                _lastFetchedQuota = missing;
            }

            RaiseStatusChanged();
            return missing;
        }

        VtUserQuotaInfo info = await _vtClient.GetUserQuotasAsync(apiKey, ct).ConfigureAwait(false);
        if (info.ApiCallsMade > 0)
        {
            _historyStore.RecordApiRequests(info.ApiCallsMade);
        }

        lock (_stateSync)
        {
            _lastFetchedQuota = info;
        }

        RaiseStatusChanged();
        return info;
    }

    public void ManualUploadRecord(ScanRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);
        if (!string.IsNullOrWhiteSpace(record.FilePath))
        {
            EnqueueFile(record.FilePath, manual: true, forceUpload: true, forceVirusTotal: true);
        }
    }

    public void RescanOnVirusTotal(ScanRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);
        if (!string.IsNullOrWhiteSpace(record.FilePath))
        {
            EnqueueFile(record.FilePath, manual: true, forceUpload: false, forceVirusTotal: true);
        }
    }

    public void AcknowledgeAllUnsafe()
    {
        if (_historyStore.AcknowledgeAllUnsafe() > 0)
        {
            RaiseStatusChanged();
        }
    }

    public IReadOnlyList<QueuedScanItem> GetQueueSnapshot()
    {
        var result = new List<QueuedScanItem>();
        var knownPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        lock (_queueSync)
        {
            if (_activeItem is not null)
            {
                QueuedScanItem activeClone = _activeItem.Clone();
                activeClone.State = "Scanning";
                activeClone.Stage = ActiveStage;
                result.Add(activeClone);
                knownPaths.Add(activeClone.FilePath);
            }

            foreach (QueuedScanItem item in _queuedItems)
            {
                QueuedScanItem clone = item.Clone();
                clone.State = "Queued";
                clone.Stage = clone.ManualBoost ? "Prioritized" : "Waiting in queue";
                result.Add(clone);
                knownPaths.Add(clone.FilePath);
            }
        }

        foreach (string pendingPath in _stabilizer.GetPendingPaths())
        {
            if (!knownPaths.Add(pendingPath))
            {
                continue;
            }

            long size = 0;
            try
            {
                var fi = new FileInfo(pendingPath);
                if (fi.Exists)
                {
                    size = fi.Length;
                }
            }
            catch
            {
                // Ignore transient file access issues while downloading.
            }

            result.Add(new QueuedScanItem
            {
                FilePath = pendingPath,
                FileName = Path.GetFileName(pendingPath),
                FileSizeBytes = size,
                RiskCategory = FileRiskCategory.Medium,
                RiskScore = 45,
                RiskReason = "Waiting for file write or download to finish",
                EnqueuedAtUtc = DateTimeOffset.UtcNow,
                State = "Waiting for file",
                Stage = "Stabilizing"
            });
        }

        return result;
    }

    public bool PromoteQueuedItem(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath))
        {
            return false;
        }

        bool changed = false;
        lock (_queueSync)
        {
            QueuedScanItem? match = _queuedItems.FirstOrDefault(i =>
                string.Equals(i.FilePath, filePath, StringComparison.OrdinalIgnoreCase));
            if (match is not null)
            {
                match.ManualBoost = true;
                match.BoostOrder = Interlocked.Increment(ref _promoteCounter);
                _queuedItems.Sort(CompareQueueItems);
                changed = true;
            }
        }

        if (changed)
        {
            RaiseQueueChanged();
        }

        return changed;
    }

    public bool RemoveQueuedItem(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath))
        {
            return false;
        }

        bool removed = false;
        lock (_queueSync)
        {
            int count = _queuedItems.RemoveAll(i =>
                string.Equals(i.FilePath, filePath, StringComparison.OrdinalIgnoreCase));
            removed = count > 0;
        }

        if (removed)
        {
            RaiseQueueChanged();
            RaiseStatusChanged();
        }

        return removed;
    }

    public int ClearQueue()
    {
        int removed;
        lock (_queueSync)
        {
            removed = _queuedItems.Count;
            _queuedItems.Clear();
        }

        if (removed > 0)
        {
            RaiseQueueChanged();
            RaiseStatusChanged();
        }

        return removed;
    }

    public void EnqueueFile(
        string filePath,
        bool manual = false,
        bool forceUpload = false,
        bool forceVirusTotal = false)
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

        // Offload classification off the UI thread when triggered from WinForms controls,
        // while staying synchronous on worker threads and in unit tests.
        if (manual && SynchronizationContext.Current is not null)
        {
            _ = Task.Run(() => EnqueueClassifiedInternal(normalized, manual: true, forceUpload, forceVirusTotal));
            return;
        }

        EnqueueClassifiedInternal(normalized, manual, forceUpload, forceVirusTotal);
    }

    private void EnqueueClassifiedInternal(
        string normalizedPath,
        bool manual,
        bool forceUpload,
        bool forceVirusTotal)
    {
        if (_disposed)
        {
            return;
        }

        long fileSize = 0;
        try
        {
            var info = new FileInfo(normalizedPath);
            if (!info.Exists)
            {
                return;
            }

            fileSize = info.Length;
        }
        catch
        {
            return;
        }

        FileRiskAssessment risk = _riskClassifier.Classify(normalizedPath, fileSize);
        long boostOrder = manual ? Interlocked.Increment(ref _promoteCounter) : 0;

        bool signalNewItem = false;
        bool queueModified = false;

        lock (_queueSync)
        {
            if (_disposed)
            {
                return;
            }

            QueuedScanItem? existing = _queuedItems.FirstOrDefault(i =>
                string.Equals(i.FilePath, normalizedPath, StringComparison.OrdinalIgnoreCase));

            if (existing is not null)
            {
                existing.FileSizeBytes = fileSize;
                existing.RiskCategory = risk.Category;
                existing.RiskScore = risk.Score;
                existing.RiskReason = risk.Reason;
                existing.SignerName = risk.SignerName;
                existing.ForceUpload |= forceUpload;
                existing.ForceVirusTotal |= forceVirusTotal;
                if (manual)
                {
                    existing.ManualBoost = true;
                    existing.BoostOrder = boostOrder;
                }

                _queuedItems.Sort(CompareQueueItems);
                queueModified = true;
            }
            else
            {
                _queuedItems.Add(new QueuedScanItem
                {
                    FilePath = normalizedPath,
                    FileName = Path.GetFileName(normalizedPath),
                    FileSizeBytes = fileSize,
                    RiskCategory = risk.Category,
                    RiskScore = risk.Score,
                    RiskReason = risk.Reason,
                    SignerName = risk.SignerName,
                    EnqueuedAtUtc = DateTimeOffset.UtcNow,
                    State = "Queued",
                    Stage = manual ? "Prioritized" : "Waiting in queue",
                    ManualBoost = manual,
                    BoostOrder = boostOrder,
                    ForceUpload = forceUpload,
                    ForceVirusTotal = forceVirusTotal
                });
                _queuedItems.Sort(CompareQueueItems);
                signalNewItem = true;
                queueModified = true;
            }
        }

        if (signalNewItem)
        {
            _queueSignal.Release();
        }

        if (queueModified)
        {
            RaiseQueueChanged();
            RaiseStatusChanged();
        }
    }

    private static int CompareQueueItems(QueuedScanItem a, QueuedScanItem b)
    {
        int boostCmp = b.ManualBoost.CompareTo(a.ManualBoost);
        if (boostCmp != 0)
        {
            return boostCmp;
        }

        if (a.ManualBoost && b.ManualBoost)
        {
            int orderCmp = b.BoostOrder.CompareTo(a.BoostOrder);
            if (orderCmp != 0)
            {
                return orderCmp;
            }
        }

        int catCmp = ((int)a.RiskCategory).CompareTo((int)b.RiskCategory);
        if (catCmp != 0)
        {
            return catCmp;
        }

        int scoreCmp = b.RiskScore.CompareTo(a.RiskScore);
        if (scoreCmp != 0)
        {
            return scoreCmp;
        }

        return a.EnqueuedAtUtc.CompareTo(b.EnqueuedAtUtc);
    }

    private void OnStabilizedFileReady(string filePath)
    {
        EnqueueFile(filePath, manual: false, forceUpload: false, forceVirusTotal: false);
    }

    private void OnStabilizerPendingChanged()
    {
        RaiseQueueChanged();
    }

    private async Task WorkerLoopAsync(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                await _queueSignal.WaitAsync(ct).ConfigureAwait(false);

                QueuedScanItem? next = null;
                lock (_queueSync)
                {
                    if (_queuedItems.Count > 0)
                    {
                        next = _queuedItems[0];
                        _queuedItems.RemoveAt(0);
                        _activeItem = next;
                    }
                }

                if (next is null)
                {
                    continue;
                }

                SetActiveState(next.FileName, "Preparing scan...");
                RaiseQueueChanged();
                try
                {
                    await ScanFileInternalAsync(next, ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.Error($"Unhandled error scanning '{next.FilePath}'", ex);
                }
                finally
                {
                    lock (_queueSync)
                    {
                        _activeItem = null;
                    }

                    SetActiveState(null, string.Empty);
                    RaiseQueueChanged();
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Clean shutdown.
        }
    }

    private async Task ScanFileInternalAsync(QueuedScanItem item, CancellationToken ct)
    {
        if (!File.Exists(item.FilePath))
        {
            return;
        }

        AppSettings settings = CurrentSettings;

        long fileSize;
        try
        {
            var info = new FileInfo(item.FilePath);
            if (!info.Exists)
            {
                return;
            }

            fileSize = info.Length;
        }
        catch (Exception ex)
        {
            _logger.Warn($"Cannot inspect file '{item.FilePath}': {ex.Message}");
            return;
        }

        if (fileSize == 0)
        {
            return;
        }

        string fileName = Path.GetFileName(item.FilePath);
        if (settings.MaxHashSizeMb > 0 && fileSize > settings.MaxHashSizeMb * 1024L * 1024L)
        {
            PublishScanRecord(new ScanRecord
            {
                FilePath = item.FilePath,
                FileName = fileName,
                FileSizeBytes = fileSize,
                Verdict = ScanVerdict.Skipped,
                RiskCategory = item.RiskCategory,
                RiskReason = item.RiskReason,
                SignerName = item.SignerName,
                SourceService = "Local Policy",
                Summary = $"Skipped: file ({fileSize / (1024.0 * 1024.0):F1} MB) exceeds max hash limit ({settings.MaxHashSizeMb} MB)."
            });
            return;
        }

        SetActiveState(fileName, "Computing SHA-256 hash...");
        string sha256;
        try
        {
            await using var fs = new FileStream(item.FilePath, FileMode.Open, FileAccess.Read, FileShare.Read, 65536, useAsync: true);
            byte[] hashBytes = await SHA256.HashDataAsync(fs, ct).ConfigureAwait(false);
            sha256 = Convert.ToHexStringLower(hashBytes);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.Warn($"Failed to hash '{item.FilePath}': {ex.Message}");
            PublishScanRecord(new ScanRecord
            {
                FilePath = item.FilePath,
                FileName = fileName,
                FileSizeBytes = fileSize,
                Verdict = ScanVerdict.Error,
                RiskCategory = item.RiskCategory,
                RiskReason = item.RiskReason,
                SignerName = item.SignerName,
                SourceService = "Local I/O",
                Summary = $"Failed to read file for hashing: {ex.Message}"
            });
            return;
        }

        string vtUrl = VirusTotalClient.BuildGuiFileUrl(sha256);

        // 1. Check local hash cache unless user explicitly forced upload or forced VT rescan.
        if (!item.ForceUpload && !item.ForceVirusTotal && _historyStore.TryGetCachedHash(sha256, out var cached) && cached is not null)
        {
            bool uploadIfNotFound = SettingsStore.ShouldUploadFile(settings, item.FilePath, fileSize);
            bool hasSecondaryVerdict = !string.IsNullOrWhiteSpace(cached.SummaryNote)
                && !string.Equals(cached.SourceService, "VirusTotal", StringComparison.OrdinalIgnoreCase);

            if (cached.WasFoundOnVirusTotal || hasSecondaryVerdict)
            {
                _historyStore.RecordCacheHit();
                ScanVerdict verdict = cached.WasFoundOnVirusTotal
                    ? VirusTotalClient.EvaluateVerdict(cached.MaliciousCount, cached.SuspiciousCount, settings.MaliciousThreshold)
                    : cached.MaliciousCount > 0
                        ? (cached.MaliciousCount >= settings.MaliciousThreshold || string.Equals(cached.SourceService, SecondaryHashLookupService.MalwareBazaarServiceName, StringComparison.OrdinalIgnoreCase)
                            ? ScanVerdict.Unsafe
                            : ScanVerdict.LowRisk)
                        : ScanVerdict.Clean;

                string summary = !string.IsNullOrWhiteSpace(cached.SummaryNote)
                    ? $"{cached.SummaryNote} (cached)"
                    : BuildVerdictSummary(verdict, cached.MaliciousCount, cached.SuspiciousCount, cached.TotalEngines, fromCache: true, uploaded: false);

                string reportUrl = !string.IsNullOrWhiteSpace(cached.ReportUrl) ? cached.ReportUrl : vtUrl;

                PublishScanRecord(new ScanRecord
                {
                    FilePath = item.FilePath,
                    FileName = fileName,
                    Sha256 = sha256,
                    FileSizeBytes = fileSize,
                    Verdict = verdict,
                    MaliciousCount = cached.MaliciousCount,
                    SuspiciousCount = cached.SuspiciousCount,
                    TotalEngines = cached.TotalEngines,
                    DetectionNames = [.. cached.DetectionNames],
                    Summary = summary,
                    VirusTotalUrl = vtUrl,
                    ReportUrl = reportUrl,
                    SourceService = string.IsNullOrWhiteSpace(cached.SourceService) ? "VirusTotal" : cached.SourceService,
                    RiskCategory = item.RiskCategory,
                    RiskReason = item.RiskReason,
                    SignerName = item.SignerName,
                    FromCache = true,
                    Uploaded = false,
                    Acknowledged = verdict != ScanVerdict.Unsafe
                });
                return;
            }
            else if (!uploadIfNotFound)
            {
                _historyStore.RecordCacheHit();
                PublishScanRecord(new ScanRecord
                {
                    FilePath = item.FilePath,
                    FileName = fileName,
                    Sha256 = sha256,
                    FileSizeBytes = fileSize,
                    Verdict = ScanVerdict.Unknown,
                    Summary = "Not in VirusTotal (cached miss); not uploaded per policy.",
                    VirusTotalUrl = vtUrl,
                    ReportUrl = vtUrl,
                    SourceService = "VirusTotal",
                    RiskCategory = item.RiskCategory,
                    RiskReason = item.RiskReason,
                    SignerName = item.SignerName,
                    FromCache = true,
                    Uploaded = false,
                    Acknowledged = true
                });
                return;
            }
        }

        // 2. Check secondary trusted hash lookup services before consuming VirusTotal quota.
        if (!item.ForceUpload
            && !item.ForceVirusTotal
            && SecondaryHashLookupService.ShouldUseSecondaryLookups(settings, item.RiskCategory))
        {
            var secondaryResult = await _secondaryLookup.LookupAsync(
                sha256,
                settings,
                item.RiskCategory,
                stage => SetActiveState(fileName, stage),
                ct).ConfigureAwait(false);

            if (secondaryResult.Outcome is SecondaryLookupOutcome.Clean or SecondaryLookupOutcome.LowRisk or SecondaryLookupOutcome.Malicious)
            {
                ScanVerdict verdict = secondaryResult.Outcome switch
                {
                    SecondaryLookupOutcome.Malicious => ScanVerdict.Unsafe,
                    SecondaryLookupOutcome.LowRisk => ScanVerdict.LowRisk,
                    _ => ScanVerdict.Clean
                };

                string reportUrl = string.IsNullOrWhiteSpace(secondaryResult.ReportUrl)
                    ? vtUrl
                    : secondaryResult.ReportUrl;

                _historyStore.UpsertCacheEntry(new HashCacheEntry
                {
                    Sha256 = sha256,
                    CachedAtUtc = DateTimeOffset.UtcNow,
                    MaliciousCount = secondaryResult.MaliciousCount,
                    SuspiciousCount = 0,
                    TotalEngines = secondaryResult.TotalEngines,
                    DetectionNames = [.. secondaryResult.DetectionNames],
                    WasFoundOnVirusTotal = false,
                    SourceService = secondaryResult.ServiceName,
                    SummaryNote = secondaryResult.Summary,
                    ReportUrl = reportUrl
                });

                PublishScanRecord(new ScanRecord
                {
                    FilePath = item.FilePath,
                    FileName = fileName,
                    Sha256 = sha256,
                    FileSizeBytes = fileSize,
                    Verdict = verdict,
                    MaliciousCount = secondaryResult.MaliciousCount,
                    SuspiciousCount = 0,
                    TotalEngines = secondaryResult.TotalEngines,
                    DetectionNames = [.. secondaryResult.DetectionNames],
                    Summary = secondaryResult.Summary,
                    VirusTotalUrl = vtUrl,
                    ReportUrl = reportUrl,
                    SourceService = secondaryResult.ServiceName,
                    RiskCategory = item.RiskCategory,
                    RiskReason = item.RiskReason,
                    SignerName = item.SignerName,
                    FromCache = false,
                    Uploaded = false,
                    Acknowledged = verdict != ScanVerdict.Unsafe
                });
                return;
            }
        }

        // 3. VirusTotal lookup / upload
        string apiKey = SettingsStore.GetDecryptedApiKey(settings);
        if (string.IsNullOrWhiteSpace(apiKey))
        {
            PublishScanRecord(new ScanRecord
            {
                FilePath = item.FilePath,
                FileName = fileName,
                Sha256 = sha256,
                FileSizeBytes = fileSize,
                Verdict = ScanVerdict.Skipped,
                RiskCategory = item.RiskCategory,
                RiskReason = item.RiskReason,
                SignerName = item.SignerName,
                SourceService = "VirusTotal",
                Summary = "Skipped: VirusTotal API key is not configured.",
                VirusTotalUrl = vtUrl,
                ReportUrl = vtUrl,
                Acknowledged = true
            });
            return;
        }

        if (!item.ForceUpload)
        {
            SetActiveState(fileName, "Querying VirusTotal hash...");
            var lookupResult = await _vtClient.LookupHashAsync(sha256, apiKey, ct).ConfigureAwait(false);
            _historyStore.RecordApiRequests(lookupResult.ApiCallsMade);

            if (lookupResult.Outcome == VtOutcome.Found)
            {
                RecordFoundResult(item, sha256, fileSize, vtUrl, lookupResult, settings.MaliciousThreshold, uploaded: false);
                return;
            }

            if (lookupResult.Outcome != VtOutcome.NotFound)
            {
                HandleFailureOutcome(item, sha256, fileSize, vtUrl, lookupResult);
                return;
            }

            bool allowUpload = SettingsStore.ShouldUploadFile(settings, item.FilePath, fileSize);
            if (!allowUpload)
            {
                _historyStore.UpsertCacheEntry(new HashCacheEntry
                {
                    Sha256 = sha256,
                    CachedAtUtc = DateTimeOffset.UtcNow,
                    WasFoundOnVirusTotal = false,
                    SourceService = "VirusTotal"
                });

                PublishScanRecord(new ScanRecord
                {
                    FilePath = item.FilePath,
                    FileName = fileName,
                    Sha256 = sha256,
                    FileSizeBytes = fileSize,
                    Verdict = ScanVerdict.Unknown,
                    Summary = "Unknown to VirusTotal; not uploaded per policy.",
                    VirusTotalUrl = vtUrl,
                    ReportUrl = vtUrl,
                    SourceService = "VirusTotal",
                    RiskCategory = item.RiskCategory,
                    RiskReason = item.RiskReason,
                    SignerName = item.SignerName,
                    Acknowledged = true
                });
                return;
            }
        }

        SetActiveState(fileName, "Uploading to VirusTotal...");
        var uploadResult = await _vtClient.UploadAndAnalyzeAsync(
            item.FilePath,
            sha256,
            apiKey,
            stage => SetActiveState(fileName, stage),
            ct).ConfigureAwait(false);
        _historyStore.RecordApiRequests(uploadResult.ApiCallsMade);

        if (uploadResult.Outcome == VtOutcome.Found)
        {
            RecordFoundResult(item, sha256, fileSize, vtUrl, uploadResult, settings.MaliciousThreshold, uploaded: true);
            return;
        }

        if (uploadResult.Outcome == VtOutcome.TimedOut)
        {
            PublishScanRecord(new ScanRecord
            {
                FilePath = item.FilePath,
                FileName = fileName,
                Sha256 = sha256,
                FileSizeBytes = fileSize,
                Verdict = ScanVerdict.Unknown,
                Summary = "Uploaded; VirusTotal analysis still in progress. Click to open on VT.",
                VirusTotalUrl = vtUrl,
                ReportUrl = vtUrl,
                SourceService = "VirusTotal",
                RiskCategory = item.RiskCategory,
                RiskReason = item.RiskReason,
                SignerName = item.SignerName,
                Uploaded = true,
                Acknowledged = true
            });
            return;
        }

        HandleFailureOutcome(item, sha256, fileSize, vtUrl, uploadResult, uploaded: true);
    }

    private void RecordFoundResult(
        QueuedScanItem item,
        string sha256,
        long fileSize,
        string vtUrl,
        VtReportResult result,
        int threshold,
        bool uploaded)
    {
        _historyStore.UpsertCacheEntry(new HashCacheEntry
        {
            Sha256 = sha256,
            CachedAtUtc = DateTimeOffset.UtcNow,
            MaliciousCount = result.MaliciousCount,
            SuspiciousCount = result.SuspiciousCount,
            TotalEngines = result.TotalEngines,
            DetectionNames = [.. result.DetectionNames],
            WasFoundOnVirusTotal = true,
            SourceService = "VirusTotal",
            ReportUrl = vtUrl
        });

        ScanVerdict verdict = VirusTotalClient.EvaluateVerdict(result.MaliciousCount, result.SuspiciousCount, threshold);
        PublishScanRecord(new ScanRecord
        {
            FilePath = item.FilePath,
            FileName = Path.GetFileName(item.FilePath),
            Sha256 = sha256,
            FileSizeBytes = fileSize,
            Verdict = verdict,
            MaliciousCount = result.MaliciousCount,
            SuspiciousCount = result.SuspiciousCount,
            TotalEngines = result.TotalEngines,
            DetectionNames = [.. result.DetectionNames],
            Summary = BuildVerdictSummary(verdict, result.MaliciousCount, result.SuspiciousCount, result.TotalEngines, fromCache: false, uploaded),
            VirusTotalUrl = vtUrl,
            ReportUrl = vtUrl,
            SourceService = "VirusTotal",
            RiskCategory = item.RiskCategory,
            RiskReason = item.RiskReason,
            SignerName = item.SignerName,
            FromCache = false,
            Uploaded = uploaded,
            Acknowledged = verdict != ScanVerdict.Unsafe
        });
    }

    private void HandleFailureOutcome(
        QueuedScanItem item,
        string sha256,
        long fileSize,
        string vtUrl,
        VtReportResult failure,
        bool uploaded = false)
    {
        var rec = new ScanRecord
        {
            FilePath = item.FilePath,
            FileName = Path.GetFileName(item.FilePath),
            Sha256 = sha256,
            FileSizeBytes = fileSize,
            Verdict = ScanVerdict.Error,
            Summary = string.IsNullOrWhiteSpace(failure.ErrorMessage) ? "VirusTotal request failed." : failure.ErrorMessage,
            VirusTotalUrl = vtUrl,
            ReportUrl = vtUrl,
            SourceService = "VirusTotal",
            RiskCategory = item.RiskCategory,
            RiskReason = item.RiskReason,
            SignerName = item.SignerName,
            Uploaded = uploaded,
            Acknowledged = true
        };

        PublishScanRecord(rec);

        if (failure.Outcome == VtOutcome.AuthError)
        {
            ApiAuthFailed?.Invoke(rec.Summary);
        }
    }

    private void PublishScanRecord(ScanRecord record)
    {
        _historyStore.AddOrUpdateScanRecord(record);
        _logger.Info($"[{record.Verdict}] {record.FileName} ({record.MaliciousCount}/{record.TotalEngines}, {record.SourceService}) - {record.Summary}");
        ScanCompleted?.Invoke(record);

        if (record.Verdict == ScanVerdict.Unsafe)
        {
            UnsafeFileDetected?.Invoke(record);
        }

        RaiseStatusChanged();
    }

    private static string BuildVerdictSummary(
        ScanVerdict verdict,
        int malicious,
        int suspicious,
        int total,
        bool fromCache,
        bool uploaded)
    {
        string source = fromCache ? "cached" : uploaded ? "uploaded" : "VT lookup";
        return verdict switch
        {
            ScanVerdict.Unsafe => $"UNSAFE: {malicious}/{total} malicious ({source})",
            ScanVerdict.LowRisk => $"Low risk: {malicious} malicious, {suspicious} suspicious of {total} ({source})",
            _ => $"Clean: 0/{total} detections ({source})"
        };
    }

    private void SetActiveState(string? fileName, string stage)
    {
        lock (_stateSync)
        {
            _activeFileName = fileName;
            _activeStage = stage;
        }

        RaiseStatusChanged();
    }

    private void RaiseStatusChanged()
    {
        StatusChanged?.Invoke();
    }

    private void RaiseQueueChanged()
    {
        QueueChanged?.Invoke();
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _watcherManager.Dispose();
        _stabilizer.FileReady -= OnStabilizedFileReady;
        _stabilizer.PendingChanged -= OnStabilizerPendingChanged;
        _stabilizer.Dispose();
        _cts.Cancel();

        try
        {
            _workerTask?.Wait(TimeSpan.FromSeconds(2));
        }
        catch
        {
            // Ignore shutdown cancellation/timeout.
        }

        _queueSignal.Dispose();
        _cts.Dispose();
        if (_ownsSecondaryLookup)
        {
            _secondaryLookup.Dispose();
        }
    }
}
