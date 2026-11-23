using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using VTDownloadGuard.Models;

namespace VTDownloadGuard.Services;

public enum SecondaryLookupOutcome
{
    NotFound = 0,
    Clean = 1,
    LowRisk = 2,
    Malicious = 3,
    Error = 4
}

public sealed class SecondaryLookupResult
{
    public SecondaryLookupOutcome Outcome { get; init; }
    public string ServiceName { get; init; } = string.Empty;
    public int MaliciousCount { get; init; }
    public int TotalEngines { get; init; }
    public List<string> DetectionNames { get; init; } = [];
    public string Summary { get; init; } = string.Empty;
    public string ReportUrl { get; init; } = string.Empty;
}

public sealed class SecondaryHashLookupService : IDisposable
{
    public const string CirclServiceName = "CIRCL Hashlookup";
    public const string MetaDefenderServiceName = "OPSWAT MetaDefender";
    public const string MalwareBazaarServiceName = "MalwareBazaar";

    private const string CirclBaseUrl = "https://hashlookup.circl.lu/lookup/sha256/";
    private const string MetaDefenderBaseUrl = "https://api.metadefender.com/v4/hash/";
    private const string MalwareBazaarApiUrl = "https://mb-api.abuse.ch/api/v1/";
    private const string EicarSha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    private readonly HistoryAndCacheStore _historyStore;
    private readonly AppLogger _logger;
    private readonly HttpClient _httpClient;
    private readonly bool _ownsHttpClient;
    private readonly TimeSpan _circlMinSpacing;
    private readonly SemaphoreSlim _circlThrottleLock = new(1, 1);
    private readonly ConcurrentDictionary<string, string> _lastStatuses = new(StringComparer.OrdinalIgnoreCase);

    private DateTimeOffset _lastCirclQueryUtc = DateTimeOffset.MinValue;

    public SecondaryHashLookupService(
        HistoryAndCacheStore historyStore,
        AppLogger logger,
        HttpClient? httpClient = null,
        TimeSpan? circlMinSpacing = null)
    {
        _historyStore = historyStore;
        _logger = logger;
        _ownsHttpClient = httpClient is null;
        _httpClient = httpClient ?? new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
        _circlMinSpacing = circlMinSpacing ?? TimeSpan.FromMilliseconds(350);

        _lastStatuses[CirclServiceName] = "Ready";
        _lastStatuses[MetaDefenderServiceName] = "Disabled";
        _lastStatuses[MalwareBazaarServiceName] = "Disabled";
    }

    public static bool ShouldUseSecondaryLookups(AppSettings settings, FileRiskCategory riskCategory)
    {
        ArgumentNullException.ThrowIfNull(settings);

        bool hasReadyService = settings.EnableCirclHashlookup
            || (settings.EnableMetaDefender && !string.IsNullOrWhiteSpace(SettingsStore.GetDecryptedMetaDefenderApiKey(settings)))
            || (settings.EnableMalwareBazaar && !string.IsNullOrWhiteSpace(SettingsStore.GetDecryptedMalwareBazaarApiKey(settings)));

        if (!hasReadyService)
        {
            return false;
        }

        if (settings.SecondaryLookupsLowerRiskOnly)
        {
            return riskCategory is FileRiskCategory.Low or FileRiskCategory.Trusted;
        }

        return true;
    }

    public IReadOnlyList<SecondaryServiceStats> GetServiceStatuses(AppSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var usage = _historyStore.GetDailyUsageSnapshot();
        bool hasMdKey = !string.IsNullOrWhiteSpace(SettingsStore.GetDecryptedMetaDefenderApiKey(settings));
        bool hasMbKey = !string.IsNullOrWhiteSpace(SettingsStore.GetDecryptedMalwareBazaarApiKey(settings));

        return
        [
            new SecondaryServiceStats
            {
                Name = CirclServiceName,
                Enabled = settings.EnableCirclHashlookup,
                RequiresApiKey = false,
                HasApiKey = true,
                RequestsToday = usage.DailyCirclRequests,
                HitsToday = usage.DailyCirclHits,
                LastStatus = ResolveStatus(CirclServiceName, settings.EnableCirclHashlookup, requiresKey: false, hasKey: true)
            },
            new SecondaryServiceStats
            {
                Name = MetaDefenderServiceName,
                Enabled = settings.EnableMetaDefender,
                RequiresApiKey = true,
                HasApiKey = hasMdKey,
                RequestsToday = usage.DailyMetaDefenderRequests,
                HitsToday = usage.DailyMetaDefenderHits,
                LastStatus = ResolveStatus(MetaDefenderServiceName, settings.EnableMetaDefender, requiresKey: true, hasKey: hasMdKey)
            },
            new SecondaryServiceStats
            {
                Name = MalwareBazaarServiceName,
                Enabled = settings.EnableMalwareBazaar,
                RequiresApiKey = true,
                HasApiKey = hasMbKey,
                RequestsToday = usage.DailyMalwareBazaarRequests,
                HitsToday = usage.DailyMalwareBazaarHits,
                LastStatus = ResolveStatus(MalwareBazaarServiceName, settings.EnableMalwareBazaar, requiresKey: true, hasKey: hasMbKey)
            }
        ];
    }

    private string ResolveStatus(string name, bool enabled, bool requiresKey, bool hasKey)
    {
        if (!enabled)
        {
            return "Disabled";
        }

        if (requiresKey && !hasKey)
        {
            return "API key missing";
        }

        return _lastStatuses.TryGetValue(name, out string? status) && !string.IsNullOrWhiteSpace(status)
            ? status
            : "Ready";
    }

    public async Task<SecondaryLookupResult> LookupAsync(
        string sha256,
        AppSettings settings,
        FileRiskCategory riskCategory,
        Action<string>? onStage,
        CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(settings);
        if (string.IsNullOrWhiteSpace(sha256))
        {
            return new SecondaryLookupResult { Outcome = SecondaryLookupOutcome.NotFound };
        }

        string normalizedHash = sha256.Trim().ToLowerInvariant();

        // 1. MalwareBazaar (verified threat feed)
        string mbKey = SettingsStore.GetDecryptedMalwareBazaarApiKey(settings);
        if (settings.EnableMalwareBazaar && !string.IsNullOrWhiteSpace(mbKey))
        {
            onStage?.Invoke("Checking MalwareBazaar...");
            var mbResult = await QueryMalwareBazaarAsync(normalizedHash, mbKey, ct).ConfigureAwait(false);
            if (mbResult.Outcome == SecondaryLookupOutcome.Malicious)
            {
                _historyStore.RecordSecondaryRequest(MalwareBazaarServiceName, savedVtCall: true);
                return mbResult;
            }

            _historyStore.RecordSecondaryRequest(MalwareBazaarServiceName, savedVtCall: false);
        }

        // 2. CIRCL Hashlookup (free NSRL known-good / known-malicious index)
        if (settings.EnableCirclHashlookup)
        {
            onStage?.Invoke("Checking CIRCL Hashlookup...");
            var circlResult = await QueryCirclAsync(normalizedHash, ct).ConfigureAwait(false);
            if (circlResult.Outcome is SecondaryLookupOutcome.Clean or SecondaryLookupOutcome.Malicious)
            {
                _historyStore.RecordSecondaryRequest(CirclServiceName, savedVtCall: true);
                return circlResult;
            }

            _historyStore.RecordSecondaryRequest(CirclServiceName, savedVtCall: false);
        }

        // 3. OPSWAT MetaDefender Cloud
        string mdKey = SettingsStore.GetDecryptedMetaDefenderApiKey(settings);
        if (settings.EnableMetaDefender && !string.IsNullOrWhiteSpace(mdKey))
        {
            onStage?.Invoke("Checking OPSWAT MetaDefender...");
            var mdResult = await QueryMetaDefenderAsync(normalizedHash, mdKey, settings.MaliciousThreshold, riskCategory, ct).ConfigureAwait(false);
            if (mdResult.Outcome is SecondaryLookupOutcome.Clean or SecondaryLookupOutcome.LowRisk or SecondaryLookupOutcome.Malicious)
            {
                _historyStore.RecordSecondaryRequest(MetaDefenderServiceName, savedVtCall: true);
                return mdResult;
            }

            _historyStore.RecordSecondaryRequest(MetaDefenderServiceName, savedVtCall: false);
        }

        return new SecondaryLookupResult { Outcome = SecondaryLookupOutcome.NotFound };
    }

    public async Task<(bool Success, string Message)> TestMetaDefenderKeyAsync(string apiKey, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(apiKey))
        {
            return (false, "Please enter an OPSWAT MetaDefender API key.");
        }

        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, MetaDefenderBaseUrl + EicarSha256);
            req.Headers.Add("apikey", apiKey.Trim());
            req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            using HttpResponseMessage resp = await _httpClient.SendAsync(req, ct).ConfigureAwait(false);
            if (resp.StatusCode == HttpStatusCode.OK || resp.StatusCode == HttpStatusCode.NotFound)
            {
                _lastStatuses[MetaDefenderServiceName] = "Connected";
                return (true, "MetaDefender API key is valid.");
            }

            if (resp.StatusCode == HttpStatusCode.Unauthorized || resp.StatusCode == HttpStatusCode.Forbidden)
            {
                return (false, $"MetaDefender rejected the API key (HTTP {(int)resp.StatusCode}).");
            }

            if (resp.StatusCode == HttpStatusCode.TooManyRequests)
            {
                return (true, "MetaDefender key accepted, though rate limit is currently active.");
            }

            return (false, $"Unexpected MetaDefender response: HTTP {(int)resp.StatusCode}.");
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            return (false, "MetaDefender key check cancelled.");
        }
        catch (Exception ex)
        {
            return (false, $"Network error contacting MetaDefender: {ex.Message}");
        }
    }

    public async Task<(bool Success, string Message)> TestMalwareBazaarKeyAsync(string apiKey, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(apiKey))
        {
            return (false, "Please enter a MalwareBazaar Auth-Key.");
        }

        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Post, MalwareBazaarApiUrl);
            req.Headers.Add("Auth-Key", apiKey.Trim());
            req.Content = new FormUrlEncodedContent(
            [
                new KeyValuePair<string, string>("query", "get_info"),
                new KeyValuePair<string, string>("hash", EicarSha256)
            ]);

            using HttpResponseMessage resp = await _httpClient.SendAsync(req, ct).ConfigureAwait(false);
            if (resp.StatusCode == HttpStatusCode.Unauthorized || resp.StatusCode == HttpStatusCode.Forbidden)
            {
                return (false, $"MalwareBazaar rejected the Auth-Key (HTTP {(int)resp.StatusCode}).");
            }

            if (resp.StatusCode == HttpStatusCode.TooManyRequests)
            {
                return (true, "MalwareBazaar key accepted, though rate limit is currently active.");
            }

            string json = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode)
            {
                return (false, $"Unexpected MalwareBazaar response: HTTP {(int)resp.StatusCode}.");
            }

            using var doc = JsonDocument.Parse(json);
            string status = doc.RootElement.TryGetProperty("query_status", out var qEl)
                ? (qEl.GetString() ?? string.Empty)
                : string.Empty;

            if (status.Equals("no_api_key", StringComparison.OrdinalIgnoreCase)
                || status.Equals("user_blacklisted", StringComparison.OrdinalIgnoreCase)
                || status.Equals("illegal_hash", StringComparison.OrdinalIgnoreCase))
            {
                return (false, $"MalwareBazaar returned '{status}'.");
            }

            _lastStatuses[MalwareBazaarServiceName] = "Connected";
            return (true, "MalwareBazaar Auth-Key is valid.");
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            return (false, "MalwareBazaar key check cancelled.");
        }
        catch (Exception ex)
        {
            return (false, $"Network error contacting MalwareBazaar: {ex.Message}");
        }
    }

    private async Task<SecondaryLookupResult> QueryMalwareBazaarAsync(string sha256, string authKey, CancellationToken ct)
    {
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Post, MalwareBazaarApiUrl);
            req.Headers.Add("Auth-Key", authKey);
            req.Content = new FormUrlEncodedContent(
            [
                new KeyValuePair<string, string>("query", "get_info"),
                new KeyValuePair<string, string>("hash", sha256)
            ]);

            using HttpResponseMessage resp = await _httpClient.SendAsync(req, ct).ConfigureAwait(false);
            if (resp.StatusCode == HttpStatusCode.Unauthorized || resp.StatusCode == HttpStatusCode.Forbidden)
            {
                _lastStatuses[MalwareBazaarServiceName] = $"Auth error (HTTP {(int)resp.StatusCode})";
                return new SecondaryLookupResult { Outcome = SecondaryLookupOutcome.Error, ServiceName = MalwareBazaarServiceName };
            }

            if (!resp.IsSuccessStatusCode)
            {
                _lastStatuses[MalwareBazaarServiceName] = $"HTTP {(int)resp.StatusCode}";
                return new SecondaryLookupResult { Outcome = SecondaryLookupOutcome.Error, ServiceName = MalwareBazaarServiceName };
            }

            string json = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            using var doc = JsonDocument.Parse(json);
            string status = doc.RootElement.TryGetProperty("query_status", out var qEl)
                ? (qEl.GetString() ?? string.Empty)
                : string.Empty;

            if (!string.Equals(status, "ok", StringComparison.OrdinalIgnoreCase))
            {
                _lastStatuses[MalwareBazaarServiceName] = "OK (not listed)";
                return new SecondaryLookupResult { Outcome = SecondaryLookupOutcome.NotFound, ServiceName = MalwareBazaarServiceName };
            }

            var detections = new List<string>();
            if (doc.RootElement.TryGetProperty("data", out var dataArr) && dataArr.ValueKind == JsonValueKind.Array)
            {
                foreach (JsonElement item in dataArr.EnumerateArray())
                {
                    if (item.TryGetProperty("signature", out var sigEl) && sigEl.ValueKind == JsonValueKind.String)
                    {
                        string? sig = sigEl.GetString();
                        if (!string.IsNullOrWhiteSpace(sig))
                        {
                            detections.Add($"MalwareBazaar: {sig}");
                        }
                    }

                    if (item.TryGetProperty("tags", out var tagsEl) && tagsEl.ValueKind == JsonValueKind.Array)
                    {
                        var tags = tagsEl.EnumerateArray()
                            .Where(t => t.ValueKind == JsonValueKind.String)
                            .Select(t => t.GetString())
                            .Where(s => !string.IsNullOrWhiteSpace(s))
                            .Take(4)
                            .ToList();
                        if (tags.Count > 0)
                        {
                            detections.Add($"Tags: {string.Join(", ", tags)}");
                        }
                    }

                    break;
                }
            }

            if (detections.Count == 0)
            {
                detections.Add("MalwareBazaar: Known malware sample");
            }

            _lastStatuses[MalwareBazaarServiceName] = "OK (match found)";
            return new SecondaryLookupResult
            {
                Outcome = SecondaryLookupOutcome.Malicious,
                ServiceName = MalwareBazaarServiceName,
                MaliciousCount = 1,
                TotalEngines = 1,
                DetectionNames = detections,
                Summary = $"UNSAFE: Matched in MalwareBazaar ({detections[0]})",
                ReportUrl = $"https://bazaar.abuse.ch/sample/{sha256}/"
            };
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _lastStatuses[MalwareBazaarServiceName] = "Network error";
            _logger.Warn($"MalwareBazaar lookup failed: {ex.Message}");
            return new SecondaryLookupResult { Outcome = SecondaryLookupOutcome.Error, ServiceName = MalwareBazaarServiceName };
        }
    }

    private async Task<SecondaryLookupResult> QueryCirclAsync(string sha256, CancellationToken ct)
    {
        try
        {
            if (_circlMinSpacing > TimeSpan.Zero)
            {
                await _circlThrottleLock.WaitAsync(ct).ConfigureAwait(false);
                try
                {
                    TimeSpan elapsed = DateTimeOffset.UtcNow - _lastCirclQueryUtc;
                    if (elapsed < _circlMinSpacing)
                    {
                        await Task.Delay(_circlMinSpacing - elapsed, ct).ConfigureAwait(false);
                    }

                    _lastCirclQueryUtc = DateTimeOffset.UtcNow;
                }
                finally
                {
                    _circlThrottleLock.Release();
                }
            }

            using var req = new HttpRequestMessage(HttpMethod.Get, CirclBaseUrl + sha256);
            req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            req.Headers.UserAgent.ParseAdd("VTDownloadGuard/1.1");

            using HttpResponseMessage resp = await _httpClient.SendAsync(req, ct).ConfigureAwait(false);
            if (resp.StatusCode == HttpStatusCode.NotFound)
            {
                _lastStatuses[CirclServiceName] = "OK (not in NSRL)";
                return new SecondaryLookupResult { Outcome = SecondaryLookupOutcome.NotFound, ServiceName = CirclServiceName };
            }

            if (!resp.IsSuccessStatusCode)
            {
                _lastStatuses[CirclServiceName] = $"HTTP {(int)resp.StatusCode}";
                return new SecondaryLookupResult { Outcome = SecondaryLookupOutcome.Error, ServiceName = CirclServiceName };
            }

            string json = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            using var doc = JsonDocument.Parse(json);
            JsonElement root = doc.RootElement;

            if (root.TryGetProperty("KnownMalicious", out var malEl) && malEl.ValueKind == JsonValueKind.Array)
            {
                var hits = malEl.EnumerateArray()
                    .Where(e => e.ValueKind == JsonValueKind.String)
                    .Select(e => e.GetString()!)
                    .Where(s => !string.IsNullOrWhiteSpace(s))
                    .Take(5)
                    .ToList();

                if (hits.Count > 0)
                {
                    _lastStatuses[CirclServiceName] = "OK (flagged malicious)";
                    return new SecondaryLookupResult
                    {
                        Outcome = SecondaryLookupOutcome.Malicious,
                        ServiceName = CirclServiceName,
                        MaliciousCount = 1,
                        TotalEngines = 1,
                        DetectionNames = hits.Select(h => $"CIRCL: {h}").ToList(),
                        Summary = $"UNSAFE: Flagged by CIRCL Hashlookup ({string.Join(", ", hits)})",
                        ReportUrl = VirusTotalClient.BuildGuiFileUrl(sha256)
                    };
                }
            }

            if (TryReadInt(root, "hashlookup:trust", out int trust) && trust >= 55)
            {
                string label = ReadCirclProductLabel(root);
                _lastStatuses[CirclServiceName] = $"OK (trusted {trust}%)";
                return new SecondaryLookupResult
                {
                    Outcome = SecondaryLookupOutcome.Clean,
                    ServiceName = CirclServiceName,
                    MaliciousCount = 0,
                    TotalEngines = 1,
                    Summary = $"Verified known-good software in CIRCL NSRL (trust {trust}): {label}",
                    ReportUrl = VirusTotalClient.BuildGuiFileUrl(sha256)
                };
            }

            _lastStatuses[CirclServiceName] = "OK (low trust / inconclusive)";
            return new SecondaryLookupResult { Outcome = SecondaryLookupOutcome.NotFound, ServiceName = CirclServiceName };
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _lastStatuses[CirclServiceName] = "Network error";
            _logger.Warn($"CIRCL Hashlookup failed: {ex.Message}");
            return new SecondaryLookupResult { Outcome = SecondaryLookupOutcome.Error, ServiceName = CirclServiceName };
        }
    }

    private async Task<SecondaryLookupResult> QueryMetaDefenderAsync(
        string sha256,
        string apiKey,
        int maliciousThreshold,
        FileRiskCategory riskCategory,
        CancellationToken ct)
    {
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, MetaDefenderBaseUrl + sha256);
            req.Headers.Add("apikey", apiKey);
            req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            using HttpResponseMessage resp = await _httpClient.SendAsync(req, ct).ConfigureAwait(false);
            if (resp.StatusCode == HttpStatusCode.NotFound)
            {
                _lastStatuses[MetaDefenderServiceName] = "OK (not found)";
                return new SecondaryLookupResult { Outcome = SecondaryLookupOutcome.NotFound, ServiceName = MetaDefenderServiceName };
            }

            if (resp.StatusCode == HttpStatusCode.Unauthorized || resp.StatusCode == HttpStatusCode.Forbidden)
            {
                _lastStatuses[MetaDefenderServiceName] = $"Auth error (HTTP {(int)resp.StatusCode})";
                return new SecondaryLookupResult { Outcome = SecondaryLookupOutcome.Error, ServiceName = MetaDefenderServiceName };
            }

            if (!resp.IsSuccessStatusCode)
            {
                _lastStatuses[MetaDefenderServiceName] = $"HTTP {(int)resp.StatusCode}";
                return new SecondaryLookupResult { Outcome = SecondaryLookupOutcome.Error, ServiceName = MetaDefenderServiceName };
            }

            string json = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            using var doc = JsonDocument.Parse(json);
            JsonElement root = doc.RootElement;

            string dataId = root.TryGetProperty("data_id", out var rootDataId) && rootDataId.ValueKind == JsonValueKind.String
                ? (rootDataId.GetString() ?? string.Empty)
                : string.Empty;

            if (!root.TryGetProperty("scan_results", out var scanResults) || scanResults.ValueKind != JsonValueKind.Object)
            {
                _lastStatuses[MetaDefenderServiceName] = "OK (no scan results)";
                return new SecondaryLookupResult { Outcome = SecondaryLookupOutcome.NotFound, ServiceName = MetaDefenderServiceName };
            }

            if (string.IsNullOrWhiteSpace(dataId)
                && scanResults.TryGetProperty("data_id", out var nestedDataId)
                && nestedDataId.ValueKind == JsonValueKind.String)
            {
                dataId = nestedDataId.GetString() ?? string.Empty;
            }

            int totalDetected = TryReadInt(scanResults, "total_detected_avs", out int det) ? det : 0;
            int totalAvs = TryReadInt(scanResults, "total_avs", out int avs) ? avs : 0;

            var detections = new List<string>();
            if (scanResults.TryGetProperty("scan_details", out var details) && details.ValueKind == JsonValueKind.Object)
            {
                foreach (JsonProperty engine in details.EnumerateObject())
                {
                    if (engine.Value.ValueKind != JsonValueKind.Object)
                    {
                        continue;
                    }

                    if (TryReadInt(engine.Value, "scan_result_i", out int code) && code == 1)
                    {
                        string threat = engine.Value.TryGetProperty("threat_found", out var thEl) && thEl.ValueKind == JsonValueKind.String
                            ? (thEl.GetString() ?? "malicious")
                            : "malicious";
                        if (string.IsNullOrWhiteSpace(threat))
                        {
                            threat = "malicious";
                        }

                        detections.Add($"{engine.Name}: {threat}");
                        if (detections.Count >= 5)
                        {
                            break;
                        }
                    }
                }
            }

            string reportUrl = !string.IsNullOrWhiteSpace(dataId)
                ? $"https://metadefender.opswat.com/results/file/{dataId}/regular/overview"
                : VirusTotalClient.BuildGuiFileUrl(sha256);

            int threshold = Math.Max(1, maliciousThreshold);
            if (totalDetected >= threshold)
            {
                _lastStatuses[MetaDefenderServiceName] = $"OK ({totalDetected}/{totalAvs} detected)";
                return new SecondaryLookupResult
                {
                    Outcome = SecondaryLookupOutcome.Malicious,
                    ServiceName = MetaDefenderServiceName,
                    MaliciousCount = totalDetected,
                    TotalEngines = Math.Max(totalAvs, totalDetected),
                    DetectionNames = detections,
                    Summary = $"UNSAFE: {totalDetected}/{totalAvs} engines flagged (OPSWAT MetaDefender)",
                    ReportUrl = reportUrl
                };
            }

            if (totalDetected == 0 && totalAvs >= 10)
            {
                _lastStatuses[MetaDefenderServiceName] = $"OK (0/{totalAvs} clean)";
                return new SecondaryLookupResult
                {
                    Outcome = SecondaryLookupOutcome.Clean,
                    ServiceName = MetaDefenderServiceName,
                    MaliciousCount = 0,
                    TotalEngines = totalAvs,
                    Summary = $"Clean: 0/{totalAvs} detections (OPSWAT MetaDefender)",
                    ReportUrl = reportUrl
                };
            }

            if (totalDetected > 0 && riskCategory is FileRiskCategory.Low or FileRiskCategory.Trusted)
            {
                _lastStatuses[MetaDefenderServiceName] = $"OK ({totalDetected}/{totalAvs} low risk)";
                return new SecondaryLookupResult
                {
                    Outcome = SecondaryLookupOutcome.LowRisk,
                    ServiceName = MetaDefenderServiceName,
                    MaliciousCount = totalDetected,
                    TotalEngines = Math.Max(totalAvs, totalDetected),
                    DetectionNames = detections,
                    Summary = $"Low risk: {totalDetected}/{totalAvs} detections (OPSWAT MetaDefender)",
                    ReportUrl = reportUrl
                };
            }

            _lastStatuses[MetaDefenderServiceName] = "OK (deferred to VT)";
            return new SecondaryLookupResult { Outcome = SecondaryLookupOutcome.NotFound, ServiceName = MetaDefenderServiceName };
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _lastStatuses[MetaDefenderServiceName] = "Network error";
            _logger.Warn($"OPSWAT MetaDefender lookup failed: {ex.Message}");
            return new SecondaryLookupResult { Outcome = SecondaryLookupOutcome.Error, ServiceName = MetaDefenderServiceName };
        }
    }

    private static string ReadCirclProductLabel(JsonElement root)
    {
        if (root.TryGetProperty("ProductCode", out var prodObj) && prodObj.ValueKind == JsonValueKind.Object)
        {
            if (prodObj.TryGetProperty("ProductName", out var prodName) && prodName.ValueKind == JsonValueKind.String)
            {
                string? name = prodName.GetString();
                if (!string.IsNullOrWhiteSpace(name))
                {
                    return name.Trim();
                }
            }
        }

        if (root.TryGetProperty("FileName", out var fileNameEl) && fileNameEl.ValueKind == JsonValueKind.String)
        {
            string? fn = fileNameEl.GetString();
            if (!string.IsNullOrWhiteSpace(fn))
            {
                return fn.Trim();
            }
        }

        return "NSRL known file";
    }

    private static bool TryReadInt(JsonElement obj, string propName, out int value)
    {
        if (obj.TryGetProperty(propName, out var el))
        {
            if (el.ValueKind == JsonValueKind.Number && el.TryGetInt32(out value))
            {
                return true;
            }

            if (el.ValueKind == JsonValueKind.String && int.TryParse(el.GetString(), out value))
            {
                return true;
            }
        }

        value = 0;
        return false;
    }

    public void Dispose()
    {
        _circlThrottleLock.Dispose();
        if (_ownsHttpClient)
        {
            _httpClient.Dispose();
        }
    }
}
