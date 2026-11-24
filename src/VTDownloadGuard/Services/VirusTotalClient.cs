using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using VTDownloadGuard.Models;

namespace VTDownloadGuard.Services;

public enum VtOutcome
{
    Found = 0,
    NotFound = 1,
    AuthError = 2,
    RateLimited = 3,
    TimedOut = 4,
    NetworkError = 5,
    Error = 6
}

public sealed class VtReportResult
{
    public VtOutcome Outcome { get; init; }
    public int MaliciousCount { get; init; }
    public int SuspiciousCount { get; init; }
    public int UndetectedCount { get; init; }
    public int HarmlessCount { get; init; }
    public int TotalEngines => MaliciousCount + SuspiciousCount + UndetectedCount + HarmlessCount;
    public List<string> DetectionNames { get; init; } = [];
    public string ErrorMessage { get; init; } = string.Empty;
    public int ApiCallsMade { get; init; }
}

public sealed class VirusTotalClient : IDisposable
{
    private const string ApiBaseUrl = "https://www.virustotal.com/api/v3/";
    private const string EicarSha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
    public const long DirectUploadLimitBytes = 32L * 1024 * 1024;
    public const long LargeUploadLimitBytes = 650L * 1024 * 1024;
    public const string GuiUploadUrl = "https://www.virustotal.com/gui/home/upload";
    public const string GuiSearchUrl = "https://www.virustotal.com/gui/home/search";
    private static readonly TimeSpan DefaultApiRequestTimeout = TimeSpan.FromMinutes(3);
    private static readonly TimeSpan UploadRequestTimeout = TimeSpan.FromMinutes(20);

    private readonly HttpClient _httpClient;
    private readonly bool _ownsHttpClient;
    private readonly RateLimiter _rateLimiter;
    private readonly AppLogger _logger;
    private readonly TimeSpan _initialAnalysisDelay;
    private readonly TimeSpan _analysisPollInterval;
    private readonly TimeSpan _rateLimitFallbackDelay;
    private readonly int _maxPolls;
    private readonly long _directUploadLimitBytes;

    public VirusTotalClient(
        RateLimiter rateLimiter,
        AppLogger logger,
        HttpClient? httpClient = null,
        TimeSpan? initialAnalysisDelay = null,
        TimeSpan? analysisPollInterval = null,
        TimeSpan? rateLimitFallbackDelay = null,
        int maxPolls = 12,
        long? directUploadLimitBytes = null)
    {
        _rateLimiter = rateLimiter;
        _logger = logger;
        _ownsHttpClient = httpClient is null;
        _httpClient = httpClient ?? new HttpClient { Timeout = Timeout.InfiniteTimeSpan };
        _initialAnalysisDelay = initialAnalysisDelay ?? TimeSpan.FromSeconds(20);
        _analysisPollInterval = analysisPollInterval ?? TimeSpan.FromSeconds(25);
        _rateLimitFallbackDelay = rateLimitFallbackDelay ?? TimeSpan.FromSeconds(61);
        _maxPolls = Math.Max(1, maxPolls);
        _directUploadLimitBytes = Math.Max(1L, directUploadLimitBytes ?? DirectUploadLimitBytes);
    }

    public static string BuildGuiFileUrl(string sha256) =>
        $"https://www.virustotal.com/gui/file/{sha256.ToLowerInvariant()}";

    public static ScanVerdict EvaluateVerdict(int malicious, int suspicious, int maliciousThreshold)
    {
        int threshold = Math.Max(1, maliciousThreshold);
        if (malicious >= threshold)
        {
            return ScanVerdict.Unsafe;
        }

        if (malicious > 0 || suspicious > 0)
        {
            return ScanVerdict.LowRisk;
        }

        return ScanVerdict.Clean;
    }

    public async Task<(bool Success, string Message)> TestApiKeyAsync(string apiKey, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(apiKey))
        {
            return (false, "Please enter a VirusTotal API key.");
        }

        try
        {
            using var request = CreateRequest(HttpMethod.Get, ApiBaseUrl + "files/" + EicarSha256, apiKey);
            using HttpResponseMessage response = await _httpClient.SendAsync(request, ct).ConfigureAwait(false);

            if (response.StatusCode == HttpStatusCode.OK || response.StatusCode == HttpStatusCode.NotFound)
            {
                return (true, "API key is valid and connected to VirusTotal.");
            }

            if (response.StatusCode == HttpStatusCode.Unauthorized || response.StatusCode == HttpStatusCode.Forbidden)
            {
                return (false, $"VirusTotal rejected the API key (HTTP {(int)response.StatusCode}).");
            }

            if (response.StatusCode == HttpStatusCode.TooManyRequests)
            {
                return (true, "API key accepted, though VirusTotal rate limit (HTTP 429) is currently active.");
            }

            return (false, $"Unexpected VirusTotal response: HTTP {(int)response.StatusCode} ({response.ReasonPhrase}).");
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            return (false, "API key check cancelled.");
        }
        catch (Exception ex)
        {
            return (false, $"Network error while testing key: {ex.Message}");
        }
    }

    public async Task<VtUserQuotaInfo> GetUserQuotasAsync(string apiKey, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(apiKey))
        {
            return new VtUserQuotaInfo
            {
                Success = false,
                ErrorMessage = "VirusTotal API key is not configured.",
                ApiCallsMade = 0
            };
        }

        string trimmedKey = apiKey.Trim();
        try
        {
            using var request = CreateRequest(
                HttpMethod.Get,
                ApiBaseUrl + "users/" + Uri.EscapeDataString(trimmedKey),
                trimmedKey);
            using HttpResponseMessage response = await _httpClient.SendAsync(request, ct).ConfigureAwait(false);

            if (response.StatusCode == HttpStatusCode.Unauthorized || response.StatusCode == HttpStatusCode.Forbidden)
            {
                return new VtUserQuotaInfo
                {
                    Success = false,
                    ErrorMessage = $"VirusTotal rejected the API key (HTTP {(int)response.StatusCode}).",
                    ApiCallsMade = 1
                };
            }

            if (response.StatusCode == HttpStatusCode.TooManyRequests)
            {
                return new VtUserQuotaInfo
                {
                    Success = false,
                    ErrorMessage = "VirusTotal rate limit active (HTTP 429). Please retry in a moment.",
                    ApiCallsMade = 1
                };
            }

            string body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                return new VtUserQuotaInfo
                {
                    Success = false,
                    ErrorMessage = $"VirusTotal quota lookup failed (HTTP {(int)response.StatusCode}).",
                    ApiCallsMade = 1
                };
            }

            using var doc = JsonDocument.Parse(body);
            if (!doc.RootElement.TryGetProperty("data", out var dataEl))
            {
                return new VtUserQuotaInfo
                {
                    Success = false,
                    ErrorMessage = "Malformed VirusTotal user quota payload.",
                    ApiCallsMade = 1
                };
            }

            string userId = dataEl.TryGetProperty("id", out var idEl) && idEl.ValueKind == JsonValueKind.String
                ? (idEl.GetString() ?? string.Empty)
                : string.Empty;

            VtQuotaBucket hourly = new(0, 0);
            VtQuotaBucket daily = new(0, 0);
            VtQuotaBucket monthly = new(0, 0);

            if (dataEl.TryGetProperty("attributes", out var attrsEl)
                && attrsEl.TryGetProperty("quotas", out var quotasEl)
                && quotasEl.ValueKind == JsonValueKind.Object)
            {
                hourly = ReadQuotaBucket(quotasEl, "api_requests_hourly");
                daily = ReadQuotaBucket(quotasEl, "api_requests_daily");
                monthly = ReadQuotaBucket(quotasEl, "api_requests_monthly");
            }

            return new VtUserQuotaInfo
            {
                Success = true,
                UserId = userId,
                Hourly = hourly,
                Daily = daily,
                Monthly = monthly,
                FetchedAtUtc = DateTimeOffset.UtcNow,
                ApiCallsMade = 1
            };
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            return new VtUserQuotaInfo
            {
                Success = false,
                ErrorMessage = "Quota request cancelled.",
                ApiCallsMade = 0
            };
        }
        catch (Exception ex)
        {
            _logger.Warn($"Failed to fetch VirusTotal user quotas: {ex.Message}");
            return new VtUserQuotaInfo
            {
                Success = false,
                ErrorMessage = $"Network error fetching quotas: {ex.Message}",
                ApiCallsMade = 0
            };
        }
    }

    private static VtQuotaBucket ReadQuotaBucket(JsonElement quotasObj, string name)
    {
        if (!quotasObj.TryGetProperty(name, out var bucketEl) || bucketEl.ValueKind != JsonValueKind.Object)
        {
            return new VtQuotaBucket(0, 0);
        }

        long used = bucketEl.TryGetProperty("used", out var usedEl) && usedEl.TryGetInt64(out long u) ? u : 0;
        long allowed = bucketEl.TryGetProperty("allowed", out var allowedEl) && allowedEl.TryGetInt64(out long a) ? a : 0;
        return new VtQuotaBucket(used, allowed);
    }

    public async Task<VtReportResult> LookupHashAsync(string sha256, string apiKey, CancellationToken ct)
    {
        int apiCalls = 0;
        var (response, errorResult) = await SendWithRateLimitAndRetriesAsync(
            () => CreateRequest(HttpMethod.Get, ApiBaseUrl + "files/" + sha256.ToLowerInvariant(), apiKey),
            () => apiCalls++,
            ct).ConfigureAwait(false);

        if (errorResult is not null || response is null)
        {
            return WithApiCalls(errorResult ?? new VtReportResult { Outcome = VtOutcome.Error }, apiCalls);
        }

        using (response)
        {
            if (response.StatusCode == HttpStatusCode.NotFound)
            {
                return new VtReportResult
                {
                    Outcome = VtOutcome.NotFound,
                    ApiCallsMade = apiCalls
                };
            }

            string body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                return new VtReportResult
                {
                    Outcome = VtOutcome.Error,
                    ErrorMessage = $"VirusTotal hash lookup failed (HTTP {(int)response.StatusCode}).",
                    ApiCallsMade = apiCalls
                };
            }

            return ParseFileReportJson(body, apiCalls);
        }
    }

    public async Task<VtReportResult> UploadAndAnalyzeAsync(
        string filePath,
        string sha256,
        string apiKey,
        Action<string>? onProgress,
        CancellationToken ct)
    {
        int apiCalls = 0;
        var fileInfo = new FileInfo(filePath);
        if (!fileInfo.Exists)
        {
            return new VtReportResult
            {
                Outcome = VtOutcome.Error,
                ErrorMessage = "File no longer exists before upload."
            };
        }

        long length = fileInfo.Length;
        if (length <= 0)
        {
            return new VtReportResult
            {
                Outcome = VtOutcome.Error,
                ErrorMessage = "Empty file cannot be uploaded."
            };
        }

        if (length > LargeUploadLimitBytes)
        {
            return new VtReportResult
            {
                Outcome = VtOutcome.Error,
                ErrorMessage = "File exceeds VirusTotal's 650 MB upload limit."
            };
        }

        string uploadEndpoint = ApiBaseUrl + "files";
        if (length > _directUploadLimitBytes)
        {
            onProgress?.Invoke("Requesting large-file upload URL...");
            var (urlResponse, urlError) = await SendWithRateLimitAndRetriesAsync(
                () => CreateRequest(HttpMethod.Get, ApiBaseUrl + "files/upload_url", apiKey),
                () => apiCalls++,
                ct).ConfigureAwait(false);

            if (urlError is not null || urlResponse is null)
            {
                return WithApiCalls(urlError ?? new VtReportResult { Outcome = VtOutcome.Error }, apiCalls);
            }

            using (urlResponse)
            {
                string urlJson = await urlResponse.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
                if (!urlResponse.IsSuccessStatusCode)
                {
                    return new VtReportResult
                    {
                        Outcome = VtOutcome.Error,
                        ErrorMessage = $"Failed to obtain upload URL (HTTP {(int)urlResponse.StatusCode}).",
                        ApiCallsMade = apiCalls
                    };
                }

                using var doc = JsonDocument.Parse(urlJson);
                if (!doc.RootElement.TryGetProperty("data", out var dataProp) || dataProp.ValueKind != JsonValueKind.String)
                {
                    return new VtReportResult
                    {
                        Outcome = VtOutcome.Error,
                        ErrorMessage = "Invalid upload URL response from VirusTotal.",
                        ApiCallsMade = apiCalls
                    };
                }

                uploadEndpoint = dataProp.GetString() ?? uploadEndpoint;
            }
        }

        onProgress?.Invoke("Uploading file to VirusTotal...");
        string? analysisId = null;

        var (uploadResponse, uploadError) = await SendWithRateLimitAndRetriesAsync(
            () => CreateMultipartUploadRequest(uploadEndpoint, filePath, length, apiKey, onProgress),
            () => apiCalls++,
            ct,
            UploadRequestTimeout).ConfigureAwait(false);

        if (uploadError is not null || uploadResponse is null)
        {
            return WithApiCalls(uploadError ?? new VtReportResult { Outcome = VtOutcome.Error }, apiCalls);
        }

        using (uploadResponse)
        {
            string uploadJson = await uploadResponse.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            if (!uploadResponse.IsSuccessStatusCode)
            {
                return new VtReportResult
                {
                    Outcome = VtOutcome.Error,
                    ErrorMessage = $"VirusTotal upload failed (HTTP {(int)uploadResponse.StatusCode}).",
                    ApiCallsMade = apiCalls
                };
            }

            try
            {
                using var doc = JsonDocument.Parse(uploadJson);
                if (doc.RootElement.TryGetProperty("data", out var dataEl)
                    && dataEl.TryGetProperty("id", out var idEl))
                {
                    analysisId = idEl.GetString();
                }
            }
            catch (Exception ex)
            {
                _logger.Error("Failed to parse VirusTotal upload response", ex);
            }
        }

        if (string.IsNullOrWhiteSpace(analysisId))
        {
            return new VtReportResult
            {
                Outcome = VtOutcome.Error,
                ErrorMessage = "VirusTotal did not return an analysis ID.",
                ApiCallsMade = apiCalls
            };
        }

        onProgress?.Invoke("Waiting for VirusTotal scan...");
        if (_initialAnalysisDelay > TimeSpan.Zero)
        {
            await Task.Delay(_initialAnalysisDelay, ct).ConfigureAwait(false);
        }

        for (int poll = 0; poll < _maxPolls; poll++)
        {
            onProgress?.Invoke($"Checking VirusTotal analysis ({poll + 1}/{_maxPolls})...");
            var (pollResponse, pollError) = await SendWithRateLimitAndRetriesAsync(
                () => CreateRequest(HttpMethod.Get, ApiBaseUrl + "analyses/" + Uri.EscapeDataString(analysisId), apiKey),
                () => apiCalls++,
                ct).ConfigureAwait(false);

            if (pollError is not null || pollResponse is null)
            {
                return WithApiCalls(pollError ?? new VtReportResult { Outcome = VtOutcome.Error }, apiCalls);
            }

            using (pollResponse)
            {
                string pollJson = await pollResponse.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
                if (!pollResponse.IsSuccessStatusCode)
                {
                    return new VtReportResult
                    {
                        Outcome = VtOutcome.Error,
                        ErrorMessage = $"Analysis polling failed (HTTP {(int)pollResponse.StatusCode}).",
                        ApiCallsMade = apiCalls
                    };
                }

                var (completed, parsed) = TryParseAnalysisReportJson(pollJson, apiCalls);
                if (completed)
                {
                    return parsed;
                }
            }

            if (poll < _maxPolls - 1 && _analysisPollInterval > TimeSpan.Zero)
            {
                await Task.Delay(_analysisPollInterval, ct).ConfigureAwait(false);
            }
        }

        // One final hash lookup attempt in case the file report finalized right as polling finished.
        var finalLookup = await LookupHashAsync(sha256, apiKey, ct).ConfigureAwait(false);
        apiCalls += finalLookup.ApiCallsMade;
        if (finalLookup.Outcome == VtOutcome.Found)
        {
            return WithApiCalls(finalLookup, apiCalls);
        }

        return new VtReportResult
        {
            Outcome = VtOutcome.TimedOut,
            ErrorMessage = "Uploaded; VirusTotal analysis is still queued.",
            ApiCallsMade = apiCalls
        };
    }

    private async Task<(HttpResponseMessage? Response, VtReportResult? ErrorResult)> SendWithRateLimitAndRetriesAsync(
        Func<HttpRequestMessage> requestFactory,
        Action onAttemptSent,
        CancellationToken ct,
        TimeSpan? requestTimeout = null)
    {
        const int maxRateLimitRetries = 3;
        TimeSpan effectiveTimeout = requestTimeout ?? DefaultApiRequestTimeout;

        for (int attempt = 0; attempt <= maxRateLimitRetries; attempt++)
        {
            await _rateLimiter.WaitForSlotAsync(ct).ConfigureAwait(false);

            HttpResponseMessage response;
            try
            {
                using HttpRequestMessage request = requestFactory();
                onAttemptSent();
                using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                timeoutCts.CancelAfter(effectiveTimeout);
                response = await _httpClient.SendAsync(request, timeoutCts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (OperationCanceledException)
            {
                _logger.Warn($"HTTP request to VirusTotal timed out after {effectiveTimeout.TotalMinutes:F0} minute(s).");
                return (null, new VtReportResult
                {
                    Outcome = VtOutcome.NetworkError,
                    ErrorMessage = "Request to VirusTotal timed out."
                });
            }
            catch (Exception ex)
            {
                _logger.Error("HTTP request to VirusTotal failed", ex);
                return (null, new VtReportResult
                {
                    Outcome = VtOutcome.NetworkError,
                    ErrorMessage = $"Network error contacting VirusTotal: {ex.Message}"
                });
            }

            if (response.StatusCode == HttpStatusCode.Unauthorized || response.StatusCode == HttpStatusCode.Forbidden)
            {
                int code = (int)response.StatusCode;
                response.Dispose();
                return (null, new VtReportResult
                {
                    Outcome = VtOutcome.AuthError,
                    ErrorMessage = $"Invalid or unauthorized VirusTotal API key (HTTP {code})."
                });
            }

            if (response.StatusCode == HttpStatusCode.TooManyRequests)
            {
                TimeSpan cooldown = ExtractRetryAfter(response) ?? _rateLimitFallbackDelay;
                response.Dispose();
                _rateLimiter.NotifyRateLimitHit(cooldown);
                _logger.Warn($"VirusTotal HTTP 429 received; backing off for {cooldown.TotalSeconds:F1}s (attempt {attempt + 1}/{maxRateLimitRetries + 1}).");

                if (attempt == maxRateLimitRetries)
                {
                    return (null, new VtReportResult
                    {
                        Outcome = VtOutcome.RateLimited,
                        ErrorMessage = "VirusTotal API rate limit / daily quota exceeded (HTTP 429)."
                    });
                }

                if (cooldown > TimeSpan.Zero)
                {
                    await Task.Delay(cooldown, ct).ConfigureAwait(false);
                }

                continue;
            }

            return (response, null);
        }

        return (null, new VtReportResult
        {
            Outcome = VtOutcome.RateLimited,
            ErrorMessage = "VirusTotal rate limit retries exhausted."
        });
    }

    private static TimeSpan? ExtractRetryAfter(HttpResponseMessage response)
    {
        if (response.Headers.RetryAfter?.Delta is TimeSpan delta && delta > TimeSpan.Zero)
        {
            return delta;
        }

        if (response.Headers.RetryAfter?.Date is DateTimeOffset retryDate)
        {
            var diff = retryDate - DateTimeOffset.UtcNow;
            if (diff > TimeSpan.Zero)
            {
                return diff;
            }
        }

        return null;
    }

    private static HttpRequestMessage CreateRequest(HttpMethod method, string url, string apiKey)
    {
        var req = new HttpRequestMessage(method, url);
        req.Headers.Add("x-apikey", apiKey);
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        return req;
    }

    private static HttpRequestMessage CreateMultipartUploadRequest(
        string url,
        string filePath,
        long fileLength,
        string apiKey,
        Action<string>? onProgress)
    {
        var req = CreateRequest(HttpMethod.Post, url, apiKey);
        var multipart = new MultipartFormDataContent();
        var fileContent = new ProgressFileContent(filePath, fileLength, onProgress);
        fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        multipart.Add(fileContent, "file", Path.GetFileName(filePath));
        req.Content = multipart;
        return req;
    }

    private sealed class ProgressFileContent : HttpContent
    {
        private readonly string _filePath;
        private readonly long _fileLength;
        private readonly Action<string>? _onProgress;

        public ProgressFileContent(string filePath, long fileLength, Action<string>? onProgress)
        {
            _filePath = filePath;
            _fileLength = Math.Max(0, fileLength);
            _onProgress = onProgress;
        }

        protected override bool TryComputeLength(out long length)
        {
            length = _fileLength;
            return true;
        }

        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) =>
            SerializeToStreamAsync(stream, context, CancellationToken.None);

        protected override async Task SerializeToStreamAsync(
            Stream stream,
            TransportContext? context,
            CancellationToken cancellationToken)
        {
            const int bufferSize = 64 * 1024;
            byte[] buffer = new byte[bufferSize];
            long totalBytes = _fileLength;
            long sentBytes = 0;
            int lastReportedPct = -5;
            long lastReportTick = Environment.TickCount64 - 1000;
            double totalMb = totalBytes / (1024.0 * 1024.0);

            await using var fileStream = new FileStream(
                _filePath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize,
                useAsync: true);

            while (true)
            {
                int read = await fileStream.ReadAsync(buffer.AsMemory(0, bufferSize), cancellationToken).ConfigureAwait(false);
                if (read <= 0)
                {
                    break;
                }

                await stream.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                sentBytes += read;

                if (_onProgress is not null && totalBytes > 0)
                {
                    int pct = (int)Math.Clamp(sentBytes * 100L / totalBytes, 0, 100);
                    long nowTick = Environment.TickCount64;
                    if (pct - lastReportedPct >= 5 || nowTick - lastReportTick >= 500 || sentBytes >= totalBytes)
                    {
                        lastReportedPct = pct;
                        lastReportTick = nowTick;
                        double sentMb = sentBytes / (1024.0 * 1024.0);
                        _onProgress($"Uploading to VirusTotal ({pct}% - {sentMb:F1} / {totalMb:F1} MB)...");
                    }
                }
            }
        }
    }

    private VtReportResult ParseFileReportJson(string json, int apiCalls)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("data", out var dataEl)
                || !dataEl.TryGetProperty("attributes", out var attrs))
            {
                return new VtReportResult
                {
                    Outcome = VtOutcome.Error,
                    ErrorMessage = "Malformed VirusTotal file report payload.",
                    ApiCallsMade = apiCalls
                };
            }

            return ParseStatsAndResults(attrs, "last_analysis_stats", "last_analysis_results", apiCalls);
        }
        catch (Exception ex)
        {
            _logger.Error("Failed to parse VirusTotal file report JSON", ex);
            return new VtReportResult
            {
                Outcome = VtOutcome.Error,
                ErrorMessage = $"Failed to parse VirusTotal response: {ex.Message}",
                ApiCallsMade = apiCalls
            };
        }
    }

    private (bool Completed, VtReportResult Result) TryParseAnalysisReportJson(string json, int apiCalls)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("data", out var dataEl)
                || !dataEl.TryGetProperty("attributes", out var attrs))
            {
                return (true, new VtReportResult
                {
                    Outcome = VtOutcome.Error,
                    ErrorMessage = "Malformed VirusTotal analysis payload.",
                    ApiCallsMade = apiCalls
                });
            }

            string status = attrs.TryGetProperty("status", out var statusEl)
                ? (statusEl.GetString() ?? string.Empty)
                : string.Empty;

            if (!string.Equals(status, "completed", StringComparison.OrdinalIgnoreCase))
            {
                return (false, new VtReportResult { ApiCallsMade = apiCalls });
            }

            return (true, ParseStatsAndResults(attrs, "stats", "results", apiCalls));
        }
        catch (Exception ex)
        {
            _logger.Error("Failed to parse VirusTotal analysis JSON", ex);
            return (true, new VtReportResult
            {
                Outcome = VtOutcome.Error,
                ErrorMessage = $"Failed to parse analysis response: {ex.Message}",
                ApiCallsMade = apiCalls
            });
        }
    }

    private static VtReportResult ParseStatsAndResults(
        JsonElement attributes,
        string statsProperty,
        string resultsProperty,
        int apiCalls)
    {
        int malicious = 0;
        int suspicious = 0;
        int undetected = 0;
        int harmless = 0;

        if (attributes.TryGetProperty(statsProperty, out var statsEl) && statsEl.ValueKind == JsonValueKind.Object)
        {
            malicious = ReadInt(statsEl, "malicious");
            suspicious = ReadInt(statsEl, "suspicious");
            undetected = ReadInt(statsEl, "undetected");
            harmless = ReadInt(statsEl, "harmless");
        }

        var maliciousNames = new List<string>();
        var suspiciousNames = new List<string>();

        if (attributes.TryGetProperty(resultsProperty, out var resultsEl) && resultsEl.ValueKind == JsonValueKind.Object)
        {
            foreach (JsonProperty engineProp in resultsEl.EnumerateObject())
            {
                if (engineProp.Value.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }

                string category = engineProp.Value.TryGetProperty("category", out var catEl)
                    ? (catEl.GetString() ?? string.Empty)
                    : string.Empty;

                if (string.Equals(category, "malicious", StringComparison.OrdinalIgnoreCase))
                {
                    string label = ReadResultString(engineProp.Value, "malicious");
                    maliciousNames.Add($"{engineProp.Name}: {label}");
                }
                else if (string.Equals(category, "suspicious", StringComparison.OrdinalIgnoreCase))
                {
                    string label = ReadResultString(engineProp.Value, "suspicious");
                    suspiciousNames.Add($"{engineProp.Name}: {label}");
                }
            }
        }

        var topDetections = maliciousNames
            .Concat(suspiciousNames)
            .Take(5)
            .ToList();

        return new VtReportResult
        {
            Outcome = VtOutcome.Found,
            MaliciousCount = malicious,
            SuspiciousCount = suspicious,
            UndetectedCount = undetected,
            HarmlessCount = harmless,
            DetectionNames = topDetections,
            ApiCallsMade = apiCalls
        };
    }

    private static int ReadInt(JsonElement obj, string name) =>
        obj.TryGetProperty(name, out var prop) && prop.TryGetInt32(out int val) ? val : 0;

    private static string ReadResultString(JsonElement engineObj, string fallback)
    {
        if (engineObj.TryGetProperty("result", out var resEl) && resEl.ValueKind == JsonValueKind.String)
        {
            string? str = resEl.GetString();
            if (!string.IsNullOrWhiteSpace(str))
            {
                return str;
            }
        }

        return fallback;
    }

    private static VtReportResult WithApiCalls(VtReportResult source, int apiCalls) => new()
    {
        Outcome = source.Outcome,
        MaliciousCount = source.MaliciousCount,
        SuspiciousCount = source.SuspiciousCount,
        UndetectedCount = source.UndetectedCount,
        HarmlessCount = source.HarmlessCount,
        DetectionNames = source.DetectionNames,
        ErrorMessage = source.ErrorMessage,
        ApiCallsMade = apiCalls
    };

    public void Dispose()
    {
        if (_ownsHttpClient)
        {
            _httpClient.Dispose();
        }
    }
}
