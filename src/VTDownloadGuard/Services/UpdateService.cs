using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using VTDownloadGuard.Models;

namespace VTDownloadGuard.Services;

public sealed partial class UpdateService : IDisposable
{
    public const string CriticalReleaseMarker = "[CRITICAL UPDATE]";
    public const string DefaultRepository = "sonnenfell/VTDownloadGuard";

    private static readonly string[] AllowedDownloadHosts =
    [
        "github.com",
        "objects.githubusercontent.com",
        "release-assets.githubusercontent.com",
        "github-releases.githubusercontent.com"
    ];

    [GeneratedRegex(@"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")]
    private static partial Regex RepoSlugRegex();

    [GeneratedRegex(@"\b([a-fA-F0-9]{64})\b")]
    private static partial Regex Sha256HexRegex();

    private readonly AppPaths _paths;
    private readonly AppLogger _logger;
    private readonly HttpClient _httpClient;
    private readonly bool _ownsHttpClient;
    private readonly Version _currentVersion;
    private readonly string _appDirectory;
    private readonly Lock _stateSync = new();

    private UpdateCheckResult? _latestCheckResult;
    private System.Threading.Timer? _autoTimer;
    private Func<bool>? _isBusyScanning;
    private Action<UpdateCheckResult>? _onAutoUpdateStarting;
    private Action? _requestAppExit;
    private AppSettings? _autoSettingsSnapshot;
    private int _checkInFlight;
    private int _updateInFlight;
    private bool _disposed;

    public event Action<UpdateCheckResult>? UpdateStatusChanged;

    public UpdateService(
        AppPaths paths,
        AppLogger logger,
        HttpClient? httpClient = null,
        Version? currentVersionOverride = null,
        string? appDirectoryOverride = null)
    {
        _paths = paths;
        _logger = logger;
        _ownsHttpClient = httpClient is null;
        _httpClient = httpClient ?? new HttpClient { Timeout = TimeSpan.FromMinutes(3) };
        _currentVersion = NormalizeVersion(currentVersionOverride ?? GetCurrentAppVersion());
        _appDirectory = string.IsNullOrWhiteSpace(appDirectoryOverride)
            ? AppContext.BaseDirectory
            : Path.GetFullPath(appDirectoryOverride);
    }

    public Version CurrentVersion => _currentVersion;

    public string AppDirectory => _appDirectory;

    public UpdateCheckResult? LatestCheckResult
    {
        get
        {
            lock (_stateSync)
            {
                return _latestCheckResult;
            }
        }
    }

    public static Version GetCurrentAppVersion()
    {
        Assembly asm = Assembly.GetEntryAssembly() ?? typeof(UpdateService).Assembly;
        string? infoVer = asm.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        if (!string.IsNullOrWhiteSpace(infoVer) && TryParseReleaseVersion(infoVer, out Version? parsed) && parsed is not null)
        {
            return parsed;
        }

        Version? asmVer = asm.GetName().Version;
        return NormalizeVersion(asmVer ?? new Version(1, 0, 0, 0));
    }

    public static Version NormalizeVersion(Version version)
    {
        ArgumentNullException.ThrowIfNull(version);
        return new Version(
            Math.Max(0, version.Major),
            Math.Max(0, version.Minor),
            Math.Max(0, version.Build),
            Math.Max(0, version.Revision));
    }

    public static bool TryParseReleaseVersion(string? tagOrVersion, out Version? version)
    {
        version = null;
        if (string.IsNullOrWhiteSpace(tagOrVersion))
        {
            return false;
        }

        string cleaned = tagOrVersion.Trim();
        if (cleaned.StartsWith('v') || cleaned.StartsWith('V'))
        {
            cleaned = cleaned[1..];
        }

        int plusIdx = cleaned.IndexOf('+');
        if (plusIdx >= 0)
        {
            cleaned = cleaned[..plusIdx];
        }

        int dashIdx = cleaned.IndexOf('-');
        if (dashIdx >= 0)
        {
            cleaned = cleaned[..dashIdx];
        }

        if (!cleaned.Contains('.'))
        {
            return false;
        }

        if (Version.TryParse(cleaned, out Version? raw) && raw is not null)
        {
            version = NormalizeVersion(raw);
            return true;
        }

        return false;
    }

    public static bool IsCriticalRelease(string? releaseNotes)
    {
        if (string.IsNullOrWhiteSpace(releaseNotes))
        {
            return false;
        }

        using var reader = new StringReader(releaseNotes);
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            string trimmed = line.Trim();
            if (trimmed.Length == 0)
            {
                continue;
            }

            return trimmed.Contains(CriticalReleaseMarker, StringComparison.OrdinalIgnoreCase);
        }

        return false;
    }

    public static bool ShouldAutoInstall(AppSettings settings, UpdateCheckResult check)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(check);

        if (!check.Success || !check.UpdateAvailable || !settings.AutoUpdateEnabled)
        {
            return false;
        }

        if (settings.AutoUpdateCriticalOnly && !check.IsCritical)
        {
            return false;
        }

        return !string.IsNullOrWhiteSpace(check.DownloadUrl);
    }

    public static UpdateInstallMode DetectInstallMode(string appDir)
    {
        if (string.IsNullOrWhiteSpace(appDir) || !Directory.Exists(appDir))
        {
            return UpdateInstallMode.PortableFrameworkDependent;
        }

        if (File.Exists(Path.Combine(appDir, "unins000.exe")))
        {
            return UpdateInstallMode.InnoInstaller;
        }

        if (File.Exists(Path.Combine(appDir, "coreclr.dll")))
        {
            return UpdateInstallMode.StandalonePortable;
        }

        return UpdateInstallMode.PortableFrameworkDependent;
    }

    public static bool IsAllowedDownloadUrl(string? url)
    {
        if (string.IsNullOrWhiteSpace(url) || !Uri.TryCreate(url, UriKind.Absolute, out Uri? uri))
        {
            return false;
        }

        if (!string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        string host = uri.Host;
        foreach (string allowed in AllowedDownloadHosts)
        {
            if (string.Equals(host, allowed, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return host.EndsWith(".githubusercontent.com", StringComparison.OrdinalIgnoreCase);
    }

    public static string ExtractExpectedSha256(string? assetDigest, string? releaseNotes, string assetName)
    {
        if (!string.IsNullOrWhiteSpace(assetDigest))
        {
            string trimmed = assetDigest.Trim();
            if (trimmed.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase))
            {
                trimmed = trimmed[7..].Trim();
            }

            if (Sha256HexRegex().IsMatch(trimmed) && trimmed.Length == 64)
            {
                return trimmed.ToLowerInvariant();
            }
        }

        if (!string.IsNullOrWhiteSpace(releaseNotes) && !string.IsNullOrWhiteSpace(assetName))
        {
            using var reader = new StringReader(releaseNotes);
            string? line;
            while ((line = reader.ReadLine()) is not null)
            {
                if (!line.Contains(assetName, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                Match match = Sha256HexRegex().Match(line);
                if (match.Success)
                {
                    return match.Groups[1].Value.ToLowerInvariant();
                }
            }
        }

        return string.Empty;
    }

    public string CreateDataBackup()
    {
        _paths.EnsureDataDirectoryExists();
        Directory.CreateDirectory(_paths.BackupsDirectory);

        string stamp = DateTimeOffset.UtcNow.ToString("yyyyMMdd-HHmmss-fff");
        string backupDir = Path.Combine(_paths.BackupsDirectory, $"pre-update-v{_currentVersion.ToString(3)}-{stamp}");
        Directory.CreateDirectory(backupDir);

        string[] dataFiles =
        [
            _paths.SettingsPath,
            _paths.HistoryPath,
            _paths.HashCachePath
        ];

        foreach (string src in dataFiles)
        {
            if (File.Exists(src))
            {
                string dst = Path.Combine(backupDir, Path.GetFileName(src));
                File.Copy(src, dst, overwrite: true);
            }
        }

        try
        {
            var oldBackups = Directory.GetDirectories(_paths.BackupsDirectory, "pre-update-*")
                .Select(d => new DirectoryInfo(d))
                .OrderByDescending(d => d.CreationTimeUtc)
                .Skip(3)
                .ToList();

            foreach (DirectoryInfo dir in oldBackups)
            {
                dir.Delete(recursive: true);
            }
        }
        catch (Exception ex)
        {
            _logger.Warn($"Failed pruning old data backups: {ex.Message}");
        }

        return backupDir;
    }

    public void ConfigureAutoUpdates(
        AppSettings settings,
        Func<bool> isBusyScanning,
        Action<UpdateCheckResult> onAutoUpdateStarting,
        Action requestAppExit)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(isBusyScanning);
        ArgumentNullException.ThrowIfNull(onAutoUpdateStarting);
        ArgumentNullException.ThrowIfNull(requestAppExit);

        lock (_stateSync)
        {
            if (_disposed)
            {
                return;
            }

            _isBusyScanning = isBusyScanning;
            _onAutoUpdateStarting = onAutoUpdateStarting;
            _requestAppExit = requestAppExit;
            _autoSettingsSnapshot = settings.Clone();

            if (!settings.AutoUpdateEnabled)
            {
                _autoTimer?.Dispose();
                _autoTimer = null;
                return;
            }

            _autoTimer ??= new System.Threading.Timer(
                _ => _ = RunAutoUpdateTickAsync(),
                null,
                TimeSpan.FromSeconds(45),
                TimeSpan.FromHours(6));
        }
    }

    public async Task<UpdateCheckResult> CheckForUpdatesAsync(AppSettings settings, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(settings);

        string repo = !string.IsNullOrWhiteSpace(settings.UpdateRepository) && RepoSlugRegex().IsMatch(settings.UpdateRepository.Trim())
            ? settings.UpdateRepository.Trim()
            : DefaultRepository;

        string url = $"https://api.github.com/repos/{repo}/releases/latest";

        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
            req.Headers.UserAgent.ParseAdd($"VTDownloadGuard/{_currentVersion.ToString(3)}");

            using HttpResponseMessage resp = await _httpClient.SendAsync(req, ct).ConfigureAwait(false);
            if (resp.StatusCode == HttpStatusCode.NotFound)
            {
                return PublishCheckResult(new UpdateCheckResult
                {
                    Success = true,
                    UpdateAvailable = false,
                    CurrentVersion = _currentVersion,
                    ErrorMessage = "No published releases found on GitHub yet."
                });
            }

            if (resp.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.TooManyRequests)
            {
                return PublishCheckResult(new UpdateCheckResult
                {
                    Success = false,
                    CurrentVersion = _currentVersion,
                    ErrorMessage = $"GitHub API rate limit reached (HTTP {(int)resp.StatusCode}). Please try again later."
                });
            }

            string json = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode)
            {
                return PublishCheckResult(new UpdateCheckResult
                {
                    Success = false,
                    CurrentVersion = _currentVersion,
                    ErrorMessage = $"GitHub update check failed (HTTP {(int)resp.StatusCode})."
                });
            }

            using var doc = JsonDocument.Parse(json);
            JsonElement root = doc.RootElement;

            bool isDraft = root.TryGetProperty("draft", out var draftEl) && draftEl.ValueKind == JsonValueKind.True;
            bool isPrerelease = root.TryGetProperty("prerelease", out var preEl) && preEl.ValueKind == JsonValueKind.True;
            if (isDraft || isPrerelease)
            {
                return PublishCheckResult(new UpdateCheckResult
                {
                    Success = true,
                    UpdateAvailable = false,
                    CurrentVersion = _currentVersion
                });
            }

            string tagName = ReadString(root, "tag_name");
            string releaseName = ReadString(root, "name");
            string body = ReadString(root, "body");
            string htmlUrl = ReadString(root, "html_url");

            DateTimeOffset? publishedAt = null;
            if (root.TryGetProperty("published_at", out var pubEl)
                && pubEl.ValueKind == JsonValueKind.String
                && DateTimeOffset.TryParse(pubEl.GetString(), out DateTimeOffset parsedDate))
            {
                publishedAt = parsedDate;
            }

            if (!TryParseReleaseVersion(tagName, out Version? latestVer) || latestVer is null)
            {
                return PublishCheckResult(new UpdateCheckResult
                {
                    Success = false,
                    CurrentVersion = _currentVersion,
                    TagName = tagName,
                    ReleaseHtmlUrl = htmlUrl,
                    ErrorMessage = $"Unable to parse version from release tag '{tagName}'."
                });
            }

            bool updateAvailable = latestVer > _currentVersion;
            bool isCritical = IsCriticalRelease(body);
            UpdateInstallMode installMode = DetectInstallMode(_appDirectory);

            var (assetName, downloadUrl, sizeBytes, digest) = SelectBestAsset(root, installMode);
            string expectedSha = ExtractExpectedSha256(digest, body, assetName);

            if (updateAvailable && string.IsNullOrWhiteSpace(downloadUrl))
            {
                return PublishCheckResult(new UpdateCheckResult
                {
                    Success = false,
                    UpdateAvailable = false,
                    IsCritical = isCritical,
                    CurrentVersion = _currentVersion,
                    LatestVersion = latestVer,
                    TagName = tagName,
                    ReleaseName = releaseName,
                    ReleaseNotes = body,
                    ReleaseHtmlUrl = htmlUrl,
                    PublishedAtUtc = publishedAt,
                    ErrorMessage = $"Version {latestVer.ToString(3)} was found, but no compatible Windows release asset was attached."
                });
            }

            return PublishCheckResult(new UpdateCheckResult
            {
                Success = true,
                UpdateAvailable = updateAvailable,
                IsCritical = isCritical,
                CurrentVersion = _currentVersion,
                LatestVersion = latestVer,
                TagName = tagName,
                ReleaseName = string.IsNullOrWhiteSpace(releaseName) ? tagName : releaseName,
                ReleaseNotes = body,
                ReleaseHtmlUrl = htmlUrl,
                PublishedAtUtc = publishedAt,
                AssetName = assetName,
                DownloadUrl = downloadUrl,
                AssetSizeBytes = sizeBytes,
                ExpectedSha256 = expectedSha
            });
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            return PublishCheckResult(new UpdateCheckResult
            {
                Success = false,
                CurrentVersion = _currentVersion,
                ErrorMessage = "Update check cancelled."
            });
        }
        catch (Exception ex)
        {
            _logger.Warn($"GitHub update check failed: {ex.Message}");
            return PublishCheckResult(new UpdateCheckResult
            {
                Success = false,
                CurrentVersion = _currentVersion,
                ErrorMessage = $"Network error checking for updates: {ex.Message}"
            });
        }
    }

    public async Task<(bool Started, string Message)> DownloadAndApplyUpdateAsync(
        UpdateCheckResult update,
        bool openDashboardAfterUpdate,
        Action<string, int>? onProgress,
        Action requestAppExit,
        CancellationToken ct = default,
        bool launchInstallerProcess = true)
    {
        ArgumentNullException.ThrowIfNull(update);
        ArgumentNullException.ThrowIfNull(requestAppExit);

        if (!update.Success || !update.UpdateAvailable || string.IsNullOrWhiteSpace(update.DownloadUrl))
        {
            return (false, "No valid update is available to install.");
        }

        if (!IsAllowedDownloadUrl(update.DownloadUrl))
        {
            return (false, "Update download URL rejected because it is not a trusted GitHub HTTPS URL.");
        }

        if (Interlocked.CompareExchange(ref _updateInFlight, 1, 0) != 0)
        {
            return (false, "An update installation is already in progress.");
        }

        try
        {
            bool isZip = update.AssetName.EndsWith(".zip", StringComparison.OrdinalIgnoreCase);
            if (isZip && !IsDirectoryWritable(_appDirectory))
            {
                return (false, "Installation folder requires administrator permissions. Please download and run the Setup installer from the release page.");
            }

            string safeTag = SanitizePathSegment(string.IsNullOrWhiteSpace(update.TagName) ? "latest" : update.TagName);
            string stagingDir = Path.Combine(_paths.UpdateStagingRoot, $"{safeTag}-{DateTimeOffset.UtcNow:yyyyMMddHHmmss}");
            Directory.CreateDirectory(stagingDir);

            string safeFileName = Path.GetFileName(string.IsNullOrWhiteSpace(update.AssetName) ? "VTDownloadGuard-update.bin" : update.AssetName);
            string downloadPath = Path.Combine(stagingDir, safeFileName);

            onProgress?.Invoke($"Downloading {safeFileName}...", 5);
            string actualSha256 = await DownloadFileWithProgressAsync(
                update.DownloadUrl,
                downloadPath,
                update.AssetSizeBytes,
                pct => onProgress?.Invoke($"Downloading {safeFileName}... ({pct}%)", 5 + (int)(pct * 0.75)),
                ct).ConfigureAwait(false);

            if (!string.IsNullOrWhiteSpace(update.ExpectedSha256)
                && !string.Equals(actualSha256, update.ExpectedSha256, StringComparison.OrdinalIgnoreCase))
            {
                TryDeleteFile(downloadPath);
                _logger.Error($"Update SHA-256 mismatch for '{safeFileName}'. Expected {update.ExpectedSha256}, got {actualSha256}.");
                return (false, "Downloaded file SHA-256 verification failed. Update cancelled.");
            }

            onProgress?.Invoke("Backing up settings and scan history...", 85);
            string backupPath = CreateDataBackup();
            _logger.Info($"Created pre-update data backup at '{backupPath}'.");

            if (isZip)
            {
                onProgress?.Invoke("Extracting update files...", 92);
                string extractDir = Path.Combine(stagingDir, "extracted");
                Directory.CreateDirectory(extractDir);
                ZipFile.ExtractToDirectory(downloadPath, extractDir, overwriteFiles: true);

                string updaterExe = Path.Combine(extractDir, "VTDownloadGuard.exe");
                if (!File.Exists(updaterExe))
                {
                    return (false, "Update archive did not contain VTDownloadGuard.exe.");
                }

                onProgress?.Invoke("Applying update and restarting...", 100);
                if (launchInstallerProcess)
                {
                    var psi = new ProcessStartInfo(updaterExe)
                    {
                        WorkingDirectory = extractDir,
                        UseShellExecute = false
                    };
                    psi.ArgumentList.Add("--apply-update");
                    psi.ArgumentList.Add("--pid");
                    psi.ArgumentList.Add(Environment.ProcessId.ToString());
                    psi.ArgumentList.Add("--source");
                    psi.ArgumentList.Add(extractDir);
                    psi.ArgumentList.Add("--target");
                    psi.ArgumentList.Add(_appDirectory);
                    psi.ArgumentList.Add("--relaunch-arg");
                    psi.ArgumentList.Add(openDashboardAfterUpdate ? "--open" : "--minimized");
                    psi.ArgumentList.Add("--staging-root");
                    psi.ArgumentList.Add(stagingDir);

                    Process.Start(psi);
                    requestAppExit();
                }

                return (true, $"Update {update.TagName} staged and ready.");
            }
            else if (safeFileName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            {
                onProgress?.Invoke("Launching installer...", 100);
                if (launchInstallerProcess)
                {
                    var psi = new ProcessStartInfo(downloadPath)
                    {
                        WorkingDirectory = stagingDir,
                        UseShellExecute = true,
                        Arguments = $"/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /CLOSEAPPLICATIONS /DIR=\"{_appDirectory}\" /OPENAFTERUPDATE={(openDashboardAfterUpdate ? 1 : 0)}"
                    };
                    Process.Start(psi);
                    requestAppExit();
                }

                return (true, $"Installer for {update.TagName} started.");
            }

            return (false, $"Unsupported update file format '{safeFileName}'.");
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            return (false, "Update download cancelled.");
        }
        catch (Exception ex)
        {
            _logger.Error("Failed downloading or applying update", ex);
            return (false, $"Update failed: {ex.Message}");
        }
        finally
        {
            Interlocked.Exchange(ref _updateInFlight, 0);
        }
    }

    private async Task<string> DownloadFileWithProgressAsync(
        string url,
        string destinationPath,
        long expectedLength,
        Action<int> onPercent,
        CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        req.Headers.UserAgent.ParseAdd($"VTDownloadGuard/{_currentVersion.ToString(3)}");

        using HttpResponseMessage resp = await _httpClient.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
        resp.EnsureSuccessStatusCode();

        long totalBytes = resp.Content.Headers.ContentLength ?? expectedLength;
        await using Stream netStream = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        await using var fileStream = new FileStream(destinationPath, FileMode.Create, FileAccess.Write, FileShare.None, 81920, useAsync: true);
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

        byte[] buffer = new byte[81920];
        long totalRead = 0;
        int lastPercent = -1;

        while (true)
        {
            int read = await netStream.ReadAsync(buffer, ct).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            await fileStream.WriteAsync(buffer.AsMemory(0, read), ct).ConfigureAwait(false);
            sha.AppendData(buffer, 0, read);
            totalRead += read;

            if (totalBytes > 0)
            {
                int pct = (int)Math.Clamp(totalRead * 100L / totalBytes, 0, 100);
                if (pct != lastPercent && (pct - lastPercent >= 2 || pct == 100))
                {
                    lastPercent = pct;
                    onPercent(pct);
                }
            }
        }

        await fileStream.FlushAsync(ct).ConfigureAwait(false);
        onPercent(100);
        return Convert.ToHexStringLower(sha.GetHashAndReset());
    }

    private async Task RunAutoUpdateTickAsync()
    {
        if (_disposed || Interlocked.CompareExchange(ref _checkInFlight, 1, 0) != 0)
        {
            return;
        }

        try
        {
            AppSettings? settings;
            Func<bool>? isBusy;
            Action<UpdateCheckResult>? onStarting;
            Action? exitAction;

            lock (_stateSync)
            {
                settings = _autoSettingsSnapshot?.Clone();
                isBusy = _isBusyScanning;
                onStarting = _onAutoUpdateStarting;
                exitAction = _requestAppExit;
            }

            if (settings is null || !settings.AutoUpdateEnabled || exitAction is null)
            {
                return;
            }

            UpdateCheckResult check = await CheckForUpdatesAsync(settings, CancellationToken.None).ConfigureAwait(false);
            if (!ShouldAutoInstall(settings, check))
            {
                return;
            }

            if (isBusy is not null)
            {
                for (int i = 0; i < 30 && isBusy() && !_disposed; i++)
                {
                    await Task.Delay(1000).ConfigureAwait(false);
                }
            }

            if (_disposed)
            {
                return;
            }

            _logger.Info($"Automatic update triggered for version {check.TagName} (Critical={check.IsCritical}).");
            onStarting?.Invoke(check);
            _ = await DownloadAndApplyUpdateAsync(
                check,
                openDashboardAfterUpdate: false,
                onProgress: null,
                exitAction,
                CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.Warn($"Background auto-update check failed: {ex.Message}");
        }
        finally
        {
            Interlocked.Exchange(ref _checkInFlight, 0);
        }
    }

    private UpdateCheckResult PublishCheckResult(UpdateCheckResult result)
    {
        lock (_stateSync)
        {
            _latestCheckResult = result;
        }

        UpdateStatusChanged?.Invoke(result);
        return result;
    }

    private static (string Name, string DownloadUrl, long Size, string Digest) SelectBestAsset(
        JsonElement releaseRoot,
        UpdateInstallMode mode)
    {
        if (!releaseRoot.TryGetProperty("assets", out var assetsEl) || assetsEl.ValueKind != JsonValueKind.Array)
        {
            return (string.Empty, string.Empty, 0, string.Empty);
        }

        var candidates = new List<(string Name, string Url, long Size, string Digest)>();
        foreach (JsonElement asset in assetsEl.EnumerateArray())
        {
            string name = ReadString(asset, "name");
            string dlUrl = ReadString(asset, "browser_download_url");
            long size = asset.TryGetProperty("size", out var szEl) && szEl.TryGetInt64(out long s) ? s : 0;
            string digest = ReadString(asset, "digest");

            if (!string.IsNullOrWhiteSpace(name) && !string.IsNullOrWhiteSpace(dlUrl))
            {
                candidates.Add((name, dlUrl, size, digest));
            }
        }

        var setupAsset = candidates.FirstOrDefault(c =>
            c.Name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
            && c.Name.Contains("Setup", StringComparison.OrdinalIgnoreCase));

        var portableAsset = candidates.FirstOrDefault(c =>
            c.Name.EndsWith(".zip", StringComparison.OrdinalIgnoreCase)
            && c.Name.Contains("Portable", StringComparison.OrdinalIgnoreCase));

        if (mode == UpdateInstallMode.PortableFrameworkDependent)
        {
            return !string.IsNullOrEmpty(portableAsset.Url) ? portableAsset : setupAsset;
        }

        return !string.IsNullOrEmpty(setupAsset.Url) ? setupAsset : portableAsset;
    }

    private static string ReadString(JsonElement obj, string propName) =>
        obj.TryGetProperty(propName, out var el) && el.ValueKind == JsonValueKind.String
            ? (el.GetString() ?? string.Empty)
            : string.Empty;

    private static bool IsDirectoryWritable(string path)
    {
        try
        {
            string probe = Path.Combine(path, $".write-test-{Guid.NewGuid():N}.tmp");
            File.WriteAllText(probe, "ok");
            File.Delete(probe);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static string SanitizePathSegment(string input)
    {
        char[] invalid = Path.GetInvalidFileNameChars();
        char[] chars = input.Select(ch => invalid.Contains(ch) ? '_' : ch).ToArray();
        return new string(chars);
    }

    private static void TryDeleteFile(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch
        {
            // Ignore cleanup failure.
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _autoTimer?.Dispose();
        _autoTimer = null;
        if (_ownsHttpClient)
        {
            _httpClient.Dispose();
        }
    }
}
