using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using VTDownloadGuard.Models;
using VTDownloadGuard.Services;
using VTDownloadGuard.UI;

namespace VTDownloadGuard.Tests;

internal static class Program
{
    private sealed class MockHttpHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, int, Task<HttpResponseMessage>> _responder;
        private int _callCount;

        public List<(HttpMethod Method, string Url)> Requests { get; } = [];

        public MockHttpHandler(Func<HttpRequestMessage, int, HttpResponseMessage> responder)
            : this((req, idx) => Task.FromResult(responder(req, idx)))
        {
        }

        public MockHttpHandler(Func<HttpRequestMessage, int, Task<HttpResponseMessage>> responder)
        {
            _responder = responder;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            int index = Interlocked.Increment(ref _callCount);
            lock (Requests)
            {
                Requests.Add((request.Method, request.RequestUri?.ToString() ?? string.Empty));
            }

            return _responder(request, index);
        }
    }

    private static async Task<int> Main()
    {
        WindowsFormsSynchronizationContext.AutoInstall = false;

        var tests = new (string Name, Func<Task> Body)[]
        {
            ("DpapiSecretProtector round-trip and edge cases", TestDpapiProtector),
            ("SettingsStore defaults, persistence, secondary keys, and directory edits", TestSettingsStore),
            ("Extension filtering and upload eligibility", TestFilteringAndUploadEligibility),
            ("HistoryAndCacheStore TTL, quota rollover, and telemetry counters", TestHistoryAndCacheStore),
            ("FileRiskClassifier heuristic categories and Windows Authenticode", TestFileRiskClassifier),
            ("SecondaryHashLookupService CIRCL, MetaDefender, MalwareBazaar, and policy", TestSecondaryHashLookupService),
            ("VirusTotalClient verdicts, upload polling, quota endpoint, auth, and 429 retry", TestVirusTotalClient),
            ("Manual upload evaluation and large-file upload flow", TestManualUploadEvaluationAndLargeFileUpload),
            ("RateLimiter sliding window enforcement and snapshot", TestRateLimiter),
            ("Priority queue ordering, promote, remove, and clear", TestPriorityQueueOrdering),
            ("Manual folder scanning recursively queues filtered files in priority order", TestManualFolderQueueing),
            ("Secondary short-circuit end-to-end saves VT quota", TestSecondaryShortCircuitEndToEnd),
            ("ScanEngine + DirectoryWatcherManager + FileStabilizer end-to-end", TestEndToEndScanning),
            ("TrayIconFactory loads AppIcon and renders all status shields", TestTrayIconFactory),
            ("ModernThresholdSlider guidance, colors, and clean text", TestThresholdSlider),
            ("UpdateService version comparison, critical marker, auto-policy, and GitHub API", TestUpdateServiceLogic),
            ("Self-update SHA-256 verification, zip staging, backup, and data preservation", TestSelfUpdateDataPreservation),
            ("AppSettings reset to defaults and VirusTotal free-API limit warnings", TestResetDefaultsAndVtLimitWarnings),
            ("DashboardForm, OnboardingDialog, and TutorialSession UI smoke test", TestDashboardUiSmoke)
        };

        int failures = 0;
        foreach (var (name, body) in tests)
        {
            try
            {
                await body();
                Console.WriteLine($"[PASS] {name}");
            }
            catch (Exception ex)
            {
                failures++;
                Console.WriteLine($"[FAIL] {name}: {ex}");
            }
        }

        Console.WriteLine();
        Console.WriteLine($"Summary: {tests.Length - failures}/{tests.Length} tests passed.");
        return failures == 0 ? 0 : 1;
    }

    private static void Assert(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException($"Assertion failed: {message}");
        }
    }

    private static string CreateTempDir()
    {
        string path = Path.Combine(Path.GetTempPath(), "VTDownloadGuardTests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }

    private static void CleanupDir(string dir)
    {
        try
        {
            if (Directory.Exists(dir))
            {
                Directory.Delete(dir, recursive: true);
            }
        }
        catch
        {
            // Ignore cleanup failure in temp dir.
        }
    }

    private static HttpResponseMessage JsonResponse(HttpStatusCode code, string json)
    {
        return new HttpResponseMessage(code)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };
    }

    private static string MakeFileReportJson(int malicious, int suspicious, int undetected, int harmless, params (string Engine, string Category, string Result)[] detections)
    {
        var detEntries = detections.Select(d =>
            $"\"{d.Engine}\": {{\"category\": \"{d.Category}\", \"result\": \"{d.Result}\"}}");
        return $$"""
        {
          "data": {
            "id": "abc",
            "attributes": {
              "last_analysis_stats": {
                "malicious": {{malicious}},
                "suspicious": {{suspicious}},
                "undetected": {{undetected}},
                "harmless": {{harmless}}
              },
              "last_analysis_results": {
                {{string.Join(",", detEntries)}}
              }
            }
          }
        }
        """;
    }

    private static string MakeAnalysisReportJson(string status, int malicious, int suspicious, int undetected, int harmless, params (string Engine, string Category, string Result)[] detections)
    {
        var detEntries = detections.Select(d =>
            $"\"{d.Engine}\": {{\"category\": \"{d.Category}\", \"result\": \"{d.Result}\"}}");
        return $$"""
        {
          "data": {
            "id": "analysis-123",
            "attributes": {
              "status": "{{status}}",
              "stats": {
                "malicious": {{malicious}},
                "suspicious": {{suspicious}},
                "undetected": {{undetected}},
                "harmless": {{harmless}}
              },
              "results": {
                {{string.Join(",", detEntries)}}
              }
            }
          }
        }
        """;
    }

    private static Task TestDpapiProtector()
    {
        const string secret = "vt-test-api-key-0123456789abcdef";
        string cipher = DpapiSecretProtector.Protect(secret);
        Assert(!string.IsNullOrWhiteSpace(cipher), "Ciphertext should not be empty.");
        Assert(cipher != secret, "Ciphertext must differ from plaintext.");
        Assert(DpapiSecretProtector.Unprotect(cipher) == secret, "Unprotect must recover original secret.");

        Assert(DpapiSecretProtector.Protect("") == string.Empty, "Empty secret protects to empty.");
        Assert(DpapiSecretProtector.Unprotect("") == string.Empty, "Empty ciphertext returns empty.");
        Assert(DpapiSecretProtector.Unprotect("not-valid-base64!!!") == string.Empty, "Invalid base64 returns empty.");
        Assert(DpapiSecretProtector.Unprotect(Convert.ToBase64String([1, 2, 3, 4])) == string.Empty, "Corrupt DPAPI bytes return empty.");
        return Task.CompletedTask;
    }

    private static Task TestSettingsStore()
    {
        string tempDir = CreateTempDir();
        try
        {
            var paths = new AppPaths(tempDir);
            var logger = new AppLogger(paths);
            var store = new SettingsStore(paths, logger);

            AppSettings defaults = store.Load();
            string expectedDownloads = AppSettings.GetDefaultDownloadsDirectory();
            Assert(!string.IsNullOrWhiteSpace(expectedDownloads), "Default Downloads directory should resolve.");
            Assert(defaults.WatchedDirectories.Any(d => d.Path.Equals(expectedDownloads, StringComparison.OrdinalIgnoreCase)),
                "Default Downloads directory missing.");
            Assert(defaults.MaliciousThreshold == 2, "Default MaliciousThreshold must be 2.");
            Assert(defaults.UploadPolicy == UploadPolicy.ExecutablesAndScriptsOnly, "Default UploadPolicy mismatch.");
            Assert(defaults.FilterMode == FileFilterMode.ExecutablesScriptsAndArchives, "Default FilterMode mismatch.");
            Assert(defaults.EnableCirclHashlookup, "CIRCL Hashlookup should be enabled by default.");
            Assert(!defaults.EnableMetaDefender, "MetaDefender should be disabled by default.");
            Assert(!defaults.EnableMalwareBazaar, "MalwareBazaar should be disabled by default.");
            Assert(!defaults.SecondaryLookupsLowerRiskOnly, "SecondaryLookupsLowerRiskOnly should be false by default.");
            Assert(defaults.ThemeMode == AppThemeMode.System, "Default ThemeMode should be System.");
            Assert(!defaults.OnboardingCompleted, "OnboardingCompleted should default to false.");

            List<string> defaultDownloads = AppSettings.GetDefaultDownloadsDirectories();
            Assert(defaultDownloads.Count >= 1 && defaultDownloads.Contains(expectedDownloads, StringComparer.OrdinalIgnoreCase),
                "GetDefaultDownloadsDirectories should include primary Downloads directory.");

            SettingsStore.SetApiKey(defaults, "my-secret-vt-key");
            SettingsStore.SetMetaDefenderApiKey(defaults, "md-secret-key");
            SettingsStore.SetMalwareBazaarApiKey(defaults, "mb-secret-key");
            defaults.EnableMetaDefender = true;
            defaults.EnableMalwareBazaar = true;
            defaults.SecondaryLookupsLowerRiskOnly = true;
            defaults.ThemeMode = AppThemeMode.Dark;
            defaults.OnboardingCompleted = true;
            defaults.HeaderBrandClickAction = HeaderBrandClickAction.ToggleMonitoring;

            defaults.WatchedDirectories.Clear();
            defaults.WatchedDirectories.Add(new WatchedDirectory { Path = expectedDownloads, IncludeSubdirectories = true, Enabled = true });
            defaults.WatchedDirectories.Add(new WatchedDirectory { Path = @"E:\Mods", IncludeSubdirectories = false, Enabled = true });
            store.Save(defaults);

            AppSettings reloaded = store.Load();
            Assert(SettingsStore.GetDecryptedApiKey(reloaded) == "my-secret-vt-key", "Decrypted VT API key mismatch.");
            Assert(SettingsStore.GetDecryptedMetaDefenderApiKey(reloaded) == "md-secret-key", "Decrypted MetaDefender key mismatch.");
            Assert(SettingsStore.GetDecryptedMalwareBazaarApiKey(reloaded) == "mb-secret-key", "Decrypted MalwareBazaar key mismatch.");
            Assert(reloaded.EnableMetaDefender && reloaded.EnableMalwareBazaar && reloaded.SecondaryLookupsLowerRiskOnly,
                "Secondary service flags should persist.");
            Assert(reloaded.ThemeMode == AppThemeMode.Dark, "ThemeMode should persist.");
            Assert(reloaded.OnboardingCompleted, "OnboardingCompleted should persist.");
            Assert(reloaded.HeaderBrandClickAction == HeaderBrandClickAction.ToggleMonitoring, "HeaderBrandClickAction should persist.");
            Assert(reloaded.WatchedDirectories.Count == 2, "Expected 2 directories after edit.");
            Assert(reloaded.WatchedDirectories.Any(d => d.Path.Equals(@"E:\Mods", StringComparison.OrdinalIgnoreCase)), "Added dir missing.");

            reloaded.WatchedDirectories.Clear();
            store.Save(reloaded);
            AppSettings restored = store.Load();
            Assert(restored.WatchedDirectories.Any(d => d.Path.Equals(expectedDownloads, StringComparison.OrdinalIgnoreCase)),
                "Sanitize should restore default Downloads directory when watched list is empty.");
        }
        finally
        {
            CleanupDir(tempDir);
        }

        return Task.CompletedTask;
    }

    private static Task TestFilteringAndUploadEligibility()
    {
        AppSettings settings = AppSettings.CreateDefault();

        string[] scanned = ["setup.exe", "mod.dll", "game.msi", "script.ps1", "run.bat", "pack.zip", "mod.7z", "arc.rar", "disk.iso"];
        foreach (string name in scanned)
        {
            Assert(SettingsStore.ShouldScanFile(settings, $@"C:\Test\{name}"), $"{name} should be scanned.");
        }

        string[] ignored = ["shot.png", "pakchunk0.pak", "save1.sav", "debug.log", "file.exe.crdownload", "dl.part", "work.tmp", "~$notes.docx"];
        foreach (string name in ignored)
        {
            Assert(!SettingsStore.ShouldScanFile(settings, $@"C:\Test\{name}"), $"{name} should be ignored under default filter.");
        }

        settings.FilterMode = FileFilterMode.AllFiles;
        Assert(SettingsStore.ShouldScanFile(settings, @"C:\Test\shot.png"), "AllFiles should scan .png.");
        Assert(!SettingsStore.ShouldScanFile(settings, @"C:\Test\game.exe.crdownload"), "AllFiles must still ignore .crdownload.");
        Assert(!SettingsStore.ShouldScanFile(settings, @"C:\Test\mod.part"), "AllFiles must still ignore .part.");
        Assert(!SettingsStore.ShouldScanFile(settings, @"C:\Test\temp.tmp"), "AllFiles must still ignore .tmp.");
        Assert(!SettingsStore.ShouldScanFile(settings, @"C:\Test\~$doc.docx"), "AllFiles must still ignore ~$ lock files.");

        settings.FilterMode = FileFilterMode.ExecutablesScriptsAndArchives;
        settings.UploadPolicy = UploadPolicy.ExecutablesAndScriptsOnly;
        Assert(SettingsStore.ShouldUploadFile(settings, @"C:\Test\app.exe", 5 * 1024 * 1024), ".exe <= 32MB should upload.");
        Assert(SettingsStore.ShouldUploadFile(settings, @"C:\Test\run.ps1", 1024), ".ps1 <= 32MB should upload.");
        Assert(!SettingsStore.ShouldUploadFile(settings, @"C:\Test\big.exe", 33L * 1024 * 1024), ".exe > 32MB must not auto-upload.");
        Assert(!SettingsStore.ShouldUploadFile(settings, @"C:\Test\mod.zip", 1024), ".zip must not auto-upload under ExecutablesAndScriptsOnly.");
        Assert(!SettingsStore.ShouldUploadFile(settings, @"C:\Test\doc.pdf", 1024), ".pdf must not auto-upload under ExecutablesAndScriptsOnly.");

        settings.UploadPolicy = UploadPolicy.HashLookupOnly;
        Assert(!SettingsStore.ShouldUploadFile(settings, @"C:\Test\app.exe", 1024), "HashLookupOnly must deny all uploads.");

        settings.UploadPolicy = UploadPolicy.UploadAllWatched;
        Assert(SettingsStore.ShouldUploadFile(settings, @"C:\Test\mod.zip", 1024), "UploadAllWatched should allow watched archive <= 32MB.");

        return Task.CompletedTask;
    }

    private static Task TestHistoryAndCacheStore()
    {
        string tempDir = CreateTempDir();
        try
        {
            DateTimeOffset clock = new(2026, 11, 23, 12, 0, 0, TimeSpan.Zero);
            var paths = new AppPaths(tempDir);
            var logger = new AppLogger(paths);
            var store = new HistoryAndCacheStore(paths, logger, () => clock);

            store.UpsertCacheEntry(new HashCacheEntry
            {
                Sha256 = "foundhash",
                CachedAtUtc = clock,
                MaliciousCount = 0,
                TotalEngines = 70,
                WasFoundOnVirusTotal = true
            });
            store.UpsertCacheEntry(new HashCacheEntry
            {
                Sha256 = "notfoundhash",
                CachedAtUtc = clock,
                WasFoundOnVirusTotal = false
            });

            store.RecordApiRequests(3);
            store.RecordCacheHit();
            store.RecordSecondaryRequest(SecondaryHashLookupService.CirclServiceName, savedVtCall: true);
            store.RecordSecondaryRequest(SecondaryHashLookupService.MetaDefenderServiceName, savedVtCall: false);

            DailyUsageSnapshot snap = store.GetDailyUsageSnapshot();
            Assert(snap.DailyVtRequests == 3, "Daily API request count should be 3.");
            Assert(snap.DailyCacheHits == 1, "Daily cache hits should be 1.");
            Assert(snap.DailySecondarySavedCalls == 1, "Daily secondary saved calls should be 1.");
            Assert(snap.DailyCirclRequests == 1 && snap.DailyCirclHits == 1, "CIRCL stats mismatch.");
            Assert(snap.DailyMetaDefenderRequests == 1 && snap.DailyMetaDefenderHits == 0, "MetaDefender stats mismatch.");

            clock = clock.AddHours(25);
            Assert(!store.TryGetCachedHash("notfoundhash", out _), "NotFound hash should expire after 1 day.");
            Assert(store.TryGetCachedHash("foundhash", out var foundEntry) && foundEntry is not null, "Found hash should remain valid at 25 hours.");

            DailyUsageSnapshot rolled = store.GetDailyUsageSnapshot();
            Assert(rolled.DailyVtRequests == 0 && rolled.DailyCacheHits == 0 && rolled.DailySecondarySavedCalls == 0,
                "All daily counters must reset on new UTC day.");

            clock = clock.AddDays(30);
            Assert(!store.TryGetCachedHash("foundhash", out _), "Found hash should expire after 30 days.");

            store.AddOrUpdateScanRecord(new ScanRecord
            {
                FileName = "bad.exe",
                FilePath = @"C:\Temp\bad.exe",
                Sha256 = "deadbeef",
                Verdict = ScanVerdict.Unsafe,
                MaliciousCount = 5,
                TotalEngines = 70,
                Acknowledged = false
            });

            var reloaded = new HistoryAndCacheStore(paths, logger, () => clock);
            Assert(reloaded.GetUnacknowledgedUnsafeCount() == 1, "Reloaded store should retain unacknowledged unsafe count.");
            Assert(reloaded.AcknowledgeAllUnsafe() == 1, "Should acknowledge 1 record.");
            Assert(reloaded.GetUnacknowledgedUnsafeCount() == 0, "Unsafe count should be 0 after acknowledgement.");
        }
        finally
        {
            CleanupDir(tempDir);
        }

        return Task.CompletedTask;
    }

    private static Task TestFileRiskClassifier()
    {
        var classifier = new FileRiskClassifier();

        var doubleExt = classifier.Classify(@"C:\Users\Sample\Downloads\invoice.pdf.exe");
        Assert(doubleExt.Category == FileRiskCategory.Critical, "Double extension must be Critical.");

        var scriptInDl = classifier.Classify(@"C:\Users\Sample\Downloads\patch.ps1");
        Assert(scriptInDl.Category == FileRiskCategory.Critical, "Unsigned script in Downloads must be Critical.");

        var crackInDl = classifier.Classify(@"C:\Users\Sample\Downloads\game_keygen.exe");
        Assert(crackInDl.Category == FileRiskCategory.Critical, "Suspicious keyword unsigned exe must be Critical.");

        var exeInDl = classifier.Classify(@"C:\Users\Sample\Downloads\random_installer.exe");
        Assert(exeInDl.Category == FileRiskCategory.High, "Unsigned exe in Downloads must be High.");

        var archive = classifier.Classify(@"C:\Users\Sample\Downloads\modpack.zip");
        Assert(archive.Category == FileRiskCategory.Medium, "Archive must be Medium.");

        var gameRuntime = classifier.Classify(@"D:\Games\CoolGame\UnityPlayer.dll");
        Assert(gameRuntime.Category == FileRiskCategory.Low, "Known game engine DLL in Games folder must be Low.");

        var gameAsset = classifier.Classify(@"D:\Games\CoolGame\textures\hero.png");
        Assert(gameAsset.Category == FileRiskCategory.Trusted, "Common game asset file must be Trusted.");

        string notepadPath = @"C:\Windows\System32\notepad.exe";
        if (File.Exists(notepadPath))
        {
            var signedWin = classifier.Classify(notepadPath);
            Assert(signedWin.IsDigitallySigned, "notepad.exe should verify offline as signed (catalog).");
            Assert(signedWin.Category == FileRiskCategory.Trusted, "notepad.exe should classify as Trusted.");
            Assert(signedWin.SignerName.Contains("Microsoft", StringComparison.OrdinalIgnoreCase),
                $"Expected Microsoft signer on notepad.exe, got '{signedWin.SignerName}'.");
        }

        string dotnetExe = @"C:\Program Files\dotnet\dotnet.exe";
        if (File.Exists(dotnetExe))
        {
            var signedDotnet = classifier.Classify(dotnetExe);
            Assert(signedDotnet.IsDigitallySigned, "dotnet.exe should verify offline as signed (embedded).");
            Assert(signedDotnet.Category == FileRiskCategory.Trusted, "dotnet.exe should classify as Trusted.");
        }

        return Task.CompletedTask;
    }

    private static async Task TestSecondaryHashLookupService()
    {
        string tempDir = CreateTempDir();
        try
        {
            var paths = new AppPaths(tempDir);
            var logger = new AppLogger(paths);
            var history = new HistoryAndCacheStore(paths, logger);

            var handler = new MockHttpHandler((req, _) =>
            {
                string url = req.RequestUri!.ToString();
                if (url.Contains("hashlookup.circl.lu/lookup/sha256/circlclean"))
                {
                    return JsonResponse(HttpStatusCode.OK, """{"FileName":"calc.exe","hashlookup:trust":92,"ProductCode":{"ProductName":"Windows"}}""");
                }

                if (url.Contains("hashlookup.circl.lu/lookup/sha256/circlbad"))
                {
                    return JsonResponse(HttpStatusCode.OK, """{"KnownMalicious":["malshare"],"hashlookup:trust":10}""");
                }

                if (url.Contains("api.metadefender.com/v4/hash/mdclean"))
                {
                    return JsonResponse(HttpStatusCode.OK, """{"data_id":"md-1","scan_results":{"total_avs":35,"total_detected_avs":0,"scan_details":{}}}""");
                }

                if (url.Contains("api.metadefender.com/v4/hash/mdbad"))
                {
                    return JsonResponse(HttpStatusCode.OK, """{"data_id":"md-2","scan_results":{"total_avs":35,"total_detected_avs":4,"scan_details":{"ClamAV":{"scan_result_i":1,"threat_found":"Trojan.Test"}}}}""");
                }

                if (url.Contains("mb-api.abuse.ch"))
                {
                    string body = req.Content?.ReadAsStringAsync().Result ?? string.Empty;
                    if (body.Contains("mbbad"))
                    {
                        return JsonResponse(HttpStatusCode.OK, """{"query_status":"ok","data":[{"signature":"RedLine","tags":["exe","stealer"]}]}""");
                    }

                    return JsonResponse(HttpStatusCode.OK, """{"query_status":"hash_not_found"}""");
                }

                return JsonResponse(HttpStatusCode.NotFound, "{}");
            });

            using var service = new SecondaryHashLookupService(history, logger, new HttpClient(handler), TimeSpan.Zero);

            var settings = AppSettings.CreateDefault();
            settings.EnableCirclHashlookup = true;
            settings.EnableMetaDefender = true;
            SettingsStore.SetMetaDefenderApiKey(settings, "md-key");
            settings.EnableMalwareBazaar = true;
            SettingsStore.SetMalwareBazaarApiKey(settings, "mb-key");
            settings.SecondaryLookupsLowerRiskOnly = true;

            Assert(!SecondaryHashLookupService.ShouldUseSecondaryLookups(settings, FileRiskCategory.Critical),
                "Lower-risk-only must skip Critical.");
            Assert(!SecondaryHashLookupService.ShouldUseSecondaryLookups(settings, FileRiskCategory.High),
                "Lower-risk-only must skip High.");
            Assert(!SecondaryHashLookupService.ShouldUseSecondaryLookups(settings, FileRiskCategory.Medium),
                "Lower-risk-only must skip Medium.");
            Assert(SecondaryHashLookupService.ShouldUseSecondaryLookups(settings, FileRiskCategory.Low),
                "Lower-risk-only must allow Low.");
            Assert(SecondaryHashLookupService.ShouldUseSecondaryLookups(settings, FileRiskCategory.Trusted),
                "Lower-risk-only must allow Trusted.");

            settings.SecondaryLookupsLowerRiskOnly = false;
            Assert(SecondaryHashLookupService.ShouldUseSecondaryLookups(settings, FileRiskCategory.High),
                "When SecondaryLookupsLowerRiskOnly=false, High risk should use secondary lookup.");

            var circlClean = await service.LookupAsync("circlclean", settings, FileRiskCategory.Low, null, CancellationToken.None);
            Assert(circlClean.Outcome == SecondaryLookupOutcome.Clean && circlClean.ServiceName == SecondaryHashLookupService.CirclServiceName,
                "Expected CIRCL clean.");

            var circlBad = await service.LookupAsync("circlbad", settings, FileRiskCategory.High, null, CancellationToken.None);
            Assert(circlBad.Outcome == SecondaryLookupOutcome.Malicious, "Expected CIRCL malicious.");

            var mdClean = await service.LookupAsync("mdclean", settings, FileRiskCategory.Low, null, CancellationToken.None);
            Assert(mdClean.Outcome == SecondaryLookupOutcome.Clean && mdClean.ServiceName == SecondaryHashLookupService.MetaDefenderServiceName,
                "Expected MetaDefender clean.");

            var mdBad = await service.LookupAsync("mdbad", settings, FileRiskCategory.High, null, CancellationToken.None);
            Assert(mdBad.Outcome == SecondaryLookupOutcome.Malicious && mdBad.ReportUrl.Contains("md-2"),
                "Expected MetaDefender malicious with report URL.");

            var mbBad = await service.LookupAsync("mbbad", settings, FileRiskCategory.High, null, CancellationToken.None);
            Assert(mbBad.Outcome == SecondaryLookupOutcome.Malicious && mbBad.ServiceName == SecondaryHashLookupService.MalwareBazaarServiceName,
                "Expected MalwareBazaar malicious.");
        }
        finally
        {
            CleanupDir(tempDir);
        }
    }

    private static async Task TestVirusTotalClient()
    {
        string tempDir = CreateTempDir();
        try
        {
            var paths = new AppPaths(tempDir);
            var logger = new AppLogger(paths);
            var limiter = new RateLimiter(100);

            var handler1 = new MockHttpHandler((req, _) =>
            {
                if (req.RequestUri!.AbsolutePath.EndsWith("/users/good-key"))
                {
                    return JsonResponse(HttpStatusCode.OK, """
                    {
                      "data": {
                        "id": "vt_test_user",
                        "attributes": {
                          "quotas": {
                            "api_requests_hourly": { "used": 12, "allowed": 240 },
                            "api_requests_daily": { "used": 42, "allowed": 500 },
                            "api_requests_monthly": { "used": 350, "allowed": 15500 }
                          }
                        }
                      }
                    }
                    """);
                }

                if (req.RequestUri.AbsolutePath.EndsWith("/users/bad-key"))
                {
                    return JsonResponse(HttpStatusCode.Unauthorized, "{}");
                }

                if (req.RequestUri.AbsolutePath.EndsWith("/clean"))
                {
                    return JsonResponse(HttpStatusCode.OK, MakeFileReportJson(0, 0, 70, 2));
                }

                if (req.RequestUri.AbsolutePath.EndsWith("/lowrisk"))
                {
                    return JsonResponse(HttpStatusCode.OK, MakeFileReportJson(1, 0, 70, 1, ("MinorAV", "malicious", "PUA.Generic")));
                }

                if (req.RequestUri.AbsolutePath.EndsWith("/unsafe"))
                {
                    return JsonResponse(HttpStatusCode.OK, MakeFileReportJson(12, 1, 59, 0,
                        ("Defender", "malicious", "Trojan:Win32/Test"),
                        ("Kaspersky", "malicious", "HEUR:Trojan.Win32.Test")));
                }

                return JsonResponse(HttpStatusCode.NotFound, "{}");
            });

            using var vt1 = new VirusTotalClient(
                limiter,
                logger,
                new HttpClient(handler1),
                initialAnalysisDelay: TimeSpan.FromMilliseconds(5),
                analysisPollInterval: TimeSpan.FromMilliseconds(5),
                rateLimitFallbackDelay: TimeSpan.FromMilliseconds(20));

            var cleanRes = await vt1.LookupHashAsync("clean", "key", CancellationToken.None);
            Assert(cleanRes.Outcome == VtOutcome.Found && cleanRes.TotalEngines == 72, "Clean lookup mismatch.");
            Assert(VirusTotalClient.EvaluateVerdict(cleanRes.MaliciousCount, cleanRes.SuspiciousCount, 2) == ScanVerdict.Clean, "Expected Clean.");

            var lowRes = await vt1.LookupHashAsync("lowrisk", "key", CancellationToken.None);
            Assert(VirusTotalClient.EvaluateVerdict(lowRes.MaliciousCount, lowRes.SuspiciousCount, 2) == ScanVerdict.LowRisk, "Expected LowRisk.");

            var unsafeRes = await vt1.LookupHashAsync("unsafe", "key", CancellationToken.None);
            Assert(VirusTotalClient.EvaluateVerdict(unsafeRes.MaliciousCount, unsafeRes.SuspiciousCount, 2) == ScanVerdict.Unsafe, "Expected Unsafe.");
            Assert(unsafeRes.DetectionNames.Count == 2, "Expected 2 detection names.");
            Assert(VirusTotalClient.BuildGuiFileUrl("AABB") == "https://www.virustotal.com/gui/file/aabb", "GUI URL mismatch.");

            var quotaOk = await vt1.GetUserQuotasAsync("good-key", CancellationToken.None);
            Assert(quotaOk.Success && quotaOk.UserId == "vt_test_user", "UserId quota parsing mismatch.");
            Assert(quotaOk.Hourly.Used == 12 && quotaOk.Hourly.Allowed == 240, "Hourly quota mismatch.");
            Assert(quotaOk.Daily.Used == 42 && quotaOk.Daily.Allowed == 500, "Daily quota mismatch.");
            Assert(quotaOk.Monthly.Used == 350 && quotaOk.Monthly.Allowed == 15500, "Monthly quota mismatch.");

            var quotaBad = await vt1.GetUserQuotasAsync("bad-key", CancellationToken.None);
            Assert(!quotaBad.Success, "Expected unauthorized quota lookup to fail.");

            string sampleExe = Path.Combine(tempDir, "sample.exe");
            await File.WriteAllBytesAsync(sampleExe, [0x4D, 0x5A, 0x90, 0x00]);
            int analysisPollCount = 0;
            var handler2 = new MockHttpHandler((req, _) =>
            {
                if (req.Method == HttpMethod.Post && req.RequestUri!.AbsolutePath.EndsWith("/files"))
                {
                    return JsonResponse(HttpStatusCode.OK, """{"data":{"type":"analysis","id":"analysis-123"}}""");
                }

                if (req.Method == HttpMethod.Get && req.RequestUri!.AbsolutePath.EndsWith("/analyses/analysis-123"))
                {
                    analysisPollCount++;
                    if (analysisPollCount == 1)
                    {
                        return JsonResponse(HttpStatusCode.OK, MakeAnalysisReportJson("queued", 0, 0, 0, 0));
                    }

                    return JsonResponse(HttpStatusCode.OK, MakeAnalysisReportJson("completed", 8, 1, 60, 1,
                        ("ESET", "malicious", "Win32/Agent")));
                }

                return JsonResponse(HttpStatusCode.BadRequest, "{}");
            });

            using var vt2 = new VirusTotalClient(
                limiter,
                logger,
                new HttpClient(handler2),
                initialAnalysisDelay: TimeSpan.FromMilliseconds(5),
                analysisPollInterval: TimeSpan.FromMilliseconds(5),
                rateLimitFallbackDelay: TimeSpan.FromMilliseconds(20));

            var upRes = await vt2.UploadAndAnalyzeAsync(sampleExe, "samplehash", "key", null, CancellationToken.None);
            Assert(upRes.Outcome == VtOutcome.Found, "Upload analysis should complete.");
            Assert(upRes.MaliciousCount == 8 && upRes.TotalEngines == 70, "Upload stats parsing mismatch.");
            Assert(upRes.DetectionNames.Contains("ESET: Win32/Agent"), "Upload detection name missing.");
            Assert(analysisPollCount == 2, "Expected 2 polls.");

            int attempt429 = 0;
            var handler3 = new MockHttpHandler((req, _) =>
            {
                if (req.RequestUri!.AbsolutePath.EndsWith("/unauth"))
                {
                    return JsonResponse(HttpStatusCode.Unauthorized, "{}");
                }

                attempt429++;
                if (attempt429 == 1)
                {
                    var resp = JsonResponse(HttpStatusCode.TooManyRequests, "{}");
                    resp.Headers.RetryAfter = new RetryConditionHeaderValue(TimeSpan.FromMilliseconds(15));
                    return resp;
                }

                return JsonResponse(HttpStatusCode.OK, MakeFileReportJson(0, 0, 65, 0));
            });

            using var vt3 = new VirusTotalClient(
                limiter,
                logger,
                new HttpClient(handler3),
                initialAnalysisDelay: TimeSpan.FromMilliseconds(5),
                analysisPollInterval: TimeSpan.FromMilliseconds(5),
                rateLimitFallbackDelay: TimeSpan.FromMilliseconds(15));

            var authRes = await vt3.LookupHashAsync("unauth", "badkey", CancellationToken.None);
            Assert(authRes.Outcome == VtOutcome.AuthError, "Expected AuthError on 401.");

            var retryRes = await vt3.LookupHashAsync("retryhash", "key", CancellationToken.None);
            Assert(retryRes.Outcome == VtOutcome.Found && attempt429 == 2, "Expected 429 retry to succeed.");
        }
        finally
        {
            CleanupDir(tempDir);
        }
    }

    private static async Task TestManualUploadEvaluationAndLargeFileUpload()
    {
        Assert(ScanEngine.EvaluateManualUpload(1024, fileExists: false, hasApiKey: true) == ManualUploadStrategy.FileMissing,
            "Missing file must evaluate to FileMissing.");
        Assert(ScanEngine.EvaluateManualUpload(0, fileExists: true, hasApiKey: true) == ManualUploadStrategy.EmptyFile,
            "Zero-byte file must evaluate to EmptyFile.");
        Assert(ScanEngine.EvaluateManualUpload(10L * 1024 * 1024, fileExists: true, hasApiKey: true) == ManualUploadStrategy.DirectApiUpload,
            "10 MB file with API key must evaluate to DirectApiUpload.");
        Assert(ScanEngine.EvaluateManualUpload(50L * 1024 * 1024, fileExists: true, hasApiKey: true) == ManualUploadStrategy.LargeApiUpload,
            "50 MB file with API key must evaluate to LargeApiUpload.");
        Assert(ScanEngine.EvaluateManualUpload(50L * 1024 * 1024, fileExists: true, hasApiKey: false) == ManualUploadStrategy.ManualBrowserOnlyNoKey,
            "50 MB file without API key must evaluate to ManualBrowserOnlyNoKey.");
        Assert(ScanEngine.EvaluateManualUpload(700L * 1024 * 1024, fileExists: true, hasApiKey: true) == ManualUploadStrategy.ExceedsVirusTotalLimit,
            "700 MB file must evaluate to ExceedsVirusTotalLimit.");

        string tempDir = CreateTempDir();
        string dataDir = Path.Combine(tempDir, "Data");
        try
        {
            var paths = new AppPaths(dataDir, Path.Combine(tempDir, "UpdateStaging"));
            var logger = new AppLogger(paths);
            var settingsStore = new SettingsStore(paths, logger);
            var settings = new AppSettings
            {
                WatchedDirectories = [],
                UploadPolicy = UploadPolicy.HashLookupOnly,
                MaxUploadSizeMb = 1,
                MaxHashSizeMb = 1,
                EnableCirclHashlookup = false,
                MaxRequestsPerMinute = 100
            };
            SettingsStore.SetApiKey(settings, "vt-test-key");
            settingsStore.Save(settings);

            var history = new HistoryAndCacheStore(paths, logger);
            var limiter = new RateLimiter(100);

            string samplePath = Path.Combine(tempDir, "large-manual.exe");
            byte[] payload = new byte[256];
            Array.Fill(payload, (byte)'A');
            await File.WriteAllBytesAsync(samplePath, payload);

            bool requestedUploadUrl = false;
            bool postedToUploadUrl = false;
            int uploadedContentLength = 0;

            var handler = new MockHttpHandler(async (req, _) =>
            {
                if (req.Method == HttpMethod.Get && req.RequestUri!.AbsolutePath.EndsWith("/files/upload_url"))
                {
                    requestedUploadUrl = true;
                    return JsonResponse(HttpStatusCode.OK, """{"data":"https://upload.example.test/large-slot"}""");
                }

                if (req.Method == HttpMethod.Post && req.RequestUri!.ToString() == "https://upload.example.test/large-slot")
                {
                    postedToUploadUrl = true;
                    byte[] bodyBytes = await req.Content!.ReadAsByteArrayAsync();
                    uploadedContentLength = bodyBytes.Length;
                    return JsonResponse(HttpStatusCode.OK, """{"data":{"type":"analysis","id":"large-analysis-1"}}""");
                }

                if (req.Method == HttpMethod.Get && req.RequestUri!.AbsolutePath.EndsWith("/analyses/large-analysis-1"))
                {
                    return JsonResponse(HttpStatusCode.OK, MakeAnalysisReportJson("completed", 0, 0, 70, 0));
                }

                return JsonResponse(HttpStatusCode.BadRequest, "{}");
            });

            using var vtClient = new VirusTotalClient(
                limiter,
                logger,
                new HttpClient(handler),
                initialAnalysisDelay: TimeSpan.FromMilliseconds(5),
                analysisPollInterval: TimeSpan.FromMilliseconds(5),
                rateLimitFallbackDelay: TimeSpan.FromMilliseconds(20),
                directUploadLimitBytes: 64);

            using var engine = new ScanEngine(settingsStore, history, limiter, vtClient, logger);
            var sawUploadProgress = false;
            var completedTcs = new TaskCompletionSource<ScanRecord>(TaskCreationOptions.RunContinuationsAsynchronously);

            engine.StatusChanged += () =>
            {
                if (engine.ActiveStage.Contains("Uploading to VirusTotal", StringComparison.Ordinal))
                {
                    sawUploadProgress = true;
                }
            };
            engine.ScanCompleted += rec => completedTcs.TrySetResult(rec);

            engine.Start();

            var missingRecord = new ScanRecord { FilePath = Path.Combine(tempDir, "missing.exe") };
            Assert(!engine.ManualUploadRecord(missingRecord), "ManualUploadRecord must return false for missing file.");

            var unknownRecord = new ScanRecord
            {
                FilePath = samplePath,
                FileName = "large-manual.exe",
                FileSizeBytes = payload.Length,
                Verdict = ScanVerdict.Unknown,
                RiskCategory = FileRiskCategory.High,
                RiskReason = "Unsigned installer"
            };
            Assert(engine.ManualUploadRecord(unknownRecord), "ManualUploadRecord should enqueue existing file.");

            ScanRecord completed = await completedTcs.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert(requestedUploadUrl, "Large upload flow must request /files/upload_url.");
            Assert(postedToUploadUrl && uploadedContentLength >= payload.Length, "Large upload flow must stream multipart body to returned upload URL.");
            Assert(sawUploadProgress, "Upload progress updates should reach engine status.");
            Assert(completed.Uploaded && completed.Verdict == ScanVerdict.Clean && completed.TotalEngines == 70,
                $"Expected Clean uploaded result with 70 engines, got {completed.Verdict} (Uploaded={completed.Uploaded}, Total={completed.TotalEngines}).");
        }
        finally
        {
            CleanupDir(tempDir);
        }
    }

    private static async Task TestRateLimiter()
    {
        DateTimeOffset now = new(2026, 11, 23, 12, 0, 0, TimeSpan.Zero);
        var limiter = new RateLimiter(maxRequestsPerMinute: 2, window: TimeSpan.FromMilliseconds(160), utcNow: () => now);

        var sw = Stopwatch.StartNew();
        await limiter.WaitForSlotAsync(CancellationToken.None);
        await limiter.WaitForSlotAsync(CancellationToken.None);
        Assert(sw.ElapsedMilliseconds < 100, "First 2 slots should be immediate.");

        RateLimiterSnapshot snapFull = limiter.GetSnapshot();
        Assert(snapFull.RequestsInWindow == 2 && snapFull.MaxRequestsPerWindow == 2, "Snapshot should report 2/2.");
        Assert(snapFull.NextSlotIn > TimeSpan.Zero, "Snapshot should report non-zero wait when full.");

        var waitTask = limiter.WaitForSlotAsync(CancellationToken.None);
        Assert(!waitTask.IsCompleted, "3rd request within window must wait.");
        await Task.Delay(200);
        now = now.AddMilliseconds(200);
        await waitTask;
    }

    private static async Task TestPriorityQueueOrdering()
    {
        string tempDir = CreateTempDir();
        string dataDir = Path.Combine(tempDir, "Data");
        string dlDir = Path.Combine(tempDir, "Downloads");
        string gameDir = Path.Combine(tempDir, "Games", "Title");
        Directory.CreateDirectory(dlDir);
        Directory.CreateDirectory(gameDir);

        try
        {
            var paths = new AppPaths(dataDir, Path.Combine(tempDir, "UpdateStaging"));
            var logger = new AppLogger(paths);
            var settingsStore = new SettingsStore(paths, logger);
            var settings = new AppSettings
            {
                WatchedDirectories = [],
                UploadPolicy = UploadPolicy.HashLookupOnly,
                FilterMode = FileFilterMode.AllFiles,
                EnableCirclHashlookup = false,
                MaxRequestsPerMinute = 100
            };
            SettingsStore.SetApiKey(settings, "test-key");
            settingsStore.Save(settings);

            var history = new HistoryAndCacheStore(paths, logger);
            var limiter = new RateLimiter(100);

            string blockerFile = Path.Combine(dlDir, "blocker.exe");
            string trustedFile = Path.Combine(gameDir, "readme.txt");
            string lowFile = Path.Combine(gameDir, "UnityPlayer.dll");
            string mediumFile = Path.Combine(dlDir, "bundle.zip");
            string highFile = Path.Combine(dlDir, "installer.exe");
            string criticalFile = Path.Combine(dlDir, "invoice.pdf.exe");

            await File.WriteAllBytesAsync(blockerFile, Encoding.UTF8.GetBytes("BLOCKER_PAYLOAD"));
            await File.WriteAllBytesAsync(trustedFile, Encoding.UTF8.GetBytes("TRUSTED_TEXT"));
            await File.WriteAllBytesAsync(lowFile, Encoding.UTF8.GetBytes("LOW_RUNTIME"));
            await File.WriteAllBytesAsync(mediumFile, Encoding.UTF8.GetBytes("MEDIUM_ARCHIVE"));
            await File.WriteAllBytesAsync(highFile, Encoding.UTF8.GetBytes("HIGH_UNSIGNED_EXE"));
            await File.WriteAllBytesAsync(criticalFile, Encoding.UTF8.GetBytes("CRITICAL_DOUBLE_EXT"));

            string blockerSha = Convert.ToHexStringLower(SHA256.HashData(await File.ReadAllBytesAsync(blockerFile)));
            var releaseFirst = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var firstStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var completionOrder = new List<string>();

            var handler = new MockHttpHandler(async (req, _) =>
            {
                if (req.RequestUri!.AbsolutePath.EndsWith("/files/" + blockerSha))
                {
                    firstStarted.TrySetResult();
                    await releaseFirst.Task;
                }

                return JsonResponse(HttpStatusCode.OK, MakeFileReportJson(0, 0, 70, 0));
            });

            using var vtClient = new VirusTotalClient(limiter, logger, new HttpClient(handler));
            using var secondary = new SecondaryHashLookupService(history, logger, new HttpClient(handler), TimeSpan.Zero);
            using var engine = new ScanEngine(settingsStore, history, limiter, vtClient, logger, secondaryLookup: secondary);
            engine.ScanCompleted += rec =>
            {
                lock (completionOrder)
                {
                    completionOrder.Add(rec.FileName);
                }
            };

            engine.Start();
            engine.EnqueueFile(blockerFile);
            await firstStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));

            // Enqueue from lowest risk to highest risk while worker is paused on blockerFile
            engine.EnqueueFile(trustedFile);
            engine.EnqueueFile(lowFile);
            engine.EnqueueFile(mediumFile);
            engine.EnqueueFile(highFile);
            engine.EnqueueFile(criticalFile);

            var snapshot = engine.GetQueueSnapshot();
            var queued = snapshot.Where(q => q.State == "Queued").ToList();
            Assert(queued.Count == 5, $"Expected 5 queued items, got {queued.Count}.");
            Assert(queued[0].FileName == "invoice.pdf.exe", $"Expected Critical first, got {queued[0].FileName}.");
            Assert(queued[1].FileName == "installer.exe", $"Expected High second, got {queued[1].FileName}.");
            Assert(queued[2].FileName == "bundle.zip", $"Expected Medium third, got {queued[2].FileName}.");
            Assert(queued[3].FileName == "UnityPlayer.dll", $"Expected Low fourth, got {queued[3].FileName}.");
            Assert(queued[4].FileName == "readme.txt", $"Expected Trusted fifth, got {queued[4].FileName}.");

            // Promote trustedFile to top and remove mediumFile
            Assert(engine.PromoteQueuedItem(trustedFile), "Promote should return true.");
            Assert(engine.RemoveQueuedItem(mediumFile), "Remove should return true.");

            var afterEdit = engine.GetQueueSnapshot().Where(q => q.State == "Queued").ToList();
            Assert(afterEdit.Count == 4, "Expected 4 queued items after removal.");
            Assert(afterEdit[0].FileName == "readme.txt", $"Promoted item must be #1, got {afterEdit[0].FileName}.");
            Assert(afterEdit[1].FileName == "invoice.pdf.exe", $"Critical must follow promoted item, got {afterEdit[1].FileName}.");

            releaseFirst.TrySetResult();

            await WaitUntilAsync(() =>
            {
                lock (completionOrder)
                {
                    return completionOrder.Count == 5;
                }
            }, TimeSpan.FromSeconds(5), "All remaining prioritized scans should finish.");

            lock (completionOrder)
            {
                Assert(completionOrder[0] == "blocker.exe", "Blocker finishes first.");
                Assert(completionOrder[1] == "readme.txt", "Promoted file must execute second.");
                Assert(completionOrder[2] == "invoice.pdf.exe", "Critical must execute third.");
                Assert(completionOrder[3] == "installer.exe", "High must execute fourth.");
                Assert(completionOrder[4] == "UnityPlayer.dll", "Low must execute fifth.");
            }

            // Test ClearQueue
            engine.EnqueueFile(mediumFile);
            _ = engine.ClearQueue();
        }
        finally
        {
            CleanupDir(tempDir);
        }
    }

    private static async Task TestManualFolderQueueing()
    {
        string tempDir = CreateTempDir();
        string dataDir = Path.Combine(tempDir, "Data");
        string rootDir = Path.Combine(tempDir, "FolderScan");
        string nestedDir = Path.Combine(rootDir, "sub", "nested");
        Directory.CreateDirectory(nestedDir);

        try
        {
            var paths = new AppPaths(dataDir, Path.Combine(tempDir, "UpdateStaging"));
            var logger = new AppLogger(paths);
            var settingsStore = new SettingsStore(paths, logger);
            var settings = new AppSettings
            {
                WatchedDirectories = [],
                FilterMode = FileFilterMode.ExecutablesScriptsAndArchives,
                EnableCirclHashlookup = false,
                MaxRequestsPerMinute = 100
            };
            settingsStore.Save(settings);

            var history = new HistoryAndCacheStore(paths, logger);
            var limiter = new RateLimiter(100);

            string topExe = Path.Combine(rootDir, "high.exe");
            string nestedZip = Path.Combine(nestedDir, "archive.zip");
            string ignoredPng = Path.Combine(nestedDir, "ignore.png");
            string tempDl = Path.Combine(nestedDir, "temp.exe.crdownload");
            string emptyExe = Path.Combine(nestedDir, "empty.exe");

            await File.WriteAllBytesAsync(topExe, Encoding.UTF8.GetBytes("HIGH_RISK_EXE"));
            await File.WriteAllBytesAsync(nestedZip, Encoding.UTF8.GetBytes("MEDIUM_ARCHIVE"));
            await File.WriteAllBytesAsync(ignoredPng, [1, 2, 3, 4]);
            await File.WriteAllBytesAsync(tempDl, Encoding.UTF8.GetBytes("TEMP_CRDL"));
            await File.WriteAllBytesAsync(emptyExe, []);

            var handler = new MockHttpHandler((_, _) => JsonResponse(HttpStatusCode.NotFound, "{}"));
            using var vtClient = new VirusTotalClient(limiter, logger, new HttpClient(handler));
            using var engine = new ScanEngine(settingsStore, history, limiter, vtClient, logger);

            var (queuedCount, skippedCount) = engine.EnqueueDirectory(rootDir, includeSubdirectories: true);
            Assert(queuedCount == 2, $"Expected 2 queued files from recursive folder scan, got {queuedCount}.");
            Assert(skippedCount >= 3, $"Expected at least 3 skipped files (.png, .crdownload, empty), got {skippedCount}.");

            var snap = engine.GetQueueSnapshot().Where(q => q.State == "Queued").ToList();
            Assert(snap.Count == 2, $"Expected 2 queued items in snapshot, got {snap.Count}.");
            Assert(snap[0].FileName == "high.exe" && snap[1].FileName == "archive.zip",
                $"Expected risk-prioritized ordering high.exe -> archive.zip, got {snap[0].FileName} -> {snap[1].FileName}.");

            _ = engine.ClearQueue();

            var (flatQueued, _) = engine.EnqueueDirectory(rootDir, includeSubdirectories: false);
            Assert(flatQueued == 1, $"Expected 1 queued file without subfolders, got {flatQueued}.");
            var flatSnap = engine.GetQueueSnapshot().Where(q => q.State == "Queued").ToList();
            Assert(flatSnap.Count == 1 && flatSnap[0].FileName == "high.exe", "Top-level scan should enqueue only high.exe.");
        }
        finally
        {
            CleanupDir(tempDir);
        }
    }

    private static async Task TestSecondaryShortCircuitEndToEnd()
    {
        string tempDir = CreateTempDir();
        string dataDir = Path.Combine(tempDir, "Data");
        string watchDir = Path.Combine(tempDir, "Watch");
        Directory.CreateDirectory(watchDir);

        try
        {
            var paths = new AppPaths(dataDir, Path.Combine(tempDir, "UpdateStaging"));
            var logger = new AppLogger(paths);
            var settingsStore = new SettingsStore(paths, logger);
            var settings = new AppSettings
            {
                WatchedDirectories = [new WatchedDirectory { Path = watchDir, IncludeSubdirectories = true, Enabled = true }],
                EnableCirclHashlookup = true,
                SecondaryLookupsLowerRiskOnly = false,
                MaxRequestsPerMinute = 100
            };
            SettingsStore.SetApiKey(settings, "vt-key");
            settingsStore.Save(settings);

            var history = new HistoryAndCacheStore(paths, logger);
            var limiter = new RateLimiter(100);

            int vtCalls = 0;
            var vtHandler = new MockHttpHandler((_, _) =>
            {
                Interlocked.Increment(ref vtCalls);
                return JsonResponse(HttpStatusCode.InternalServerError, "{}");
            });

            var secHandler = new MockHttpHandler((req, _) =>
            {
                if (req.RequestUri!.ToString().Contains("hashlookup.circl.lu/lookup/sha256/"))
                {
                    return JsonResponse(HttpStatusCode.OK, """{"FileName":"signed_helper.dll","hashlookup:trust":88,"ProductCode":{"ProductName":"Trusted SDK"}}""");
                }

                return JsonResponse(HttpStatusCode.NotFound, "{}");
            });

            using var vtClient = new VirusTotalClient(limiter, logger, new HttpClient(vtHandler));
            using var secService = new SecondaryHashLookupService(history, logger, new HttpClient(secHandler), TimeSpan.Zero);
            using var engine = new ScanEngine(
                settingsStore,
                history,
                limiter,
                vtClient,
                logger,
                stabilityInterval: TimeSpan.FromMilliseconds(50),
                stabilizerCheckInterval: TimeSpan.FromMilliseconds(20),
                zeroByteGrace: TimeSpan.FromMilliseconds(150),
                secondaryLookup: secService);

            ScanRecord? completed = null;
            engine.ScanCompleted += r => completed = r;
            engine.Start();

            await File.WriteAllBytesAsync(Path.Combine(watchDir, "signed_helper.dll"), Encoding.UTF8.GetBytes("KNOWN_GOOD_DLL_BYTES"));
            await WaitUntilAsync(() => completed is not null, TimeSpan.FromSeconds(5), "CIRCL short-circuit scan should complete.");

            Assert(completed!.Verdict == ScanVerdict.Clean, "CIRCL verified file must be Clean.");
            Assert(completed.SourceService == SecondaryHashLookupService.CirclServiceName, "SourceService must be CIRCL Hashlookup.");
            Assert(vtCalls == 0, $"Expected 0 VT API calls, got {vtCalls}.");
            Assert(engine.GetDailyUsageSnapshot().DailySecondarySavedCalls == 1, "Expected 1 secondary saved VT call.");
        }
        finally
        {
            CleanupDir(tempDir);
        }
    }

    private static async Task TestEndToEndScanning()
    {
        string tempDir = CreateTempDir();
        string dataDir = Path.Combine(tempDir, "AppData");
        string watchDir = Path.Combine(tempDir, "Watch");
        Directory.CreateDirectory(watchDir);

        try
        {
            var paths = new AppPaths(dataDir, Path.Combine(tempDir, "UpdateStaging"));
            var logger = new AppLogger(paths);
            var settingsStore = new SettingsStore(paths, logger);
            var settings = new AppSettings
            {
                WatchedDirectories = [new WatchedDirectory { Path = watchDir, IncludeSubdirectories = true, Enabled = true }],
                UploadPolicy = UploadPolicy.ExecutablesAndScriptsOnly,
                FilterMode = FileFilterMode.ExecutablesScriptsAndArchives,
                EnableCirclHashlookup = false,
                MaliciousThreshold = 2,
                MaxRequestsPerMinute = 100
            };
            SettingsStore.SetApiKey(settings, "valid-test-key");
            settingsStore.Save(settings);

            var historyStore = new HistoryAndCacheStore(paths, logger);
            var limiter = new RateLimiter(100);

            byte[] unsafeExeBytes = Encoding.UTF8.GetBytes("MZ_FAKE_UNSAFE_PAYLOAD");
            byte[] lockedExeBytes = Encoding.UTF8.GetBytes("MZ_FAKE_CLEAN_LOCKED");
            byte[] unknownZipBytes = Encoding.UTF8.GetBytes("PK_UNKNOWN_ARCHIVE");

            string unsafeSha = Convert.ToHexStringLower(SHA256.HashData(unsafeExeBytes));
            string lockedSha = Convert.ToHexStringLower(SHA256.HashData(lockedExeBytes));
            string zipSha = Convert.ToHexStringLower(SHA256.HashData(unknownZipBytes));

            int postCount = 0;
            var handler = new MockHttpHandler((req, _) =>
            {
                string path = req.RequestUri!.AbsolutePath;
                if (req.Method == HttpMethod.Get && path.EndsWith("/files/" + unsafeSha))
                {
                    return JsonResponse(HttpStatusCode.NotFound, "{}");
                }

                if (req.Method == HttpMethod.Post && path.EndsWith("/files"))
                {
                    Interlocked.Increment(ref postCount);
                    return JsonResponse(HttpStatusCode.OK, """{"data":{"id":"up-unsafe"}}""");
                }

                if (req.Method == HttpMethod.Get && path.EndsWith("/analyses/up-unsafe"))
                {
                    return JsonResponse(HttpStatusCode.OK, MakeAnalysisReportJson("completed", 6, 0, 64, 0,
                        ("Defender", "malicious", "Trojan:Win32/Mock")));
                }

                if (req.Method == HttpMethod.Get && path.EndsWith("/files/" + lockedSha))
                {
                    return JsonResponse(HttpStatusCode.OK, MakeFileReportJson(0, 0, 70, 1));
                }

                if (req.Method == HttpMethod.Get && path.EndsWith("/files/" + zipSha))
                {
                    return JsonResponse(HttpStatusCode.NotFound, "{}");
                }

                return JsonResponse(HttpStatusCode.NotFound, "{}");
            });

            using var vtClient = new VirusTotalClient(
                limiter,
                logger,
                new HttpClient(handler),
                initialAnalysisDelay: TimeSpan.FromMilliseconds(10),
                analysisPollInterval: TimeSpan.FromMilliseconds(10),
                rateLimitFallbackDelay: TimeSpan.FromMilliseconds(20));

            using var engine = new ScanEngine(
                settingsStore,
                historyStore,
                limiter,
                vtClient,
                logger,
                stabilityInterval: TimeSpan.FromMilliseconds(60),
                stabilizerCheckInterval: TimeSpan.FromMilliseconds(25),
                zeroByteGrace: TimeSpan.FromMilliseconds(200));

            var observedRecords = new ConcurrentBag<ScanRecord>();
            var observedStatuses = new ConcurrentBag<TrayStatus>();
            engine.StatusChanged += () => observedStatuses.Add(engine.CurrentTrayStatus);
            engine.ScanCompleted += rec => observedRecords.Add(rec);

            Assert(engine.CurrentTrayStatus == TrayStatus.Safe, "Initial status with API key should be Safe.");
            engine.Start();

            string tempDownload = Path.Combine(watchDir, "installer.exe.crdownload");
            string finalExe = Path.Combine(watchDir, "installer.exe");
            await File.WriteAllBytesAsync(tempDownload, unsafeExeBytes);
            await Task.Delay(120);
            Assert(observedRecords.IsEmpty, ".crdownload must not be scanned.");

            File.Move(tempDownload, finalExe);
            await WaitUntilAsync(() => observedRecords.Any(r => r.FileName == "installer.exe"), TimeSpan.FromSeconds(5),
                "Renamed installer.exe should be scanned.");

            var unsafeRec = observedRecords.First(r => r.FileName == "installer.exe");
            Assert(unsafeRec.Verdict == ScanVerdict.Unsafe, "Expected Unsafe verdict after upload.");
            Assert(unsafeRec.Uploaded, "Expected Uploaded == true.");
            Assert(engine.CurrentTrayStatus == TrayStatus.Unsafe, "Tray status must stay Unsafe while unacknowledged.");

            await File.WriteAllBytesAsync(Path.Combine(watchDir, "asset.pak"), [1, 2, 3, 4]);
            await File.WriteAllBytesAsync(Path.Combine(watchDir, "preview.png"), [1, 2, 3, 4]);
            await Task.Delay(200);
            Assert(!observedRecords.Any(r => r.FileName is "asset.pak" or "preview.png"), ".pak and .png must be ignored.");

            string lockedExe = Path.Combine(watchDir, "clean_game.exe");
            using (var fs = new FileStream(lockedExe, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                await fs.WriteAsync(lockedExeBytes.AsMemory(0, 8));
                await fs.FlushAsync();
                await Task.Delay(250);
                Assert(!observedRecords.Any(r => r.FileName == "clean_game.exe"), "Locked file must not scan before closing.");
                await fs.WriteAsync(lockedExeBytes.AsMemory(8));
            }

            await WaitUntilAsync(() => observedRecords.Any(r => r.FileName == "clean_game.exe"), TimeSpan.FromSeconds(5),
                "Unlocked clean_game.exe should finish scanning.");
            var cleanRec = observedRecords.First(r => r.FileName == "clean_game.exe");
            Assert(cleanRec.Verdict == ScanVerdict.Clean, "Expected Clean verdict for clean_game.exe.");
            Assert(engine.CurrentTrayStatus == TrayStatus.Unsafe, "Tray status must remain Unsafe until alert acknowledged.");

            string unknownZip = Path.Combine(watchDir, "modpack.zip");
            await File.WriteAllBytesAsync(unknownZip, unknownZipBytes);
            await WaitUntilAsync(() => observedRecords.Any(r => r.FileName == "modpack.zip"), TimeSpan.FromSeconds(5),
                "modpack.zip should be hashed and checked.");
            var zipRec = observedRecords.First(r => r.FileName == "modpack.zip");
            Assert(zipRec.Verdict == ScanVerdict.Unknown && !zipRec.Uploaded, ".zip 404 must become Unknown without upload.");
            Assert(postCount == 1, "Only the unknown .exe should have triggered POST /files.");

            engine.AcknowledgeAllUnsafe();
            Assert(engine.CurrentTrayStatus == TrayStatus.Safe, "Status should return to Safe after acknowledging alert.");
            Assert(observedStatuses.Contains(TrayStatus.Scanning) || observedStatuses.Contains(TrayStatus.Unsafe),
                "Expected status transitions during scanning.");
        }
        finally
        {
            CleanupDir(tempDir);
        }
    }

    private static async Task WaitUntilAsync(Func<bool> predicate, TimeSpan timeout, string failMessage)
    {
        var sw = Stopwatch.StartNew();
        while (sw.Elapsed < timeout)
        {
            if (predicate())
            {
                return;
            }

            await Task.Delay(25);
        }

        throw new TimeoutException(failMessage);
    }

    private static Task TestTrayIconFactory()
    {
        using var factory = new TrayIconFactory();
        Assert(factory.AppIcon.Width > 0 && factory.AppIcon.Height > 0, "Embedded AppIcon invalid.");
        foreach (TrayStatus status in Enum.GetValues<TrayStatus>())
        {
            var icon0 = factory.GetIcon(status, 0);
            var icon1 = factory.GetIcon(status, 1);
            Assert(icon0.Width > 0 && icon0.Height > 0, $"Icon {status} frame 0 invalid.");
            Assert(icon1.Width > 0 && icon1.Height > 0, $"Icon {status} frame 1 invalid.");
        }

        return Task.CompletedTask;
    }

    private static Task TestThresholdSlider()
    {
        for (int v = ModernThresholdSlider.MinThreshold; v <= ModernThresholdSlider.MaxThreshold; v++)
        {
            var (title, desc) = ModernThresholdSlider.GetThresholdGuidance(v);
            Assert(!string.IsNullOrWhiteSpace(title), $"Missing slider title for {v}.");
            Assert(!string.IsNullOrWhiteSpace(desc), $"Missing slider description for {v}.");
            Assert(!title.Contains('\u2014') && !title.Contains('\u2013'), "Unicode dashes forbidden in slider title.");
            Assert(!desc.Contains('\u2014') && !desc.Contains('\u2013'), "Unicode dashes forbidden in slider description.");
        }

        var c1 = ModernThresholdSlider.GetThresholdColor(1, ThemePalette.Dark);
        var c2 = ModernThresholdSlider.GetThresholdColor(2, ThemePalette.Dark);
        var c4 = ModernThresholdSlider.GetThresholdColor(4, ThemePalette.Dark);
        var c6 = ModernThresholdSlider.GetThresholdColor(6, ThemePalette.Dark);
        var c8 = ModernThresholdSlider.GetThresholdColor(8, ThemePalette.Dark);
        Assert(c1 != c2 && c2 != c4 && c4 != c6 && c6 != c8, "Slider colors must change across sensitivity ranges.");

        Exception? threadEx = null;
        var sta = new Thread(() =>
        {
            try
            {
                using var slider = new ModernThresholdSlider();
                Assert(slider.Value == ModernThresholdSlider.RecommendedThreshold, "Default slider value must be 2.");
                slider.Value = 50;
                Assert(slider.Value == ModernThresholdSlider.MaxThreshold, "Slider must clamp to max.");
                slider.Value = 0;
                Assert(slider.Value == ModernThresholdSlider.MinThreshold, "Slider must clamp to min.");
            }
            catch (Exception ex)
            {
                threadEx = ex;
            }
        });
        sta.SetApartmentState(ApartmentState.STA);
        sta.Start();
        sta.Join();

        if (threadEx is not null)
        {
            throw new InvalidOperationException("Threshold slider control test failed.", threadEx);
        }

        return Task.CompletedTask;
    }

    private static async Task TestUpdateServiceLogic()
    {
        Assert(UpdateService.TryParseReleaseVersion("v1.2.0", out Version? v120) && v120 == new Version(1, 2, 0, 0),
            "Should parse v1.2.0 tag.");
        Assert(UpdateService.TryParseReleaseVersion("1.2.0-rc1", out Version? vRc) && vRc == new Version(1, 2, 0, 0),
            "Should parse prerelease stripped version.");

        Assert(UpdateService.IsCriticalRelease("[CRITICAL UPDATE] Urgent API fix\nDetails..."),
            "First-line critical marker must match.");
        Assert(UpdateService.IsCriticalRelease("\n  [critical update] Security patch\nMore text"),
            "Case-insensitive marker after blank line must match.");
        Assert(!UpdateService.IsCriticalRelease("Normal update\n[CRITICAL UPDATE] Not on first line"),
            "Marker on second line must NOT count as critical.");
        Assert(!UpdateService.IsCriticalRelease("Regular feature release"),
            "Regular release notes must not count as critical.");

        Assert(UpdateService.IsAllowedDownloadUrl("https://github.com/sonnenfell/VTDownloadGuard/releases/download/v1.2.0/app.zip"),
            "GitHub HTTPS URL should be allowed.");
        Assert(UpdateService.IsAllowedDownloadUrl("https://objects.githubusercontent.com/github-production-release-asset/123"),
            "GitHub objects CDN URL should be allowed.");
        Assert(!UpdateService.IsAllowedDownloadUrl("http://github.com/sonnenfell/VTDownloadGuard/app.zip"),
            "Non-HTTPS URL must be rejected.");
        Assert(!UpdateService.IsAllowedDownloadUrl("https://evil.example.com/VTDownloadGuard.exe"),
            "Untrusted host must be rejected.");

        var defaultUpdateSettings = AppSettings.CreateDefault();
        Assert(defaultUpdateSettings.AutoUpdateEnabled && defaultUpdateSettings.AutoUpdateCriticalOnly,
            "Auto-updates must default to critical updates only.");

        var normalUpdate = new UpdateCheckResult
        {
            Success = true,
            UpdateAvailable = true,
            IsCritical = false,
            DownloadUrl = "https://github.com/sonnenfell/VTDownloadGuard/releases/download/v1.2.2/VTDownloadGuard.zip"
        };
        var criticalUpdate = new UpdateCheckResult
        {
            Success = true,
            UpdateAvailable = true,
            IsCritical = true,
            DownloadUrl = "https://github.com/sonnenfell/VTDownloadGuard/releases/download/v1.2.2/VTDownloadGuard.zip"
        };

        // Default: Critical updates only
        Assert(!UpdateService.ShouldAutoInstall(defaultUpdateSettings, normalUpdate),
            "Critical-only default must skip non-critical updates.");
        Assert(UpdateService.ShouldAutoInstall(defaultUpdateSettings, criticalUpdate),
            "Critical-only default must allow critical updates.");

        // Mode: Off (manual checks only)
        defaultUpdateSettings.AutoUpdateEnabled = false;
        defaultUpdateSettings.AutoUpdateCriticalOnly = false;
        Assert(!UpdateService.ShouldAutoInstall(defaultUpdateSettings, normalUpdate),
            "Off mode must skip normal updates.");
        Assert(!UpdateService.ShouldAutoInstall(defaultUpdateSettings, criticalUpdate),
            "Off mode must never auto-install even for critical updates.");

        // Mode: On (all releases)
        defaultUpdateSettings.AutoUpdateEnabled = true;
        defaultUpdateSettings.AutoUpdateCriticalOnly = false;
        Assert(UpdateService.ShouldAutoInstall(defaultUpdateSettings, normalUpdate),
            "On mode should allow normal updates.");
        Assert(UpdateService.ShouldAutoInstall(defaultUpdateSettings, criticalUpdate),
            "On mode should allow critical updates.");

        // Restore critical-only mode for mocked GitHub API check below
        defaultUpdateSettings.AutoUpdateCriticalOnly = true;

        string tempDir = CreateTempDir();
        try
        {
            string appDir = Path.Combine(tempDir, "AppPortable");
            Directory.CreateDirectory(appDir);

            var paths = new AppPaths(Path.Combine(tempDir, "Data"));
            var logger = new AppLogger(paths);

            var handler = new MockHttpHandler((req, _) =>
            {
                if (req.RequestUri!.ToString().Contains("/releases/latest"))
                {
                    return JsonResponse(HttpStatusCode.OK, """
                    {
                      "tag_name": "v1.3.0",
                      "name": "VTDownloadGuard 1.3.0",
                      "draft": false,
                      "prerelease": false,
                      "html_url": "https://github.com/sonnenfell/VTDownloadGuard/releases/tag/v1.3.0",
                      "body": "[CRITICAL UPDATE] Fixes detection parsing.\nDetails here.",
                      "assets": [
                        {
                          "name": "VTDownloadGuard-1.3.0-win-x64-Setup.exe",
                          "browser_download_url": "https://github.com/sonnenfell/VTDownloadGuard/releases/download/v1.3.0/VTDownloadGuard-1.3.0-win-x64-Setup.exe",
                          "size": 36000000,
                          "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        },
                        {
                          "name": "VTDownloadGuard-1.3.0-win-x64-Portable-FrameworkDependent.zip",
                          "browser_download_url": "https://github.com/sonnenfell/VTDownloadGuard/releases/download/v1.3.0/VTDownloadGuard-1.3.0-win-x64-Portable-FrameworkDependent.zip",
                          "size": 230000,
                          "digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                        }
                      ]
                    }
                    """);
                }

                return JsonResponse(HttpStatusCode.NotFound, "{}");
            });

            using var updateSvc = new UpdateService(
                paths,
                logger,
                new HttpClient(handler),
                currentVersionOverride: new Version(1, 2, 0),
                appDirectoryOverride: appDir);

            UpdateCheckResult res = await updateSvc.CheckForUpdatesAsync(defaultUpdateSettings, CancellationToken.None);
            Assert(res.Success && res.UpdateAvailable && res.IsCritical, "Expected critical update v1.3.0 available.");
            Assert(res.AssetName.EndsWith(".zip", StringComparison.OrdinalIgnoreCase),
                $"Portable install should prefer .zip asset, got '{res.AssetName}'.");
            Assert(res.ExpectedSha256 == new string('b', 64), "Expected SHA-256 digest from GitHub API asset.");

            // Inno install should select Setup.exe
            File.WriteAllBytes(Path.Combine(appDir, "unins000.exe"), [1, 2, 3]);
            UpdateCheckResult resInno = await updateSvc.CheckForUpdatesAsync(defaultUpdateSettings, CancellationToken.None);
            Assert(resInno.AssetName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase),
                $"Inno install should prefer Setup.exe asset, got '{resInno.AssetName}'.");
        }
        finally
        {
            CleanupDir(tempDir);
        }
    }

    private static async Task TestSelfUpdateDataPreservation()
    {
        string tempDir = CreateTempDir();
        string appDir = Path.Combine(tempDir, "App");
        string dataDir = Path.Combine(tempDir, "Data");
        Directory.CreateDirectory(appDir);
        Directory.CreateDirectory(dataDir);

        try
        {
            await File.WriteAllTextAsync(Path.Combine(appDir, "VTDownloadGuard.exe"), "OLD_EXE_V1.1.0");
            await File.WriteAllTextAsync(Path.Combine(appDir, "VTDownloadGuard.dll"), "OLD_DLL_V1.1.0");

            var paths = new AppPaths(dataDir, Path.Combine(tempDir, "UpdateStaging"));
            var logger = new AppLogger(paths);
            var settingsStore = new SettingsStore(paths, logger);
            var settings = AppSettings.CreateDefault();
            SettingsStore.SetApiKey(settings, "preserved-vt-key-xyz");
            settings.WatchedDirectories.Add(new WatchedDirectory { Path = @"E:\CustomWatched", IncludeSubdirectories = true, Enabled = true });
            settings.AutoUpdateEnabled = true;
            settings.AutoUpdateCriticalOnly = true;
            settingsStore.Save(settings);

            var historyStore = new HistoryAndCacheStore(paths, logger);
            historyStore.AddOrUpdateScanRecord(new ScanRecord
            {
                FileName = "preserved.exe",
                FilePath = @"C:\Temp\preserved.exe",
                Sha256 = "feedface1234",
                Verdict = ScanVerdict.Clean,
                TotalEngines = 70,
                Summary = "Preserved record"
            });
            historyStore.UpsertCacheEntry(new HashCacheEntry
            {
                Sha256 = "feedface1234",
                CachedAtUtc = DateTimeOffset.UtcNow,
                WasFoundOnVirusTotal = true,
                TotalEngines = 70
            });

            // Build in-memory update zip
            byte[] zipBytes;
            using (var ms = new MemoryStream())
            {
                using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
                {
                    var exeEntry = zip.CreateEntry("VTDownloadGuard.exe");
                    await using (var s = exeEntry.Open())
                    await using (var w = new StreamWriter(s))
                    {
                        await w.WriteAsync("NEW_EXE_V1.2.0");
                    }

                    var dllEntry = zip.CreateEntry("VTDownloadGuard.dll");
                    await using (var s = dllEntry.Open())
                    await using (var w = new StreamWriter(s))
                    {
                        await w.WriteAsync("NEW_DLL_V1.2.0");
                    }
                }

                zipBytes = ms.ToArray();
            }

            string goodSha = Convert.ToHexStringLower(SHA256.HashData(zipBytes));

            var handler = new MockHttpHandler((req, _) =>
            {
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new ByteArrayContent(zipBytes)
                };
            });

            using var updateSvc = new UpdateService(
                paths,
                logger,
                new HttpClient(handler),
                currentVersionOverride: new Version(1, 1, 0),
                appDirectoryOverride: appDir);

            // 1. Corrupted hash must abort without modifying appDir
            var badCheck = new UpdateCheckResult
            {
                Success = true,
                UpdateAvailable = true,
                TagName = "v1.2.0",
                AssetName = "VTDownloadGuard-1.2.0-win-x64-Portable-FrameworkDependent.zip",
                DownloadUrl = "https://github.com/sonnenfell/VTDownloadGuard/releases/download/v1.2.0/update.zip",
                AssetSizeBytes = zipBytes.Length,
                ExpectedSha256 = new string('0', 64)
            };

            var (badStarted, _) = await updateSvc.DownloadAndApplyUpdateAsync(
                badCheck,
                openDashboardAfterUpdate: false,
                onProgress: null,
                requestAppExit: () => { },
                CancellationToken.None,
                launchInstallerProcess: false);
            Assert(!badStarted, "SHA-256 mismatch must abort update.");
            Assert(await File.ReadAllTextAsync(Path.Combine(appDir, "VTDownloadGuard.exe")) == "OLD_EXE_V1.1.0",
                "Old executable must stay untouched on hash mismatch.");

            // 2. Valid hash downloads, backs up data, extracts, and SelfUpdateApplier replaces binaries while preserving AppData
            var goodCheck = new UpdateCheckResult
            {
                Success = true,
                UpdateAvailable = true,
                TagName = "v1.2.0",
                AssetName = "VTDownloadGuard-1.2.0-win-x64-Portable-FrameworkDependent.zip",
                DownloadUrl = "https://github.com/sonnenfell/VTDownloadGuard/releases/download/v1.2.0/update.zip",
                AssetSizeBytes = zipBytes.Length,
                ExpectedSha256 = goodSha
            };

            var (okStarted, okMsg) = await updateSvc.DownloadAndApplyUpdateAsync(
                goodCheck,
                openDashboardAfterUpdate: false,
                onProgress: null,
                requestAppExit: () => { },
                CancellationToken.None,
                launchInstallerProcess: false);
            Assert(okStarted, $"Valid update staging failed: {okMsg}");

            string[] backups = Directory.GetDirectories(paths.BackupsDirectory, "pre-update-*");
            Assert(backups.Length == 1, "Expected 1 pre-update backup directory.");
            Assert(File.Exists(Path.Combine(backups[0], "settings.json")), "Backup must contain settings.json.");
            Assert(File.Exists(Path.Combine(backups[0], "history.json")), "Backup must contain history.json.");
            Assert(File.Exists(Path.Combine(backups[0], "hash-cache.json")), "Backup must contain hash-cache.json.");

            string extractedDir = Directory.GetDirectories(paths.UpdateStagingRoot, "extracted", SearchOption.AllDirectories).Single();
            SelfUpdateApplier.ApplyDirectoryCopy(extractedDir, appDir);

            Assert(await File.ReadAllTextAsync(Path.Combine(appDir, "VTDownloadGuard.exe")) == "NEW_EXE_V1.2.0",
                "Updated executable should be copied.");
            Assert(await File.ReadAllTextAsync(Path.Combine(appDir, "VTDownloadGuard.dll")) == "NEW_DLL_V1.2.0",
                "Updated DLL should be copied.");

            var reloadedSettings = new SettingsStore(paths, logger).Load();
            Assert(SettingsStore.GetDecryptedApiKey(reloadedSettings) == "preserved-vt-key-xyz",
                "Encrypted API key must survive update.");
            Assert(reloadedSettings.WatchedDirectories.Any(d => d.Path.Equals(@"E:\CustomWatched", StringComparison.OrdinalIgnoreCase)),
                "Configured directories must survive update.");
            Assert(reloadedSettings.AutoUpdateEnabled && reloadedSettings.AutoUpdateCriticalOnly,
                "Update preferences must survive update.");

            var reloadedHistory = new HistoryAndCacheStore(paths, logger);
            Assert(reloadedHistory.GetHistory().Any(r => r.FileName == "preserved.exe"),
                "Scan history must survive update.");
            Assert(reloadedHistory.TryGetCachedHash("feedface1234", out _),
                "Hash cache must survive update.");
        }
        finally
        {
            CleanupDir(tempDir);
        }
    }

    private static Task TestResetDefaultsAndVtLimitWarnings()
    {
        var defaults = AppSettings.CreateDefault();
        var s = AppSettings.CreateDefault();

        SettingsStore.SetApiKey(s, "vt-keep-me");
        SettingsStore.SetMetaDefenderApiKey(s, "md-keep-me");
        SettingsStore.SetMalwareBazaarApiKey(s, "mb-keep-me");
        s.WatchedDirectories = [new WatchedDirectory { Path = @"C:\CustomDir", IncludeSubdirectories = true, Enabled = true }];
        s.OnboardingCompleted = true;
        s.UpdateRepository = "sonnenfell/VTDownloadGuard";

        s.ThemeMode = AppThemeMode.Light;
        s.StartWithWindows = false;
        s.UploadPolicy = UploadPolicy.HashLookupOnly;
        s.FilterMode = FileFilterMode.AllFiles;
        s.UploadExtensions = [".bin"];
        s.ArchiveExtensions = [".tar"];
        s.MaliciousThreshold = 7;
        s.MaxRequestsPerMinute = 30;
        s.MaxUploadSizeMb = 200;
        s.MaxHashSizeMb = 4096;
        s.SecondaryLookupsLowerRiskOnly = true;
        s.EnableCirclHashlookup = false;
        s.EnableMetaDefender = true;
        s.EnableMalwareBazaar = true;
        s.AutoUpdateEnabled = false;
        s.AutoUpdateCriticalOnly = false;
        s.HeaderBrandClickAction = HeaderBrandClickAction.ToggleMonitoring;

        s.ResetPreferencesToDefaults();

        Assert(s.ThemeMode == defaults.ThemeMode, "ThemeMode must reset to default.");
        Assert(s.StartWithWindows == defaults.StartWithWindows, "StartWithWindows must reset to default.");
        Assert(s.UploadPolicy == defaults.UploadPolicy, "UploadPolicy must reset to default.");
        Assert(s.FilterMode == defaults.FilterMode, "FilterMode must reset to default.");
        Assert(s.UploadExtensions.SequenceEqual(defaults.UploadExtensions), "UploadExtensions must reset to default.");
        Assert(s.ArchiveExtensions.SequenceEqual(defaults.ArchiveExtensions), "ArchiveExtensions must reset to default.");
        Assert(s.MaliciousThreshold == defaults.MaliciousThreshold, "MaliciousThreshold must reset to default.");
        Assert(s.MaxRequestsPerMinute == defaults.MaxRequestsPerMinute, "MaxRequestsPerMinute must reset to default.");
        Assert(s.MaxUploadSizeMb == defaults.MaxUploadSizeMb, "MaxUploadSizeMb must reset to default.");
        Assert(s.MaxHashSizeMb == defaults.MaxHashSizeMb, "MaxHashSizeMb must reset to default.");
        Assert(s.SecondaryLookupsLowerRiskOnly == defaults.SecondaryLookupsLowerRiskOnly, "SecondaryLookupsLowerRiskOnly must reset to default.");
        Assert(s.EnableCirclHashlookup == defaults.EnableCirclHashlookup, "EnableCirclHashlookup must reset to default.");
        Assert(s.EnableMetaDefender == defaults.EnableMetaDefender, "EnableMetaDefender must reset to default.");
        Assert(s.EnableMalwareBazaar == defaults.EnableMalwareBazaar, "EnableMalwareBazaar must reset to default.");
        Assert(s.AutoUpdateEnabled == defaults.AutoUpdateEnabled, "AutoUpdateEnabled must reset to default.");
        Assert(s.AutoUpdateCriticalOnly == defaults.AutoUpdateCriticalOnly, "AutoUpdateCriticalOnly must reset to default.");
        Assert(s.HeaderBrandClickAction == HeaderBrandClickAction.OpenRecentScans, "HeaderBrandClickAction must reset to OpenRecentScans.");

        Assert(SettingsStore.GetDecryptedApiKey(s) == "vt-keep-me", "VT API key must be preserved on reset.");
        Assert(SettingsStore.GetDecryptedMetaDefenderApiKey(s) == "md-keep-me", "MetaDefender key must be preserved on reset.");
        Assert(SettingsStore.GetDecryptedMalwareBazaarApiKey(s) == "mb-keep-me", "MalwareBazaar key must be preserved on reset.");
        Assert(s.WatchedDirectories.Count == 1 && s.WatchedDirectories[0].Path == @"C:\CustomDir", "Watched directories must be preserved on reset.");
        Assert(s.OnboardingCompleted, "OnboardingCompleted must be preserved on reset.");

        var atDefaults = DashboardForm.EvaluateVirusTotalLimitWarnings(4, 32, 2048);
        Assert(atDefaults.RateLimitWarning.Length == 0, "Default rate limit (4) must not trigger warning.");
        Assert(atDefaults.MaxUploadWarning.Length == 0, "Default upload limit (32 MB) must not trigger warning.");
        Assert(!atDefaults.MaxHashIsWarning, "Default max hash size (2048 MB) must not trigger warning.");
        Assert(!atDefaults.MaxHashWarning.Contains('\u2014') && !atDefaults.MaxHashWarning.Contains('\u2013'),
            "Limit hint text must not contain Unicode em/en dashes.");

        var withinUpload = DashboardForm.EvaluateVirusTotalLimitWarnings(4, 32, 512);
        Assert(withinUpload.MaxHashWarning.Length == 0 && !withinUpload.MaxHashIsWarning,
            "Max hash <= 650 MB should not show a notice.");

        var overRate = DashboardForm.EvaluateVirusTotalLimitWarnings(5, 32, 2048);
        Assert(overRate.RateLimitWarning.Contains("4 requests/minute", StringComparison.OrdinalIgnoreCase),
            "Rate limit above 4 must warn about the free API limit.");
        Assert(!overRate.RateLimitWarning.Contains('\u2014') && !overRate.RateLimitWarning.Contains('\u2013'),
            "Rate limit warning must not contain Unicode em/en dashes.");

        var overUpload = DashboardForm.EvaluateVirusTotalLimitWarnings(4, 33, 2048);
        Assert(overUpload.MaxUploadWarning.Contains("32 MB", StringComparison.OrdinalIgnoreCase),
            "Upload limit above 32 MB must warn about the free API direct upload limit.");
        Assert(!overUpload.MaxUploadWarning.Contains('\u2014') && !overUpload.MaxUploadWarning.Contains('\u2013'),
            "Upload limit warning must not contain Unicode em/en dashes.");

        var unlimitedHash = DashboardForm.EvaluateVirusTotalLimitWarnings(4, 32, 0);
        Assert(unlimitedHash.MaxHashIsWarning && unlimitedHash.MaxHashWarning.Contains("2048 MB", StringComparison.OrdinalIgnoreCase),
            "Unlimited max hash (0) must warn.");
        Assert(!unlimitedHash.MaxHashWarning.Contains('\u2014') && !unlimitedHash.MaxHashWarning.Contains('\u2013'),
            "Max hash warning must not contain Unicode em/en dashes.");

        var overHash = DashboardForm.EvaluateVirusTotalLimitWarnings(4, 32, 4096);
        Assert(overHash.MaxHashIsWarning && overHash.MaxHashWarning.Contains("2048 MB", StringComparison.OrdinalIgnoreCase),
            "Max hash above 2048 MB must warn.");

        return Task.CompletedTask;
    }

    private static Task TestDashboardUiSmoke()
    {
        string tempDir = CreateTempDir();
        Exception? threadEx = null;

        var sta = new Thread(() =>
        {
            try
            {
                var paths = new AppPaths(tempDir);
                var logger = new AppLogger(paths);
                var settingsStore = new SettingsStore(paths, logger);
                var settings = AppSettings.CreateDefault();
                settings.ThemeMode = AppThemeMode.Dark;
                settings.OnboardingCompleted = true;
                settingsStore.Save(settings);

                var history = new HistoryAndCacheStore(paths, logger);
                history.AddOrUpdateScanRecord(new ScanRecord
                {
                    FileName = "smoke_test.exe",
                    FilePath = Path.Combine(tempDir, "smoke_test.exe"),
                    Sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                    FileSizeBytes = 2048,
                    Verdict = ScanVerdict.Clean,
                    MaliciousCount = 0,
                    TotalEngines = 72,
                    RiskCategory = FileRiskCategory.Low,
                    RiskReason = "Digitally signed by Test",
                    SignerName = "Test Publisher",
                    SourceService = "VirusTotal",
                    Summary = "Clean: 0/72 detections"
                });

                var limiter = new RateLimiter(4);
                var handler = new MockHttpHandler((_, _) => JsonResponse(HttpStatusCode.NotFound, "{}"));
                using var vtClient = new VirusTotalClient(limiter, logger, new HttpClient(handler));
                using var engine = new ScanEngine(settingsStore, history, limiter, vtClient, logger);
                using var updateSvc = new UpdateService(paths, logger, new HttpClient(handler));
                using var icons = new TrayIconFactory();

                using var form = new DashboardForm(engine, paths, logger, icons.AppIcon, updateSvc);
                form.CreateControl();
                form.PerformLayout();
                Assert(!form.UsesCompositedExStyleForTest(),
                    "DashboardForm must not use WS_EX_COMPOSITED (prevents black startup frames and dropdown border flicker).");

                IReadOnlyList<string> expectedCardOrder =
                [
                    "Setup and Help",
                    "Updates",
                    "General and Appearance",
                    "VirusTotal Configuration",
                    "Secondary Hash Lookup Services",
                    "Reset Settings"
                ];
                IReadOnlyList<string> actualCardOrder = form.GetSettingsCardTitlesForTest();
                Assert(actualCardOrder.SequenceEqual(expectedCardOrder),
                    $"Unexpected Settings card order: [{string.Join(", ", actualCardOrder)}].");

                var darkMetrics = form.GetHeaderLayoutMetricsForTest();
                Assert(darkMetrics.HeaderBottom <= darkMetrics.NavTop,
                    $"Header ({darkMetrics.HeaderBottom}) must not overlap nav tabs ({darkMetrics.NavTop}).");
                Assert(darkMetrics.SubtitleBottom <= darkMetrics.HeaderHeight,
                    $"Subtitle bottom ({darkMetrics.SubtitleBottom}) must stay within header ({darkMetrics.HeaderHeight}).");
                Assert(darkMetrics.ScanBtnBottom <= darkMetrics.HeaderHeight,
                    $"Header buttons ({darkMetrics.ScanBtnBottom}) must stay within header ({darkMetrics.HeaderHeight}).");

                // Exercise RecommendedStarIndicator and wheel-safe input controls
                using (var star = new RecommendedStarIndicator())
                {
                    Assert(!star.IsAtRecommended, "Star indicator must start false.");
                    star.IsAtRecommended = true;
                    Assert(star.IsAtRecommended, "Star indicator must update to true.");
                    star.ApplyTheme(ThemePalette.Light);
                }

                using (var combo = new NoWheelComboBox())
                {
                    combo.Items.AddRange(["One", "Two"]);
                    combo.SelectedIndex = 1;
                    Assert(combo.SelectedIndex == 1, "NoWheelComboBox should support normal selection.");
                }

                using (var num = new NoWheelNumericUpDown { Minimum = 1, Maximum = 100 })
                {
                    num.Value = 42;
                    Assert(num.Value == 42, "NoWheelNumericUpDown should preserve assigned numeric value.");
                }

                for (int tab = 0; tab < 5; tab++)
                {
                    form.SelectTab(tab);
                    form.PerformLayout();
                }

                form.Size = new System.Drawing.Size(1180, 760);
                form.PerformLayout();

                // Verify changing brand click dropdown takes effect immediately and persists
                form.SelectTab(0);
                form.SetBrandClickActionForTest(HeaderBrandClickAction.OpenSettings);
                Assert(engine.CurrentSettings.HeaderBrandClickAction == HeaderBrandClickAction.OpenSettings,
                    "Changing brand click dropdown must immediately update engine settings.");
                Assert(settingsStore.Load().HeaderBrandClickAction == HeaderBrandClickAction.OpenSettings,
                    "Changing brand click dropdown must immediately persist to SettingsStore.");
                form.ExecuteHeaderBrandClick();
                Assert(form.ActiveTabIndex == 4, $"Expected Settings tab (4), got {form.ActiveTabIndex}.");

                form.SetBrandClickActionForTest(HeaderBrandClickAction.OpenRecentScans);
                form.ExecuteHeaderBrandClick();
                Assert(form.ActiveTabIndex == 0, $"Expected Recent Scans tab (0), got {form.ActiveTabIndex}.");

                form.SetBrandClickActionForTest(HeaderBrandClickAction.ToggleMonitoring);
                Assert(!engine.IsPaused, "Engine should start unpaused.");
                form.ExecuteHeaderBrandClick();
                Assert(engine.IsPaused, "Brand click ToggleMonitoring should pause engine.");

                form.HandlePausedSubtitleClick();
                Assert(!engine.IsPaused, "Clicking paused subtitle should resume monitoring.");

                // Exercise OnboardingDialog across all 4 steps (Dark)
                using (var onboardingDark = new OnboardingDialog(engine, logger, icons.AppIcon))
                {
                    for (int step = 0; step < 4; step++)
                    {
                        onboardingDark.ShowStep(step);
                        onboardingDark.PerformLayout();
                    }
                }

                // Exercise TutorialSession across all 7 spotlight steps and ensure closing/skipping preserves form
                using (var tutorial = form.CreateTutorialSession())
                {
                    tutorial.Start();
                    for (int s = 0; s < 6; s++)
                    {
                        tutorial.NextStep();
                    }
                }

                Assert(!form.IsDisposed, "Skipping or finishing the UI tour must keep the main Dashboard window open.");

                // Switch to Light theme and revisit Dashboard + Onboarding
                settings.ThemeMode = AppThemeMode.Light;
                engine.ApplySettings(settings);
                using var formLight = new DashboardForm(engine, paths, logger, icons.AppIcon, updateSvc);
                formLight.CreateControl();
                formLight.PerformLayout();
                var lightMetrics = formLight.GetHeaderLayoutMetricsForTest();
                Assert(lightMetrics.HeaderBottom <= lightMetrics.NavTop,
                    $"Light header ({lightMetrics.HeaderBottom}) must not overlap nav tabs ({lightMetrics.NavTop}).");
                Assert(lightMetrics.SubtitleBottom <= lightMetrics.HeaderHeight,
                    $"Light subtitle ({lightMetrics.SubtitleBottom}) must stay within header ({lightMetrics.HeaderHeight}).");
                Assert(lightMetrics.ScanBtnBottom <= lightMetrics.HeaderHeight,
                    $"Light header buttons ({lightMetrics.ScanBtnBottom}) must stay within header ({lightMetrics.HeaderHeight}).");

                for (int tab = 0; tab < 5; tab++)
                {
                    formLight.SelectTab(tab);
                    formLight.PerformLayout();
                }

                using (var onboardingLight = new OnboardingDialog(engine, logger, icons.AppIcon))
                {
                    onboardingLight.ShowStep(1);
                    onboardingLight.PerformLayout();
                }

                // Exercise ManualUploadAssistDialog across all 3 strategy modes in Dark and Light themes
                var sampleRec = new ScanRecord
                {
                    FilePath = Path.Combine(tempDir, "large-installer.exe"),
                    FileName = "large-installer.exe",
                    Sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                    FileSizeBytes = 120L * 1024 * 1024,
                    Verdict = ScanVerdict.Unknown
                };
                foreach (ThemePalette pal in new[] { ThemePalette.Dark, ThemePalette.Light })
                {
                    foreach (ManualUploadStrategy strat in new[]
                    {
                        ManualUploadStrategy.LargeApiUpload,
                        ManualUploadStrategy.ManualBrowserOnlyNoKey,
                        ManualUploadStrategy.ExceedsVirusTotalLimit
                    })
                    {
                        long testSize = strat == ManualUploadStrategy.ExceedsVirusTotalLimit
                            ? 750L * 1024 * 1024
                            : 120L * 1024 * 1024;
                        using var assistDlg = new ManualUploadAssistDialog(sampleRec, testSize, strat, pal, icons.AppIcon);
                        assistDlg.CreateControl();
                        assistDlg.PerformLayout();
                    }
                }
            }
            catch (Exception ex)
            {
                threadEx = ex;
            }
        });

        sta.SetApartmentState(ApartmentState.STA);
        sta.Start();
        sta.Join();

        CleanupDir(tempDir);
        if (threadEx is not null)
        {
            throw new InvalidOperationException("DashboardForm UI smoke test failed.", threadEx);
        }

        return Task.CompletedTask;
    }
}
