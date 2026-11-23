using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;

namespace VTDownloadGuard.Models;

public enum UploadPolicy
{
    ExecutablesAndScriptsOnly = 0,
    HashLookupOnly = 1,
    UploadAllWatched = 2
}

public enum FileFilterMode
{
    ExecutablesScriptsAndArchives = 0,
    AllFiles = 1
}

public enum ScanVerdict
{
    Clean = 0,
    LowRisk = 1,
    Unsafe = 2,
    Unknown = 3,
    Skipped = 4,
    Error = 5
}

public enum TrayStatus
{
    NeedsSetup = 0,
    Safe = 1,
    Scanning = 2,
    Unsafe = 3
}

/// <summary>
/// Ordered by scan priority: lower numeric value means scanned first.
/// </summary>
public enum FileRiskCategory
{
    Critical = 0,
    High = 1,
    Medium = 2,
    Low = 3,
    Trusted = 4
}

public enum AppThemeMode
{
    System = 0,
    Dark = 1,
    Light = 2
}

public enum UpdateInstallMode
{
    InnoInstaller = 0,
    PortableFrameworkDependent = 1,
    StandalonePortable = 2
}

public sealed class UpdateCheckResult
{
    public bool Success { get; init; }
    public string ErrorMessage { get; init; } = string.Empty;
    public bool UpdateAvailable { get; init; }
    public bool IsCritical { get; init; }
    public Version CurrentVersion { get; init; } = new(1, 0, 0);
    public Version? LatestVersion { get; init; }
    public string TagName { get; init; } = string.Empty;
    public string ReleaseName { get; init; } = string.Empty;
    public string ReleaseNotes { get; init; } = string.Empty;
    public string ReleaseHtmlUrl { get; init; } = string.Empty;
    public DateTimeOffset? PublishedAtUtc { get; init; }
    public string AssetName { get; init; } = string.Empty;
    public string DownloadUrl { get; init; } = string.Empty;
    public long AssetSizeBytes { get; init; }
    public string ExpectedSha256 { get; init; } = string.Empty;
    public DateTimeOffset CheckedAtUtc { get; init; } = DateTimeOffset.UtcNow;
}

public sealed class FileRiskAssessment
{
    public FileRiskCategory Category { get; init; } = FileRiskCategory.Medium;
    public int Score { get; init; } = 50;
    public string Reason { get; init; } = string.Empty;
    public bool IsDigitallySigned { get; init; }
    public bool SignatureTampered { get; init; }
    public string SignerName { get; init; } = string.Empty;
}

public sealed class QueuedScanItem
{
    public string FilePath { get; set; } = string.Empty;
    public string FileName { get; set; } = string.Empty;
    public long FileSizeBytes { get; set; }
    public FileRiskCategory RiskCategory { get; set; } = FileRiskCategory.Medium;
    public int RiskScore { get; set; } = 50;
    public string RiskReason { get; set; } = string.Empty;
    public string SignerName { get; set; } = string.Empty;
    public DateTimeOffset EnqueuedAtUtc { get; set; } = DateTimeOffset.UtcNow;
    public string State { get; set; } = "Queued";
    public string Stage { get; set; } = string.Empty;
    public bool ManualBoost { get; set; }
    public long BoostOrder { get; set; }
    public bool ForceUpload { get; set; }
    public bool ForceVirusTotal { get; set; }

    public QueuedScanItem Clone() => new()
    {
        FilePath = FilePath,
        FileName = FileName,
        FileSizeBytes = FileSizeBytes,
        RiskCategory = RiskCategory,
        RiskScore = RiskScore,
        RiskReason = RiskReason,
        SignerName = SignerName,
        EnqueuedAtUtc = EnqueuedAtUtc,
        State = State,
        Stage = Stage,
        ManualBoost = ManualBoost,
        BoostOrder = BoostOrder,
        ForceUpload = ForceUpload,
        ForceVirusTotal = ForceVirusTotal
    };
}

public sealed record VtQuotaBucket(long Used, long Allowed);

public sealed class VtUserQuotaInfo
{
    public bool Success { get; init; }
    public string ErrorMessage { get; init; } = string.Empty;
    public string UserId { get; init; } = string.Empty;
    public VtQuotaBucket Hourly { get; init; } = new(0, 0);
    public VtQuotaBucket Daily { get; init; } = new(0, 0);
    public VtQuotaBucket Monthly { get; init; } = new(0, 0);
    public DateTimeOffset FetchedAtUtc { get; init; } = DateTimeOffset.UtcNow;
    public int ApiCallsMade { get; init; }
}

public sealed class SecondaryServiceStats
{
    public string Name { get; init; } = string.Empty;
    public bool Enabled { get; init; }
    public bool RequiresApiKey { get; init; }
    public bool HasApiKey { get; init; }
    public int RequestsToday { get; init; }
    public int HitsToday { get; init; }
    public string LastStatus { get; init; } = string.Empty;
}

public sealed record DailyUsageSnapshot(
    int DailyVtRequests,
    int DailyCacheHits,
    int DailySecondarySavedCalls,
    int DailyCirclRequests,
    int DailyMetaDefenderRequests,
    int DailyMalwareBazaarRequests,
    int DailyCirclHits,
    int DailyMetaDefenderHits,
    int DailyMalwareBazaarHits,
    DateOnly QuotaDateUtc);

public sealed class WatchedDirectory
{
    public string Path { get; set; } = string.Empty;
    public bool IncludeSubdirectories { get; set; } = true;
    public bool Enabled { get; set; } = true;

    public WatchedDirectory Clone() => new()
    {
        Path = Path,
        IncludeSubdirectories = IncludeSubdirectories,
        Enabled = Enabled
    };
}

public sealed class AppSettings
{
    private static readonly Guid FolderIdDownloads = new("374DE290-123F-4565-9164-39C4925E467B");

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern int SHGetKnownFolderPath(
        [MarshalAs(UnmanagedType.LPStruct)] Guid rfid,
        uint dwFlags,
        IntPtr hToken,
        out IntPtr ppszPath);

    public static readonly string[] DefaultUploadExtensions =
    [
        ".exe", ".dll", ".msi", ".msp", ".msu", ".bat", ".cmd", ".ps1",
        ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".scr", ".com",
        ".pif", ".cpl", ".sys", ".ocx", ".jar", ".hta", ".lnk", ".appx",
        ".msix", ".apk"
    ];

    public static readonly string[] DefaultArchiveExtensions =
    [
        ".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2", ".xz",
        ".cab", ".iso", ".img", ".vhd", ".vhdx", ".dmg"
    ];

    public string EncryptedApiKey { get; set; } = string.Empty;
    public List<WatchedDirectory> WatchedDirectories { get; set; } = [];
    public UploadPolicy UploadPolicy { get; set; } = UploadPolicy.ExecutablesAndScriptsOnly;
    public FileFilterMode FilterMode { get; set; } = FileFilterMode.ExecutablesScriptsAndArchives;
    public List<string> UploadExtensions { get; set; } = [.. DefaultUploadExtensions];
    public List<string> ArchiveExtensions { get; set; } = [.. DefaultArchiveExtensions];
    public int MaliciousThreshold { get; set; } = 2;
    public int MaxRequestsPerMinute { get; set; } = 4;
    public int MaxUploadSizeMb { get; set; } = 32;
    public int MaxHashSizeMb { get; set; } = 2048;
    public bool StartWithWindows { get; set; } = true;

    public bool SecondaryLookupsLowerRiskOnly { get; set; } = false;
    public bool EnableCirclHashlookup { get; set; } = true;
    public bool EnableMetaDefender { get; set; } = false;
    public string EncryptedMetaDefenderApiKey { get; set; } = string.Empty;
    public bool EnableMalwareBazaar { get; set; } = false;
    public string EncryptedMalwareBazaarApiKey { get; set; } = string.Empty;
    public AppThemeMode ThemeMode { get; set; } = AppThemeMode.System;
    public bool OnboardingCompleted { get; set; } = false;
    public bool AutoUpdateEnabled { get; set; } = false;
    public bool AutoUpdateCriticalOnly { get; set; } = false;
    public string UpdateRepository { get; set; } = "sonnenfell/VTDownloadGuard";

    public static string GetDefaultDownloadsDirectory()
    {
        IntPtr pathPtr = IntPtr.Zero;
        try
        {
            if (SHGetKnownFolderPath(FolderIdDownloads, 0, IntPtr.Zero, out pathPtr) == 0 && pathPtr != IntPtr.Zero)
            {
                string? knownPath = Marshal.PtrToStringUni(pathPtr);
                if (!string.IsNullOrWhiteSpace(knownPath))
                {
                    return knownPath;
                }
            }
        }
        catch
        {
            // Fall back to UserProfile\Downloads on unsupported platforms.
        }
        finally
        {
            if (pathPtr != IntPtr.Zero)
            {
                Marshal.FreeCoTaskMem(pathPtr);
            }
        }

        return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
    }

    public static List<string> GetDefaultDownloadsDirectories()
    {
        var list = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void TryAdd(string? path, bool requireExists)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return;
            }

            try
            {
                string full = Path.GetFullPath(path.Trim());
                if ((!requireExists || Directory.Exists(full)) && seen.Add(full))
                {
                    list.Add(full);
                }
            }
            catch
            {
                // Ignore invalid path entries.
            }
        }

        TryAdd(GetDefaultDownloadsDirectory(), requireExists: false);

        string userProfileDownloads = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            "Downloads");
        TryAdd(userProfileDownloads, requireExists: true);

        try
        {
            foreach (DriveInfo drive in DriveInfo.GetDrives())
            {
                if (drive.IsReady && drive.DriveType == DriveType.Fixed)
                {
                    TryAdd(Path.Combine(drive.RootDirectory.FullName, "Downloads"), requireExists: true);
                }
            }
        }
        catch
        {
            // Ignore drive enumeration failures.
        }

        return list;
    }

    public static List<string> GetSuggestedGameDirectories()
    {
        string[] candidates =
        [
            @"C:\Games",
            @"D:\Games",
            @"E:\Games",
            @"C:\Program Files (x86)\Steam\steamapps\common",
            @"D:\SteamLibrary\steamapps\common",
            @"E:\SteamLibrary\steamapps\common",
            @"C:\Program Files\Epic Games",
            @"D:\Epic Games",
            @"C:\GOG Games",
            @"D:\GOG Games",
            @"C:\XboxGames",
            @"D:\XboxGames"
        ];

        var list = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (string candidate in candidates)
        {
            try
            {
                if (Directory.Exists(candidate) && seen.Add(candidate))
                {
                    list.Add(candidate);
                }
            }
            catch
            {
                // Ignore inaccessible drive or directory.
            }
        }

        return list;
    }

    public static AppSettings CreateDefault()
    {
        var dirs = new List<WatchedDirectory>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (string dlPath in GetDefaultDownloadsDirectories())
        {
            if (seen.Add(dlPath))
            {
                dirs.Add(new WatchedDirectory { Path = dlPath, IncludeSubdirectories = true, Enabled = true });
            }
        }

        foreach (string gamePath in new[] { @"D:\Games", @"C:\Games" })
        {
            if (Directory.Exists(gamePath) && seen.Add(gamePath))
            {
                dirs.Add(new WatchedDirectory { Path = gamePath, IncludeSubdirectories = true, Enabled = true });
            }
        }

        return new AppSettings
        {
            WatchedDirectories = dirs,
            UploadPolicy = UploadPolicy.ExecutablesAndScriptsOnly,
            FilterMode = FileFilterMode.ExecutablesScriptsAndArchives,
            UploadExtensions = [.. DefaultUploadExtensions],
            ArchiveExtensions = [.. DefaultArchiveExtensions],
            MaliciousThreshold = 2,
            MaxRequestsPerMinute = 4,
            MaxUploadSizeMb = 32,
            MaxHashSizeMb = 2048,
            StartWithWindows = true,
            SecondaryLookupsLowerRiskOnly = false,
            EnableCirclHashlookup = true,
            EnableMetaDefender = false,
            EncryptedMetaDefenderApiKey = string.Empty,
            EnableMalwareBazaar = false,
            EncryptedMalwareBazaarApiKey = string.Empty,
            ThemeMode = AppThemeMode.System,
            OnboardingCompleted = false,
            AutoUpdateEnabled = false,
            AutoUpdateCriticalOnly = false,
            UpdateRepository = "sonnenfell/VTDownloadGuard"
        };
    }

    public AppSettings Clone()
    {
        return new AppSettings
        {
            EncryptedApiKey = EncryptedApiKey,
            WatchedDirectories = WatchedDirectories.ConvertAll(d => d.Clone()),
            UploadPolicy = UploadPolicy,
            FilterMode = FilterMode,
            UploadExtensions = [.. UploadExtensions],
            ArchiveExtensions = [.. ArchiveExtensions],
            MaliciousThreshold = MaliciousThreshold,
            MaxRequestsPerMinute = MaxRequestsPerMinute,
            MaxUploadSizeMb = MaxUploadSizeMb,
            MaxHashSizeMb = MaxHashSizeMb,
            StartWithWindows = StartWithWindows,
            SecondaryLookupsLowerRiskOnly = SecondaryLookupsLowerRiskOnly,
            EnableCirclHashlookup = EnableCirclHashlookup,
            EnableMetaDefender = EnableMetaDefender,
            EncryptedMetaDefenderApiKey = EncryptedMetaDefenderApiKey,
            EnableMalwareBazaar = EnableMalwareBazaar,
            EncryptedMalwareBazaarApiKey = EncryptedMalwareBazaarApiKey,
            ThemeMode = ThemeMode,
            OnboardingCompleted = OnboardingCompleted,
            AutoUpdateEnabled = AutoUpdateEnabled,
            AutoUpdateCriticalOnly = AutoUpdateCriticalOnly,
            UpdateRepository = UpdateRepository
        };
    }
}

public sealed class ScanRecord
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public DateTimeOffset ScannedAtUtc { get; set; } = DateTimeOffset.UtcNow;
    public string FilePath { get; set; } = string.Empty;
    public string FileName { get; set; } = string.Empty;
    public string Sha256 { get; set; } = string.Empty;
    public long FileSizeBytes { get; set; }
    public ScanVerdict Verdict { get; set; }
    public int MaliciousCount { get; set; }
    public int SuspiciousCount { get; set; }
    public int TotalEngines { get; set; }
    public List<string> DetectionNames { get; set; } = [];
    public string Summary { get; set; } = string.Empty;
    public string VirusTotalUrl { get; set; } = string.Empty;
    public bool FromCache { get; set; }
    public bool Uploaded { get; set; }
    public bool Acknowledged { get; set; }

    public FileRiskCategory RiskCategory { get; set; } = FileRiskCategory.Medium;
    public string RiskReason { get; set; } = string.Empty;
    public string SignerName { get; set; } = string.Empty;
    public string SourceService { get; set; } = "VirusTotal";
    public string ReportUrl { get; set; } = string.Empty;

    public string EffectiveReportUrl =>
        !string.IsNullOrWhiteSpace(ReportUrl) ? ReportUrl : VirusTotalUrl;
}

public sealed class HashCacheEntry
{
    public string Sha256 { get; set; } = string.Empty;
    public DateTimeOffset CachedAtUtc { get; set; }
    public int MaliciousCount { get; set; }
    public int SuspiciousCount { get; set; }
    public int TotalEngines { get; set; }
    public List<string> DetectionNames { get; set; } = [];
    public bool WasFoundOnVirusTotal { get; set; }
    public string SourceService { get; set; } = "VirusTotal";
    public string SummaryNote { get; set; } = string.Empty;
    public string ReportUrl { get; set; } = string.Empty;
}

public sealed class HashCacheFileData
{
    public DateOnly DailyQuotaDateUtc { get; set; } = DateOnly.FromDateTime(DateTime.UtcNow);
    public int DailyApiRequests { get; set; }
    public int DailyCacheHits { get; set; }
    public int DailySecondarySavedCalls { get; set; }
    public int DailyCirclRequests { get; set; }
    public int DailyMetaDefenderRequests { get; set; }
    public int DailyMalwareBazaarRequests { get; set; }
    public int DailyCirclHits { get; set; }
    public int DailyMetaDefenderHits { get; set; }
    public int DailyMalwareBazaarHits { get; set; }
    public List<HashCacheEntry> Entries { get; set; } = [];
}
