using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using VTDownloadGuard.Models;

namespace VTDownloadGuard.Services;

public sealed class SettingsStore
{
    private static readonly HashSet<string> InProgressTempExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".crdownload", ".part", ".tmp", ".download", ".opdownload", ".partial", ".!qb", ".!ut"
    };

    private readonly AppPaths _paths;
    private readonly AppLogger _logger;
    private readonly Lock _sync = new();

    public SettingsStore(AppPaths paths, AppLogger logger)
    {
        _paths = paths;
        _logger = logger;
    }

    public AppSettings Load()
    {
        lock (_sync)
        {
            _paths.EnsureDataDirectoryExists();
            if (!File.Exists(_paths.SettingsPath))
            {
                var defaults = AppSettings.CreateDefault();
                AtomicJsonStorage.WriteAtomic(_paths.SettingsPath, defaults, _logger);
                return defaults;
            }

            var loaded = AtomicJsonStorage.ReadOrDefault<AppSettings>(_paths.SettingsPath, _logger);
            if (loaded is null)
            {
                var fallback = AppSettings.CreateDefault();
                AtomicJsonStorage.WriteAtomic(_paths.SettingsPath, fallback, _logger);
                return fallback;
            }

            Sanitize(loaded);
            return loaded;
        }
    }

    public void Save(AppSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        lock (_sync)
        {
            Sanitize(settings);
            AtomicJsonStorage.WriteAtomic(_paths.SettingsPath, settings, _logger);
        }
    }

    public static string GetDecryptedApiKey(AppSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        return DpapiSecretProtector.Unprotect(settings.EncryptedApiKey).Trim();
    }

    public static void SetApiKey(AppSettings settings, string? plainApiKey)
    {
        ArgumentNullException.ThrowIfNull(settings);
        string trimmed = (plainApiKey ?? string.Empty).Trim();
        settings.EncryptedApiKey = string.IsNullOrEmpty(trimmed)
            ? string.Empty
            : DpapiSecretProtector.Protect(trimmed);
    }

    public static string GetDecryptedMetaDefenderApiKey(AppSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        return DpapiSecretProtector.Unprotect(settings.EncryptedMetaDefenderApiKey).Trim();
    }

    public static void SetMetaDefenderApiKey(AppSettings settings, string? plainApiKey)
    {
        ArgumentNullException.ThrowIfNull(settings);
        string trimmed = (plainApiKey ?? string.Empty).Trim();
        settings.EncryptedMetaDefenderApiKey = string.IsNullOrEmpty(trimmed)
            ? string.Empty
            : DpapiSecretProtector.Protect(trimmed);
    }

    public static string GetDecryptedMalwareBazaarApiKey(AppSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        return DpapiSecretProtector.Unprotect(settings.EncryptedMalwareBazaarApiKey).Trim();
    }

    public static void SetMalwareBazaarApiKey(AppSettings settings, string? plainApiKey)
    {
        ArgumentNullException.ThrowIfNull(settings);
        string trimmed = (plainApiKey ?? string.Empty).Trim();
        settings.EncryptedMalwareBazaarApiKey = string.IsNullOrEmpty(trimmed)
            ? string.Empty
            : DpapiSecretProtector.Protect(trimmed);
    }

    public static bool IsTemporaryOrIgnoredName(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath))
        {
            return true;
        }

        string fileName = Path.GetFileName(filePath);
        if (string.IsNullOrWhiteSpace(fileName))
        {
            return true;
        }

        if (fileName.StartsWith("~$", StringComparison.Ordinal))
        {
            return true;
        }

        string ext = Path.GetExtension(fileName);
        return !string.IsNullOrEmpty(ext) && InProgressTempExtensions.Contains(ext);
    }

    public static bool ShouldScanFile(AppSettings settings, string filePath)
    {
        ArgumentNullException.ThrowIfNull(settings);
        if (IsTemporaryOrIgnoredName(filePath))
        {
            return false;
        }

        if (settings.FilterMode == FileFilterMode.AllFiles)
        {
            return true;
        }

        string ext = Path.GetExtension(filePath);
        if (string.IsNullOrEmpty(ext))
        {
            return false;
        }

        return ContainsExtension(settings.UploadExtensions, ext)
            || ContainsExtension(settings.ArchiveExtensions, ext);
    }

    public static bool ShouldUploadFile(AppSettings settings, string filePath, long sizeBytes)
    {
        ArgumentNullException.ThrowIfNull(settings);
        if (sizeBytes <= 0 || IsTemporaryOrIgnoredName(filePath))
        {
            return false;
        }

        long maxBytes = Math.Clamp(settings.MaxUploadSizeMb, 1, 650) * 1024L * 1024L;
        if (sizeBytes > maxBytes)
        {
            return false;
        }

        return settings.UploadPolicy switch
        {
            UploadPolicy.HashLookupOnly => false,
            UploadPolicy.UploadAllWatched => ShouldScanFile(settings, filePath),
            UploadPolicy.ExecutablesAndScriptsOnly => ContainsExtension(settings.UploadExtensions, Path.GetExtension(filePath)),
            _ => false
        };
    }

    public static List<string> NormalizeExtensions(IEnumerable<string>? extensions)
    {
        if (extensions is null)
        {
            return [];
        }

        var result = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (string raw in extensions)
        {
            string trimmed = raw.Trim().ToLowerInvariant();
            if (string.IsNullOrEmpty(trimmed))
            {
                continue;
            }

            if (!trimmed.StartsWith('.'))
            {
                trimmed = "." + trimmed;
            }

            if (trimmed.Length > 1 && seen.Add(trimmed))
            {
                result.Add(trimmed);
            }
        }

        return result;
    }

    private static bool ContainsExtension(IEnumerable<string>? extensions, string ext)
    {
        if (extensions is null || string.IsNullOrEmpty(ext))
        {
            return false;
        }

        foreach (string item in extensions)
        {
            if (string.Equals(item, ext, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    public static void EnsureDefaultDownloadsIncluded(AppSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        settings.WatchedDirectories ??= [];

        var existing = new HashSet<string>(
            settings.WatchedDirectories.Select(d => d.Path.Trim()),
            StringComparer.OrdinalIgnoreCase);

        List<string> defaults = AppSettings.GetDefaultDownloadsDirectories();
        int insertIndex = 0;
        foreach (string dlPath in defaults)
        {
            if (existing.Add(dlPath))
            {
                settings.WatchedDirectories.Insert(insertIndex++, new WatchedDirectory
                {
                    Path = dlPath,
                    IncludeSubdirectories = true,
                    Enabled = true
                });
            }
        }
    }

    private static void Sanitize(AppSettings settings)
    {
        settings.EncryptedApiKey ??= string.Empty;
        settings.EncryptedMetaDefenderApiKey ??= string.Empty;
        settings.EncryptedMalwareBazaarApiKey ??= string.Empty;
        settings.WatchedDirectories ??= [];
        settings.WatchedDirectories = settings.WatchedDirectories
            .Where(d => d is not null && !string.IsNullOrWhiteSpace(d.Path))
            .GroupBy(d => d.Path.Trim(), StringComparer.OrdinalIgnoreCase)
            .Select(g =>
            {
                var first = g.First();
                return new WatchedDirectory
                {
                    Path = first.Path.Trim(),
                    IncludeSubdirectories = first.IncludeSubdirectories,
                    Enabled = first.Enabled
                };
            })
            .ToList();

        if (settings.WatchedDirectories.Count == 0)
        {
            EnsureDefaultDownloadsIncluded(settings);
        }

        settings.UploadExtensions = settings.UploadExtensions is null
            ? [.. AppSettings.DefaultUploadExtensions]
            : NormalizeExtensions(settings.UploadExtensions);

        settings.ArchiveExtensions = settings.ArchiveExtensions is null
            ? [.. AppSettings.DefaultArchiveExtensions]
            : NormalizeExtensions(settings.ArchiveExtensions);

        settings.MaliciousThreshold = Math.Clamp(settings.MaliciousThreshold, 1, 20);
        settings.MaxRequestsPerMinute = Math.Clamp(settings.MaxRequestsPerMinute, 1, 1000);
        settings.MaxUploadSizeMb = Math.Clamp(settings.MaxUploadSizeMb, 1, 650);
        settings.MaxHashSizeMb = Math.Clamp(settings.MaxHashSizeMb, 0, 50000);

        if (!Enum.IsDefined(settings.ThemeMode))
        {
            settings.ThemeMode = AppThemeMode.System;
        }

        if (!Enum.IsDefined(settings.HeaderBrandClickAction))
        {
            settings.HeaderBrandClickAction = HeaderBrandClickAction.OpenRecentScans;
        }

        if (string.IsNullOrWhiteSpace(settings.UpdateRepository))
        {
            settings.UpdateRepository = "sonnenfell/VTDownloadGuard";
        }
        else
        {
            settings.UpdateRepository = settings.UpdateRepository.Trim();
        }
    }
}
