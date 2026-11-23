using System;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace VTDownloadGuard.Services;

internal static class AtomicJsonStorage
{
    public static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter() }
    };

    public static T? ReadOrDefault<T>(string path, AppLogger? logger = null)
    {
        try
        {
            if (!File.Exists(path))
            {
                return default;
            }

            string json = File.ReadAllText(path, Encoding.UTF8);
            if (string.IsNullOrWhiteSpace(json))
            {
                return default;
            }

            return JsonSerializer.Deserialize<T>(json, JsonOptions);
        }
        catch (Exception ex)
        {
            logger?.Error($"Failed to read JSON file '{path}'", ex);
            return default;
        }
    }

    public static void WriteAtomic<T>(string path, T value, AppLogger? logger = null)
    {
        string? dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }

        string tempPath = $"{path}.{Guid.NewGuid():N}.tmp";
        try
        {
            string json = JsonSerializer.Serialize(value, JsonOptions);
            File.WriteAllText(tempPath, json, Encoding.UTF8);
            File.Move(tempPath, path, overwrite: true);
        }
        catch (Exception ex)
        {
            logger?.Error($"Failed to write JSON file '{path}'", ex);
            throw;
        }
        finally
        {
            try
            {
                if (File.Exists(tempPath))
                {
                    File.Delete(tempPath);
                }
            }
            catch
            {
                // Ignore temp cleanup failure.
            }
        }
    }
}
