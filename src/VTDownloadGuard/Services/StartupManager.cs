using System;
using System.Diagnostics;
using Microsoft.Win32;

namespace VTDownloadGuard.Services;

public static class StartupManager
{
    private const string RunKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string ValueName = "VTDownloadGuard";

    public static bool IsStartupEnabled()
    {
        using RegistryKey? key = Registry.CurrentUser.OpenSubKey(RunKeyPath, writable: false);
        object? value = key?.GetValue(ValueName);
        return value is string s && !string.IsNullOrWhiteSpace(s);
    }

    public static void SetStartupEnabled(bool enabled, string? executablePath = null)
    {
        using RegistryKey? key = Registry.CurrentUser.CreateSubKey(RunKeyPath, writable: true);
        if (key is null)
        {
            return;
        }

        if (!enabled)
        {
            key.DeleteValue(ValueName, throwOnMissingValue: false);
            return;
        }

        string exe = executablePath
            ?? Environment.ProcessPath
            ?? Process.GetCurrentProcess().MainModule?.FileName
            ?? throw new InvalidOperationException("Unable to determine executable path for startup registration.");

        string command = $"\"{exe}\" --minimized";
        key.SetValue(ValueName, command, RegistryValueKind.String);
    }
}
