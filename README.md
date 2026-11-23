# VTDownloadGuard

VTDownloadGuard is a lightweight Windows system tray program that watches your download and game folders and checks new files against VirusTotal and optional secondary hash databases.

It runs quietly in the background with almost zero idle CPU usage, sorts pending checks so higher-risk files are scanned first, and notifies you if a file crosses your detection threshold.

## Key Features

- **Automatic Folder Monitoring**: Watches your configured folders (including your Windows Downloads folder and optional game folders) and waits until browsers or installers finish writing before computing SHA-256 hashes.
- **Risk-Based Scan Priority**: Quickly classifies each file locally using offline Authenticode signature checks, file extensions, naming patterns, and folder context:
  1. **Very High Risk** (`Critical`): Modified or invalid digital signatures, double extensions (such as `invoice.pdf.exe`), suspicious unsigned tools, or unsigned scripts/shortcuts in Downloads.
  2. **High Risk** (`High`): Unsigned executables outside game folders or disk images in Downloads.
  3. **Medium Risk** (`Medium`): Archives (`.zip`, `.7z`, `.rar`) and unsigned game binaries.
  4. **Low Risk** (`Low`): Signed files from smaller publishers or known game engine and redistributable DLLs inside game directories.
  5. **Likely Safe** (`Trusted`): Files officially signed by major trusted publishers (Microsoft, Valve, NVIDIA, AMD, Intel, Epic Games, Unity, Google, and others) or common game asset files.
  Higher-risk files jump ahead in the scan queue so potential threats are checked first.
- **Secondary Hash Lookup Services**: Screens SHA-256 hashes against additional trusted databases before spending VirusTotal quota:
  - **CIRCL Hashlookup** (enabled by default, no API key required): Checks the free NIST NSRL known-software database and malicious hash feeds.
  - **OPSWAT MetaDefender Cloud** (optional, disabled by default, requires free API key).
  - **MalwareBazaar by abuse.ch** (optional, disabled by default, requires free Auth-Key).
  - Includes an option in Settings to run secondary lookups only on lower-risk files (`Low Risk` and `Likely Safe`).
- **Queued Tab**: Displays active, queued, and stabilizing files in exact priority order, with controls to move a file to the top, remove items, or clear the queue.
- **API Tab**: Tracks your local minute rate-limit window, live hourly/daily/monthly quotas pulled directly from the VirusTotal user quota endpoint (`/api/v3/users/{apikey}`), cache hit savings, and per-service secondary lookup counts.
- **Detection Sensitivity Slider**: Choose how many antivirus vendors must flag a file before it triggers an unsafe alert (default `2+` vendors recommended), with color-coded feedback and clear guidance on false positives versus missed detections.
- **Guided First-Run Setup and Optional UI Tour**: Automatically discovers and initializes your Windows Downloads directories, suggests detected game folders, helps connect your API keys, and offers an optional spotlight UI tour highlighting key controls (reopenable anytime from the header bar or Settings).
- **VirusTotal-Inspired Interface**: Clean dashboard with Dark, Light, and Follow Windows themes, verdict and risk pills, live search/filtering, and a matching system tray icon (`Green` = safe, `Blue animated` = checking, `Red` = unsafe file detected, `Gray` = setup needed).
- **Local Privacy and Security**: All API keys are encrypted locally with Windows DPAPI (`CryptProtectData` scoped to your Windows user account). Files are always checked by SHA-256 hash first; only unknown executables/scripts within your configured size limit (32 MB by default) are uploaded when auto-upload is enabled.

## Installation on Windows

### Option 1: Windows Installer (Recommended)

Use this option on any 64-bit Windows 10 or Windows 11 PC. No extra runtime or SDK is required.

1. Go to the **Releases** page on GitHub and download `VTDownloadGuard-1.2.1-win-x64-Setup.exe`.
2. Double-click the installer and follow the setup steps.
3. Keep **Start automatically minimized to the system tray when Windows starts** checked if you want background protection on every login.
4. Click **Finish** to launch VTDownloadGuard.

### Option 2: Lightweight Portable Zip (Requires .NET 10)

Use this option if you already have the **.NET 10 Desktop Runtime (x64)** installed and want a tiny portable folder (under 1 MB).

1. Download `VTDownloadGuard-1.2.1-win-x64-Portable-FrameworkDependent.zip` from the **Releases** page.
2. Extract the zip to a folder of your choice (for example, `C:\Program Files\VTDownloadGuard` or `%LocalAppData%\VTDownloadGuard`).
3. Run `VTDownloadGuard.exe --open` to open the dashboard on first launch.

## Updating VTDownloadGuard

VTDownloadGuard checks `https://github.com/sonnenfell/VTDownloadGuard/releases/latest` for new versions without overwriting your user data (`settings.json`, `history.json`, and `hash-cache.json` remain in `%AppData%\VTDownloadGuard\` and are backed up before every update).

- **Manual checks (default)**: Click **Check for Updates** in **Settings -> Updates** or right-click the system tray icon and choose **Check for Updates...**.
- **Automatic updates (optional)**: Enable **Enable automatic update checks and installation** in **Settings -> Updates**.
- **Critical-only automatic updates (optional)**: When automatic updates are enabled, you can check **Only automatically install updates marked as critical**. Updates are treated as critical when the first line of the GitHub release notes contains `[CRITICAL UPDATE]`.

## Quick Start

1. On first launch, follow the built-in **Setup Wizard** (your Windows Downloads folder is added automatically, common game folders are offered if detected, and you can paste and test your free API key from `https://www.virustotal.com/gui/my-apikey`).
2. At the end of setup, choose **Finish and Start UI Tour** for a quick interactive walkthrough of the interface, or **Finish Without Tour** to start monitoring immediately.
3. Anytime later, click the **VTDownloadGuard** icon in the system tray (or open **VTDownloadGuard** from the Start Menu) to view recent scans, inspect the prioritized queue, check live VirusTotal quotas in the **API** tab, adjust the detection threshold slider in **Settings**, or rerun the setup wizard or UI tour.

## Data Storage Locations

- **Settings, History, Cache, and Logs**: `%AppData%\VTDownloadGuard\` (`settings.json`, `history.json`, `hash-cache.json`, `app.log`)
- **Auto-Start Registry Value** (when enabled): `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\VTDownloadGuard`

## Building from Source

Requirements: Windows 10/11 (x64) and **.NET 10 SDK** (plus **Inno Setup 6** if building the setup executable).

```powershell
# Run build and automated test suite
dotnet build VTDownloadGuard.sln -c Release
dotnet run --project tests/VTDownloadGuard.Tests/VTDownloadGuard.Tests.csproj -c Release

# Build both Windows release packages (Setup.exe and Portable .zip)
.\scripts\build-release.ps1
```

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
