using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using VTDownloadGuard.Models;

namespace VTDownloadGuard.Services;

/// <summary>
/// Fast local heuristic classifier that assigns a risk category and score
/// based on offline Authenticode verification, file extension, naming patterns,
/// and folder context.
/// </summary>
public sealed class FileRiskClassifier
{
    private const long MaxSignatureCheckBytes = 150L * 1024 * 1024;

    private static readonly Guid WinTrustActionGenericVerifyV2 = new("00aac56b-cd44-11d0-8cc2-00c04fc295ee");

    private const uint WtdUiNone = 2;
    private const uint WtdRevokeNone = 0;
    private const uint WtdChoiceFile = 1;
    private const uint WtdChoiceCatalog = 2;
    private const uint WtdStateActionVerify = 1;
    private const uint WtdStateActionClose = 2;
    private const uint WtdRevocationCheckNone = 0x00000010;
    private const uint WtdCacheOnlyUrlRetrieval = 0x00001000;

    private const int TrustENoSignature = unchecked((int)0x800B0100);
    private const int TrustEBadDigest = unchecked((int)0x80096010);
    private const int TrustEExplicitDistrust = unchecked((int)0x800B0111);

    private const uint CertNameAttrType = 3;
    private const uint CertNameSimpleDisplayType = 4;

    private static readonly HashSet<string> SignableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".msi", ".msp", ".msu", ".sys", ".ocx", ".cab",
        ".ps1", ".appx", ".msix", ".scr", ".cpl"
    };

    private static readonly HashSet<string> HighRiskScriptAndLauncherExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".ps1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf",
        ".wsh", ".hta", ".scr", ".pif", ".com", ".lnk", ".cpl"
    };

    private static readonly HashSet<string> ExecutableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".msi", ".msp", ".msu", ".sys", ".ocx", ".jar", ".appx", ".msix", ".apk"
    };

    private static readonly HashSet<string> DiskImageExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".iso", ".img", ".vhd", ".vhdx", ".dmg"
    };

    private static readonly HashSet<string> ArchiveExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".cab"
    };

    private static readonly HashSet<string> MasqueradedInnerExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".txt", ".rtf", ".csv", ".jpg", ".jpeg", ".png", ".gif", ".bmp",
        ".mp3", ".mp4", ".avi", ".mkv", ".wav", ".zip", ".rar", ".7z"
    };

    private static readonly HashSet<string> CommonAssetExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".png", ".jpg", ".jpeg", ".webp", ".dds", ".tga", ".bmp", ".gif",
        ".wav", ".ogg", ".mp3", ".mp4", ".bik", ".bk2", ".avi", ".mkv",
        ".pak", ".uasset", ".umap", ".assets", ".unity3d", ".txt", ".json",
        ".xml", ".cfg", ".ini", ".sav", ".log", ".dat", ".bin", ".pdb"
    };

    private static readonly string[] SuspiciousKeywords =
    [
        "crack", "keygen", "activator", "patcher", "kms", "cheat",
        "trainer", "bypass", "loader", "inject", "stealer"
    ];

    private static readonly string[] TrustedPublishers =
    [
        "Microsoft", "Valve", "NVIDIA", "Advanced Micro Devices", "AMD",
        "Intel", "Epic Games", "Unity Technologies", "Electronic Arts",
        "Ubisoft", "CD PROJEKT", "Blizzard Entertainment", "Riot Games",
        "GOG", "Google", "Mozilla", "Adobe", "Oracle", "JetBrains",
        "GitHub", "Discord", "Igor Pavlov", "Rockstar Games", "Take-Two",
        "Capcom", "Bandai Namco", "Square Enix", "Activision", "Bethesda",
        "ZeniMax", "Larian"
    ];

    private static readonly string[] GameFolderMarkers =
    [
        "\\games\\", "\\steamlibrary\\", "\\steamapps\\", "\\epic games\\",
        "\\gog galaxy\\", "\\xboxgames\\", "\\_commonredist\\", "\\redist\\",
        "\\engine\\binaries\\thirdparty\\"
    ];

    private static readonly string[] KnownGameRuntimePrefixes =
    [
        "unityplayer.dll", "unitycrashhandler", "gameassembly.dll", "mono-2.0",
        "ue4prereq", "unrealcef", "steam_api", "eossdk", "d3dcompiler",
        "dxcompiler", "vcruntime140", "msvcp140", "nvngx_dlss", "amd_ags",
        "fmod", "bink2", "physx", "openal32", "sdl2", "xinput", "dstorage",
        "oo2core", "crashreportclient", "easyanticheat", "battleye",
        "vcredist", "dxsetup"
    ];

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustFileInfo
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustCatalogInfo
    {
        public uint cbStruct;
        public uint dwCatalogVersion;
        public IntPtr pcwszCatalogFilePath;
        public IntPtr pcwszMemberTag;
        public IntPtr pcwszMemberFilePath;
        public IntPtr hMemberFile;
        public IntPtr pbCalculatedFileHash;
        public uint cbCalculatedFileHash;
        public IntPtr pcCatalogContext;
        public IntPtr hCatAdmin;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustData
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pInfoStruct;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CatalogInfo
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string wszCatalogFile;
    }

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false)]
    private static extern int WinVerifyTrust(
        IntPtr hwnd,
        [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID,
        ref WinTrustData pWVTData);

    [DllImport("wintrust.dll", SetLastError = false)]
    private static extern IntPtr WTHelperProvDataFromStateData(IntPtr hStateData);

    [DllImport("wintrust.dll", SetLastError = false)]
    private static extern IntPtr WTHelperGetProvSignerFromChain(
        IntPtr pProvData,
        uint idxSigner,
        [MarshalAs(UnmanagedType.Bool)] bool fCounterSigner,
        uint idxCounterSigner);

    [DllImport("wintrust.dll", SetLastError = false)]
    private static extern IntPtr WTHelperGetProvCertFromChain(
        IntPtr pSgnr,
        uint idxCert);

    [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminAcquireContext2(
        out IntPtr phCatAdmin,
        IntPtr pgSubsystem,
        string? pwszHashAlgorithm,
        IntPtr pStrongHashPolicy,
        uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle2(
        IntPtr hCatAdmin,
        IntPtr hFile,
        ref uint pcbHash,
        [Out] byte[]? pbHash,
        uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(
        IntPtr hCatAdmin,
        byte[] pbHash,
        uint cbHash,
        uint dwFlags,
        ref IntPtr phPrevCatInfo);

    [DllImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminReleaseCatalogContext(
        IntPtr hCatAdmin,
        IntPtr hCatInfo,
        uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATCatalogInfoFromContext(
        IntPtr hCatInfo,
        ref CatalogInfo psCatInfo,
        uint dwFlags);

    [DllImport("crypt32.dll", CharSet = CharSet.Unicode)]
    private static extern uint CertGetNameStringW(
        IntPtr pCertContext,
        uint dwType,
        uint dwFlags,
        IntPtr pvTypePara,
        [Out] StringBuilder? pszNameString,
        uint cchNameString);

    public static string GetCategoryLabel(FileRiskCategory category) => category switch
    {
        FileRiskCategory.Critical => "Very High Risk",
        FileRiskCategory.High => "High Risk",
        FileRiskCategory.Medium => "Medium Risk",
        FileRiskCategory.Low => "Low Risk",
        FileRiskCategory.Trusted => "Likely Safe",
        _ => category.ToString()
    };

    public FileRiskAssessment Classify(string filePath, long? knownFileSizeBytes = null)
    {
        if (string.IsNullOrWhiteSpace(filePath))
        {
            return new FileRiskAssessment
            {
                Category = FileRiskCategory.Medium,
                Score = 45,
                Reason = "Standard watched file"
            };
        }

        string fileName = Path.GetFileName(filePath);
        string ext = Path.GetExtension(fileName);
        string lowerName = fileName.ToLowerInvariant();
        string lowerPath = filePath.ToLowerInvariant();

        bool isInDownloadsOrTemp = lowerPath.Contains("\\downloads\\", StringComparison.Ordinal)
            || lowerPath.Contains("\\desktop\\", StringComparison.Ordinal)
            || lowerPath.Contains("\\temp\\", StringComparison.Ordinal)
            || lowerPath.EndsWith("\\downloads", StringComparison.Ordinal);

        bool isInGameFolder = false;
        foreach (string marker in GameFolderMarkers)
        {
            if (lowerPath.Contains(marker, StringComparison.Ordinal))
            {
                isInGameFolder = true;
                break;
            }
        }

        bool isSigned = false;
        bool signatureTampered = false;
        string signerName = string.Empty;

        if (SignableExtensions.Contains(ext) && TryGetExistingFileSize(filePath, knownFileSizeBytes, out long size)
            && size > 0 && size <= MaxSignatureCheckBytes)
        {
            (isSigned, signatureTampered, signerName) = VerifyAuthenticodeOffline(filePath);
        }

        // 1. Tampered or explicitly distrusted signature
        if (signatureTampered)
        {
            return new FileRiskAssessment
            {
                Category = FileRiskCategory.Critical,
                Score = 100,
                Reason = "Modified or invalid digital signature",
                IsDigitallySigned = false,
                SignatureTampered = true,
                SignerName = signerName
            };
        }

        // 2. Double extension masquerading (e.g., invoice.pdf.exe)
        if (HasDoubleExtensionMasquerade(fileName, ext))
        {
            return new FileRiskAssessment
            {
                Category = FileRiskCategory.Critical,
                Score = 96,
                Reason = "Double file extension detected",
                IsDigitallySigned = isSigned,
                SignerName = signerName
            };
        }

        // 3. Suspicious keywords on unsigned files
        if (!isSigned && HasSuspiciousKeyword(lowerName))
        {
            if (ExecutableExtensions.Contains(ext) || HighRiskScriptAndLauncherExtensions.Contains(ext))
            {
                return new FileRiskAssessment
                {
                    Category = FileRiskCategory.Critical,
                    Score = 90,
                    Reason = "Suspicious filename pattern on unsigned executable",
                    IsDigitallySigned = false
                };
            }

            if (ArchiveExtensions.Contains(ext) || DiskImageExtensions.Contains(ext))
            {
                return new FileRiskAssessment
                {
                    Category = FileRiskCategory.High,
                    Score = 75,
                    Reason = "Suspicious filename pattern on archive or disk image",
                    IsDigitallySigned = false
                };
            }
        }

        // 4. High-risk scripts, launchers, and shortcuts when unsigned
        if (!isSigned && HighRiskScriptAndLauncherExtensions.Contains(ext))
        {
            if (isInDownloadsOrTemp || !isInGameFolder)
            {
                return new FileRiskAssessment
                {
                    Category = FileRiskCategory.Critical,
                    Score = 88,
                    Reason = isInDownloadsOrTemp
                        ? "Unsigned script or shortcut in Downloads"
                        : "Unsigned script or shortcut",
                    IsDigitallySigned = false
                };
            }

            return new FileRiskAssessment
            {
                Category = FileRiskCategory.High,
                Score = 72,
                Reason = "Unsigned script in game folder",
                IsDigitallySigned = false
            };
        }

        // 5. Disk image or virtual disk container in Downloads
        if (DiskImageExtensions.Contains(ext) && (isInDownloadsOrTemp || !isInGameFolder))
        {
            return new FileRiskAssessment
            {
                Category = FileRiskCategory.High,
                Score = 78,
                Reason = isInDownloadsOrTemp ? "Disk image in Downloads" : "Disk image container",
                IsDigitallySigned = isSigned,
                SignerName = signerName
            };
        }

        // 6. Validly signed by a recognized trusted publisher
        if (isSigned && IsTrustedPublisher(signerName))
        {
            string label = string.IsNullOrWhiteSpace(signerName) ? "trusted publisher" : signerName;
            return new FileRiskAssessment
            {
                Category = FileRiskCategory.Trusted,
                Score = 10,
                Reason = $"Officially signed by {label}",
                IsDigitallySigned = true,
                SignerName = signerName
            };
        }

        // 7. Validly signed by another publisher
        if (isSigned)
        {
            string label = string.IsNullOrWhiteSpace(signerName) ? "valid certificate" : signerName;
            return new FileRiskAssessment
            {
                Category = FileRiskCategory.Low,
                Score = 25,
                Reason = $"Digitally signed by {label}",
                IsDigitallySigned = true,
                SignerName = signerName
            };
        }

        // 8. Known game engine / redistributable / middleware binary in a game folder
        if (isInGameFolder && IsKnownGameRuntimeName(lowerName))
        {
            return new FileRiskAssessment
            {
                Category = FileRiskCategory.Low,
                Score = 22,
                Reason = "Known game engine or runtime library",
                IsDigitallySigned = false
            };
        }

        // 9. Unsigned executable/installer/DLL outside game directories
        if (ExecutableExtensions.Contains(ext) && !isInGameFolder)
        {
            return new FileRiskAssessment
            {
                Category = FileRiskCategory.High,
                Score = 74,
                Reason = isInDownloadsOrTemp ? "Unsigned executable in Downloads" : "Unsigned executable",
                IsDigitallySigned = false
            };
        }

        // 10. Standard archive
        if (ArchiveExtensions.Contains(ext) || DiskImageExtensions.Contains(ext))
        {
            return new FileRiskAssessment
            {
                Category = FileRiskCategory.Medium,
                Score = 52,
                Reason = "Archive file",
                IsDigitallySigned = false
            };
        }

        // 11. Unsigned DLL/EXE inside a game folder
        if (ExecutableExtensions.Contains(ext) && isInGameFolder)
        {
            return new FileRiskAssessment
            {
                Category = FileRiskCategory.Medium,
                Score = 48,
                Reason = "Unsigned game binary",
                IsDigitallySigned = false
            };
        }

        // 12. Common non-executable asset/media/data files (when AllFiles mode is used)
        if (CommonAssetExtensions.Contains(ext))
        {
            return new FileRiskAssessment
            {
                Category = FileRiskCategory.Trusted,
                Score = 12,
                Reason = "Common game asset or data file",
                IsDigitallySigned = false
            };
        }

        // 13. Fallback
        return new FileRiskAssessment
        {
            Category = FileRiskCategory.Medium,
            Score = 45,
            Reason = "Standard watched file",
            IsDigitallySigned = false
        };
    }

    private static bool TryGetExistingFileSize(string filePath, long? knownSize, out long size)
    {
        if (knownSize.HasValue && File.Exists(filePath))
        {
            size = knownSize.Value;
            return true;
        }

        try
        {
            var info = new FileInfo(filePath);
            if (info.Exists)
            {
                size = info.Length;
                return true;
            }
        }
        catch
        {
            // Ignore unreadable path metadata.
        }

        size = 0;
        return false;
    }

    private static bool HasDoubleExtensionMasquerade(string fileName, string outerExt)
    {
        if (string.IsNullOrEmpty(outerExt))
        {
            return false;
        }

        if (!ExecutableExtensions.Contains(outerExt) && !HighRiskScriptAndLauncherExtensions.Contains(outerExt))
        {
            return false;
        }

        string withoutOuter = Path.GetFileNameWithoutExtension(fileName);
        string innerExt = Path.GetExtension(withoutOuter);
        return !string.IsNullOrEmpty(innerExt) && MasqueradedInnerExtensions.Contains(innerExt);
    }

    private static bool HasSuspiciousKeyword(string lowerFileName)
    {
        foreach (string kw in SuspiciousKeywords)
        {
            if (lowerFileName.Contains(kw, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsTrustedPublisher(string signerName)
    {
        if (string.IsNullOrWhiteSpace(signerName))
        {
            return false;
        }

        foreach (string publisher in TrustedPublishers)
        {
            if (signerName.Contains(publisher, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsKnownGameRuntimeName(string lowerFileName)
    {
        foreach (string prefix in KnownGameRuntimePrefixes)
        {
            if (lowerFileName.StartsWith(prefix, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private static (bool IsSigned, bool Tampered, string SignerName) VerifyAuthenticodeOffline(string filePath)
    {
        try
        {
            var (status, signer) = VerifyEmbeddedSignature(filePath);
            if (status == 0)
            {
                return (true, false, signer);
            }

            if (status == TrustEBadDigest || status == TrustEExplicitDistrust)
            {
                return (false, true, signer);
            }

            if (status == TrustENoSignature)
            {
                var (catStatus, catSigner) = VerifyCatalogSignature(filePath);
                if (catStatus == 0)
                {
                    return (true, false, catSigner);
                }

                if (catStatus == TrustEBadDigest || catStatus == TrustEExplicitDistrust)
                {
                    return (false, true, catSigner);
                }
            }
        }
        catch
        {
            // Treat verification exceptions as unsigned.
        }

        return (false, false, string.Empty);
    }

    private static (int Status, string SignerName) VerifyEmbeddedSignature(string filePath)
    {
        IntPtr pPath = IntPtr.Zero;
        IntPtr pFileInfo = IntPtr.Zero;

        var wtData = new WinTrustData
        {
            cbStruct = (uint)Marshal.SizeOf<WinTrustData>(),
            dwUIChoice = WtdUiNone,
            fdwRevocationChecks = WtdRevokeNone,
            dwUnionChoice = WtdChoiceFile,
            dwStateAction = WtdStateActionVerify,
            dwProvFlags = WtdRevocationCheckNone | WtdCacheOnlyUrlRetrieval
        };

        try
        {
            pPath = Marshal.StringToHGlobalUni(filePath);
            var fileInfo = new WinTrustFileInfo
            {
                cbStruct = (uint)Marshal.SizeOf<WinTrustFileInfo>(),
                pcwszFilePath = pPath
            };

            pFileInfo = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
            Marshal.StructureToPtr(fileInfo, pFileInfo, false);
            wtData.pInfoStruct = pFileInfo;

            int status = WinVerifyTrust(IntPtr.Zero, WinTrustActionGenericVerifyV2, ref wtData);
            string signer = ExtractSignerFromStateData(wtData.hWVTStateData);
            return (status, signer);
        }
        finally
        {
            if (wtData.hWVTStateData != IntPtr.Zero)
            {
                wtData.dwStateAction = WtdStateActionClose;
                _ = WinVerifyTrust(IntPtr.Zero, WinTrustActionGenericVerifyV2, ref wtData);
            }

            if (pFileInfo != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(pFileInfo);
            }

            if (pPath != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(pPath);
            }
        }
    }

    private static (int Status, string SignerName) VerifyCatalogSignature(string filePath)
    {
        if (!CryptCATAdminAcquireContext2(out IntPtr hCatAdmin, IntPtr.Zero, "SHA256", IntPtr.Zero, 0))
        {
            return (TrustENoSignature, string.Empty);
        }

        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            IntPtr hFile = fs.SafeFileHandle.DangerousGetHandle();

            uint hashSize = 0;
            _ = CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, ref hashSize, null, 0);
            if (hashSize == 0)
            {
                return (TrustENoSignature, string.Empty);
            }

            byte[] hashBytes = new byte[hashSize];
            if (!CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, ref hashSize, hashBytes, 0))
            {
                return (TrustENoSignature, string.Empty);
            }

            IntPtr hPrev = IntPtr.Zero;
            IntPtr hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, hashBytes, hashSize, 0, ref hPrev);
            if (hCatInfo == IntPtr.Zero)
            {
                return (TrustENoSignature, string.Empty);
            }

            try
            {
                var catInfo = new CatalogInfo { cbStruct = (uint)Marshal.SizeOf<CatalogInfo>() };
                if (!CryptCATCatalogInfoFromContext(hCatInfo, ref catInfo, 0) || string.IsNullOrWhiteSpace(catInfo.wszCatalogFile))
                {
                    return (TrustENoSignature, string.Empty);
                }

                string memberTag = Convert.ToHexString(hashBytes);
                return VerifyCatalogMember(catInfo.wszCatalogFile, memberTag, filePath, hFile);
            }
            finally
            {
                _ = CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
            }
        }
        catch
        {
            return (TrustENoSignature, string.Empty);
        }
        finally
        {
            _ = CryptCATAdminReleaseContext(hCatAdmin, 0);
        }
    }

    private static (int Status, string SignerName) VerifyCatalogMember(
        string catalogPath,
        string memberTag,
        string filePath,
        IntPtr hMemberFile)
    {
        IntPtr pCatPath = IntPtr.Zero;
        IntPtr pTag = IntPtr.Zero;
        IntPtr pFilePath = IntPtr.Zero;
        IntPtr pCatalogInfo = IntPtr.Zero;

        var wtData = new WinTrustData
        {
            cbStruct = (uint)Marshal.SizeOf<WinTrustData>(),
            dwUIChoice = WtdUiNone,
            fdwRevocationChecks = WtdRevokeNone,
            dwUnionChoice = WtdChoiceCatalog,
            dwStateAction = WtdStateActionVerify,
            dwProvFlags = WtdRevocationCheckNone | WtdCacheOnlyUrlRetrieval
        };

        try
        {
            pCatPath = Marshal.StringToHGlobalUni(catalogPath);
            pTag = Marshal.StringToHGlobalUni(memberTag);
            pFilePath = Marshal.StringToHGlobalUni(filePath);

            var catStruct = new WinTrustCatalogInfo
            {
                cbStruct = (uint)Marshal.SizeOf<WinTrustCatalogInfo>(),
                pcwszCatalogFilePath = pCatPath,
                pcwszMemberTag = pTag,
                pcwszMemberFilePath = pFilePath,
                hMemberFile = hMemberFile
            };

            pCatalogInfo = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustCatalogInfo>());
            Marshal.StructureToPtr(catStruct, pCatalogInfo, false);
            wtData.pInfoStruct = pCatalogInfo;

            int status = WinVerifyTrust(IntPtr.Zero, WinTrustActionGenericVerifyV2, ref wtData);
            string signer = ExtractSignerFromStateData(wtData.hWVTStateData);
            return (status, signer);
        }
        finally
        {
            if (wtData.hWVTStateData != IntPtr.Zero)
            {
                wtData.dwStateAction = WtdStateActionClose;
                _ = WinVerifyTrust(IntPtr.Zero, WinTrustActionGenericVerifyV2, ref wtData);
            }

            if (pCatalogInfo != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(pCatalogInfo);
            }

            if (pCatPath != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(pCatPath);
            }

            if (pTag != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(pTag);
            }

            if (pFilePath != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(pFilePath);
            }
        }
    }

    private static string ExtractSignerFromStateData(IntPtr hWvtStateData)
    {
        if (hWvtStateData == IntPtr.Zero)
        {
            return string.Empty;
        }

        try
        {
            IntPtr pProvData = WTHelperProvDataFromStateData(hWvtStateData);
            if (pProvData == IntPtr.Zero)
            {
                return string.Empty;
            }

            IntPtr pSigner = WTHelperGetProvSignerFromChain(pProvData, 0, false, 0);
            if (pSigner == IntPtr.Zero)
            {
                return string.Empty;
            }

            IntPtr pProvCert = WTHelperGetProvCertFromChain(pSigner, 0);
            if (pProvCert == IntPtr.Zero)
            {
                return string.Empty;
            }

            // CRYPT_PROVIDER_CERT starts with DWORD cbStruct (padded to IntPtr.Size) followed by PCCERT_CONTEXT pCert.
            IntPtr pCertContext = Marshal.ReadIntPtr(pProvCert, IntPtr.Size);
            if (pCertContext == IntPtr.Zero)
            {
                return string.Empty;
            }

            string simpleName = ReadCertNameString(pCertContext, CertNameSimpleDisplayType, IntPtr.Zero);
            string orgName = ReadCertOrganizationName(pCertContext);

            if (string.IsNullOrWhiteSpace(orgName))
            {
                return simpleName;
            }

            if (string.IsNullOrWhiteSpace(simpleName) || string.Equals(simpleName, orgName, StringComparison.OrdinalIgnoreCase))
            {
                return orgName;
            }

            return simpleName.Contains(orgName, StringComparison.OrdinalIgnoreCase)
                ? simpleName
                : $"{simpleName} ({orgName})";
        }
        catch
        {
            return string.Empty;
        }
    }

    private static string ReadCertOrganizationName(IntPtr pCertContext)
    {
        IntPtr pOid = Marshal.StringToHGlobalAnsi("2.5.4.10");
        try
        {
            return ReadCertNameString(pCertContext, CertNameAttrType, pOid);
        }
        finally
        {
            Marshal.FreeHGlobal(pOid);
        }
    }

    private static string ReadCertNameString(IntPtr pCertContext, uint dwType, IntPtr pvTypePara)
    {
        uint chars = CertGetNameStringW(pCertContext, dwType, 0, pvTypePara, null, 0);
        if (chars <= 1)
        {
            return string.Empty;
        }

        var sb = new StringBuilder((int)chars);
        _ = CertGetNameStringW(pCertContext, dwType, 0, pvTypePara, sb, chars);
        return sb.ToString().Trim();
    }
}
