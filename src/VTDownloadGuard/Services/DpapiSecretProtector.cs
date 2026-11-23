using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace VTDownloadGuard.Services;

/// <summary>
/// Protects sensitive strings using Windows DPAPI (CryptProtectData / CryptUnprotectData)
/// scoped to the current Windows user without requiring any external NuGet packages.
/// </summary>
public static class DpapiSecretProtector
{
    private const int CryptProtectUiForbidden = 0x1;
    private static readonly byte[] EntropyBytes = Encoding.UTF8.GetBytes("VTDownloadGuard-v1");

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct DataBlob
    {
        public int cbData;
        public IntPtr pbData;
    }

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptProtectData(
        ref DataBlob pDataIn,
        string? szDataDescr,
        ref DataBlob pOptionalEntropy,
        IntPtr pvReserved,
        IntPtr pPromptStruct,
        int dwFlags,
        out DataBlob pDataOut);

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptUnprotectData(
        ref DataBlob pDataIn,
        IntPtr ppszDataDescr,
        ref DataBlob pOptionalEntropy,
        IntPtr pvReserved,
        IntPtr pPromptStruct,
        int dwFlags,
        out DataBlob pDataOut);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr hMem);

    public static string Protect(string plaintext)
    {
        if (string.IsNullOrWhiteSpace(plaintext))
        {
            return string.Empty;
        }

        byte[] inputBytes = Encoding.UTF8.GetBytes(plaintext);
        DataBlob dataIn = default;
        DataBlob entropy = default;
        DataBlob dataOut = default;

        try
        {
            dataIn = CreateBlob(inputBytes);
            entropy = CreateBlob(EntropyBytes);

            if (!CryptProtectData(ref dataIn, "VTDownloadGuardApiKey", ref entropy, IntPtr.Zero, IntPtr.Zero, CryptProtectUiForbidden, out dataOut))
            {
                int err = Marshal.GetLastWin32Error();
                throw new CryptographicException($"CryptProtectData failed with Win32 error {err}.");
            }

            byte[] protectedBytes = new byte[dataOut.cbData];
            Marshal.Copy(dataOut.pbData, protectedBytes, 0, dataOut.cbData);
            return Convert.ToBase64String(protectedBytes);
        }
        finally
        {
            FreeInputBlob(ref dataIn);
            FreeInputBlob(ref entropy);
            FreeOutputBlob(ref dataOut);
        }
    }

    public static string Unprotect(string protectedBase64)
    {
        if (string.IsNullOrWhiteSpace(protectedBase64))
        {
            return string.Empty;
        }

        byte[] protectedBytes;
        try
        {
            protectedBytes = Convert.FromBase64String(protectedBase64.Trim());
        }
        catch (FormatException)
        {
            return string.Empty;
        }

        if (protectedBytes.Length == 0)
        {
            return string.Empty;
        }

        DataBlob dataIn = default;
        DataBlob entropy = default;
        DataBlob dataOut = default;

        try
        {
            dataIn = CreateBlob(protectedBytes);
            entropy = CreateBlob(EntropyBytes);

            if (!CryptUnprotectData(ref dataIn, IntPtr.Zero, ref entropy, IntPtr.Zero, IntPtr.Zero, CryptProtectUiForbidden, out dataOut))
            {
                return string.Empty;
            }

            byte[] plainBytes = new byte[dataOut.cbData];
            Marshal.Copy(dataOut.pbData, plainBytes, 0, dataOut.cbData);
            return Encoding.UTF8.GetString(plainBytes);
        }
        catch
        {
            return string.Empty;
        }
        finally
        {
            FreeInputBlob(ref dataIn);
            FreeInputBlob(ref entropy);
            FreeOutputBlob(ref dataOut);
        }
    }

    private static DataBlob CreateBlob(byte[] data)
    {
        if (data.Length == 0)
        {
            return default;
        }

        IntPtr ptr = Marshal.AllocHGlobal(data.Length);
        Marshal.Copy(data, 0, ptr, data.Length);
        return new DataBlob { cbData = data.Length, pbData = ptr };
    }

    private static void FreeInputBlob(ref DataBlob blob)
    {
        if (blob.pbData != IntPtr.Zero)
        {
            Marshal.FreeHGlobal(blob.pbData);
            blob.pbData = IntPtr.Zero;
            blob.cbData = 0;
        }
    }

    private static void FreeOutputBlob(ref DataBlob blob)
    {
        if (blob.pbData != IntPtr.Zero)
        {
            LocalFree(blob.pbData);
            blob.pbData = IntPtr.Zero;
            blob.cbData = 0;
        }
    }
}
