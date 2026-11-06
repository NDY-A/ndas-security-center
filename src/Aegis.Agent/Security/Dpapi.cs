using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Aegis.Agent.Security;

internal static class Dpapi
{
    private const int CryptProtectUiForbidden = 0x1;

    public static byte[] Protect(ReadOnlySpan<byte> plaintext)
    {
        if (plaintext.Length == 0)
        {
            throw new ArgumentException("DPAPI 明文不能为空。", nameof(plaintext));
        }

        return Transform(plaintext, protect: true);
    }

    public static byte[] Unprotect(ReadOnlySpan<byte> ciphertext)
    {
        if (ciphertext.Length == 0)
        {
            throw new ArgumentException("DPAPI 密文不能为空。", nameof(ciphertext));
        }

        return Transform(ciphertext, protect: false);
    }

    private static byte[] Transform(ReadOnlySpan<byte> input, bool protect)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("DPAPI 仅在 Windows 上可用。");
        }

        var inputArray = input.ToArray();
        var inputPointer = Marshal.AllocHGlobal(inputArray.Length);
        try
        {
            Marshal.Copy(inputArray, 0, inputPointer, inputArray.Length);
            var inputBlob = new DataBlob
            {
                Size = inputArray.Length,
                Data = inputPointer
            };

            DataBlob outputBlob;
            var success = protect
                ? CryptProtectData(ref inputBlob, "NDAS local secret", IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, CryptProtectUiForbidden, out outputBlob)
                : CryptUnprotectData(ref inputBlob, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, CryptProtectUiForbidden, out outputBlob);

            if (!success)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "DPAPI 操作失败。");
            }

            try
            {
                if (outputBlob.Size <= 0 || outputBlob.Data == IntPtr.Zero)
                {
                    throw new CryptographicException("DPAPI 返回了空数据。");
                }

                var output = new byte[outputBlob.Size];
                Marshal.Copy(outputBlob.Data, output, 0, outputBlob.Size);
                return output;
            }
            finally
            {
                ZeroUnmanaged(outputBlob.Data, outputBlob.Size);
                if (outputBlob.Data != IntPtr.Zero)
                {
                    _ = LocalFree(outputBlob.Data);
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(inputArray);
            ZeroUnmanaged(inputPointer, inputArray.Length);
            Marshal.FreeHGlobal(inputPointer);
        }
    }

    private static void ZeroUnmanaged(IntPtr pointer, int length)
    {
        if (pointer == IntPtr.Zero || length <= 0)
        {
            return;
        }

        for (var index = 0; index < length; index++)
        {
            Marshal.WriteByte(pointer, index, 0);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DataBlob
    {
        public int Size;
        public IntPtr Data;
    }

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptProtectData(
        ref DataBlob dataIn,
        string? description,
        IntPtr optionalEntropy,
        IntPtr reserved,
        IntPtr promptStruct,
        int flags,
        out DataBlob dataOut);

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptUnprotectData(
        ref DataBlob dataIn,
        IntPtr description,
        IntPtr optionalEntropy,
        IntPtr reserved,
        IntPtr promptStruct,
        int flags,
        out DataBlob dataOut);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr memory);
}
