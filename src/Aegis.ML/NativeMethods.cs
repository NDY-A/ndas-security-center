using System.Runtime.InteropServices;

namespace Aegis.ML;

internal static class NativeMethods
{
    private const string DllName = "AegisMl.dll";

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
    internal static extern int AegisMlGetFeatureCount();

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode)]
    internal static extern int AegisMlLoadModel(string modelPath);

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode)]
    internal static extern int AegisMlScoreFile(string path, out float maliciousProbability);

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
    internal static extern IntPtr AegisMlLastError();

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
    internal static extern IntPtr AegisMlModelVersion();

    internal static string LastError()
    {
        var ptr = AegisMlLastError();
        return ptr == IntPtr.Zero ? string.Empty : Marshal.PtrToStringUTF8(ptr) ?? string.Empty;
    }

    internal static string ModelVersion()
    {
        var ptr = AegisMlModelVersion();
        return ptr == IntPtr.Zero ? string.Empty : Marshal.PtrToStringUTF8(ptr) ?? string.Empty;
    }
}
