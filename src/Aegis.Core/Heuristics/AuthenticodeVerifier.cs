using System.Runtime.InteropServices;

namespace Aegis.Core.Heuristics;

public enum AuthenticodeState
{
    None = 0,
    Valid = 1,
    Invalid = 2
}

public static class AuthenticodeVerifier
{
    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustFileInfo
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustData
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    [DllImport("wintrust.dll", PreserveSig = true)]
    private static extern int WinVerifyTrust(
        IntPtr hwnd,
        [MarshalAs(UnmanagedType.LPStruct)] Guid actionId,
        IntPtr data);

    public static AuthenticodeState Verify(string path)
    {
        if (!OperatingSystem.IsWindows())
        {
            return AuthenticodeState.None;
        }

        var pathPointer = IntPtr.Zero;
        var fileInfoPointer = IntPtr.Zero;
        var dataPointer = IntPtr.Zero;
        try
        {
            pathPointer = Marshal.StringToHGlobalUni(path);
            var fileInfo = new WinTrustFileInfo
            {
                cbStruct = (uint)Marshal.SizeOf<WinTrustFileInfo>(),
                pcwszFilePath = pathPointer
            };
            fileInfoPointer = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
            Marshal.StructureToPtr(fileInfo, fileInfoPointer, false);

            var data = new WinTrustData
            {
                cbStruct = (uint)Marshal.SizeOf<WinTrustData>(),
                dwUIChoice = 2,
                fdwRevocationChecks = 0,
                dwUnionChoice = 1,
                pFile = fileInfoPointer,
                dwStateAction = 1,
                dwProvFlags = 0x10 | 0x1000
            };
            dataPointer = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustData>());
            Marshal.StructureToPtr(data, dataPointer, false);

            int status;
            try
            {
                status = WinVerifyTrust(IntPtr.Zero, GenericVerifyV2, dataPointer);
            }
            finally
            {
                var cleanup = Marshal.PtrToStructure<WinTrustData>(dataPointer);
                cleanup.cbStruct = (uint)Marshal.SizeOf<WinTrustData>();
                cleanup.dwStateAction = 2;
                Marshal.StructureToPtr(cleanup, dataPointer, false);
                WinVerifyTrust(IntPtr.Zero, GenericVerifyV2, dataPointer);
            }

            return status == 0 ? AuthenticodeState.Valid : AuthenticodeState.Invalid;
        }
        catch (Exception)
        {
            return AuthenticodeState.None;
        }
        finally
        {
            if (dataPointer != IntPtr.Zero) Marshal.FreeHGlobal(dataPointer);
            if (fileInfoPointer != IntPtr.Zero) Marshal.FreeHGlobal(fileInfoPointer);
            if (pathPointer != IntPtr.Zero) Marshal.FreeHGlobal(pathPointer);
        }
    }
}
