param([long]$LimitBytes = 6GB)

$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class JobMem
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr CreateJobObject(IntPtr a, string lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetInformationJobObject(IntPtr hJob, int infoClass, IntPtr info, int infoLen);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool QueryInformationJobObject(IntPtr hJob, int infoClass, IntPtr info, int infoLen, out int retLen);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(int access, bool inherit, int pid);

    [StructLayout(LayoutKind.Sequential)]
    public struct JOBOBJECT_BASIC_LIMIT_INFORMATION
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IO_COUNTERS
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    const int JobObjectExtendedLimitInformation = 9;
    const uint JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100;
    const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;

    public static IntPtr CreateLimitedJob(long memoryLimit)
    {
        IntPtr job = CreateJobObject(IntPtr.Zero, null);
        if (job == IntPtr.Zero) throw new Exception("CreateJobObject failed: " + Marshal.GetLastWin32Error());

        var info = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        info.ProcessMemoryLimit = (UIntPtr)(ulong)memoryLimit;

        int len = Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
        IntPtr ptr = Marshal.AllocHGlobal(len);
        try
        {
            Marshal.StructureToPtr(info, ptr, false);
            if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, ptr, len))
                throw new Exception("SetInformationJobObject failed: " + Marshal.GetLastWin32Error());
        }
        finally { Marshal.FreeHGlobal(ptr); }
        return job;
    }

    public static void Assign(IntPtr job, int pid)
    {
        IntPtr process = OpenProcess(0x0100 | 0x0001, false, pid); // SET_QUOTA | TERMINATE
        if (process == IntPtr.Zero) throw new Exception("OpenProcess failed: " + Marshal.GetLastWin32Error());
        if (!AssignProcessToJobObject(job, process))
            throw new Exception("AssignProcessToJobObject failed: " + Marshal.GetLastWin32Error());
    }

    public static string Peak(IntPtr job)
    {
        int len = Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
        IntPtr ptr = Marshal.AllocHGlobal(len);
        try
        {
            int returned;
            if (!QueryInformationJobObject(job, JobObjectExtendedLimitInformation, ptr, len, out returned))
                return "unknown";
            var info = (JOBOBJECT_EXTENDED_LIMIT_INFORMATION)Marshal.PtrToStructure(ptr, typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
            return string.Format("{0:N2} GB", (ulong)info.PeakProcessMemoryUsed / 1073741824.0);
        }
        finally { Marshal.FreeHGlobal(ptr); }
    }
}
"@

$job = [JobMem]::CreateLimitedJob($LimitBytes)
$proc = Start-Process -FilePath 'python' -ArgumentList '-u', 'quantize_int8.py' `
    -WorkingDirectory $PSScriptRoot -NoNewWindow -PassThru `
    -RedirectStandardOutput (Join-Path $PSScriptRoot 'quantize-int8.log') `
    -RedirectStandardError (Join-Path $PSScriptRoot 'quantize-int8.err.log')

[JobMem]::Assign($job, $proc.Id) | Out-Null
$proc.WaitForExit()

"exit code: $($proc.ExitCode)"
"job peak memory: $([JobMem]::Peak($job))"
Get-Content -LiteralPath (Join-Path $PSScriptRoot 'quantize-int8.log') -ErrorAction SilentlyContinue
$err = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'quantize-int8.err.log') -ErrorAction SilentlyContinue
if ($err) { "--- stderr ---"; $err }
