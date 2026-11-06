using System.Runtime.InteropServices;
using Aegis.Core.Service;

namespace Aegis.Service;

internal static class ServiceRecovery
{
    private const uint ScManagerConnect = 0x0001;
    private const uint ServiceAllAccess = 0xF01FF;
    private const uint ServiceConfigFailureActions = 2;
    private const uint ServiceConfigFailureActionsFlag = 4;
    private const uint ScActionRestart = 1;
    private const uint ResetPeriodSeconds = 86_400;

    public static void Configure()
    {
        var scm = OpenSCManager(null, null, ScManagerConnect);
        if (scm == IntPtr.Zero)
        {
            return;
        }

        IntPtr actionsPointer = IntPtr.Zero;
        try
        {
            var service = OpenService(scm, ServiceProtocol.WindowsServiceName, ServiceAllAccess);
            if (service == IntPtr.Zero)
            {
                return;
            }

            try
            {
                var actions = new[]
                {
                    new ScAction { Type = ScActionRestart, Delay = 30_000 },
                    new ScAction { Type = ScActionRestart, Delay = 30_000 },
                    new ScAction { Type = ScActionRestart, Delay = 30_000 }
                };
                var elementSize = Marshal.SizeOf<ScAction>();
                actionsPointer = Marshal.AllocHGlobal(elementSize * actions.Length);
                for (var index = 0; index < actions.Length; index++)
                {
                    Marshal.StructureToPtr(actions[index], actionsPointer + index * elementSize, false);
                }

                var failureActions = new ServiceFailureActions
                {
                    ResetPeriod = ResetPeriodSeconds,
                    RebootMessage = null,
                    Command = null,
                    ActionsCount = (uint)actions.Length,
                    Actions = actionsPointer
                };

                if (!ChangeServiceConfig2(service, ServiceConfigFailureActions, ref failureActions))
                {
                    return;
                }

                var applyOnNonCrashFailure = 1;
                ChangeServiceConfig2(service, ServiceConfigFailureActionsFlag, ref applyOnNonCrashFailure);
            }
            finally
            {
                CloseServiceHandle(service);
            }
        }
        catch
        {
            // Recovery configuration is best-effort; the service must still start.
        }
        finally
        {
            if (actionsPointer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(actionsPointer);
            }

            CloseServiceHandle(scm);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ScAction
    {
        public uint Type;
        public uint Delay;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ServiceFailureActions
    {
        public uint ResetPeriod;
        public string? RebootMessage;
        public string? Command;
        public uint ActionsCount;
        public IntPtr Actions;
    }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenSCManager(string? machineName, string? databaseName, uint access);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenService(IntPtr scManager, string serviceName, uint access);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool ChangeServiceConfig2(IntPtr service, uint infoLevel, ref ServiceFailureActions info);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool ChangeServiceConfig2(IntPtr service, uint infoLevel, ref int info);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CloseServiceHandle(IntPtr handle);
}
