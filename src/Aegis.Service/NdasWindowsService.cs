using System.ServiceProcess;
using Aegis.Core.Service;

namespace Aegis.Service;

public sealed class NdasWindowsService : ServiceBase
{
    private readonly ProtectionHost _host = new();

    public NdasWindowsService()
    {
        ServiceName = ServiceProtocol.WindowsServiceName;
        CanStop = true;
        CanShutdown = true;
        CanPauseAndContinue = false;
        AutoLog = true;
    }

    protected override void OnStart(string[] args)
    {
        _host.StartAsync().GetAwaiter().GetResult();
    }

    protected override void OnStop()
    {
        _host.StopAsync().GetAwaiter().GetResult();
    }

    protected override void OnShutdown()
    {
        OnStop();
    }
}
