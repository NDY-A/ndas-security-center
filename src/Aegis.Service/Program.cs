using System.ServiceProcess;
using Aegis.Service;

if (args.Contains("--console", StringComparer.OrdinalIgnoreCase))
{
    var seedArgument = GetArgument(args, "--seed");
    using var host = new ProtectionHost(seedArgument);
    await host.StartAsync();
    Console.WriteLine("NDAS 防护服务（控制台模式）已启动。按 Ctrl+C 停止。");
    var stop = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
    Console.CancelKeyPress += (_, eventArgs) =>
    {
        eventArgs.Cancel = true;
        stop.TrySetResult();
    };
    AppDomain.CurrentDomain.ProcessExit += (_, _) => stop.TrySetResult();
    await stop.Task;
    await host.StopAsync();
    return;
}

if (Environment.UserInteractive)
{
    Console.Error.WriteLine("NDASService 必须由服务控制管理器启动；本地调试请使用 --console。");
    return;
}

ServiceRecovery.Configure();
ServiceBase.Run(new NdasWindowsService());

static string? GetArgument(string[] arguments, string name)
{
    var index = Array.FindIndex(arguments, value => value.Equals(name, StringComparison.OrdinalIgnoreCase));
    return index >= 0 && index + 1 < arguments.Length ? arguments[index + 1] : null;
}
