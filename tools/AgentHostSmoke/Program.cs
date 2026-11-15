using Aegis.AgentHost;

// Hard product constraint: the action catalog must never grow an
// exclusion/whitelist/config/spawn capability.
var banned = new[] { "exclude", "whitelist", "allow_hash", "allowlist", "configure",
    "setting", "write_file", "delete_file", "run_process", "shell", "disable" };
var violations = AgentActionCatalog.Names
    .Where(name => banned.Any(word => name.Contains(word, StringComparison.OrdinalIgnoreCase)))
    .ToList();
if (violations.Count > 0)
{
    Console.WriteLine("ACTION CATALOG VIOLATION: " + string.Join(",", violations));
    return 3;
}

Console.WriteLine($"catalog ok ({AgentActionCatalog.Names.Count} actions): {string.Join(",", AgentActionCatalog.Names.OrderBy(n => n))}");

var agentDir = args.Length > 0 ? args[0] : @"E:\My_Project\Aegis\tools\security-agent";
var component = AgentLocator.Locate(agentDir);
Console.WriteLine($"available={component.Available} python={component.PythonPath} error={component.Error}");
if (!component.Available)
{
    return 2;
}

var root = Path.Combine(Path.GetTempPath(), "ndas-agent-smoke");
var dataRoot = Path.Combine(root, "data");
var logsRoot = Path.Combine(root, "logs");
Directory.CreateDirectory(dataRoot);
Directory.CreateDirectory(logsRoot);

await using var coordinator = new AgentCoordinator(component, dataRoot, logsRoot);
coordinator.StateChanged += (state, error) => Console.WriteLine($"[state] {state} {error}");

coordinator.Start();
var reachedRunning = false;
for (var i = 0; i < 20; i++)
{
    await Task.Delay(1000);
    var status = coordinator.GetStatus();
    Console.WriteLine($"{i + 1,2}s state={status.State} model={status.ModelLoaded} restarts={status.RestartCount} error={status.LastError}");
    if (status.State == "running")
    {
        reachedRunning = true;
        coordinator.QueueEvent("system_tick", new AgentSystemTickMessage
        {
            TickId = "smoke-tick",
            IntervalMs = 30000,
            IdleSeconds = 0,
            CpuPercent = 5,
            QueueDepth = 0,
            DroppedEvents = 0,
        });
        await Task.Delay(3000);
        var after = coordinator.GetStatus();
        Console.WriteLine($"after tick: state={after.State} decisions={after.DecisionCount} errors={after.DecisionErrors} queued={after.QueuedEvents}");
        break;
    }
}

Console.WriteLine(reachedRunning ? "SMOKE OK" : "SMOKE FAILED");
await coordinator.StopAsync();
return reachedRunning ? 0 : 1;
