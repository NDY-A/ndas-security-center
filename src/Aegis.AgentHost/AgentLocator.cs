using System.Text.Json;

namespace Aegis.AgentHost;

public sealed class AgentComponentInfo
{
    public bool Available { get; init; }
    public string DirectoryPath { get; init; } = string.Empty;
    public string PythonPath { get; init; } = string.Empty;
    public string DaemonPath { get; init; } = string.Empty;
    public string? ModelPath { get; init; }
    public string? ScriptModelPath { get; init; }
    public string? Version { get; init; }
    public string? Error { get; init; }
}

/// <summary>
/// Finds the agent component. The daemon lives in <c>Program Files\NDAS\Agent</c> and shares
/// the sandbox's embedded Python runtime so the MSI only ships one interpreter.
/// </summary>
public static class AgentLocator
{
    public const string DaemonFileName = "agent_daemon.py";
    public const string ComponentFileName = "component.json";
    public const string ModelFileName = "agent-model.onnx";

    public static AgentComponentInfo Locate(string? overrideDirectory = null)
    {
        foreach (var candidate in EnumerateCandidates(overrideDirectory))
        {
            var info = TryLoad(candidate);
            if (info.Available)
            {
                return info;
            }
        }

        return new AgentComponentInfo { Error = "未找到 agent 组件（Agent 目录或 Python 运行时缺失）" };
    }

    private static IEnumerable<string> EnumerateCandidates(string? overrideDirectory)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (!string.IsNullOrWhiteSpace(overrideDirectory) && seen.Add(overrideDirectory))
        {
            yield return overrideDirectory;
        }

        var fromEnvironment = Environment.GetEnvironmentVariable("NDAS_AGENT_DIR");
        if (!string.IsNullOrWhiteSpace(fromEnvironment) && seen.Add(fromEnvironment))
        {
            yield return fromEnvironment;
        }

        var baseDirectory = AppContext.BaseDirectory;
        var local = Path.Combine(baseDirectory, "Agent");
        if (seen.Add(local))
        {
            yield return local;
        }

        var parent = Path.GetFullPath(Path.Combine(baseDirectory, "..", "Agent"));
        if (seen.Add(parent))
        {
            yield return parent;
        }

        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var installed = Path.Combine(programFiles, "NDAS", "Agent");
        if (seen.Add(installed))
        {
            yield return installed;
        }
    }

    private static AgentComponentInfo TryLoad(string directory)
    {
        try
        {
            var daemon = Path.Combine(directory, DaemonFileName);
            if (!File.Exists(daemon))
            {
                return new AgentComponentInfo { Error = "agent 守护脚本缺失" };
            }

            var python = ResolvePython(directory);
            if (python is null)
            {
                return new AgentComponentInfo { Error = "Python 运行时缺失（Agent 或 Sandbox 目录）" };
            }

            var model = Path.Combine(directory, ModelFileName);
            string? version = null;
            var componentPath = Path.Combine(directory, ComponentFileName);
            if (File.Exists(componentPath))
            {
                try
                {
                    using var document = JsonDocument.Parse(File.ReadAllText(componentPath));
                    if (document.RootElement.TryGetProperty("version", out var versionElement))
                    {
                        version = versionElement.GetString();
                    }
                }
                catch
                {
                    // A malformed component file only loses version reporting.
                }
            }

            var scriptModel = Path.Combine(directory, "script-ngram.onnx");
            if (!File.Exists(scriptModel))
            {
                var sandboxModel = Path.Combine(Path.GetDirectoryName(directory) ?? directory,
                    "..", "Agent", "script-ngram.onnx");
                scriptModel = Path.GetFullPath(sandboxModel);
            }

            return new AgentComponentInfo
            {
                Available = true,
                DirectoryPath = Path.GetFullPath(directory),
                PythonPath = python,
                DaemonPath = daemon,
                ModelPath = File.Exists(model) ? model : null,
                ScriptModelPath = File.Exists(scriptModel) ? scriptModel : null,
                Version = version,
            };
        }
        catch (Exception exception)
        {
            return new AgentComponentInfo { Error = exception.Message };
        }
    }

    private static string? ResolvePython(string agentDirectory)
    {
        var local = Path.Combine(agentDirectory, "python", "python.exe");
        if (File.Exists(local))
        {
            return local;
        }

        var sibling = Path.GetFullPath(Path.Combine(agentDirectory, "..", "Sandbox", "python", "python.exe"));
        if (File.Exists(sibling))
        {
            return sibling;
        }

        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var installed = Path.Combine(programFiles, "NDAS", "Sandbox", "python", "python.exe");
        if (File.Exists(installed))
        {
            return installed;
        }

        return null;
    }
}
