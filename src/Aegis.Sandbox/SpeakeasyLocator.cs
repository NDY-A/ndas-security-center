using System.Text.Json;

namespace Aegis.Sandbox;

public sealed record SandboxComponentInfo(
    bool Available,
    string? DirectoryPath,
    string? PythonPath,
    string? RunnerPath,
    string EngineVersion,
    string? Error);

public static class SpeakeasyLocator
{
    public const string RunnerFileName = "ndas_sandbox_runner.py";
    public const string ComponentFileName = "component.json";

    public static SandboxComponentInfo Locate(string? overrideDirectory = null)
    {
        foreach (var candidate in EnumerateCandidates(overrideDirectory))
        {
            if (TryLoad(candidate, out var info))
            {
                return info;
            }
        }

        return new SandboxComponentInfo(
            false,
            null,
            null,
            null,
            string.Empty,
            "未找到内置沙箱组件（Sandbox\\python\\python.exe、运行器或 component.json 缺失）。");
    }

    private static IEnumerable<string> EnumerateCandidates(string? overrideDirectory)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (!string.IsNullOrWhiteSpace(overrideDirectory) && seen.Add(overrideDirectory))
        {
            yield return overrideDirectory;
        }

        var fromEnvironment = Environment.GetEnvironmentVariable("NDAS_SANDBOX_DIR");
        if (!string.IsNullOrWhiteSpace(fromEnvironment) && seen.Add(fromEnvironment))
        {
            yield return fromEnvironment;
        }

        var baseDirectory = AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var beside = Path.Combine(baseDirectory, "Sandbox");
        if (seen.Add(beside))
        {
            yield return beside;
        }

        var parent = Path.GetFullPath(Path.Combine(baseDirectory, "..", "Sandbox"));
        if (seen.Add(parent))
        {
            yield return parent;
        }

        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        if (!string.IsNullOrWhiteSpace(programFiles))
        {
            var installed = Path.Combine(programFiles, "NDAS", "Sandbox");
            if (seen.Add(installed))
            {
                yield return installed;
            }
        }
    }

    private static bool TryLoad(string directory, out SandboxComponentInfo info)
    {
        directory = Path.GetFullPath(directory);
        info = new SandboxComponentInfo(false, directory, null, null, string.Empty, null);

        var python = Path.Combine(directory, "python", "python.exe");
        var runner = Path.Combine(directory, RunnerFileName);
        var component = Path.Combine(directory, ComponentFileName);
        if (!File.Exists(python) || !File.Exists(runner))
        {
            info = info with { Error = "沙箱组件不完整。" };
            return false;
        }

        var version = "speakeasy";
        if (File.Exists(component))
        {
            try
            {
                using var document = JsonDocument.Parse(File.ReadAllText(component));
                if (document.RootElement.TryGetProperty("version", out var value) &&
                    value.ValueKind == JsonValueKind.String &&
                    value.GetString() is { Length: > 0 } text)
                {
                    version = text;
                }
            }
            catch
            {
                // A malformed component manifest falls back to the default label.
            }
        }

        info = new SandboxComponentInfo(true, directory, python, runner, version, null);
        return true;
    }
}
