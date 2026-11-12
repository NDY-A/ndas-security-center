using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace Aegis.Sandbox;

public sealed record SandboxRunOutcome(
    bool Completed,
    bool TimedOut,
    bool Cancelled,
    string? Error,
    byte[]? ReportJson,
    TimeSpan Duration,
    string LogPath,
    bool LowIntegrity,
    string? IsolationWarning);

public sealed class SpeakeasyRunner
{
    public const int MaxReportBytes = 20 * 1024 * 1024;
    private static readonly TimeSpan GraceAfterTimeout = TimeSpan.FromSeconds(10);
    private readonly SandboxComponentInfo _component;

    public SpeakeasyRunner(SandboxComponentInfo component)
    {
        _component = component;
    }

    public async Task<SandboxRunOutcome> RunAsync(
        string samplePath,
        string workDirectory,
        TimeSpan maxRuntime,
        CancellationToken cancellationToken)
    {
        var started = Stopwatch.StartNew();
        var logPath = Path.Combine(workDirectory, "runner.log");
        var reportPath = Path.Combine(workDirectory, "report.json");
        var timedOut = false;
        var cancelled = false;
        var lowIntegrity = false;
        string? isolationWarning = null;

        if (_component.PythonPath is null || _component.RunnerPath is null || !_component.Available)
        {
            return new SandboxRunOutcome(false, false, false,
                _component.Error ?? "沙箱组件不可用。", null, started.Elapsed, logPath, false, null);
        }

        Directory.CreateDirectory(workDirectory);
        Directory.CreateDirectory(Path.Combine(workDirectory, "tmp"));
        TrySetLowIntegrity(workDirectory);
        EnsureRunnerOutboundBlocked(_component.PythonPath, out isolationWarning);

        var arguments = new List<string>
        {
            "-B",
            _component.RunnerPath,
            "--sample", samplePath,
            "--report", reportPath,
            "--work-dir", workDirectory,
            "--max-run-time", Math.Clamp((int)maxRuntime.TotalSeconds, 10, 600).ToString()
        };

        var launchOptions = new SandboxProcessLaunchOptions
        {
            ExecutablePath = _component.PythonPath,
            Arguments = arguments,
            WorkingDirectory = workDirectory,
            LogPath = logPath
        };

        var process = SandboxProcessLauncher.Start(launchOptions, out var launchError);
        if (process is null)
        {
            return new SandboxRunOutcome(false, false, false,
                "无法启动沙箱模拟器：" + launchError, null, started.Elapsed, logPath, false, isolationWarning);
        }

        using (process)
        {
            lowIntegrity = process.LowIntegrity;
            if (process.Warning is { Length: > 0 } warning)
            {
                isolationWarning = warning;
            }

            var wallLimit = maxRuntime + GraceAfterTimeout;
            try
            {
                while (!process.WaitForExit(TimeSpan.FromMilliseconds(250)))
                {
                    if (cancellationToken.IsCancellationRequested)
                    {
                        cancelled = true;
                        break;
                    }

                    if (started.Elapsed > wallLimit)
                    {
                        timedOut = true;
                        break;
                    }
                }
            }
            finally
            {
                if (timedOut || cancelled)
                {
                    process.Kill();
                    process.WaitForExit(TimeSpan.FromSeconds(5));
                }
            }
        }

        started.Stop();
        byte[]? report = null;
        string? error = null;
        if (cancelled)
        {
            error = "沙箱分析已取消。";
        }
        else if (timedOut)
        {
            error = $"沙箱分析超时（{maxRuntime.TotalSeconds:F0} 秒）。";
            report = TryReadReport(reportPath);
        }
        else
        {
            report = TryReadReport(reportPath);
            if (report is null)
            {
                error = "沙箱运行结束但没有生成报告；模拟器可能不支持该样本。";
            }
        }

        return new SandboxRunOutcome(report is not null && error is null, timedOut, cancelled, error,
            report, started.Elapsed, logPath, lowIntegrity, isolationWarning);
    }

    private static byte[]? TryReadReport(string path)
    {
        try
        {
            if (!File.Exists(path))
            {
                return null;
            }

            var info = new FileInfo(path);
            if (info.Length <= 0 || info.Length > MaxReportBytes)
            {
                return null;
            }

            return File.ReadAllBytes(path);
        }
        catch
        {
            return null;
        }
    }

    private static void TrySetLowIntegrity(string directory)
    {
        try
        {
            var startInfo = new ProcessStartInfo("icacls.exe")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            startInfo.ArgumentList.Add(directory);
            startInfo.ArgumentList.Add("/setintegritylevel");
            startInfo.ArgumentList.Add("(OI)(CI)Low");
            using var process = Process.Start(startInfo);
            if (process is null)
            {
                return;
            }

            process.StandardOutput.ReadToEnd();
            process.StandardError.ReadToEnd();
            process.WaitForExit(10_000);
        }
        catch
        {
            // The launcher still applies a low-integrity token; the label is defense in depth.
        }
    }

    public static void EnsureRunnerOutboundBlocked(string pythonPath, out string? warning)
    {
        warning = null;
        try
        {
            pythonPath = Path.GetFullPath(pythonPath);
            var ruleName = BuildFirewallRuleName(pythonPath);
            if (RunNetsh($"advfirewall firewall show rule name=\"{ruleName}\"") == 0)
            {
                return;
            }

            var exitCode = RunNetsh(
                $"advfirewall firewall add rule name=\"{ruleName}\" dir=out action=block " +
                $"program=\"{pythonPath}\" profile=any enable=yes");
            if (exitCode != 0)
            {
                warning = "无法为沙箱模拟器创建出站阻断防火墙规则；作业对象限制仍然生效。";
            }
        }
        catch
        {
            warning = "无法为沙箱模拟器创建出站阻断防火墙规则。";
        }
    }

    private static string BuildFirewallRuleName(string pythonPath)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(pythonPath.ToLowerInvariant()));
        return "NDAS-Sandbox-" + Convert.ToHexString(hash)[..8] + "-Out";
    }

    private static int RunNetsh(string arguments)
    {
        try
        {
            var startInfo = new ProcessStartInfo("netsh.exe", arguments)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using var process = Process.Start(startInfo);
            if (process is null)
            {
                return -1;
            }

            process.StandardOutput.ReadToEnd();
            process.StandardError.ReadToEnd();
            if (!process.WaitForExit(15_000))
            {
                try
                {
                    process.Kill(entireProcessTree: true);
                }
                catch
                {
                    // Best effort.
                }

                return -1;
            }

            return process.ExitCode;
        }
        catch
        {
            return -1;
        }
    }
}
