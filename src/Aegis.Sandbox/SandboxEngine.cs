using System.Diagnostics;
using System.Security.Cryptography;
using Aegis.Core.Models;
using Aegis.Core.Signatures;

namespace Aegis.Sandbox;

public sealed class SandboxEngine
{
    private const int MaxRetainedReports = 50;
    private static readonly TimeSpan ReportRetention = TimeSpan.FromDays(30);
    private readonly string _workRoot;
    private readonly string _reportsRoot;
    private readonly SpeakeasyRunner? _runner;

    public SandboxEngine(string dataRoot, SandboxComponentInfo component)
    {
        Component = component;
        _workRoot = Path.Combine(dataRoot, "work");
        _reportsRoot = Path.Combine(dataRoot, "reports");
        _runner = component.Available ? new SpeakeasyRunner(component) : null;
    }

    public SandboxComponentInfo Component { get; }

    public async Task<SandboxResult> AnalyzeAsync(
        SandboxCandidate candidate,
        SandboxOptions options,
        SignatureSnapshot signatures,
        CancellationToken cancellationToken)
    {
        var jobId = Guid.NewGuid().ToString("N");
        var workDirectory = Path.Combine(_workRoot, jobId);
        var started = Stopwatch.StartNew();
        try
        {
            if (_runner is null || !Component.Available)
            {
                return ErrorResult(candidate, Component.Error ?? "沙箱组件不可用。", started.Elapsed);
            }

            Directory.CreateDirectory(workDirectory);
            var source = candidate.AnalysisPath ?? candidate.SourcePath;
            var staged = Path.Combine(workDirectory, "sample.bin");
            var actualHash = await CopyAndHashAsync(source, staged, cancellationToken).ConfigureAwait(false);
            if (!string.Equals(actualHash, candidate.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                return ErrorResult(candidate, "文件在扫描后发生变化，已跳过沙箱分析。", started.Elapsed);
            }

            var maxRuntime = TimeSpan.FromSeconds(Math.Clamp(options.MaxRuntimeSeconds, 30, 300));
            var outcome = await _runner.RunAsync(staged, workDirectory, maxRuntime, cancellationToken)
                .ConfigureAwait(false);
            if (outcome.ReportJson is null)
            {
                return ErrorResult(candidate, outcome.Error ?? "沙箱未生成报告。", started.Elapsed);
            }

            TryStoreReport(candidate, outcome.ReportJson);

            ParsedSandboxReport report;
            try
            {
                report = SandboxReportParser.Parse(outcome.ReportJson);
            }
            catch (Exception exception)
            {
                return ErrorResult(candidate, "沙箱报告解析失败：" + exception.Message, started.Elapsed);
            }

            var duration = outcome.Duration > TimeSpan.Zero ? outcome.Duration : started.Elapsed;
            return SandboxScorer.Score(report, signatures, Path.GetFileName(candidate.SourcePath),
                candidate.Sha256, duration, Component.EngineVersion);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception)
        {
            return ErrorResult(candidate, "沙箱分析失败：" + exception.Message, started.Elapsed);
        }
        finally
        {
            TryDeleteDirectory(workDirectory);
            if (candidate.CleanupDirectory is { Length: > 0 } cleanup)
            {
                TryDeleteDirectory(cleanup);
            }

            TryPruneReports();
        }
    }

    private static async Task<string> CopyAndHashAsync(string source, string destination, CancellationToken cancellationToken)
    {
        await using var input = new FileStream(source, FileMode.Open, FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete, 1024 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        await using var output = new FileStream(destination, FileMode.Create, FileAccess.Write, FileShare.None,
            1024 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[1024 * 1024];
        while (true)
        {
            var read = await input.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            hasher.AppendData(buffer, 0, read);
            await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
        }

        await output.FlushAsync(cancellationToken).ConfigureAwait(false);
        return Convert.ToHexString(hasher.GetHashAndReset()).ToLowerInvariant();
    }

    private void TryStoreReport(SandboxCandidate candidate, byte[] json)
    {
        try
        {
            Directory.CreateDirectory(_reportsRoot);
            var name = $"{DateTimeOffset.UtcNow:yyyyMMdd-HHmmss}-{candidate.Sha256[..12]}.json";
            File.WriteAllBytes(Path.Combine(_reportsRoot, name), json);
        }
        catch
        {
            // Report retention is best-effort.
        }
    }

    private void TryPruneReports()
    {
        try
        {
            if (!Directory.Exists(_reportsRoot))
            {
                return;
            }

            var cutoff = DateTime.UtcNow - ReportRetention;
            var files = new DirectoryInfo(_reportsRoot).GetFiles("*.json")
                .OrderByDescending(file => file.LastWriteTimeUtc)
                .ToArray();
            for (var index = 0; index < files.Length; index++)
            {
                if (index >= MaxRetainedReports || files[index].LastWriteTimeUtc < cutoff)
                {
                    try
                    {
                        files[index].Delete();
                    }
                    catch
                    {
                        // Best effort.
                    }
                }
            }
        }
        catch
        {
            // Pruning must never break analysis.
        }
    }

    private static void TryDeleteDirectory(string path)
    {
        try
        {
            if (Directory.Exists(path))
            {
                Directory.Delete(path, recursive: true);
            }
        }
        catch
        {
            // The low-integrity child may briefly hold handles; the parent is pruned later.
        }
    }

    private SandboxResult ErrorResult(SandboxCandidate candidate, string error, TimeSpan duration) => new()
    {
        Sha256 = candidate.Sha256,
        FileName = Path.GetFileName(candidate.SourcePath),
        Verdict = ThreatVerdict.Clean,
        Score = 0,
        ThreatName = null,
        Summary = "沙箱分析失败：" + error,
        Signals = Array.Empty<SandboxSignal>(),
        Indicators = Array.Empty<NetworkIndicator>(),
        Confidence = "Low",
        EngineVersion = Component.EngineVersion,
        Duration = duration,
        CompletedAt = DateTimeOffset.Now,
        Error = error
    };
}
