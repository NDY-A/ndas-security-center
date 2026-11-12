using Aegis.Core.Models;
using Aegis.Core.Remediation;
using Aegis.Core.Signatures;
using Aegis.Hips;
using Aegis.Sandbox;

namespace Aegis.Service;

public sealed class SandboxCoordinator : IDisposable
{
    private readonly string _dataRoot;
    private readonly Func<SignatureSnapshot?> _signatures;
    private readonly Func<SandboxOptions> _options;
    private readonly Func<string, string, bool> _lockFile;
    private readonly Func<IReadOnlyList<NetworkIndicator>, int> _blockNetwork;
    private readonly Action<int, string, string, string, int> _recordActiveThreat;
    private readonly Action<HipsEvent> _reportEvent;
    private readonly Func<IReadOnlyList<string>> _exclusions;
    private readonly object _sync = new();
    private readonly object _statusLock = new();
    private readonly HashSet<string> _inFlight = new(StringComparer.OrdinalIgnoreCase);
    private readonly LinkedList<DateTimeOffset> _submissionTimes = new();

    private SandboxQueue? _queue;
    private Task? _worker;
    private CancellationTokenSource? _cancellation;
    private SandboxCache? _cache;
    private SandboxEngine? _engine;
    private string _componentVersion = string.Empty;
    private volatile bool _available;
    private volatile bool _analyzing;
    private string? _lastError;
    private long _analyzed;
    private long _malicious;
    private string? _lastVerdict;
    private string? _lastPath;
    private long _lastScore;
    private DateTimeOffset? _lastAt;
    private bool _disposed;

    public SandboxCoordinator(
        string dataRoot,
        Func<SignatureSnapshot?> signatures,
        Func<SandboxOptions> options,
        Func<string, string, bool> lockFile,
        Func<IReadOnlyList<NetworkIndicator>, int> blockNetwork,
        Action<int, string, string, string, int> recordActiveThreat,
        Action<HipsEvent> reportEvent,
        Func<IReadOnlyList<string>> exclusions)
    {
        _dataRoot = dataRoot;
        _signatures = signatures;
        _options = options;
        _lockFile = lockFile;
        _blockNetwork = blockNetwork;
        _recordActiveThreat = recordActiveThreat;
        _reportEvent = reportEvent;
        _exclusions = exclusions;
    }

    public bool Supported => true;

    public void Start()
    {
        try
        {
            Directory.CreateDirectory(_dataRoot);
            var component = SpeakeasyLocator.Locate();
            _componentVersion = component.EngineVersion;
            _available = component.Available;
            _cache = new SandboxCache(Path.Combine(_dataRoot, "cache.json"));

            if (!component.Available)
            {
                _lastError = component.Error;
                Report("HIPS.SANDBOX.UNAVAILABLE", "沙箱组件不可用",
                    component.Error ?? "没有找到内置 Speakeasy 组件，高熵样本仍按常规启发式处理。",
                    HipsSeverity.Medium, null);
                return;
            }

            SpeakeasyRunner.EnsureRunnerOutboundBlocked(component.PythonPath!,
                out var isolationWarning);
            if (isolationWarning is { Length: > 0 })
            {
                _lastError = isolationWarning;
            }

            _engine = new SandboxEngine(_dataRoot, component);
            _queue = new SandboxQueue(_options().QueueCapacity);
            _cancellation = new CancellationTokenSource();
            _worker = Task.Run(() => WorkerLoopAsync(_cancellation.Token));
        }
        catch (Exception exception)
        {
            _available = false;
            _lastError = "沙箱初始化失败：" + exception.Message;
            Report("HIPS.SANDBOX.UNAVAILABLE", "沙箱初始化失败", _lastError,
                HipsSeverity.Medium, null);
        }
    }

    public bool MaybeSubmit(FileScanResult result, int? processId, DateTime? processStartTime,
        string ruleId, bool isSystemPath)
    {
        if (_disposed || _engine is null || _queue is null)
        {
            return false;
        }

        var options = _options();
        if (!options.Enabled)
        {
            return false;
        }

        try
        {
            if (result.Kind == FileKind.Archive)
            {
                return MaybeSubmitArchive(result, options, isSystemPath);
            }

            if (!SandboxTrigger.ShouldSubmit(result, options, isSystemPath, out _))
            {
                return false;
            }

            var candidate = new SandboxCandidate(result.FilePath, result.Sha256, result.Size,
                processId, ruleId, ProcessStartTime: processStartTime);
            return Enqueue(candidate, options);
        }
        catch (Exception exception)
        {
            _lastError = "沙箱触发失败：" + exception.Message;
            return false;
        }
    }

    private bool MaybeSubmitArchive(FileScanResult archive, SandboxOptions options, bool isSystemPath)
    {
        if (isSystemPath)
        {
            return false;
        }

        if (archive.Verdict is not (ThreatVerdict.Clean or ThreatVerdict.Suspicious or ThreatVerdict.Attention))
        {
            return false;
        }

        if (archive.Size < options.MinFileSizeBytes || archive.Size > options.MaxFileSizeBytes)
        {
            return false;
        }

        if (!SandboxCandidateExtractor.IsZipCandidate(archive))
        {
            return false;
        }

        lock (_sync)
        {
            if (!WithinRateLimitCore(options))
            {
                _lastError = "沙箱提交频率超过限制，压缩包未提交。";
                return false;
            }
        }

        var stagingRoot = Path.Combine(_dataRoot, "extract");
        var candidates = SandboxCandidateExtractor.Extract(archive, stagingRoot, options, out var error);
        if (error.Length > 0)
        {
            _lastError = error;
        }

        var submitted = false;
        foreach (var candidate in candidates)
        {
            submitted |= Enqueue(candidate, options);
        }

        if (!submitted && candidates.Count > 0)
        {
            // Draft candidates that never made it into the queue must not leave files behind.
            foreach (var candidate in candidates)
            {
                if (candidate.CleanupDirectory is { Length: > 0 } cleanup)
                {
                    try
                    {
                        if (Directory.Exists(cleanup))
                        {
                            Directory.Delete(cleanup, recursive: true);
                        }
                    }
                    catch
                    {
                        // Best effort.
                    }
                }
            }
        }

        return submitted;
    }

    private bool Enqueue(SandboxCandidate candidate, SandboxOptions options)
    {
        if (_cache is not null &&
            _cache.TryGet(candidate.Sha256, options.ResultCacheTtl, out var cached) &&
            cached is not null)
        {
            UpdateLast(candidate.SourcePath, cached);
            if (cached.Verdict == ThreatVerdict.Malicious && options.AutoRemediate)
            {
                Remediate(candidate, cached, options);
            }

            return false;
        }

        SandboxJob job;
        lock (_sync)
        {
            if (_inFlight.Contains(candidate.Sha256))
            {
                return false;
            }

            if (!WithinRateLimitCore(options))
            {
                _lastError = "沙箱提交频率超过限制（10 分钟内最多 6 个）。";
                return false;
            }

            job = new SandboxJob(Guid.NewGuid().ToString("N"), candidate,
                candidate.AnalysisPath ?? candidate.SourcePath, string.Empty, DateTimeOffset.UtcNow);
            if (_queue is null || !_queue.TryEnqueue(job))
            {
                _lastError = "沙箱队列已满，样本未提交。";
                return false;
            }

            _inFlight.Add(candidate.Sha256);
            _submissionTimes.AddLast(DateTimeOffset.UtcNow);
        }

        var target = candidate.IsArchiveChild
            ? $"{Path.GetFileName(candidate.SourcePath)} → {candidate.ArchiveEntryName}"
            : Path.GetFileName(candidate.SourcePath);
        Report("HIPS.SANDBOX.SUBMITTED", "高熵样本已提交沙箱",
            $"{target}（{candidate.Sha256[..12]}）已排队做本地动态模拟；不会真实运行样本。",
            HipsSeverity.Low, candidate.SourcePath);
        return true;
    }

    private bool WithinRateLimitCore(SandboxOptions options)
    {
        var cutoff = DateTimeOffset.UtcNow.AddMinutes(-10);
        while (_submissionTimes.First is { } first && first.Value < cutoff)
        {
            _submissionTimes.RemoveFirst();
        }

        return _submissionTimes.Count < options.MaxSubmissionsPer10Minutes;
    }

    private async Task WorkerLoopAsync(CancellationToken cancellationToken)
    {
        var queue = _queue;
        if (queue is null)
        {
            return;
        }

        try
        {
            await foreach (var job in queue.ReadAllAsync(cancellationToken).ConfigureAwait(false))
            {
                var options = _options();
                if (!options.Enabled || _engine is null)
                {
                    RemoveInFlight(job.Candidate.Sha256);
                    continue;
                }

                var signatures = _signatures();
                if (signatures is null)
                {
                    RemoveInFlight(job.Candidate.Sha256);
                    continue;
                }

                _analyzing = true;
                SandboxResult result;
                try
                {
                    result = await _engine.AnalyzeAsync(job.Candidate, options, signatures, cancellationToken)
                        .ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    RemoveInFlight(job.Candidate.Sha256);
                    break;
                }
                catch (Exception exception)
                {
                    result = new SandboxResult
                    {
                        Sha256 = job.Candidate.Sha256,
                        FileName = Path.GetFileName(job.Candidate.SourcePath),
                        Verdict = ThreatVerdict.Clean,
                        Score = 0,
                        Summary = "沙箱分析失败：" + exception.Message,
                        Signals = Array.Empty<SandboxSignal>(),
                        Indicators = Array.Empty<NetworkIndicator>(),
                        Confidence = "Low",
                        EngineVersion = _componentVersion,
                        Duration = TimeSpan.Zero,
                        CompletedAt = DateTimeOffset.Now,
                        Error = exception.Message
                    };
                }
                finally
                {
                    _analyzing = false;
                }

                RemoveInFlight(job.Candidate.Sha256);
                try
                {
                    HandleResult(job, result, options);
                }
                catch (Exception exception)
                {
                    _lastError = "沙箱结果处理失败：" + exception.Message;
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown.
        }
        catch (Exception exception)
        {
            _lastError = "沙箱后台循环异常：" + exception.Message;
        }
    }

    private void HandleResult(SandboxJob job, SandboxResult result, SandboxOptions options)
    {
        var candidate = job.Candidate;
        _cache?.Store(result);
        Interlocked.Increment(ref _analyzed);
        if (result.Verdict == ThreatVerdict.Malicious)
        {
            Interlocked.Increment(ref _malicious);
        }

        UpdateLast(candidate.SourcePath, result);
        if (result.Error is { Length: > 0 } error)
        {
            _lastError = error;
        }

        var target = candidate.IsArchiveChild
            ? $"{Path.GetFileName(candidate.SourcePath)} → {candidate.ArchiveEntryName}"
            : Path.GetFileName(candidate.SourcePath);
        var detail = $"{target} · {result.Summary}（置信度 {result.Confidence}，耗时 {result.Duration.TotalSeconds:F0} 秒）";

        var remediated = false;
        if (result.Verdict == ThreatVerdict.Malicious && options.AutoRemediate)
        {
            var actions = Remediate(candidate, result, options);
            if (actions.Count > 0)
            {
                detail += "；" + string.Join("，", actions);
                remediated = true;
            }
        }

        var severity = result.Verdict switch
        {
            ThreatVerdict.Malicious => HipsSeverity.Critical,
            ThreatVerdict.Pua => HipsSeverity.High,
            ThreatVerdict.Attention => HipsSeverity.Medium,
            _ => HipsSeverity.Low
        };
        Report("HIPS.SANDBOX.RESULT", "沙箱分析完成", detail, severity, candidate.SourcePath, remediated);
    }

    private List<string> Remediate(SandboxCandidate candidate, SandboxResult result, SandboxOptions options)
    {
        var actions = new List<string>();
        try
        {
            var lockTarget = candidate.ParentArchivePath ?? candidate.SourcePath;
            if (_lockFile(lockTarget, "沙箱分析判定恶意"))
            {
                actions.Add(candidate.IsArchiveChild
                    ? "已锁定压缩包 " + Path.GetFileName(lockTarget)
                    : "已锁定文件");
            }

            if (!candidate.IsArchiveChild && candidate.ProcessId is int pid && pid > 0)
            {
                if (ProcessRemediator.TryTerminate(pid, candidate.SourcePath, candidate.ProcessStartTime,
                        _exclusions(), out var terminationDetail))
                {
                    actions.Add($"已终止进程 PID {pid}");
                    _recordActiveThreat(pid, candidate.SourcePath,
                        result.ThreatName ?? "Behavior:Win32/Speakeasy.HighEntropy", "SANDBOX", result.Score);
                }
                else if (terminationDetail.Length > 0)
                {
                    actions.Add(terminationDetail);
                }
            }

            if (options.AutoBlockNetwork && result.Indicators.Count > 0)
            {
                var added = _blockNetwork(result.Indicators);
                if (added > 0)
                {
                    actions.Add($"已封禁网络指标 {added} 项");
                }
            }
        }
        catch (Exception exception)
        {
            actions.Add("自动处置失败：" + exception.Message);
        }

        return actions;
    }

    private void UpdateLast(string path, SandboxResult result)
    {
        lock (_statusLock)
        {
            _lastVerdict = result.Verdict.ToString();
            _lastPath = path;
            _lastScore = result.Score;
            _lastAt = result.CompletedAt;
        }
    }

    private void RemoveInFlight(string sha256)
    {
        lock (_sync)
        {
            _inFlight.Remove(sha256);
        }
    }

    public SandboxCoordinatorStatus GetStatus()
    {
        lock (_statusLock)
        {
            return new SandboxCoordinatorStatus
            {
                Supported = Supported,
                Available = _available,
                Enabled = _options().Enabled,
                EngineVersion = _componentVersion,
                QueueDepth = _queue?.Depth ?? 0,
                Analyzing = _analyzing,
                Analyzed = Interlocked.Read(ref _analyzed),
                Malicious = Interlocked.Read(ref _malicious),
                LastVerdict = _lastVerdict,
                LastPath = _lastPath,
                LastScore = _lastScore,
                LastAt = _lastAt,
                LastError = _lastError
            };
        }
    }

    private void Report(string ruleId, string title, string detail, HipsSeverity severity,
        string? target, bool blocked = false)
    {
        try
        {
            _reportEvent(new HipsEvent(DateTimeOffset.Now, ruleId, title, detail, severity,
                null, null, target, blocked));
        }
        catch
        {
            // Event reporting must not break the sandbox pipeline.
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        try
        {
            _queue?.Complete();
            _cancellation?.Cancel();
            if (_worker is not null)
            {
                _worker.Wait(TimeSpan.FromSeconds(5));
            }
        }
        catch
        {
            // Best effort.
        }
        finally
        {
            _cancellation?.Dispose();
            _cancellation = null;
        }
    }
}
