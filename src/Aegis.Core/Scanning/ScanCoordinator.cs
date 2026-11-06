using System.Collections.Concurrent;
using Aegis.Core.Models;

namespace Aegis.Core.Scanning;

public sealed class ScanCoordinator : IDisposable
{
    private const int MaxQueuedJobs = 16;
    private const int MaxRetainedJobs = 100;
    private readonly ConcurrentDictionary<string, ScanJob> _jobs = new(StringComparer.Ordinal);
    private readonly SemaphoreSlim _executionGate = new(1, 1);
    private bool _disposed;

    public ScanJob Start(AegisScanner scanner, ScanRequest request)
    {
        ArgumentNullException.ThrowIfNull(scanner);
        ArgumentNullException.ThrowIfNull(request);
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(ScanCoordinator));
        }

        var active = _jobs.Values.Count(job => !job.IsFinished);
        if (active >= MaxQueuedJobs)
        {
            throw new InvalidOperationException("扫描队列已满，请等待现有任务完成。");
        }

        var job = new ScanJob(request);
        if (!_jobs.TryAdd(job.Id, job))
        {
            throw new InvalidOperationException("无法创建扫描任务。");
        }

        _ = RunAsync(scanner, job);
        return job;
    }

    public ScanJob? Get(string id)
    {
        return _jobs.TryGetValue(id, out var job) ? job : null;
    }

    public ScanJob? ActiveJob => _jobs.Values
        .Where(job => job.State is ScanJobState.Queued or ScanJobState.Running)
        .OrderBy(job => job.SubmittedAt)
        .FirstOrDefault();

    public IReadOnlyList<ScanJob> GetRecent(int count = 10)
    {
        return _jobs.Values
            .OrderByDescending(job => job.SubmittedAt)
            .Take(Math.Clamp(count, 1, MaxRetainedJobs))
            .ToArray();
    }

    public IReadOnlyList<ScanJob> GetRunning()
    {
        return _jobs.Values
            .Where(job => job.State is ScanJobState.Queued or ScanJobState.Running)
            .OrderBy(job => job.SubmittedAt)
            .ToArray();
    }

    private async Task RunAsync(AegisScanner scanner, ScanJob job)
    {
        var gateAcquired = false;
        try
        {
            await _executionGate.WaitAsync(job.CancellationToken).ConfigureAwait(false);
            gateAcquired = true;
            job.MarkRunning();

            var progress = new Progress<ScanProgress>(job.ReportProgress);
            var summary = await new ScanEngine(scanner).ScanAsync(job.Request, progress, job.CancellationToken).ConfigureAwait(false);
            if (summary.Cancelled)
            {
                job.MarkCancelled();
            }
            else
            {
                job.MarkCompleted(summary);
            }
        }
        catch (OperationCanceledException)
        {
            job.MarkCancelled();
        }
        catch (Exception exception)
        {
            job.MarkFailed(SafeError(exception));
        }
        finally
        {
            if (gateAcquired)
            {
                _executionGate.Release();
            }

            TrimHistory();
        }
    }

    private void TrimHistory()
    {
        var completed = _jobs.Values
            .Where(job => job.IsFinished)
            .OrderByDescending(job => job.CompletedAt ?? job.SubmittedAt)
            .Skip(MaxRetainedJobs)
            .ToArray();

        foreach (var job in completed)
        {
            _jobs.TryRemove(job.Id, out _);
        }
    }

    private static string SafeError(Exception exception) => exception switch
    {
        UnauthorizedAccessException => "没有访问扫描目标的权限。",
        DirectoryNotFoundException => "扫描目标不存在。",
        PathTooLongException => "扫描路径过长。",
        IOException => "扫描过程中发生 I/O 错误。",
        ArgumentException => "扫描参数无效。",
        _ => "扫描引擎发生内部错误（" + exception.GetType().Name + "）。"
    };

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        foreach (var job in _jobs.Values)
        {
            if (!job.IsFinished)
            {
                job.Cancel();
            }
        }
    }
}
