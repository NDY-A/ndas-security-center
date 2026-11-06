using Aegis.Core.Models;

namespace Aegis.Core.Scanning;

public sealed class ScanJob
{
    private readonly object _gate = new();
    private readonly CancellationTokenSource _cancellation = new();
    private readonly TaskCompletionSource<ScanSummary?> _completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private ScanJobState _state = ScanJobState.Queued;
    private ScanProgress? _progress;
    private ScanSummary? _summary;
    private string? _error;
    private DateTimeOffset? _startedAt;
    private DateTimeOffset? _completedAt;
    private bool _cancelRequested;

    public ScanJob(ScanRequest request)
    {
        Id = Guid.NewGuid().ToString("N");
        Request = request;
        SubmittedAt = DateTimeOffset.UtcNow;
    }

    public string Id { get; }

    public ScanRequest Request { get; }

    public DateTimeOffset SubmittedAt { get; }

    public ScanJobState State
    {
        get
        {
            lock (_gate)
            {
                return _state;
            }
        }
    }

    public ScanProgress? Progress
    {
        get
        {
            lock (_gate)
            {
                return _progress;
            }
        }
    }

    public ScanSummary? Summary
    {
        get
        {
            lock (_gate)
            {
                return _summary;
            }
        }
    }

    public string? Error
    {
        get
        {
            lock (_gate)
            {
                return _error;
            }
        }
    }

    public DateTimeOffset? StartedAt
    {
        get
        {
            lock (_gate)
            {
                return _startedAt;
            }
        }
    }

    public DateTimeOffset? CompletedAt
    {
        get
        {
            lock (_gate)
            {
                return _completedAt;
            }
        }
    }

    public bool CancelRequested
    {
        get
        {
            lock (_gate)
            {
                return _cancelRequested;
            }
        }
    }

    public bool IsFinished => State is ScanJobState.Completed or ScanJobState.Failed or ScanJobState.Cancelled;

    public Task<ScanSummary?> Completion => _completion.Task;

    public event EventHandler? Changed;

    internal CancellationToken CancellationToken => _cancellation.Token;

    public void Cancel()
    {
        lock (_gate)
        {
            if (_state is ScanJobState.Completed or ScanJobState.Failed or ScanJobState.Cancelled)
            {
                return;
            }

            _cancelRequested = true;
        }

        try
        {
            _cancellation.Cancel();
        }
        catch (ObjectDisposedException)
        {
            // A completed job may already have released its token source.
        }

        RaiseChanged();
    }

    internal void MarkRunning()
    {
        lock (_gate)
        {
            if (_state != ScanJobState.Queued)
            {
                return;
            }

            _state = ScanJobState.Running;
            _startedAt = DateTimeOffset.UtcNow;
        }

        RaiseChanged();
    }

    internal void ReportProgress(ScanProgress progress)
    {
        lock (_gate)
        {
            if (_state is not (ScanJobState.Queued or ScanJobState.Running))
            {
                return;
            }

            _progress = progress;
        }

        RaiseChanged();
    }

    internal void MarkCompleted(ScanSummary summary)
    {
        lock (_gate)
        {
            if (IsTerminalState(_state))
            {
                return;
            }

            _state = ScanJobState.Completed;
            _summary = summary;
            _completedAt = DateTimeOffset.UtcNow;
        }

        _completion.TrySetResult(summary);
        RaiseChanged();
    }

    internal void MarkCancelled()
    {
        lock (_gate)
        {
            if (IsTerminalState(_state))
            {
                return;
            }

            _state = ScanJobState.Cancelled;
            _cancelRequested = true;
            _completedAt = DateTimeOffset.UtcNow;
        }

        _completion.TrySetResult(null);
        RaiseChanged();
    }

    internal void MarkFailed(string error)
    {
        lock (_gate)
        {
            if (IsTerminalState(_state))
            {
                return;
            }

            _state = ScanJobState.Failed;
            _error = error;
            _completedAt = DateTimeOffset.UtcNow;
        }

        _completion.TrySetResult(null);
        RaiseChanged();
    }

    private static bool IsTerminalState(ScanJobState state) =>
        state is ScanJobState.Completed or ScanJobState.Failed or ScanJobState.Cancelled;

    private void RaiseChanged()
    {
        try
        {
            Changed?.Invoke(this, EventArgs.Empty);
        }
        catch
        {
            // Subscriber failures must not break scan bookkeeping.
        }
    }
}
