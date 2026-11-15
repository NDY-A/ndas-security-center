using System.Text.Json;
using Aegis.Core.Service;

namespace Aegis.AgentHost;

public sealed class AgentCoordinatorStatus
{
    public string State { get; init; } = AgentStates.Unavailable;
    public DateTimeOffset? StateSince { get; init; }
    public string? Version { get; init; }
    public string? LastError { get; init; }
    public int RestartCount { get; init; }
    public bool ModelLoaded { get; init; }
    public long DecisionCount { get; init; }
    public long DecisionErrors { get; init; }
    public int QueuedEvents { get; init; }
    public long DroppedEvents { get; init; }
    public int RttMs { get; init; }
    public bool ScanGateOpen { get; init; }
    public string? ComponentError { get; init; }
}

/// <summary>
/// Supervises the Python decision daemon: launch, handshake, heartbeat, protocol
/// validation, fail-stop restart budget, and the event queue that feeds the agent.
/// When the agent is not Running the scan gate stays closed and nothing falls back
/// to the old hard-coded schedulers.
/// </summary>
public sealed class AgentCoordinator : IAsyncDisposable
{
    private static readonly int[] BackoffSeconds = { 2, 5, 15, 60, 300 };
    private const int MaxConsecutiveFailures = 5;
    private const int RunningQueueLimit = 4096;
    private const int StoppedQueueLimit = 1024;
    private const int MaxActionsPerMinute = 300;
    private static readonly TimeSpan StableResetAfter = TimeSpan.FromMinutes(5);
    // The daemon loads the 300M ONNX model before its first heartbeat; allow
    // slower machines and first-read AV scans some headroom.
    private static readonly TimeSpan HandshakeTimeout = TimeSpan.FromSeconds(25);
    private static readonly TimeSpan HeartbeatTimeout = TimeSpan.FromSeconds(AgentProtocol.HeartbeatTimeoutSeconds);

    private readonly AgentComponentInfo _component;
    private readonly string _dataRoot;
    private readonly string _logsRoot;
    private readonly AgentStateStore _stateStore;
    private readonly object _eventLock = new();
    private readonly Queue<AgentOutboundMessage> _eventQueue = new();
    private readonly SemaphoreSlim _eventSignal = new(0);
    private readonly SemaphoreSlim _retrySignal = new(0);
    private readonly object _stateLock = new();
    private readonly Dictionary<string, DateTimeOffset> _recentActionIds = new(StringComparer.Ordinal);
    private readonly List<DateTimeOffset> _protocolErrorTimes = new();
    private readonly CancellationTokenSource _lifetime = new();

    private AgentLaunchedProcess? _process;
    private AgentConnection? _connection;
    private Task? _supervisorTask;
    private Task? _readLoopTask;
    private Task? _eventLoopTask;
    private DateTimeOffset? _lastHeartbeatAt;
    private DateTimeOffset? _stoppedAt;
    private DateTimeOffset _runningSince;
    private DateTimeOffset _rateWindowStart = DateTimeOffset.UtcNow;
    private int _actionsThisWindow;
    private int _consecutiveFailures;
    private long _outboundSeq;
    private long _droppedEvents;
    private long _droppedDuringStop;
    private long _decisionCount;
    private long _decisionErrors;
    private int _restartCount;
    private int _lastRttMs;
    private bool _modelLoaded;
    private string _state = AgentStates.Starting;
    private string? _lastError;
    private DateTimeOffset? _stateSince;
    private int _stopping;

    public AgentCoordinator(AgentComponentInfo component, string dataRoot, string logsRoot)
    {
        _component = component;
        _dataRoot = dataRoot;
        _logsRoot = logsRoot;
        _stateStore = new AgentStateStore(Path.Combine(dataRoot, "Agent", "state.json"));
    }

    public event Action<string, string?>? StateChanged;

    public AgentPolicy Policy { get; set; } = new();

    public Func<IReadOnlyList<AgentScanRoot>>? ScanRootsProvider { get; set; }

    public Func<IReadOnlyList<AgentCaseSummary>>? OpenCasesProvider { get; set; }

    public Func<IReadOnlyList<AgentScheduleSummary>>? SchedulesProvider { get; set; }

    public Func<AgentValidationContext>? ValidationContextFactory { get; set; }

    public Func<AgentInboundMessage, AgentValidationContext, CancellationToken, Task<AgentActionResultMessage>>? ActionHandler { get; set; }

    public string State
    {
        get
        {
            lock (_stateLock)
            {
                return _state;
            }
        }
    }

    public string? LastError
    {
        get
        {
            lock (_stateLock)
            {
                return _lastError;
            }
        }
    }

    public bool ScanGateOpen => State == AgentStates.Running;

    public int? ProcessId => _process?.ProcessId;

    public bool Available => _component.Available;

    public AgentCoordinatorStatus GetStatus()
    {
        var state = State;
        return new AgentCoordinatorStatus
        {
            State = state,
            StateSince = _stateSince,
            Version = _component.Version,
            LastError = LastError ?? _component.Error,
            RestartCount = _restartCount,
            ModelLoaded = _modelLoaded,
            DecisionCount = Interlocked.Read(ref _decisionCount),
            DecisionErrors = Interlocked.Read(ref _decisionErrors),
            QueuedEvents = CurrentQueueDepth(),
            DroppedEvents = Interlocked.Read(ref _droppedEvents),
            RttMs = _lastRttMs,
            ScanGateOpen = state == AgentStates.Running,
            ComponentError = _component.Error,
        };
    }

    public void Start()
    {
        if (!_component.Available)
        {
            SetState(AgentStates.Unavailable, _component.Error ?? "agent 组件不可用");
            return;
        }

        if (_supervisorTask is not null)
        {
            return;
        }

        _supervisorTask = Task.Run(() => SupervisorLoopAsync(_lifetime.Token));
    }

    public async Task StopAsync()
    {
        if (Interlocked.Exchange(ref _stopping, 1) == 1)
        {
            return;
        }

        _lifetime.Cancel();
        try
        {
            if (_connection is not null)
            {
                using var grace = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                try
                {
                    await _connection.WriteAsync(CreateOutbound(AgentProtocol.KindShutdown,
                        new AgentShutdownMessage { Reason = "service stopping", GraceMs = 2000 }), grace.Token)
                        .ConfigureAwait(false);
                }
                catch
                {
                    // Best effort.
                }
            }
        }
        finally
        {
            Teardown();
        }

        if (_supervisorTask is not null)
        {
            try
            {
                await Task.WhenAny(_supervisorTask, Task.Delay(5000)).ConfigureAwait(false);
            }
            catch
            {
                // ignore
            }
        }
    }

    /// <summary>Manual recovery entry used by the IPC agent-retry command.</summary>
    public void RequestRetry()
    {
        if (State == AgentStates.Failed || State == AgentStates.Stopped)
        {
            _consecutiveFailures = 0;
            PersistState();
            SetState(AgentStates.Restarting, "手动重试");
            try
            {
                _retrySignal.Release();
            }
            catch (SemaphoreFullException)
            {
                // already signaled
            }
        }
    }

    public void QueueEvent(string kind, object? data)
    {
        var limit = ScanGateOpen ? RunningQueueLimit : StoppedQueueLimit;
        lock (_eventLock)
        {
            while (_eventQueue.Count >= limit)
            {
                _eventQueue.Dequeue();
                Interlocked.Increment(ref _droppedEvents);
                if (!ScanGateOpen)
                {
                    Interlocked.Increment(ref _droppedDuringStop);
                }
            }

            _eventQueue.Enqueue(CreateOutbound(kind, data));
        }

        try
        {
            _eventSignal.Release();
        }
        catch (SemaphoreFullException)
        {
            // The event loop will drain on its next wake-up.
        }
    }

    public void NotifyPolicyChanged()
    {
        QueueEvent(AgentProtocol.KindPolicyChanged, new AgentPolicyChangedMessage { Policy = Policy });
    }

    private async Task SupervisorLoopAsync(CancellationToken cancellationToken)
    {
        var persisted = _stateStore.Load();
        _consecutiveFailures = persisted.ConsecutiveFailures;

        while (!cancellationToken.IsCancellationRequested)
        {
            if (_consecutiveFailures >= MaxConsecutiveFailures)
            {
                SetState(AgentStates.Failed, _lastError ?? "agent 连续启动失败");
                try
                {
                    await _retrySignal.WaitAsync(TimeSpan.FromSeconds(30), cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    return;
                }

                if (_consecutiveFailures >= MaxConsecutiveFailures)
                {
                    continue;
                }
            }

            SetState(AgentStates.Starting);

            if (!await LaunchAndHandshakeAsync(cancellationToken).ConfigureAwait(false))
            {
                await HandleFailureAsync(_lastError ?? "agent 启动或握手失败", cancellationToken).ConfigureAwait(false);
                continue;
            }

            _runningSince = DateTimeOffset.UtcNow;
            _lastHeartbeatAt = null;
            _stoppedAt = null;
            SetState(AgentStates.Running);
            SendRecoveryGap();

            var reason = await MonitorAsync(cancellationToken).ConfigureAwait(false);
            if (cancellationToken.IsCancellationRequested)
            {
                return;
            }

            await HandleFailureAsync(reason, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task<bool> LaunchAndHandshakeAsync(CancellationToken cancellationToken)
    {
        Teardown();
        _lastHeartbeatAt = null;
        _stateSince = DateTimeOffset.UtcNow;

        var workRoot = Path.Combine(_dataRoot, "Agent", "work");
        Directory.CreateDirectory(workRoot);
        Directory.CreateDirectory(_logsRoot);

        var options = new AgentLaunchOptions
        {
            ExecutablePath = _component.PythonPath,
            Arguments = new[] { "-B", "-X", "utf8", _component.DaemonPath },
            WorkingDirectory = workRoot,
            LogPath = Path.Combine(_logsRoot, "agent.log"),
        };

        var launched = AgentProcessLauncher.Start(options, out var launchError);
        if (launched is null)
        {
            _lastError = "启动失败：" + launchError;
            return false;
        }

        _process = launched;
        _connection = new AgentConnection(launched.StandardInput, launched.StandardOutput);

        _readLoopTask = Task.Run(() => ReadLoopAsync(_connection, cancellationToken));
        _eventLoopTask = Task.Run(() => EventLoopAsync(_connection, cancellationToken));

        var hello = new AgentHelloMessage
        {
            ProtocolVersion = AgentProtocol.Version,
            AgentVersion = _component.Version ?? "unknown",
            SessionToken = Guid.NewGuid().ToString("N"),
            Policy = Policy,
            Limits = new AgentLimits(),
            ScanRoots = ScanRootsProvider?.Invoke().ToList() ?? new List<AgentScanRoot>(),
            OpenCases = OpenCasesProvider?.Invoke().ToList() ?? new List<AgentCaseSummary>(),
            Schedules = SchedulesProvider?.Invoke().ToList() ?? new List<AgentScheduleSummary>(),
        };

        try
        {
            await _connection.WriteAsync(CreateOutbound(AgentProtocol.KindHello, hello), cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            _lastError = "发送 hello 失败：" + exception.Message;
            return false;
        }

        var deadline = DateTimeOffset.UtcNow + HandshakeTimeout;
        while (DateTimeOffset.UtcNow < deadline && !cancellationToken.IsCancellationRequested)
        {
            if (_lastHeartbeatAt is not null)
            {
                return true;
            }

            if (_readLoopTask.IsCompleted)
            {
                _lastError = "agent 在握手前退出";
                return false;
            }

            await Task.Delay(100, cancellationToken).ConfigureAwait(false);
        }

        _lastError = "握手超时（未收到首个心跳）";
        return false;
    }

    private async Task<string> MonitorAsync(CancellationToken cancellationToken)
    {
        var protocolErrorWindow = TimeSpan.FromSeconds(60);
        while (!cancellationToken.IsCancellationRequested)
        {
            await Task.Delay(1000, cancellationToken).ConfigureAwait(false);

            if (_readLoopTask is { IsCompleted: true })
            {
                return "agent 进程断开";
            }

            var heartbeat = _lastHeartbeatAt;
            if (heartbeat is not null && DateTimeOffset.UtcNow - heartbeat.Value > HeartbeatTimeout)
            {
                return "心跳超时";
            }

            if (_consecutiveFailures > 0 && DateTimeOffset.UtcNow - _runningSince > StableResetAfter)
            {
                _consecutiveFailures = 0;
                PersistState();
            }

            lock (_protocolErrorTimes)
            {
                _protocolErrorTimes.RemoveAll(at => DateTimeOffset.UtcNow - at > protocolErrorWindow);
                if (_protocolErrorTimes.Count >= 3)
                {
                    return "协议错误过多";
                }
            }
        }

        return "服务停止";
    }

    private async Task HandleFailureAsync(string reason, CancellationToken cancellationToken)
    {
        _stoppedAt = DateTimeOffset.UtcNow;
        _lastError = reason;
        _consecutiveFailures++;
        _restartCount++;
        PersistState();
        Teardown();

        if (_consecutiveFailures >= MaxConsecutiveFailures)
        {
            SetState(AgentStates.Failed, reason);
            return;
        }

        SetState(AgentStates.Restarting, reason);
        var delayIndex = Math.Min(_consecutiveFailures - 1, BackoffSeconds.Length - 1);
        var delay = TimeSpan.FromSeconds(BackoffSeconds[delayIndex]);
        try
        {
            await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Shutting down.
        }
    }

    private async Task ReadLoopAsync(AgentConnection connection, CancellationToken cancellationToken)
    {
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var result = await connection.ReadAsync(cancellationToken).ConfigureAwait(false);
                switch (result.Status)
                {
                    case AgentReadStatus.EndOfStream:
                        return;

                    case AgentReadStatus.BadLine:
                        RegisterProtocolError(result.Error ?? "协议行无法解析");
                        continue;

                    case AgentReadStatus.Message when result.Message is not null:
                        await HandleInboundAsync(connection, result.Message, cancellationToken).ConfigureAwait(false);
                        continue;
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Shutdown.
        }
        catch (Exception exception)
        {
            _lastError = "读取 agent 输出失败：" + exception.Message;
        }
    }

    private async Task HandleInboundAsync(AgentConnection connection, AgentInboundMessage message,
        CancellationToken cancellationToken)
    {
        if (string.Equals(message.Action, AgentActionCatalog.Heartbeat, StringComparison.Ordinal))
        {
            _lastHeartbeatAt = DateTimeOffset.UtcNow;
            if (_runningSince != default)
            {
                _lastRttMs = (int)Math.Clamp((DateTimeOffset.UtcNow - _runningSince).TotalMilliseconds % 1000, 0, 999);
            }

            if (message.Args is { ValueKind: JsonValueKind.Object } args &&
                args.TryGetProperty("modelLoaded", out var modelElement) &&
                modelElement.ValueKind is JsonValueKind.True or JsonValueKind.False)
            {
                _modelLoaded = modelElement.GetBoolean();
            }

            return;
        }

        PruneActionIds();

        if (!TryConsumeRateBudget())
        {
            _decisionErrors++;
            await WriteResultAsync(connection, new AgentActionResultMessage
            {
                ActionId = message.Id,
                Ok = false,
                Code = "E_RATE_LIMIT",
                Message = "动作速率超限",
            }, cancellationToken).ConfigureAwait(false);
            return;
        }

        if (string.IsNullOrEmpty(message.Id) || _recentActionIds.ContainsKey(message.Id))
        {
            _decisionErrors++;
            await WriteResultAsync(connection, new AgentActionResultMessage
            {
                ActionId = message.Id,
                Ok = false,
                Code = AgentValidationCodes.BadId,
                Message = "动作 id 重复或缺失",
            }, cancellationToken).ConfigureAwait(false);
            return;
        }

        _recentActionIds[message.Id] = DateTimeOffset.UtcNow;

        var context = ValidationContextFactory?.Invoke() ?? new AgentValidationContext
        {
            References = new InMemoryAgentReferenceRegistry(),
        };

        var validation = AgentActionValidator.Validate(message, context);
        if (!validation.Ok)
        {
            _decisionErrors++;
            await WriteResultAsync(connection, new AgentActionResultMessage
            {
                ActionId = message.Id,
                Ok = false,
                Code = validation.Code,
                Message = validation.Message,
            }, cancellationToken).ConfigureAwait(false);
            return;
        }

        Interlocked.Increment(ref _decisionCount);

        AgentActionResultMessage result;
        if (ActionHandler is null)
        {
            result = new AgentActionResultMessage
            {
                ActionId = message.Id,
                Ok = false,
                Code = "E_NO_HANDLER",
                Message = "动作执行器未装配",
            };
        }
        else
        {
            try
            {
                result = await ActionHandler(message, context, cancellationToken).ConfigureAwait(false);
                result.ActionId = message.Id;
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception exception)
            {
                _decisionErrors++;
                result = new AgentActionResultMessage
                {
                    ActionId = message.Id,
                    Ok = false,
                    Code = "E_INTERNAL",
                    Message = exception.Message,
                };
            }
        }

        await WriteResultAsync(connection, result, cancellationToken).ConfigureAwait(false);
    }

    private async Task EventLoopAsync(AgentConnection connection, CancellationToken cancellationToken)
    {
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                await _eventSignal.WaitAsync(cancellationToken).ConfigureAwait(false);
                if (!ScanGateOpen)
                {
                    continue;
                }

                AgentOutboundMessage? next;
                lock (_eventLock)
                {
                    next = _eventQueue.Count > 0 ? _eventQueue.Dequeue() : null;
                }

                if (next is null)
                {
                    continue;
                }

                await connection.WriteAsync(next, cancellationToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            // Shutdown.
        }
        catch (Exception exception)
        {
            _lastError = "向 agent 写入事件失败：" + exception.Message;
        }
    }

    private void SendRecoveryGap()
    {
        var dropped = Interlocked.Exchange(ref _droppedDuringStop, 0);
        var stoppedAt = _stoppedAt;
        if (stoppedAt is null && dropped == 0)
        {
            return;
        }

        var resumedAt = DateTimeOffset.UtcNow;
        QueueEvent(AgentProtocol.KindRecoveryGap, new AgentRecoveryGapMessage
        {
            StoppedAt = stoppedAt ?? resumedAt,
            ResumedAt = resumedAt,
            DroppedEventCount = dropped,
            GapSeconds = (resumedAt - (stoppedAt ?? resumedAt)).TotalSeconds,
        });
    }

    private void RegisterProtocolError(string detail)
    {
        lock (_protocolErrorTimes)
        {
            _protocolErrorTimes.Add(DateTimeOffset.UtcNow);
        }

        _lastError = detail;
    }

    private bool TryConsumeRateBudget()
    {
        var now = DateTimeOffset.UtcNow;
        if (now - _rateWindowStart >= TimeSpan.FromMinutes(1))
        {
            _rateWindowStart = now;
            _actionsThisWindow = 0;
        }

        _actionsThisWindow++;
        return _actionsThisWindow <= MaxActionsPerMinute;
    }

    private void PruneActionIds()
    {
        var cutoff = DateTimeOffset.UtcNow - TimeSpan.FromMinutes(5);
        var stale = _recentActionIds.Where(pair => pair.Value < cutoff).Select(pair => pair.Key).ToList();
        foreach (var key in stale)
        {
            _recentActionIds.Remove(key);
        }
    }

    private async Task WriteResultAsync(AgentConnection connection, AgentActionResultMessage result,
        CancellationToken cancellationToken)
    {
        try
        {
            await connection.WriteAsync(CreateOutbound(AgentProtocol.KindResult, result), cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            _lastError = "回写动作结果失败：" + exception.Message;
        }
    }

    private AgentOutboundMessage CreateOutbound(string kind, object? data) =>
        AgentOutboundMessage.Create(kind, data, Interlocked.Increment(ref _outboundSeq));

    private void Teardown()
    {
        try
        {
            _process?.Kill();
        }
        catch
        {
            // Best effort.
        }

        _process?.Dispose();
        _process = null;

        if (_connection is not null)
        {
            try
            {
                _connection.DisposeAsync().AsTask().Wait(500);
            }
            catch
            {
                // ignore
            }
        }

        _connection = null;
        _readLoopTask = null;
        _eventLoopTask = null;
        _lastHeartbeatAt = null;
    }

    private void SetState(string state, string? error = null)
    {
        lock (_stateLock)
        {
            _state = state;
            _stateSince = DateTimeOffset.UtcNow;
            if (error is not null)
            {
                _lastError = error;
            }
        }

        if (error is not null)
        {
            _lastError = error;
        }

        PersistState(state);
        StateChanged?.Invoke(state, error);
    }

    private void PersistState(string? state = null)
    {
        var store = _stateStore.Load();
        store.ConsecutiveFailures = _consecutiveFailures;
        store.LastState = state ?? State;
        store.AgentVersion = _component.Version;
        _stateStore.Save(store);
    }

    private int CurrentQueueDepth()
    {
        lock (_eventLock)
        {
            return _eventQueue.Count;
        }
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync().ConfigureAwait(false);
        _lifetime.Dispose();
        _eventSignal.Dispose();
        _retrySignal.Dispose();
    }
}
