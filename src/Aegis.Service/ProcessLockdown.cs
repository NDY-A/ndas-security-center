using System.Diagnostics;

namespace Aegis.Service;

/// <summary>
/// User-mode containment guard: repeatedly terminates non-essential interactive
/// processes and sweeps away newly launched ones. There is no kernel filter, so
/// "block new processes" is best-effort polling, not a hard guarantee.
/// </summary>
public sealed class ProcessLockdown : IDisposable
{
    private static readonly HashSet<string> ProtectedNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "system", "idle", "registry", "memory compression", "smss", "csrss", "wininit", "winlogon",
        "services", "lsass", "lsaiso", "svchost", "dwm", "fontdrvhost", "ctfmon", "textinputhost",
        "sihost", "taskhostw", "runtimebroker", "startmenuexperiencehost", "shellexperiencehost",
        "searchhost", "applicationframehost", "explorer", "dllhost", "spoolsv", "audiodg",
        "wudfhost", "searchindexer", "securityhealthservice", "securityhealthsystray", "windefend",
        "msmpeng", "nissrv", "mpdefendercoreservice", "smartscreen", "sgrmbroker", "consent",
        "logonui", "lockapp", "userinit", "rdpclip", "ndasservice", "ndas", "aegis"
    };

    private readonly object _lock = new();
    private readonly List<string> _recent = new();
    private CancellationTokenSource? _cancellation;
    private Task? _loop;
    private int _protectedPid;
    private int _targetSessionId;
    private long _kills;
    private string? _lastError;

    public bool IsRunning { get; private set; }

    public long KillCount => Interlocked.Read(ref _kills);

    public string? LastError
    {
        get
        {
            lock (_lock)
            {
                return _lastError;
            }
        }
    }

    public IReadOnlyList<string> Recent
    {
        get
        {
            lock (_lock)
            {
                return _recent.ToArray();
            }
        }
    }

    public void Start(int protectedPid, int targetSessionId)
    {
        lock (_lock)
        {
            if (IsRunning)
            {
                return;
            }

            _protectedPid = protectedPid;
            _targetSessionId = targetSessionId;
            PrivilegeHelper.TryEnable("SeDebugPrivilege", out var privilegeError);
            if (!string.IsNullOrWhiteSpace(privilegeError))
            {
                _lastError = "启用调试权限失败：" + privilegeError;
            }
            _cancellation = new CancellationTokenSource();
            IsRunning = true;
            var token = _cancellation.Token;
            _loop = Task.Run(() => RunAsync(token), CancellationToken.None);
        }
    }

    public void Stop()
    {
        CancellationTokenSource? cancellation;
        Task? loop;
        lock (_lock)
        {
            if (!IsRunning)
            {
                return;
            }

            IsRunning = false;
            cancellation = _cancellation;
            loop = _loop;
            _cancellation = null;
            _loop = null;
        }

        try
        {
            cancellation?.Cancel();
        }
        catch
        {
            // Best-effort teardown.
        }

        try
        {
            loop?.Wait(TimeSpan.FromSeconds(2));
        }
        catch
        {
            // The loop is best-effort during teardown.
        }

        cancellation?.Dispose();
    }

    private async Task RunAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            Sweep();
            try
            {
                await Task.Delay(350, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    private void Sweep()
    {
        Process[] processes;
        try
        {
            processes = Process.GetProcesses();
        }
        catch (Exception exception)
        {
            SetError("枚举进程失败：" + exception.Message);
            return;
        }

        foreach (var process in processes)
        {
            using (process)
            {
                try
                {
                    if (process.Id <= 4 || process.Id == _protectedPid)
                    {
                        continue;
                    }

                    // Only the interactive session that requested containment is swept.
                    // Other local/RDP sessions and session 0 services are left alone.
                    if (process.SessionId != _targetSessionId)
                    {
                        continue;
                    }

                    var name = process.ProcessName;
                    if (ProtectedNames.Contains(name))
                    {
                        continue;
                    }

                    process.Kill(entireProcessTree: false);
                    RecordKill(name, process.Id);
                }
                catch (InvalidOperationException)
                {
                    // Process exited while enumerating.
                }
                catch (System.ComponentModel.Win32Exception exception)
                {
                    SetError("无法终止进程：" + exception.Message);
                }
                catch
                {
                    // Access denied on protected processes is expected.
                }
            }
        }
    }

    private void RecordKill(string name, int pid)
    {
        Interlocked.Increment(ref _kills);
        lock (_lock)
        {
            _recent.Add($"{name} (PID {pid})");
            if (_recent.Count > 25)
            {
                _recent.RemoveAt(0);
            }
        }
    }

    private void SetError(string message)
    {
        lock (_lock)
        {
            _lastError = message;
        }
    }

    public void Dispose() => Stop();
}
