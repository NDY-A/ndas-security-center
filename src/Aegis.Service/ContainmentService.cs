using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Aegis.Core.Infrastructure;
using Aegis.Core.Models;
using Aegis.Core.Remediation;
using Aegis.Core.Service;
using Aegis.Hips;
using Microsoft.Win32;

namespace Aegis.Service;

/// <summary>
/// High-threat containment: sweep non-essential processes, scan critical system
/// locations, lock malicious files, repair boot once, then force a shutdown and
/// queue a post-logon scan for the next start.
/// </summary>
public sealed class ContainmentService : IDisposable
{
    private static readonly HashSet<string> ScannableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".com", ".msi", ".ps1", ".bat", ".cmd",
        ".vbs", ".vbe", ".js", ".jse", ".hta", ".jar", ".p7b"
    };

    private static readonly HashSet<string> SkippedDirectoryNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "winsxs", "windowsapps", "windows defender", "defender", "package cache", "installer",
        "system volume information", "$recycle.bin", "node_modules", ".git", "obj", "bin",
        "microsoft", "windows", "temp", "cache"
    };

    private readonly object _statusLock = new();
    private readonly Func<string, CancellationToken, Task<FileScanResult?>> _scanFile;
    private readonly Func<string, string, ServiceBlockedFile?> _blockFile;
    private readonly IReadOnlyList<string> _exclusions;
    private readonly Action<HipsEvent> _report;
    private ServiceContainmentStatus _status = new();
    private CancellationTokenSource? _cancellation;
    private Task? _run;
    private ProcessLockdown? _lockdown;
    private int _targetSessionId;

    public ContainmentService(
        Func<string, CancellationToken, Task<FileScanResult?>> scanFile,
        Func<string, string, ServiceBlockedFile?> blockFile,
        IReadOnlyList<string> exclusions,
        Action<HipsEvent> report)
    {
        _scanFile = scanFile;
        _blockFile = blockFile;
        _exclusions = exclusions;
        _report = report;
    }

    public bool IsActive
    {
        get
        {
            lock (_statusLock)
            {
                return _status.Active;
            }
        }
    }

    public ServiceContainmentStatus GetStatus() => Clone(_status);

    public bool Start(ServiceThreatIncident incident, int targetSessionId, out string error)
    {
        lock (_statusLock)
        {
            if (_status.Active)
            {
                error = "高威胁强力清除已经在进行中。";
                return false;
            }

            if (targetSessionId <= 0)
            {
                error = "无法确定发起请求的交互会话，已拒绝启动强力清除。";
                return false;
            }

            _targetSessionId = targetSessionId;
            _status = new ServiceContainmentStatus
            {
                Active = true,
                State = ContainmentStates.Starting,
                StartedAt = DateTimeOffset.Now,
                Phase = "正在准备强力清除…",
                Actions = new List<string> { "已收到活动威胁：" + incident.ThreatName }
            };
            _cancellation = new CancellationTokenSource(TimeSpan.FromMinutes(30));
            var token = _cancellation.Token;
            _run = Task.Run(() => RunAsync(incident, token), CancellationToken.None);
            error = string.Empty;
            return true;
        }
    }

    public bool Abort(out string message)
    {
        CancellationTokenSource? cancellation;
        bool shutdownPending;
        lock (_statusLock)
        {
            if (!_status.Active)
            {
                message = "当前没有可以取消的强力清除。";
                return false;
            }

            cancellation = _cancellation;
            shutdownPending = _status.ShutdownPending;
            message = shutdownPending ? "已取消强制关机并解除进程锁定。" : "已请求取消强力清除。";
        }

        if (shutdownPending)
        {
            TryAbortShutdown();
            RemovePostRebootUi();
            _lockdown?.Stop();
            Update(status =>
            {
                status.Active = false;
                status.State = ContainmentStates.Cancelled;
                status.FinishedAt = DateTimeOffset.Now;
                status.ShutdownPending = false;
                status.Phase = "强制关机已取消。";
                AddActionCore(status, "用户取消了倒计时关机，进程锁定已解除，开机自动扫描已撤销。");
            });
            Report("HIPS.CONTAINMENT.CANCELLED", "已取消强制关机",
                "用户在倒计时期间取消了关机，进程锁定已解除，开机自动扫描已撤销。", HipsSeverity.Medium, null, false);
            return true;
        }

        try
        {
            _lockdown?.Stop();
            cancellation?.Cancel();
        }
        catch
        {
            // Best-effort cancellation.
        }

        return true;
    }

    private async Task RunAsync(ServiceThreatIncident incident, CancellationToken cancellationToken)
    {
        try
        {
            Report("HIPS.CONTAINMENT.START", "高威胁强力清除已启动",
                $"{incident.ThreatName}（{incident.ProcessName}，PID {incident.ProcessId}）正在处理：{incident.Evidence}",
                HipsSeverity.Critical, incident.ProcessPath, false);

            Update(status =>
            {
                status.State = ContainmentStates.Lockdown;
                status.Phase = "正在关闭所有非系统必需进程…";
            });

            _lockdown = new ProcessLockdown();
            _lockdown.Start(Environment.ProcessId, _targetSessionId);
            AddAction("进程锁定已启用：关闭非系统必需的用户进程，并持续清扫新进程。");
            await Task.Delay(TimeSpan.FromSeconds(3), cancellationToken).ConfigureAwait(false);

            Update(status =>
            {
                status.GuardSweepKills = (int)_lockdown.KillCount;
                status.Phase = $"进程锁定已生效，已关闭 {_lockdown.KillCount} 个进程。";
            });
            Report("HIPS.CONTAINMENT.LOCKDOWN", "进程锁定已生效",
                $"已关闭 {_lockdown.KillCount} 个非系统必需进程；新进程将被持续清扫（用户态尽力而为，非内核拦截）。",
                HipsSeverity.High, null, false);

            await ScanCriticalLocationsAsync(cancellationToken).ConfigureAwait(false);

            Update(status =>
            {
                status.State = ContainmentStates.RepairingBoot;
                status.Phase = "正在备份 BCD 并修复一次引导…";
            });

            var boot = await BootRepairService.RepairOnceAsync(cancellationToken).ConfigureAwait(false);
            Update(status =>
            {
                status.BootRepairResult = boot.Detail;
                status.Phase = boot.Success ? "引导修复完成。" : "引导修复失败。";
                AddAction(boot.Success ? boot.Detail : "引导修复失败：" + boot.Detail);
            });
            Report(boot.Success ? "HIPS.CONTAINMENT.BOOT_REPAIRED" : "HIPS.CONTAINMENT.BOOT_REPAIR_FAILED",
                boot.Success ? "引导修复完成" : "引导修复失败",
                boot.Detail, boot.Success ? HipsSeverity.High : HipsSeverity.Critical, boot.BackupPath, boot.Success);

            var schedule = SchedulePostRebootUi();
            Update(status =>
            {
                status.Phase = schedule.Success ? "已安排下次开机自动扫描。" : "未能安排开机自动扫描。";
                AddAction(schedule.Detail);
            });
            Report("HIPS.CONTAINMENT.POST_BOOT_SCHEDULED",
                schedule.Success ? "已安排开机自动扫描" : "开机自动扫描安排失败",
                schedule.Detail, schedule.Success ? HipsSeverity.Informational : HipsSeverity.High, null, schedule.Success);

            Update(status =>
            {
                status.State = ContainmentStates.ShuttingDown;
                status.ShutdownPending = true;
                status.Phase = "清除完成，正在强制关机…";
                status.GuardSweepKills = (int)(_lockdown?.KillCount ?? 0);
            });

            var shutdown = TryForceShutdown(out var shutdownDetail);
            Update(status =>
            {
                AddAction(shutdownDetail);
                if (shutdown)
                {
                    status.Phase = "系统将在 60 秒后强制关机。";
                }
                else
                {
                    status.Active = false;
                    status.State = ContainmentStates.Failed;
                    status.FinishedAt = DateTimeOffset.Now;
                    status.LastError = shutdownDetail;
                    status.Phase = "强制关机失败，请手动关机。";
                }
            });
            Report(shutdown ? "HIPS.CONTAINMENT.SHUTDOWN" : "HIPS.CONTAINMENT.SHUTDOWN_FAILED",
                shutdown ? "系统即将强制关机" : "强制关机失败",
                shutdownDetail, shutdown ? HipsSeverity.High : HipsSeverity.Critical, null, shutdown);

            if (!shutdown)
            {
                _lockdown?.Stop();
            }
        }
        catch (OperationCanceledException)
        {
            _lockdown?.Stop();
            Update(status =>
            {
                status.Active = false;
                status.State = ContainmentStates.Cancelled;
                status.FinishedAt = DateTimeOffset.Now;
                status.Phase = "强力清除已取消。";
                status.LastError = "已取消。";
                AddAction("强力清除被取消，进程锁定已解除。");
            });
            Report("HIPS.CONTAINMENT.CANCELLED", "强力清除已取消", "进程锁定已解除，未执行强制关机。",
                HipsSeverity.Medium, null, false);
        }
        catch (Exception exception)
        {
            _lockdown?.Stop();
            Update(status =>
            {
                status.Active = false;
                status.State = ContainmentStates.Failed;
                status.FinishedAt = DateTimeOffset.Now;
                status.LastError = exception.Message;
                status.Phase = "强力清除失败。";
                AddAction("失败：" + exception.Message);
            });
            Report("HIPS.CONTAINMENT.FAILED", "强力清除失败", exception.Message,
                HipsSeverity.Critical, null, false);
        }
    }

    private async Task ScanCriticalLocationsAsync(CancellationToken cancellationToken)
    {
        Update(status =>
        {
            status.State = ContainmentStates.Scanning;
            status.Phase = "正在扫描系统关键位置…";
        });
        Report("HIPS.CONTAINMENT.SCAN_START", "开始扫描系统关键位置",
            "启动目录、驱动目录、系统目录近期可执行文件、ProgramData 与用户临时目录。",
            HipsSeverity.Informational, null, false);

        var deadline = DateTime.UtcNow.AddMinutes(12);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var scanned = 0;
        long threats = 0;

        foreach (var path in EnumerateCriticalCandidates(cancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (DateTime.UtcNow > deadline || scanned >= 20000)
            {
                AddAction("关键位置扫描达到时间/数量上限，已停止扩展扫描。");
                break;
            }

            if (!seen.Add(path))
            {
                continue;
            }

            scanned++;
            FileScanResult? result;
            try
            {
                result = await _scanFile(path, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch
            {
                continue;
            }

            if (result is { Verdict: ThreatVerdict.Malicious } && HasDecisiveEvidence(result))
            {
                threats++;
                Remediate(result);
            }

            if (scanned % 10 == 0)
            {
                Update(status =>
                {
                    status.FilesScanned = scanned;
                    status.CriticalFilesScanned = scanned;
                    status.ThreatsFound = threats;
                    status.CurrentPath = path;
                });
            }
        }

        Update(status =>
        {
            status.FilesScanned = scanned;
            status.CriticalFilesScanned = scanned;
            status.ThreatsFound = threats;
            status.CurrentPath = null;
            status.GuardSweepKills = (int)(_lockdown?.KillCount ?? 0);
            status.Phase = $"关键位置扫描完成：{scanned:N0} 个文件，{threats:N0} 个恶意项。";
        });
        Report("HIPS.CONTAINMENT.SCAN_DONE", "关键位置扫描完成",
            $"扫描 {scanned:N0} 个文件，发现 {threats:N0} 个恶意项。",
            threats > 0 ? HipsSeverity.Critical : HipsSeverity.Informational, null, false);
    }

    private void Remediate(FileScanResult result)
    {
        var reason = result.ThreatName ?? result.VerdictText;
        var userWritable = IsUserWritablePath(result.FilePath);
        var blocked = false;
        if (userWritable)
        {
            try
            {
                var entry = _blockFile(result.FilePath, reason);
                blocked = entry is not null;
            }
            catch
            {
                // Locking is best-effort; the scan continues.
            }
        }

        var terminated = TerminateProcessesRunningFrom(result.FilePath);
        Update(status =>
        {
            if (blocked || terminated > 0)
            {
                status.ThreatsRemediated++;
            }

            status.TerminatedProcesses += terminated;
            AddAction($"已处置 {Path.GetFileName(result.FilePath)}：{reason}"
                      + (blocked ? "，文件已锁定" : userWritable ? "，未能锁定文件" : "，系统目录文件仅记录不加锁")
                      + (terminated > 0 ? $"，终止 {terminated} 个进程" : "，未发现运行中的进程"));
        });
        Report("HIPS.CONTAINMENT.THREAT", "强力清除处置恶意文件",
            $"{result.FilePath} · {reason}（评分 {result.Score}）"
            + (blocked ? "，文件已锁定" : userWritable ? "，未能锁定文件" : "，系统目录文件仅记录不加锁")
            + (terminated > 0 ? $"，终止 {terminated} 个进程" : string.Empty),
            HipsSeverity.Critical, result.FilePath, blocked || terminated > 0);
    }

    private static bool IsUserWritablePath(string path)
    {
        var roots = new List<string> { Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData) };
        foreach (var profile in UserProfileResolver.GetCached(TimeSpan.FromSeconds(10)))
        {
            roots.Add(profile.ProfilePath);
        }

        roots.Add(Path.GetTempPath());
        return roots.Any(root => !string.IsNullOrWhiteSpace(root) && IsUnder(path, root));
    }

    private static bool IsUnder(string path, string directory)
    {
        var root = directory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) +
                   Path.DirectorySeparatorChar;
        return path.StartsWith(root, StringComparison.OrdinalIgnoreCase) ||
               path.Equals(directory, StringComparison.OrdinalIgnoreCase);
    }

    private int TerminateProcessesRunningFrom(string path)
    {
        var terminated = 0;
        var comparisonPath = Path.GetFullPath(path);
        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                try
                {
                    var image = process.MainModule?.FileName;
                    if (string.IsNullOrWhiteSpace(image) ||
                        !string.Equals(Path.GetFullPath(image), comparisonPath, StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    if (ProcessRemediator.TryTerminate(process.Id, comparisonPath, _exclusions, out _))
                    {
                        terminated++;
                    }
                }
                catch
                {
                    // Protected/system processes deny inspection; skip them.
                }
            }
        }

        return terminated;
    }

    private IEnumerable<string> EnumerateCriticalCandidates(CancellationToken cancellationToken)
    {
        var profiles = UserProfileResolver.GetCached(TimeSpan.FromSeconds(10));
        var commonProgramData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);

        foreach (var profile in profiles)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var startup = Path.Combine(profile.ProfilePath, "AppData", "Roaming", "Microsoft", "Windows",
                "Start Menu", "Programs", "Startup");
            foreach (var file in EnumerateFilesSafe(startup, recursive: true, minWriteUtc: null,
                         extensions: null, maxFiles: 2000))
            {
                yield return file;
            }
        }

        var commonStartup = Path.Combine(commonProgramData, "Microsoft", "Windows", "Start Menu",
            "Programs", "Startup");
        foreach (var file in EnumerateFilesSafe(commonStartup, recursive: true, minWriteUtc: null,
                     extensions: null, maxFiles: 2000))
        {
            yield return file;
        }

        var systemRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var recent = DateTime.UtcNow.AddDays(-30);

        foreach (var file in EnumerateFilesSafe(Path.Combine(systemRoot, "System32", "drivers"),
                     recursive: true, minWriteUtc: null, extensions: ScannableExtensions, maxFiles: 5000))
        {
            yield return file;
        }

        foreach (var directory in new[] { "System32", "SysWOW64" })
        {
            foreach (var file in EnumerateFilesSafe(Path.Combine(systemRoot, directory), recursive: false,
                         minWriteUtc: recent, extensions: ScannableExtensions, maxFiles: 8000))
            {
                yield return file;
            }
        }

        foreach (var file in EnumerateFilesSafe(commonProgramData, recursive: true, minWriteUtc: recent,
                     extensions: ScannableExtensions, maxFiles: 8000, maxDepth: 3))
        {
            yield return file;
        }

        foreach (var profile in profiles)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var temp = Path.Combine(profile.ProfilePath, "AppData", "Local", "Temp");
            foreach (var file in EnumerateFilesSafe(temp, recursive: true, minWriteUtc: DateTime.UtcNow.AddDays(-7),
                         extensions: ScannableExtensions, maxFiles: 4000, maxDepth: 2))
            {
                yield return file;
            }
        }
    }

    private static IEnumerable<string> EnumerateFilesSafe(string root, bool recursive, DateTime? minWriteUtc,
        IReadOnlySet<string>? extensions, int maxFiles, int maxDepth = 6)
    {
        if (string.IsNullOrWhiteSpace(root) || !Directory.Exists(root))
        {
            yield break;
        }

        var stack = new Stack<(string Directory, int Depth)>();
        stack.Push((root, 0));
        var emitted = 0;

        while (stack.Count > 0)
        {
            var (directory, depth) = stack.Pop();
            string[] files;
            try
            {
                files = Directory.GetFiles(directory);
            }
            catch
            {
                continue;
            }

            foreach (var file in files)
            {
                if (extensions is not null && !extensions.Contains(Path.GetExtension(file)))
                {
                    continue;
                }

                if (minWriteUtc is DateTime threshold)
                {
                    try
                    {
                        if (File.GetLastWriteTimeUtc(file) < threshold)
                        {
                            continue;
                        }
                    }
                    catch
                    {
                        continue;
                    }
                }

                yield return file;
                emitted++;
                if (emitted >= maxFiles)
                {
                    yield break;
                }
            }

            if (!recursive || depth >= maxDepth)
            {
                continue;
            }

            string[] directories;
            try
            {
                directories = Directory.GetDirectories(directory);
            }
            catch
            {
                continue;
            }

            foreach (var child in directories)
            {
                try
                {
                    var info = new DirectoryInfo(child);
                    if ((info.Attributes & FileAttributes.ReparsePoint) != 0)
                    {
                        continue;
                    }

                    if (SkippedDirectoryNames.Contains(info.Name))
                    {
                        continue;
                    }
                }
                catch
                {
                    continue;
                }

                stack.Push((child, depth + 1));
            }
        }
    }

    private static bool HasDecisiveEvidence(FileScanResult result) =>
        result.Detections.Any(detection => detection.Source is
            DetectionSource.Hash or DetectionSource.PathIoc or DetectionSource.Yara or DetectionSource.BuiltInTest);

    private static (bool Success, string Detail) SchedulePostRebootUi()
    {
        var appPath = ResolveAppPath();
        if (appPath is null)
        {
            return (false, "找不到 NDAS.exe，无法安排重启后自动打开并扫描；请在托盘手动打开。");
        }

        var written = 0;
        var failed = 0;
        foreach (var profile in UserProfileResolver.GetCached(TimeSpan.FromSeconds(5)))
        {
            try
            {
                using var hive = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Default);
                using var runOnce = hive.CreateSubKey(
                    $"{profile.Sid}\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
                if (runOnce is null)
                {
                    failed++;
                    continue;
                }

                runOnce.SetValue("NDASPostRemediationScan", $"\"{appPath}\" --post-remediation-scan",
                    RegistryValueKind.String);
                written++;
            }
            catch
            {
                failed++;
            }
        }

        return written > 0
            ? (true, $"已为 {written} 个用户写入开机自启扫描任务（RunOnce）"
                    + (failed > 0 ? $"，{failed} 个用户写入失败。" : "。"))
            : (false, "写入 RunOnce 失败，未能安排自动扫描。");
    }

    private static string? ResolveAppPath()
    {
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var candidates = new[]
        {
            Path.Combine(programFiles, "NDAS", "NDAS.exe"),
            Path.Combine(AppContext.BaseDirectory, "NDAS.exe"),
            Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "NDAS.exe")),
            Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "NDAS.exe"))
        };

        return candidates.FirstOrDefault(File.Exists);
    }

    private static bool TryForceShutdown(out string detail)
    {
        try
        {
            if (!PrivilegeHelper.TryEnable("SeShutdownPrivilege", out var privilegeError))
            {
                detail = "启用关机权限失败：" + privilegeError;
                return false;
            }

            const uint reason = 0x80000000 | 0x00040000; // planned + application
            if (InitiateSystemShutdownExW(null,
                    "NDAS 高威胁强力清除已完成。系统将在 60 秒后强制关机，下次开机后会自动打开 NDAS 并扫描。",
                    60, true, false, reason))
            {
                detail = "已请求系统在 60 秒后强制关机（下次登录自动扫描）。";
                return true;
            }

            detail = "强制关机请求失败：" + new Win32Exception(Marshal.GetLastWin32Error()).Message;
            return false;
        }
        catch (Exception exception)
        {
            detail = "强制关机调用异常：" + exception.Message;
            return false;
        }
    }

    private static void TryAbortShutdown()
    {
        try
        {
            AbortSystemShutdownW(null);
        }
        catch
        {
            // Best-effort cancellation.
        }
    }

    private static void RemovePostRebootUi()
    {
        foreach (var profile in UserProfileResolver.GetCached(TimeSpan.FromSeconds(5)))
        {
            try
            {
                using var hive = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Default);
                using var runOnce = hive.OpenSubKey(
                    $"{profile.Sid}\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", writable: true);
                runOnce?.DeleteValue("NDASPostRemediationScan", throwOnMissingValue: false);
            }
            catch
            {
                // Best-effort cleanup.
            }
        }
    }

    private void Update(Action<ServiceContainmentStatus> mutate)
    {
        lock (_statusLock)
        {
            mutate(_status);
        }
    }

    private void AddAction(string text)
    {
        lock (_statusLock)
        {
            AddActionCore(_status, text);
        }
    }

    private static void AddActionCore(ServiceContainmentStatus status, string text)
    {
        status.Actions.Add($"{DateTime.Now:HH:mm:ss} {text}");
        if (status.Actions.Count > 60)
        {
            status.Actions.RemoveAt(0);
        }
    }

    private void Report(string ruleId, string title, string detail, HipsSeverity severity, string? target,
        bool blocked)
    {
        try
        {
            _report(new HipsEvent(DateTimeOffset.Now, ruleId, title, detail, severity, null, null, target,
                blocked));
        }
        catch
        {
            // Reporting must not break containment.
        }
    }

    private static ServiceContainmentStatus Clone(ServiceContainmentStatus status) => new()
    {
        Active = status.Active,
        State = status.State,
        StartedAt = status.StartedAt,
        FinishedAt = status.FinishedAt,
        Phase = status.Phase,
        FilesScanned = status.FilesScanned,
        ThreatsFound = status.ThreatsFound,
        CurrentPath = status.CurrentPath,
        TerminatedProcesses = status.TerminatedProcesses,
        GuardSweepKills = status.GuardSweepKills,
        CriticalFilesScanned = status.CriticalFilesScanned,
        ThreatsRemediated = status.ThreatsRemediated,
        BootRepairResult = status.BootRepairResult,
        LastError = status.LastError,
        ShutdownPending = status.ShutdownPending,
        Actions = status.Actions.ToList()
    };

    public void Dispose()
    {
        // Never abort a pending system shutdown here: service stop during Windows
        // shutdown must not cancel the shutdown the user asked for.
        try
        {
            _cancellation?.Cancel();
            _lockdown?.Stop();
        }
        catch
        {
            // Best-effort teardown.
        }

        _lockdown?.Dispose();
        _lockdown = null;
    }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool InitiateSystemShutdownExW(string? machineName, string? message, uint timeout,
        bool forceAppsClosed, bool rebootAfterShutdown, uint reason);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool AbortSystemShutdownW(string? machineName);
}
