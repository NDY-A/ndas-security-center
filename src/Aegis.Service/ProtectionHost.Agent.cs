using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using Aegis.AgentHost;
using Aegis.Core.Infrastructure;
using Aegis.Core.Models;
using Aegis.Core.Remediation;
using Aegis.Core.Service;
using Aegis.Core.Signatures;
using Aegis.Hips;
using Aegis.Sandbox;

namespace Aegis.Service;

public sealed partial class ProtectionHost
{
    private readonly InMemoryAgentReferenceRegistry _agentRefs = new();
    private readonly ConcurrentDictionary<string, NetworkIndicator> _agentIndicators = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, CancellationTokenSource> _agentJobs = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, AgentScheduleState> _agentSchedules = new(StringComparer.Ordinal);
    private readonly SemaphoreSlim _agentScanGate = new(2, 2);
    private long _agentScanned;
    private long _agentThreats;
    private int _agentMaxConcurrent = 1;
    private int _agentMaxCpuPercent = 25;
    private Timer? _agentTickTimer;

    private sealed class AgentScheduleState
    {
        public string ScheduleId { get; init; } = string.Empty;
        public string Kind { get; init; } = "once";
        public int? IntervalSeconds { get; init; }
        public int? IdleSeconds { get; init; }
        public int MaxFilesPerRun { get; init; } = 500;
        public int MaxCpuPercent { get; init; } = 25;
        public bool Enabled { get; set; } = true;
        public DateTimeOffset NextRunAt { get; set; } = DateTimeOffset.UtcNow;
    }

    private sealed class AgentCaseState
    {
        public string CaseId { get; init; } = string.Empty;
        public string RootPath { get; init; } = string.Empty;
        public string? RootSha256 { get; init; }
        public string? RootDetectionId { get; init; }
        public string? ThreatName { get; init; }
        public string Status { get; set; } = "triage";
        public DateTimeOffset OpenedAt { get; init; } = DateTimeOffset.UtcNow;
        public int CascadeDepth { get; init; }
        public List<AgentCaseArtifact> Artifacts { get; } = new();
    }

    private readonly ConcurrentDictionary<string, AgentCaseState> _agentCases = new(StringComparer.Ordinal);
    private readonly object _caseLock = new();
    private long _casesReported;
    private long _casesAutoRemediated;
    private string? _lastCaseId;
    private string? _lastCaseStatus;

    private bool AgentRoutingEnabled => _agent is not null && _settings.AgentModeEnabled;

    private void SendAgentTick()
    {
        var agent = _agent;
        if (agent is null || !agent.ScanGateOpen)
        {
            return;
        }

        try
        {
            var due = new List<AgentDueSchedule>();
            foreach (var schedule in _agentSchedules.Values)
            {
                if (!schedule.Enabled || DateTimeOffset.UtcNow < schedule.NextRunAt)
                {
                    continue;
                }

                due.Add(new AgentDueSchedule { ScheduleId = schedule.ScheduleId, TargetSetId = schedule.ScheduleId });
                if (schedule.Kind == "interval" && schedule.IntervalSeconds is int seconds)
                {
                    schedule.NextRunAt = DateTimeOffset.UtcNow.AddSeconds(seconds);
                }
                else
                {
                    schedule.Enabled = false;
                }
            }

            agent.QueueEvent(AgentProtocol.KindSystemTick, new AgentSystemTickMessage
            {
                TickId = Guid.NewGuid().ToString("N"),
                IntervalMs = 30000,
                IdleSeconds = GetIdleSeconds(),
                CpuPercent = 0,
                QueueDepth = 0,
                DroppedEvents = agent.GetStatus().DroppedEvents,
                DueSchedules = due,
            });
        }
        catch
        {
            // Tick delivery is best-effort.
        }
    }

    private static double GetIdleSeconds()
    {
        try
        {
            var info = new LastInputInfo { Size = (uint)Marshal.SizeOf<LastInputInfo>() };
            if (GetLastInputInfo(ref info))
            {
                var idleMilliseconds = unchecked((uint)Environment.TickCount - info.Time);
                return idleMilliseconds / 1000.0;
            }
        }
        catch
        {
            // Idle detection unavailable.
        }

        return 0;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LastInputInfo
    {
        public uint Size;
        public uint Time;
    }

    [DllImport("user32.dll")]
    private static extern bool GetLastInputInfo(ref LastInputInfo info);

    private void WireAgent(AgentCoordinator coordinator)
    {
        coordinator.ScanRootsProvider = GetAgentScanRoots;
        coordinator.OpenCasesProvider = GetAgentCaseSummaries;
        coordinator.SchedulesProvider = () => Array.Empty<AgentScheduleSummary>();
        coordinator.ValidationContextFactory = () => new AgentValidationContext
        {
            References = _agentRefs,
            ScanRoots = GetAgentScanRoots(),
            RealtimeEnabled = _settings.RealtimeProtectionEnabled,
            MaxScanTargets = 64,
            MaxFilesPerScan = 10000,
            MaxCaseActions = 20,
        };
        coordinator.ActionHandler = HandleAgentActionAsync;
    }

    private IReadOnlyList<AgentScanRoot> GetAgentScanRoots()
    {
        var roots = new List<AgentScanRoot>();

        void Add(string? path, string kind)
        {
            if (string.IsNullOrWhiteSpace(path) || !Directory.Exists(path))
            {
                return;
            }

            if (roots.Any(root => string.Equals(root.Path, path, StringComparison.OrdinalIgnoreCase)))
            {
                return;
            }

            roots.Add(new AgentScanRoot { RootId = "root:" + path, Path = path, Kind = kind });
        }

        try
        {
            foreach (var profile in UserProfileResolver.GetCached(TimeSpan.FromSeconds(30)))
            {
                Add(profile.Desktop, "user");
                Add(profile.Downloads, "user");
                Add(Path.Combine(profile.ProfilePath, "AppData", "Roaming", "Microsoft", "Windows",
                    "Start Menu", "Programs", "Startup"), "user");
            }
        }
        catch
        {
            // Profile resolution is best-effort.
        }

        Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartMenu), "Programs", "Startup"), "system");
        Add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "system");
        Add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "system");
        Add(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "system");
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        Add(Path.Combine(windows, "Temp"), "system");
        Add(Path.Combine(windows, "System32"), "system");
        return roots;
    }

    // ---- sensor routing ----

    private void RouteFileEvent(string path, int? processId, DateTime? processStartTime, string source,
        string? label = null)
    {
        var agent = _agent;
        if (agent is null)
        {
            return;
        }

        var eventId = Guid.NewGuid().ToString("N");
        _agentRefs.AddEvent(eventId, path);
        long size = 0;
        try
        {
            size = new FileInfo(path).Length;
        }
        catch
        {
            // Size is advisory.
        }

        var item = new AgentFileEventItem
        {
            EventId = eventId,
            Path = path,
            Size = size,
            Extension = Path.GetExtension(path).TrimStart('.').ToLowerInvariant(),
            CreatedAt = DateTimeOffset.UtcNow,
            ProcessId = processId,
            Source = source,
            SpecialPathLabel = label,
        };

        agent.QueueEvent(AgentProtocol.KindFileBatch, new AgentFileBatch { Events = { item } });
    }

    private void RouteProcessEvent(HipsProcessObservation observation, DateTime? started)
    {
        var agent = _agent;
        if (agent is null || string.IsNullOrWhiteSpace(observation.ProcessPath))
        {
            return;
        }

        var eventId = Guid.NewGuid().ToString("N");
        _agentRefs.AddEvent(eventId, observation.ProcessPath);
        var item = new AgentProcessEventItem
        {
            EventId = eventId,
            Pid = observation.ProcessId,
            Path = observation.ProcessPath,
            CommandLine = observation.CommandLine,
            StartedAt = started is null ? null : new DateTimeOffset(started.Value),
        };

        agent.QueueEvent(AgentProtocol.KindProcessBatch, new AgentProcessBatch { Events = { item } });
    }

    private void RouteSpecialPathEvent(SpecialPathEntry entry, bool isDirectory)
    {
        var agent = _agent;
        if (agent is null)
        {
            return;
        }

        var eventId = Guid.NewGuid().ToString("N");
        if (!isDirectory)
        {
            _agentRefs.AddEvent(eventId, entry.Path);
        }

        var p7bTrust = "none";
        if (!isDirectory && entry.Path.EndsWith(".p7b", StringComparison.OrdinalIgnoreCase))
        {
            var inspection = P7bRemediator.Inspect(entry.Path);
            p7bTrust = inspection.Verdict switch
            {
                P7bPolicyVerdict.Trusted => "trusted",
                P7bPolicyVerdict.Suspicious => "untrusted",
                _ => "invalid",
            };
        }

        agent.QueueEvent(AgentProtocol.KindSpecialPath, new AgentSpecialPathMessage
        {
            EventId = eventId,
            Path = entry.Path,
            Label = entry.Label ?? string.Empty,
            IsDirectory = isDirectory,
            Comment = entry.Comment,
            Kind = isDirectory ? "directory" : "file",
            P7bTrust = p7bTrust,
        });
    }

    // ---- scan execution ----

    private async Task<FileScanResult?> AnalyzeOnlyAsync(string path, int? processId, DateTime? processStartTime,
        string ruleId, CancellationToken cancellationToken, bool requireDecisiveEvidence = false,
        bool submitSandbox = false)
    {
        if (!await WaitForStableAsync(path, cancellationToken).ConfigureAwait(false))
        {
            return null;
        }

        var scanner = Volatile.Read(ref _scanner);
        if (scanner is null)
        {
            return null;
        }

        try
        {
            var result = await scanner.ScanFileAsync(path, _scanOptions, cancellationToken).ConfigureAwait(false);
            Interlocked.Increment(ref _scannedFiles);
            Interlocked.Increment(ref _agentScanned);
            if (submitSandbox && _settings.SandboxEnabled)
            {
                try
                {
                    _sandbox?.MaybeSubmit(result, processId, processStartTime, ruleId, requireDecisiveEvidence);
                }
                catch
                {
                    // Sandbox submission is best-effort.
                }
            }

            return result;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return null;
        }
    }

    private void PublishScanResult(FileScanResult result, string scanId)
    {
        var agent = _agent;
        if (agent is null)
        {
            return;
        }

        if (result.Verdict is ThreatVerdict.Malicious or ThreatVerdict.Pua)
        {
            Interlocked.Increment(ref _threatsFound);
            Interlocked.Increment(ref _agentThreats);
        }

        var detectionId = Guid.NewGuid().ToString("N");
        _agentRefs.AddDetection(detectionId, result.FilePath);

        var caseId = MaybeOpenAgentCase(result, detectionId);
        if (caseId is null && result.Verdict == ThreatVerdict.Malicious)
        {
            caseId = AttachToRelatedCase(result, detectionId);
        }

        var indicators = new List<AgentIndicatorRef>();
        foreach (var indicator in result.NetworkIndicators)
        {
            var indicatorId = Guid.NewGuid().ToString("N");
            _agentRefs.AddIndicator(indicatorId);
            _agentIndicators[indicatorId] = indicator;
            indicators.Add(new AgentIndicatorRef
            {
                IndicatorId = indicatorId,
                Type = indicator.Kind == IndicatorKind.Domain ? "domain" : "ip",
                Value = indicator.Value,
            });
        }

        agent.QueueEvent(AgentProtocol.KindScanResult, new AgentScanResultMessage
        {
            ScanId = scanId,
            DetectionId = detectionId,
            CaseId = caseId,
            Path = result.FilePath,
            Sha256 = result.Sha256,
            Size = result.Size,
            Kind = result.Kind.ToString().ToLowerInvariant(),
            Verdict = result.Verdict.ToString().ToLowerInvariant(),
            Score = result.Score,
            ThreatName = result.ThreatName,
            Detections = result.Detections.Select(detection => new AgentDetectionEvidence
            {
                Source = detection.Source.ToString(),
                RuleId = detection.RuleId,
                Name = detection.Name,
                Score = detection.Score,
                Severity = detection.Severity.ToString(),
            }).ToList(),
            Indicators = indicators,
            DurationMs = result.ScanDuration.TotalMilliseconds,
        });
    }

    private void PublishSandboxResult(SandboxResult result, SandboxCandidate candidate)
    {
        var agent = _agent;
        if (agent is null)
        {
            return;
        }

        var indicators = new List<AgentIndicatorRef>();
        foreach (var indicator in result.Indicators)
        {
            var indicatorId = Guid.NewGuid().ToString("N");
            _agentRefs.AddIndicator(indicatorId);
            _agentIndicators[indicatorId] = indicator;
            indicators.Add(new AgentIndicatorRef
            {
                IndicatorId = indicatorId,
                Type = indicator.Kind == IndicatorKind.Domain ? "domain" : "ip",
                Value = indicator.Value,
            });
        }

        agent.QueueEvent(AgentProtocol.KindSandboxResult, new AgentSandboxResultMessage
        {
            TaskId = result.Sha256[..Math.Min(12, result.Sha256.Length)],
            Sha256 = result.Sha256,
            Path = candidate.SourcePath,
            Verdict = result.Verdict.ToString().ToLowerInvariant(),
            Score = result.Score,
            Summary = result.Summary,
            Indicators = indicators,
            DroppedFiles = Array.Empty<string>().ToList(),
            Signals = result.Signals.Select(signal => $"{signal.Category}:{signal.Detail}").ToList(),
            Error = result.Error,
        });
    }

    // ---- investigation (always on, no switch) ----

    private string? MaybeOpenAgentCase(FileScanResult result, string detectionId)
    {
        if (_agent is null || result.Verdict != ThreatVerdict.Malicious || !HasDecisiveEvidence(result))
        {
            return null;
        }

        AgentCaseState? opened;
        lock (_caseLock)
        {
            foreach (var existing in _agentCases.Values)
            {
                if (existing.Status != "closed" &&
                    string.Equals(existing.RootPath, result.FilePath, StringComparison.OrdinalIgnoreCase))
                {
                    return existing.CaseId;
                }
            }

            var caseId = Guid.NewGuid().ToString("N");
            opened = new AgentCaseState
            {
                CaseId = caseId,
                RootPath = result.FilePath,
                RootSha256 = result.Sha256,
                RootDetectionId = detectionId,
                ThreatName = result.ThreatName,
                Status = "triage",
            };
            var artifact = new AgentCaseArtifact
            {
                ArtifactId = Guid.NewGuid().ToString("N"),
                Type = "file",
                Value = result.FilePath,
                DetectionId = detectionId,
            };
            opened.Artifacts.Add(artifact);
            _agentRefs.AddArtifact(artifact.ArtifactId, result.FilePath);
            _agentCases[caseId] = opened;
            _lastCaseId = caseId;
            _lastCaseStatus = opened.Status;
        }

        Interlocked.Increment(ref _casesReported);
        PersistAgentCases();
        _hips?.ReportEvent(new HipsEvent(
            DateTimeOffset.Now,
            "HIPS.INVESTIGATION.STARTED",
            "已开启病毒链追查",
            $"{Path.GetFileName(opened.RootPath)} · {opened.ThreatName ?? "未知威胁"}（追查始终启用）",
            HipsSeverity.High,
            null, null, opened.RootPath, false));

        _agent.QueueEvent(AgentProtocol.KindInvestigationOpened, new AgentInvestigationOpenedMessage
        {
            CaseId = opened.CaseId,
            RootDetectionId = opened.RootDetectionId,
            Severity = "high",
            CascadeDepth = 0,
            Artifacts = opened.Artifacts.ToList(),
        });
        return opened.CaseId;
    }

    private string? AttachToRelatedCase(FileScanResult result, string detectionId)
    {
        AgentCaseState? parent;
        AgentCaseArtifact? artifact = null;
        lock (_caseLock)
        {
            var directory = Path.GetDirectoryName(result.FilePath) ?? string.Empty;
            parent = _agentCases.Values.FirstOrDefault(candidate =>
                candidate.Status != "closed" &&
                (string.Equals(candidate.RootSha256, result.Sha256, StringComparison.OrdinalIgnoreCase) ||
                 (directory.Length > 0 &&
                  string.Equals(Path.GetDirectoryName(candidate.RootPath), directory, StringComparison.OrdinalIgnoreCase))));
            if (parent is null || parent.Artifacts.Count >= 50)
            {
                return null;
            }

            artifact = new AgentCaseArtifact
            {
                ArtifactId = Guid.NewGuid().ToString("N"),
                Type = "file",
                Value = result.FilePath,
                DetectionId = detectionId,
            };
            parent.Artifacts.Add(artifact);
            _agentRefs.AddArtifact(artifact.ArtifactId, result.FilePath);
            parent.Status = "expanding";
            _lastCaseStatus = parent.Status;
        }

        if (string.Equals(_settings.InvestigationRemediateMode, "auto", StringComparison.OrdinalIgnoreCase))
        {
            var entry = _blocker?.Block(result.FilePath, "调查级联判定恶意");
            if (entry is not null)
            {
                Interlocked.Increment(ref _casesAutoRemediated);
            }

            _hips?.ReportEvent(new HipsEvent(
                DateTimeOffset.Now,
                "HIPS.INVESTIGATION.REMEDIATED",
                "追查发现级联威胁，已自动处置",
                $"{Path.GetFileName(result.FilePath)} · {result.ThreatName ?? "未知威胁"}（案卷 {parent.CaseId[..8]}）",
                HipsSeverity.Critical,
                null, null, result.FilePath, true));
        }
        else
        {
            _hips?.ReportEvent(new HipsEvent(
                DateTimeOffset.Now,
                "HIPS.INVESTIGATION.PROPOSED",
                "追查发现级联威胁（仅报告）",
                $"{Path.GetFileName(result.FilePath)} · {result.ThreatName ?? "未知威胁"}；处置模式为仅报告，未执行锁定。",
                HipsSeverity.High,
                null, null, result.FilePath, false));
        }

        PersistAgentCases();
        _agent?.QueueEvent(AgentProtocol.KindInvestigationUpdate, new AgentInvestigationUpdateMessage
        {
            CaseId = parent.CaseId,
            Status = parent.Status,
            AddedArtifacts = artifact is null ? new List<AgentCaseArtifact>() : new List<AgentCaseArtifact> { artifact },
        });
        return parent.CaseId;
    }

    private bool IsCascadeRemediationSuppressed(AgentInboundMessage message)
    {
        if (!string.Equals(_settings.InvestigationRemediateMode, "report", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (string.IsNullOrEmpty(message.CaseId) || !_agentCases.TryGetValue(message.CaseId, out var state))
        {
            return false;
        }

        return message.DetectionId is null ||
               !string.Equals(message.DetectionId, state.RootDetectionId, StringComparison.Ordinal);
    }

    private void CloseAgentCase(string? caseId, string? summary)
    {
        if (string.IsNullOrEmpty(caseId) || !_agentCases.TryGetValue(caseId, out var state))
        {
            return;
        }

        state.Status = "closed";
        _lastCaseStatus = "closed";
        PersistAgentCases();
        _hips?.ReportEvent(new HipsEvent(
            DateTimeOffset.Now,
            "HIPS.INVESTIGATION.RESULT",
            "病毒链追查结束",
            string.IsNullOrWhiteSpace(summary) ? $"案卷 {caseId[..8]} 已归档" : summary,
            HipsSeverity.Medium,
            null, null, state.RootPath, false));
    }

    private void PersistAgentCases()
    {
        try
        {
            lock (_caseLock)
            {
                var directory = Path.Combine(ServicePaths.DataRoot, "Agent");
                Directory.CreateDirectory(directory);
                var payload = _agentCases.Values.Select(state => new
                {
                    state.CaseId,
                    state.RootPath,
                    state.RootSha256,
                    state.RootDetectionId,
                    state.ThreatName,
                    state.Status,
                    state.OpenedAt,
                    state.CascadeDepth,
                    Artifacts = state.Artifacts,
                }).ToList();
                File.WriteAllText(Path.Combine(directory, "cases.json"),
                    JsonSerializer.Serialize(payload));
            }
        }
        catch
        {
            // Case persistence is advisory.
        }
    }

    private IReadOnlyList<AgentCaseSummary> GetAgentCaseSummaries()
    {
        return _agentCases.Values
            .Where(state => state.Status != "closed")
            .Select(state => new AgentCaseSummary
            {
                CaseId = state.CaseId,
                Status = state.Status,
                RootPath = state.RootPath,
                Sha256 = state.RootSha256,
                ThreatName = state.ThreatName,
                ArtifactCount = state.Artifacts.Count,
                CascadeDepth = state.CascadeDepth,
                OpenedAt = state.OpenedAt,
            })
            .ToList();
    }

    // ---- action execution ----

    private static bool IsScanOrRemediationAction(string action) => action is
        AgentActionCatalog.LocalAnalyze or AgentActionCatalog.ScriptClassify or
        AgentActionCatalog.ScanPaths or AgentActionCatalog.ScanRelated or
        AgentActionCatalog.SandboxSubmit or AgentActionCatalog.LockFile or
        AgentActionCatalog.TerminateProcess or AgentActionCatalog.BlockNetwork or
        AgentActionCatalog.P7bDecide;

    private async Task<AgentActionResultMessage> HandleAgentActionAsync(AgentInboundMessage message,
        AgentValidationContext context, CancellationToken cancellationToken)
    {
        static AgentActionResultMessage Ok(object? data = null) => new() { Ok = true, Data = data };
        static AgentActionResultMessage Fail(string code, string text) => new() { Ok = false, Code = code, Message = text };

        if (!_settings.RealtimeProtectionEnabled && IsScanOrRemediationAction(message.Action))
        {
            return Fail("E_PROTECTION_OFF", "实时防护已关闭，拒绝扫描与处置动作");
        }

        var args = message.Args;
        try
        {
            switch (message.Action)
            {
                case AgentActionCatalog.LocalAnalyze:
                case AgentActionCatalog.ScriptClassify:
                {
                    if (!AgentPathResolver.TryResolve(context, args, out var path, out var pathError))
                    {
                        return Fail(pathError!.Code!, pathError.Message!);
                    }

                    var submitSandbox = AgentPathResolver.TryGetBool(args, "submitSandbox", out var submit) && submit;
                    var scanId = Guid.NewGuid().ToString("N");
                    var result = await AnalyzeOnlyAsync(path, null, null, "HIPS.AGENT.SCAN", cancellationToken,
                        IsSystemSoftwarePath(path), submitSandbox).ConfigureAwait(false);
                    if (result is null)
                    {
                        return Fail("E_SCAN_FAILED", "扫描失败或文件不可读");
                    }

                    PublishScanResult(result, scanId);
                    return Ok(new { scanId });
                }

                case AgentActionCatalog.LookupIoc:
                {
                    var sha = AgentPathResolver.GetString(args, "sha256") ?? string.Empty;
                    var snapshot = Volatile.Read(ref _snapshot);
                    if (snapshot is not null && snapshot.TryMatchHash(sha, out var signature) && signature is not null)
                    {
                        return Ok(new { known = true, label = signature.ThreatName ?? signature.Label });
                    }

                    return Ok(new { known = false });
                }

                case AgentActionCatalog.ScanPaths:
                case AgentActionCatalog.ScanRelated:
                {
                    if (!TryBuildAgentScanTargets(context, args, out var targets, out var targetError))
                    {
                        return Fail("E_BAD_ARG", targetError!);
                    }

                    var maxFiles = AgentPathResolver.TryGetInt(args, "maxFiles", out var files) ? Math.Clamp(files, 1, 5000) : 1500;
                    var maxSeconds = AgentPathResolver.TryGetInt(args, "maxDurationSeconds", out var seconds)
                        ? Math.Clamp(seconds, 10, 600)
                        : 120;
                    var jobId = Guid.NewGuid().ToString("N");
                    var jobCts = CancellationTokenSource.CreateLinkedTokenSource(_cancellation.Token);
                    _agentJobs[jobId] = jobCts;
                    _ = Task.Run(() => RunAgentScanJobAsync(jobId, jobCts, targets, maxFiles, maxSeconds));
                    return Ok(new { jobId });
                }

                case AgentActionCatalog.CancelJob:
                {
                    var jobId = AgentPathResolver.GetString(args, "jobId");
                    if (jobId is null)
                    {
                        return Fail("E_BAD_ARG", "缺少 jobId");
                    }

                    if (_agentJobs.TryRemove(jobId, out var cancelled))
                    {
                        cancelled.Cancel();
                        return Ok(new { cancelled = true });
                    }

                    return Fail("E_UNKNOWN_JOB", "没有该扫描任务");
                }

                case AgentActionCatalog.SetScanBudget:
                {
                    if (AgentPathResolver.TryGetInt(args, "maxConcurrent", out var concurrent))
                    {
                        _agentMaxConcurrent = Math.Clamp(concurrent, 1, 2);
                    }

                    if (AgentPathResolver.TryGetInt(args, "maxCpuPercent", out var cpu))
                    {
                        _agentMaxCpuPercent = Math.Clamp(cpu, 1, 50);
                    }

                    return Ok(new { maxConcurrent = _agentMaxConcurrent, maxCpuPercent = _agentMaxCpuPercent });
                }

                case AgentActionCatalog.ScheduleScan:
                {
                    var scheduleId = AgentPathResolver.GetString(args, "scheduleId") ?? Guid.NewGuid().ToString("N");
                    var kind = AgentPathResolver.GetString(args, "kind") ?? "once";
                    var enabled = !AgentPathResolver.TryGetBool(args, "enabled", out var enabledValue) || enabledValue;
                    var intervalSeconds = AgentPathResolver.TryGetInt(args, "intervalSeconds", out var interval)
                        ? interval
                        : (int?)null;
                    var idleSeconds = AgentPathResolver.TryGetInt(args, "idleSeconds", out var idle)
                        ? idle
                        : (int?)null;
                    var maxFilesPerRun = AgentPathResolver.TryGetInt(args, "maxFilesPerRun", out var perRun)
                        ? Math.Clamp(perRun, 1, 5000)
                        : 500;
                    var scheduleCpu = AgentPathResolver.TryGetInt(args, "maxCpuPercent", out var scheduleCpuValue)
                        ? Math.Clamp(scheduleCpuValue, 1, 50)
                        : _agentMaxCpuPercent;

                    var schedule = new AgentScheduleState
                    {
                        ScheduleId = scheduleId,
                        Kind = kind,
                        IntervalSeconds = intervalSeconds,
                        IdleSeconds = idleSeconds,
                        MaxFilesPerRun = maxFilesPerRun,
                        MaxCpuPercent = scheduleCpu,
                        Enabled = enabled,
                        NextRunAt = kind == "interval" && intervalSeconds is int seconds
                            ? DateTimeOffset.UtcNow.AddSeconds(seconds)
                            : DateTimeOffset.UtcNow,
                    };
                    _agentSchedules[scheduleId] = schedule;
                    return Ok(new { scheduleId });
                }

                case AgentActionCatalog.Defer:
                    return Ok();

                case AgentActionCatalog.QueryProcessTree:
                {
                    if (!AgentPathResolver.TryGetInt(args, "pid", out var pid))
                    {
                        return Fail("E_BAD_ARG", "缺少 pid");
                    }

                    return Ok(new { nodes = DescribeProcess(pid) });
                }

                case AgentActionCatalog.QueryNetwork:
                    return Ok(new { rows = Array.Empty<object>() });

                case AgentActionCatalog.LockFile:
                {
                    if (IsCascadeRemediationSuppressed(message))
                    {
                        _hips?.ReportEvent(new HipsEvent(DateTimeOffset.Now, "HIPS.INVESTIGATION.PROPOSED",
                            "级联处置被只报告模式抑制", message.Reason, HipsSeverity.Medium,
                            null, null, null, false));
                        return Ok(new { suppressed = true });
                    }

                    if (!AgentPathResolver.TryResolve(context, args, out var path, out var pathError))
                    {
                        return Fail(pathError!.Code!, pathError.Message!);
                    }

                    var entry = _blocker?.Block(path, "agent 判定：" + message.Reason);
                    var locked = entry is not null && (entry.AclApplied || entry.HandleHeld);
                    ReportAgentRemediation("锁定文件", path, locked, message.Reason);
                    return locked
                        ? Ok(new { path, aclApplied = entry!.AclApplied, handleHeld = entry.HandleHeld })
                        : Fail("E_LOCK_FAILED", "文件锁定未生效");
                }

                case AgentActionCatalog.TerminateProcess:
                {
                    if (IsCascadeRemediationSuppressed(message))
                    {
                        _hips?.ReportEvent(new HipsEvent(DateTimeOffset.Now, "HIPS.INVESTIGATION.PROPOSED",
                            "级联处置被只报告模式抑制", message.Reason, HipsSeverity.Medium,
                            null, null, null, false));
                        return Ok(new { suppressed = true });
                    }

                    if (!AgentPathResolver.TryGetInt(args, "pid", out var pid) ||
                        AgentPathResolver.GetString(args, "expectedPath") is not { } expectedPath)
                    {
                        return Fail("E_BAD_ARG", "缺少 pid 或 expectedPath");
                    }

                    DateTime? startTime = null;
                    if (DateTimeOffset.TryParse(AgentPathResolver.GetString(args, "expectedStartTime"), out var parsed))
                    {
                        startTime = parsed.LocalDateTime;
                    }

                    var terminated = ProcessRemediator.TryTerminate(pid, expectedPath, startTime, _exclusions,
                        out var detail);
                    ReportAgentRemediation("终止进程", $"{expectedPath} (PID {pid})", terminated,
                        terminated ? message.Reason : detail);
                    if (terminated)
                    {
                        RecordActiveThreat(pid, expectedPath, "Agent decision", "AGENT", 0);
                    }

                    return terminated
                        ? Ok(new { pid })
                        : Fail("E_TERMINATE_FAILED", detail.Length > 0 ? detail : "进程无法终止");
                }

                case AgentActionCatalog.BlockNetwork:
                {
                    if (IsCascadeRemediationSuppressed(message))
                    {
                        _hips?.ReportEvent(new HipsEvent(DateTimeOffset.Now, "HIPS.INVESTIGATION.PROPOSED",
                            "级联处置被只报告模式抑制", message.Reason, HipsSeverity.Medium,
                            null, null, null, false));
                        return Ok(new { suppressed = true });
                    }

                    var ids = AgentPathResolver.GetArray(args, "indicatorIds");
                    if (ids is null)
                    {
                        return Fail("E_BAD_ARG", "缺少 indicatorIds");
                    }

                    var indicators = new List<NetworkIndicator>();
                    foreach (var element in ids.Value.EnumerateArray())
                    {
                        var indicatorId = element.ValueKind == JsonValueKind.String ? element.GetString() : null;
                        if (indicatorId is not null && _agentIndicators.TryGetValue(indicatorId, out var indicator))
                        {
                            indicators.Add(indicator);
                        }
                    }

                    if (indicators.Count == 0)
                    {
                        return Fail("E_UNKNOWN_REF", "没有可封禁的指标");
                    }

                    var added = _networkBlocker?.Apply(indicators).TotalAdded ?? 0;
                    ReportAgentRemediation("封禁网络指标", $"{indicators.Count} 项（新增 {added}）", added > 0,
                        message.Reason);
                    return Ok(new { added });
                }

                case AgentActionCatalog.P7bDecide:
                {
                    if (IsCascadeRemediationSuppressed(message))
                    {
                        return Ok(new { suppressed = true });
                    }

                    if (!AgentPathResolver.TryResolve(context, args, out var path, out var pathError))
                    {
                        return Fail(pathError!.Code!, pathError.Message!);
                    }

                    var decision = AgentPathResolver.GetString(args, "decision");
                    if (decision == "report")
                    {
                        return Ok(new { action = "report" });
                    }

                    var inspection = P7bRemediator.Inspect(path);
                    if (inspection.Verdict == P7bPolicyVerdict.Trusted)
                    {
                        return Fail("E_TRUSTED_P7B", "p7b 签名可信，拒绝删除");
                    }

                    var deleted = P7bRemediator.TryBackupAndDelete(path, ServicePaths.DataRoot, out var outcome);
                    ReportAgentRemediation("删除 p7b 策略", path, deleted, outcome);
                    return deleted ? Ok(new { deleted }) : Fail("E_DELETE_FAILED", outcome);
                }

                case AgentActionCatalog.RecordIoc:
                {
                    var line = JsonSerializer.Serialize(new
                    {
                        at = DateTimeOffset.UtcNow,
                        sha256 = AgentPathResolver.GetString(args, "sha256"),
                        domain = AgentPathResolver.GetString(args, "domain"),
                        ip = AgentPathResolver.GetString(args, "ip"),
                        label = AgentPathResolver.GetString(args, "label"),
                        reason = message.Reason,
                    });
                    try
                    {
                        var directory = Path.Combine(ServicePaths.DataRoot, "Agent");
                        Directory.CreateDirectory(directory);
                        File.AppendAllText(Path.Combine(directory, "ioc-extra.jsonl"), line + Environment.NewLine);
                    }
                    catch (Exception exception)
                    {
                        return Fail("E_WRITE_FAILED", exception.Message);
                    }

                    return Ok();
                }

                case AgentActionCatalog.CloseCase:
                {
                    var verdict = AgentPathResolver.GetString(args, "verdict") ?? "unknown";
                    var summary = AgentPathResolver.GetString(args, "summary");
                    CloseAgentCase(message.CaseId, summary);
                    _hips?.ReportEvent(new HipsEvent(
                        DateTimeOffset.Now,
                        "HIPS.AGENT.VERDICT",
                        "决策 agent 结案",
                        $"结论：{verdict}；理由：{message.Reason}",
                        verdict == "malicious" ? HipsSeverity.High : HipsSeverity.Medium,
                        null, null, message.CaseId, false));
                    return Ok();
                }

                case AgentActionCatalog.FinalVerdict:
                {
                    var verdict = AgentPathResolver.GetString(args, "verdict") ?? "unknown";
                    _hips?.ReportEvent(new HipsEvent(
                        DateTimeOffset.Now,
                        "HIPS.AGENT.VERDICT",
                        "决策 agent 结论",
                        $"结论：{verdict}；理由：{message.Reason}",
                        verdict == "malicious" ? HipsSeverity.High : HipsSeverity.Medium,
                        null, null, message.CaseId, false));
                    return Ok();
                }

                case AgentActionCatalog.SandboxSubmit:
                {
                    if (!AgentPathResolver.TryResolve(context, args, out var path, out var pathError))
                    {
                        return Fail(pathError!.Code!, pathError.Message!);
                    }

                    var scanId = Guid.NewGuid().ToString("N");
                    var result = await AnalyzeOnlyAsync(path, null, null, "HIPS.AGENT.SANDBOX", cancellationToken,
                        IsSystemSoftwarePath(path), submitSandbox: true).ConfigureAwait(false);
                    if (result is null)
                    {
                        return Fail("E_SCAN_FAILED", "无法读取样本文件");
                    }

                    PublishScanResult(result, scanId);
                    return Ok(new { submitted = true, sha256 = result.Sha256 });
                }

                case AgentActionCatalog.QueryFileMetadata:
                {
                    if (!AgentPathResolver.TryResolve(context, args, out var path, out var pathError))
                    {
                        return Fail(pathError!.Code!, pathError.Message!);
                    }

                    var info = new FileInfo(path);
                    if (!info.Exists)
                    {
                        return Fail("E_NOT_FOUND", "文件不存在");
                    }

                    string? sha = null;
                    if (info.Length <= 64L * 1024 * 1024)
                    {
                        using var stream = File.OpenRead(path);
                        sha = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(stream))
                            .ToLowerInvariant();
                    }

                    return Ok(new
                    {
                        size = info.Length,
                        sha256 = sha,
                        createdAt = info.CreationTimeUtc,
                        modifiedAt = info.LastWriteTimeUtc,
                    });
                }

                case AgentActionCatalog.SandboxStatus:
                case AgentActionCatalog.SandboxReport:
                    return Fail("E_NOT_AVAILABLE", "沙箱任务查询暂未开放");

                default:
                    return Fail(AgentValidationCodes.UnknownAction, "未实现的动作");
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception)
        {
            return Fail("E_INTERNAL", exception.Message);
        }
    }

    private void ReportAgentRemediation(string action, string target, bool success, string detail)
    {
        _hips?.ReportEvent(new HipsEvent(
            DateTimeOffset.Now,
            "HIPS.AGENT.REMEDIATE",
            success ? $"agent 已执行：{action}" : $"agent 尝试{action}未成功",
            detail,
            success ? HipsSeverity.Critical : HipsSeverity.High,
            null, null, target, success));
    }

    private static object DescribeProcess(int pid)
    {
        var nodes = new List<object>();
        try
        {
            using var process = Process.GetProcessById(pid);
            string? image = null;
            DateTimeOffset? started = null;
            try
            {
                image = process.MainModule?.FileName;
                started = process.StartTime;
            }
            catch
            {
                // Protected processes.
            }

            nodes.Add(new { pid, name = process.ProcessName, path = image, startedAt = started });
        }
        catch
        {
            // Process already exited.
        }

        return nodes;
    }

    private bool TryBuildAgentScanTargets(AgentValidationContext context, JsonElement? args,
        out List<string> targets, out string? error)
    {
        targets = new List<string>();
        error = null;
        var roots = context.ScanRoots.ToDictionary(root => root.RootId, root => root.Path, StringComparer.Ordinal);
        var array = AgentPathResolver.GetArray(args, "targets");
        if (array is null)
        {
            error = "缺少 targets";
            return false;
        }

        foreach (var element in array.Value.EnumerateArray())
        {
            string? basePath = null;
            var rootId = AgentPathResolver.GetString(element, "rootId");
            if (!string.IsNullOrEmpty(rootId) && roots.TryGetValue(rootId, out var rootPath))
            {
                basePath = rootPath;
            }

            var parentRef = AgentPathResolver.GetString(element, "parentRef");
            if (basePath is null && !string.IsNullOrEmpty(parentRef) &&
                context.References.TryResolvePath(parentRef, out var parentPath))
            {
                basePath = parentPath;
            }

            if (basePath is null)
            {
                error = "target 引用的 rootId/parentRef 未授权";
                return false;
            }

            var absolute = basePath;
            var relative = AgentPathResolver.GetString(element, "relativePath");
            if (!string.IsNullOrEmpty(relative))
            {
                absolute = Path.GetFullPath(Path.Combine(basePath, relative));
                if (!AgentPathRules.IsUnder(absolute, basePath))
                {
                    error = "relativePath 越出授权根";
                    return false;
                }
            }

            targets.Add(absolute);
        }

        return true;
    }

    private async Task RunAgentScanJobAsync(string jobId, CancellationTokenSource jobCts, List<string> targets,
        int maxFiles, int maxSeconds)
    {
        var cancellationToken = jobCts.Token;
        var deadline = DateTimeOffset.UtcNow.AddSeconds(maxSeconds);
        var count = 0;
        var options = new EnumerationOptions
        {
            RecurseSubdirectories = true,
            IgnoreInaccessible = true,
            AttributesToSkip = FileAttributes.Hidden | FileAttributes.System,
            MaxRecursionDepth = 12,
        };

        try
        {
            await _agentScanGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            _agentJobs.TryRemove(jobId, out _);
            jobCts.Dispose();
            return;
        }

        try
        {
            foreach (var target in targets)
            {
                if (cancellationToken.IsCancellationRequested || count >= maxFiles || DateTimeOffset.UtcNow > deadline)
                {
                    return;
                }

                IEnumerable<string> files;
                try
                {
                    files = Directory.Exists(target)
                        ? Directory.EnumerateFiles(target, "*", options)
                        : new[] { target };
                }
                catch
                {
                    continue;
                }

                foreach (var file in files)
                {
                    if (cancellationToken.IsCancellationRequested || count >= maxFiles || DateTimeOffset.UtcNow > deadline)
                    {
                        return;
                    }

                    if (!ShouldScan(file))
                    {
                        continue;
                    }

                    var system = IsSystemSoftwarePath(file);
                    FileScanResult? result;
                    try
                    {
                        result = await AnalyzeOnlyAsync(file, null, null, "HIPS.AGENT.SCAN",
                            cancellationToken, system).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException)
                    {
                        return;
                    }

                    count++;
                    if (result is not null)
                    {
                        PublishScanResult(result, $"{jobId}:{count}");
                    }

                    await Task.Delay(5, cancellationToken).ConfigureAwait(false);
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Cancelled by the agent or service shutdown.
        }
        catch
        {
            // Scan jobs are best-effort; the agent re-schedules on ticks.
        }
        finally
        {
            _agentScanGate.Release();
            _agentJobs.TryRemove(jobId, out _);
            jobCts.Dispose();
        }
    }
}
