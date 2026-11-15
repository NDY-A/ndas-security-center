using System.Collections.Concurrent;
using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Aegis.AgentHost;

public static class AgentValidationCodes
{
    public const string BadVersion = "E_BAD_VERSION";
    public const string BadKind = "E_BAD_KIND";
    public const string BadId = "E_BAD_ID";
    public const string UnknownAction = "E_UNKNOWN_ACTION";
    public const string MissingReason = "E_MISSING_REASON";
    public const string MissingCase = "E_MISSING_CASE";
    public const string MissingArg = "E_MISSING_ARG";
    public const string BadArg = "E_BAD_ARG";
    public const string BadPath = "E_BAD_PATH";
    public const string PathOutsideScope = "E_PATH_OUTSIDE_SCOPE";
    public const string UnknownReference = "E_UNKNOWN_REF";
    public const string LimitExceeded = "E_LIMIT";
}

public sealed class AgentValidationResult
{
    public bool Ok { get; private init; }
    public string? Code { get; private init; }
    public string? Message { get; private init; }
    public AgentActionSpec? Spec { get; private init; }

    public static AgentValidationResult Success(AgentActionSpec spec) =>
        new() { Ok = true, Spec = spec };

    public static AgentValidationResult Fail(string code, string message) =>
        new() { Ok = false, Code = code, Message = message };
}

/// <summary>Service-issued references. The agent may only point at things the host observed.</summary>
public interface IAgentReferenceRegistry
{
    bool ContainsDetection(string detectionId);
    bool ContainsIndicator(string indicatorId);
    bool ContainsArtifact(string artifactId);
    bool TryResolvePath(string referenceId, out string path);
}

public sealed class InMemoryAgentReferenceRegistry : IAgentReferenceRegistry
{
    private readonly record struct PathEntry(string Path, DateTimeOffset AddedAt);

    private readonly ConcurrentDictionary<string, PathEntry> _paths = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, DateTimeOffset> _detections = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, DateTimeOffset> _indicators = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, DateTimeOffset> _artifacts = new(StringComparer.Ordinal);
    private readonly TimeSpan _ttl;

    public InMemoryAgentReferenceRegistry(TimeSpan? ttl = null) =>
        _ttl = ttl ?? TimeSpan.FromHours(24);

    public void AddEvent(string eventId, string path) =>
        _paths[eventId] = new PathEntry(path, DateTimeOffset.UtcNow);

    public void AddDetection(string detectionId, string path)
    {
        _paths[detectionId] = new PathEntry(path, DateTimeOffset.UtcNow);
        _detections[detectionId] = DateTimeOffset.UtcNow;
    }

    public void AddIndicator(string indicatorId) =>
        _indicators[indicatorId] = DateTimeOffset.UtcNow;

    public void AddArtifact(string artifactId, string path)
    {
        _paths[artifactId] = new PathEntry(path, DateTimeOffset.UtcNow);
        _artifacts[artifactId] = DateTimeOffset.UtcNow;
    }

    public bool ContainsDetection(string detectionId) =>
        _detections.TryGetValue(detectionId, out var at) && Fresh(at);

    public bool ContainsIndicator(string indicatorId) =>
        _indicators.TryGetValue(indicatorId, out var at) && Fresh(at);

    public bool ContainsArtifact(string artifactId) =>
        _artifacts.TryGetValue(artifactId, out var at) && Fresh(at);

    public bool TryResolvePath(string referenceId, out string path)
    {
        if (_paths.TryGetValue(referenceId, out var entry) && Fresh(entry.AddedAt))
        {
            path = entry.Path;
            return true;
        }

        path = string.Empty;
        return false;
    }

    public void Prune()
    {
        var cutoff = DateTimeOffset.UtcNow - _ttl;
        foreach (var (key, entry) in _paths)
        {
            if (entry.AddedAt < cutoff)
            {
                _paths.TryRemove(key, out _);
            }
        }

        PruneMap(_detections, cutoff);
        PruneMap(_indicators, cutoff);
        PruneMap(_artifacts, cutoff);
    }

    private static void PruneMap(ConcurrentDictionary<string, DateTimeOffset> map, DateTimeOffset cutoff)
    {
        foreach (var (key, at) in map)
        {
            if (at < cutoff)
            {
                map.TryRemove(key, out _);
            }
        }
    }

    private bool Fresh(DateTimeOffset at) => DateTimeOffset.UtcNow - at <= _ttl;
}

public sealed class AgentValidationContext
{
    public required IAgentReferenceRegistry References { get; init; }
    public IReadOnlyList<AgentScanRoot> ScanRoots { get; init; } = Array.Empty<AgentScanRoot>();
    public bool RealtimeEnabled { get; init; } = true;
    public int MaxScanTargets { get; init; } = 64;
    public int MaxFilesPerScan { get; init; } = 10000;
    public int MaxCaseActions { get; init; } = 20;
    public DateTimeOffset Now { get; init; } = DateTimeOffset.UtcNow;

    public bool IsUnderScanRoot(string fullPath)
    {
        if (ScanRoots.Count == 0)
        {
            return true;
        }

        foreach (var root in ScanRoots)
        {
            if (AgentPathRules.IsUnder(fullPath, root.Path))
            {
                return true;
            }
        }

        return false;
    }
}

public static class AgentPathRules
{
    private static readonly char[] SegmentSeparators = { '\\', '/' };

    public static bool IsUnder(string candidate, string root)
    {
        if (string.IsNullOrWhiteSpace(candidate) || string.IsNullOrWhiteSpace(root))
        {
            return false;
        }

        var full = Path.GetFullPath(candidate);
        var rootFull = Path.GetFullPath(root).TrimEnd(SegmentSeparators);
        if (full.Length <= rootFull.Length || !full.StartsWith(rootFull, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return SegmentSeparators.Contains(full[rootFull.Length]);
    }

    /// <summary>Absolute fixed-disk local path; no UNC, device or alternate-data-stream form.</summary>
    public static bool IsValidLocalPath(string candidate, out string fullPath)
    {
        fullPath = string.Empty;
        if (string.IsNullOrWhiteSpace(candidate) || candidate.Length > 32767)
        {
            return false;
        }

        if (!Path.IsPathFullyQualified(candidate))
        {
            return false;
        }

        if (candidate.StartsWith(@"\\", StringComparison.Ordinal) ||
            candidate.StartsWith(@"\\.\", StringComparison.Ordinal) ||
            candidate.StartsWith(@"\\?\", StringComparison.Ordinal))
        {
            return false;
        }

        var root = Path.GetPathRoot(candidate);
        if (string.IsNullOrEmpty(root) || root.Length != 3 || root[1] != ':' ||
            root[2] is not ('\\' or '/') || !char.IsLetter(root[0]))
        {
            return false;
        }

        var drive = new DriveInfo(root);
        if (drive.DriveType is not (DriveType.Fixed or DriveType.Removable))
        {
            return false;
        }

        var rest = candidate.Substring(3);
        if (rest.Contains(':', StringComparison.Ordinal))
        {
            return false;
        }

        foreach (var segment in rest.Split(SegmentSeparators, StringSplitOptions.RemoveEmptyEntries))
        {
            if (segment == "..")
            {
                return false;
            }
        }

        try
        {
            fullPath = Path.GetFullPath(candidate);
            return true;
        }
        catch
        {
            return false;
        }
    }
}

public static class AgentPathResolver
{
    public static bool TryResolve(AgentValidationContext ctx, JsonElement? args, out string path, out AgentValidationResult? error)
    {
        path = string.Empty;
        error = null;

        var reference = GetString(args, "pathRef");
        if (!string.IsNullOrEmpty(reference))
        {
            if (!ctx.References.TryResolvePath(reference, out path))
            {
                error = AgentValidationResult.Fail(AgentValidationCodes.UnknownReference, $"未签发的路径引用: {reference}");
                return false;
            }

            return true;
        }

        var direct = GetString(args, "path");
        if (string.IsNullOrEmpty(direct))
        {
            error = AgentValidationResult.Fail(AgentValidationCodes.MissingArg, "缺少 pathRef 或 path");
            return false;
        }

        if (!AgentPathRules.IsValidLocalPath(direct, out path))
        {
            error = AgentValidationResult.Fail(AgentValidationCodes.BadPath, "路径必须是本地固定盘绝对路径");
            return false;
        }

        if (!ctx.IsUnderScanRoot(path))
        {
            error = AgentValidationResult.Fail(AgentValidationCodes.PathOutsideScope, "路径不在已授权的扫描范围内");
            return false;
        }

        return true;
    }

    public static string? GetString(JsonElement? args, string name)
    {
        if (args is not { ValueKind: JsonValueKind.Object } obj ||
            !obj.TryGetProperty(name, out var element) ||
            element.ValueKind != JsonValueKind.String)
        {
            return null;
        }

        return element.GetString();
    }

    public static bool TryGetBool(JsonElement? args, string name, out bool value)
    {
        value = false;
        if (args is not { ValueKind: JsonValueKind.Object } obj ||
            !obj.TryGetProperty(name, out var element) ||
            element.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
        {
            return false;
        }

        value = element.GetBoolean();
        return true;
    }

    public static bool TryGetInt(JsonElement? args, string name, out int value)
    {
        value = 0;
        if (args is not { ValueKind: JsonValueKind.Object } obj ||
            !obj.TryGetProperty(name, out var element) ||
            element.ValueKind != JsonValueKind.Number ||
            !element.TryGetInt32(out value))
        {
            return false;
        }

        return true;
    }

    public static bool TryGetLong(JsonElement? args, string name, out long value)
    {
        value = 0;
        if (args is not { ValueKind: JsonValueKind.Object } obj ||
            !obj.TryGetProperty(name, out var element) ||
            element.ValueKind != JsonValueKind.Number ||
            !element.TryGetInt64(out value))
        {
            return false;
        }

        return true;
    }

    public static bool TryGetDouble(JsonElement? args, string name, out double value)
    {
        value = 0;
        if (args is not { ValueKind: JsonValueKind.Object } obj ||
            !obj.TryGetProperty(name, out var element) ||
            element.ValueKind != JsonValueKind.Number ||
            !element.TryGetDouble(out value))
        {
            return false;
        }

        return true;
    }

    public static JsonElement? GetArray(JsonElement? args, string name)
    {
        if (args is not { ValueKind: JsonValueKind.Object } obj ||
            !obj.TryGetProperty(name, out var element) ||
            element.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        return element;
    }
}

public static class AgentActionValidator
{
    private static readonly Regex Sha256Regex = new("^[0-9a-fA-F]{64}$", RegexOptions.Compiled);
    private static readonly Regex HexIdRegex = new("^[A-Za-z0-9_.-]{1,128}$", RegexOptions.Compiled);
    private static readonly Regex DomainRegex = new(
        @"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$",
        RegexOptions.Compiled);

    private static readonly string[] Verdicts = { "malicious", "benign", "suspicious", "clean" };

    public static AgentValidationResult Validate(AgentInboundMessage message, AgentValidationContext ctx)
    {
        if (message.V != AgentProtocol.Version)
        {
            return AgentValidationResult.Fail(AgentValidationCodes.BadVersion, "协议版本不匹配");
        }

        if (!string.Equals(message.Kind, AgentProtocol.KindAction, StringComparison.Ordinal))
        {
            return AgentValidationResult.Fail(AgentValidationCodes.BadKind, "未知消息类型");
        }

        if (string.IsNullOrWhiteSpace(message.Id) || message.Id.Length > 128)
        {
            return AgentValidationResult.Fail(AgentValidationCodes.BadId, "动作缺少合法 id");
        }

        if (!AgentActionCatalog.TryGet(message.Action, out var spec))
        {
            return AgentValidationResult.Fail(AgentValidationCodes.UnknownAction, $"未知动作: {message.Action}");
        }

        if (spec.RequiresReason &&
            (string.IsNullOrWhiteSpace(message.Reason) || message.Reason.Length > AgentProtocol.MaxReasonLength))
        {
            return AgentValidationResult.Fail(AgentValidationCodes.MissingReason, "动作必须携带简短理由");
        }

        if (spec.RequiresCase && string.IsNullOrWhiteSpace(message.CaseId))
        {
            return AgentValidationResult.Fail(AgentValidationCodes.MissingCase, "动作必须关联调查案卷");
        }

        if (message.Reason is { Length: > AgentProtocol.MaxReasonLength })
        {
            return AgentValidationResult.Fail(AgentValidationCodes.BadArg, "理由过长");
        }

        var args = message.Args;
        return spec.Kind switch
        {
            AgentActionKind.Heartbeat => AgentValidationResult.Success(spec),
            AgentActionKind.LookupIoc => ValidateHashAction(args, spec),
            AgentActionKind.LocalAnalyze => ValidatePathAction(ctx, args, spec),
            AgentActionKind.ScriptClassify => ValidatePathAction(ctx, args, spec),
            AgentActionKind.SandboxSubmit => ValidateSandboxSubmit(ctx, args, spec),
            AgentActionKind.SandboxStatus => ValidateTaskAction(args, spec),
            AgentActionKind.SandboxReport => ValidateTaskAction(args, spec),
            AgentActionKind.QueryFileMetadata => ValidatePathAction(ctx, args, spec),
            AgentActionKind.ScanPaths => ValidateScanTargets(ctx, args, spec, ctx.MaxScanTargets),
            AgentActionKind.ScheduleScan => ValidateScheduleScan(ctx, args, spec),
            AgentActionKind.CancelJob => ValidateJobAction(args, spec),
            AgentActionKind.SetScanBudget => ValidateScanBudget(args, spec),
            AgentActionKind.Defer => ValidateDefer(args, spec),
            AgentActionKind.QueryProcessTree => ValidateProcessTree(args, spec),
            AgentActionKind.QueryNetwork => ValidateQueryNetwork(args, spec),
            AgentActionKind.ScanRelated => ValidateScanTargets(ctx, args, spec, ctx.MaxScanTargets),
            AgentActionKind.LockFile => ValidateLockFile(ctx, args, spec),
            AgentActionKind.TerminateProcess => ValidateTerminateProcess(args, spec),
            AgentActionKind.BlockNetwork => ValidateBlockNetwork(ctx, args, spec),
            AgentActionKind.P7bDecide => ValidateP7bDecide(ctx, args, spec),
            AgentActionKind.CloseCase => ValidateVerdictAction(args, spec, requireSummary: true),
            AgentActionKind.FinalVerdict => ValidateVerdictAction(args, spec, requireSummary: false),
            AgentActionKind.RecordIoc => ValidateRecordIoc(args, spec),
            _ => AgentValidationResult.Fail(AgentValidationCodes.UnknownAction, "动作未实现"),
        };
    }

    private static AgentValidationResult ValidateHashAction(JsonElement? args, AgentActionSpec spec)
    {
        var sha = AgentPathResolver.GetString(args, "sha256");
        if (sha is null || !Sha256Regex.IsMatch(sha))
        {
            return AgentValidationResult.Fail(AgentValidationCodes.BadArg, "sha256 必须是 64 位十六进制");
        }

        return AgentValidationResult.Success(spec);
    }

    private static AgentValidationResult ValidatePathAction(AgentValidationContext ctx, JsonElement? args, AgentActionSpec spec)
    {
        return AgentPathResolver.TryResolve(ctx, args, out _, out var error)
            ? AgentValidationResult.Success(spec)
            : error!;
    }

    private static AgentValidationResult ValidateSandboxSubmit(AgentValidationContext ctx, JsonElement? args, AgentActionSpec spec)
    {
        if (!AgentPathResolver.TryResolve(ctx, args, out _, out var error))
        {
            return error!;
        }

        var sha = AgentPathResolver.GetString(args, "sha256");
        if (sha is not null && !Sha256Regex.IsMatch(sha))
        {
            return AgentValidationResult.Fail(AgentValidationCodes.BadArg, "sha256 格式非法");
        }

        if (AgentPathResolver.TryGetInt(args, "processId", out var pid) && pid <= 0)
        {
            return AgentValidationResult.Fail(AgentValidationCodes.BadArg, "processId 非法");
        }

        return AgentValidationResult.Success(spec);
    }

    private static AgentValidationResult ValidateTaskAction(JsonElement? args, AgentActionSpec spec)
    {
        var taskId = AgentPathResolver.GetString(args, "taskId");
        if (taskId is null || !HexIdRegex.IsMatch(taskId))
        {
            return AgentValidationResult.Fail(AgentValidationCodes.BadArg, "taskId 非法");
        }

        return AgentValidationResult.Success(spec);
    }

    private static AgentValidationResult ValidateJobAction(JsonElement? args, AgentActionSpec spec)
    {
        var jobId = AgentPathResolver.GetString(args, "jobId");
        if (jobId is null || !HexIdRegex.IsMatch(jobId))
        {
            return AgentValidationResult.Fail(AgentValidationCodes.BadArg, "jobId 非法");
        }

        return AgentValidationResult.Success(spec);
    }

    private static AgentValidationResult ValidateScanTargets(
        AgentValidationContext ctx, JsonElement? args, AgentActionSpec spec, int maxTargets)
    {
        var targets = AgentPathResolver.GetArray(args, "targets");
        if (targets is null || targets.Value.GetArrayLength() is 0 or > 64)
        {
            return AgentValidationResult.Fail(AgentValidationCodes.BadArg, "targets 数量非法");
        }

        if (targets.Value.GetArrayLength() > maxTargets)
        {
            return AgentValidationResult.Fail(AgentValidationCodes.LimitExceeded, "targets 超过上限");
        }

        if (AgentPathResolver.TryGetInt(args, "maxDurationSeconds", out var duration) &&
            duration is < 10 or > 600)
        {
            return AgentValidationResult.Fail(AgentValidationCodes.BadArg, "maxDurationSeconds 超范围");
        }

        if (AgentPathResolver.TryGetInt(args, "priority", out var priority) && priority is < 0 or > 2)
        {
            return AgentValidationResult.Fail(AgentValidationCodes.BadArg, "priority 超范围");
        }

        foreach (var target in targets.Value.EnumerateArray())
        {
            var error = ValidateSingleTarget(ctx, target);
            if (error is not null)
            {
                return error;
            }
        }

        return AgentValidationResult.Success(spec);
    }

    private static AgentValidationResult? ValidateSingleTarget(AgentValidationContext ctx, JsonElement target)
    {
        if (target.ValueKind != JsonValueKind.Object)
        {
            return AgentValidationResult.Fail(AgentValidationCodes.BadArg, "target 必须是对象");
        }

        var rootId = AgentPathResolver.GetString(target, "rootId");
        var parentRef = AgentPathResolver.GetString(target, "parentRef");
        if (string.IsNullOrEmpty(rootId) && string.IsNullOrEmpty(parentRef))
        {
            return AgentValidationResult.Fail(AgentValidationCodes.MissingArg, "target 需要 rootId 或 parentRef");
        }

        if (!string.IsNullOrEmpty(parentRef) && !ctx.References.TryResolvePath(parentRef, out _))
        {
            return AgentValidationResult.Fail(AgentValidationCodes.UnknownReference, "parentRef 未签发");
        }

        var relative = AgentPathResolver.GetString(target, "relativePath");
        if (!string.IsNullOrEmpty(relative))
        {
            if (Path.IsPathFullyQualified(relative) || relative.Length > 512)
            {
                return AgentValidationResult.Fail(AgentValidationCodes.BadPath, "relativePath 非法");
            }

            var segments = relative.Split(new[] { '\\', '/' }, StringSplitOptions.RemoveEmptyEntries);
            if (segments.Length > 4 || segments.Any(s => s == ".."))
            {
                return AgentValidationResult.Fail(AgentValidationCodes.BadPath, "relativePath 过深或含 ..");
            }
        }

        if (AgentPathResolver.TryGetInt(target, "maxFiles", out var maxFiles) && maxFiles is < 1 or > 10000)
        {
            return AgentValidationResult.Fail(AgentValidationCodes.BadArg, "maxFiles 超范围");
        }

        return null;
    }

    private static AgentValidationResult ValidateScheduleScan(AgentValidationContext ctx, JsonElement? args, AgentActionSpec spec)
    {
        var kind = AgentPathResolver.GetString(args, "kind");
        if (kind is not ("once" or "interval" or "idle"))
        {
            return AgentValidationResult.Fail(AgentValidationCodes.BadArg, "kind 必须是 once/interval/idle");
        }

        if (kind == "interval" &&
            (!AgentPathResolver.TryGetInt(args, "intervalSeconds", out var interval) || interval is < 60 or > 86400))
        {
            return AgentValidationResult.Fail(AgentValidationCodes.BadArg, "intervalSeconds 超范围");
        }

        if (kind == "idle" &&
            (!AgentPathResolver.TryGetInt(args, "idleSeconds", out var idle) || idle is < 60 or > 86400))
        {
            return AgentValidationResult.Fail(AgentValidationCodes.BadArg, "idleSeconds 超范围");
        }

        if (AgentPathResolver.TryGetInt(args, "maxFilesPerRun", out var maxFiles) && maxFiles is < 1 or > 10000)
        {
            return AgentValidationResult.Fail(AgentValidationCodes.BadArg, "maxFilesPerRun 超范围");
        }

        if (AgentPathResolver.TryGetInt(args, "maxCpuPercent", out var cpu) && cpu is < 1 or > 50)
        {
            return AgentValidationResult.Fail(AgentValidationCodes.BadArg, "maxCpuPercent 超范围");
        }

        return ValidateScanTargets(ctx, args, spec, ctx.MaxScanTargets);
    }

    private static AgentValidationResult ValidateScanBudget(JsonElement? args, AgentActionSpec spec)
    {
        if (AgentPathResolver.TryGetInt(args, "maxConcurrent", out var concurrent) && concurrent is < 1 or > 2)
        {
            return AgentValidationResult.Fail(AgentValidationCodes.BadArg, "maxConcurrent 超范围");
        }

        if (AgentPathResolver.TryGetInt(args, "maxCpuPercent", out var cpu) && cpu is < 1 or > 50)
        {
            return AgentValidationResult.Fail(AgentValidationCodes.BadArg, "maxCpuPercent 超范围");
        }

        return AgentValidationResult.Success(spec);
    }

    private static AgentValidationResult ValidateDefer(JsonElement? args, AgentActionSpec spec)
    {
        if (!AgentPathResolver.TryGetInt(args, "milliseconds", out var ms) || ms is < 1 or > 30000)
        {
            return AgentValidationResult.Fail(AgentValidationCodes.BadArg, "milliseconds 超范围");
        }

        return AgentValidationResult.Success(spec);
    }

    private static AgentValidationResult ValidateProcessTree(JsonElement? args, AgentActionSpec spec)
    {
        if (!AgentPathResolver.TryGetInt(args, "pid", out var pid) || pid <= 4)
        {
            return AgentValidationResult.Fail(AgentValidationCodes.BadArg, "pid 非法");
        }

        if (AgentPathResolver.TryGetInt(args, "depth", out var depth) && depth is < 1 or > 4)
        {
            return AgentValidationResult.Fail(AgentValidationCodes.BadArg, "depth 超范围");
        }

        if (AgentPathResolver.TryGetInt(args, "maxNodes", out var nodes) && nodes is < 1 or > 512)
        {
            return AgentValidationResult.Fail(AgentValidationCodes.BadArg, "maxNodes 超范围");
        }

        return AgentValidationResult.Success(spec);
    }

    private static AgentValidationResult ValidateQueryNetwork(JsonElement? args, AgentActionSpec spec)
    {
        if (AgentPathResolver.TryGetInt(args, "pid", out var pid) && pid <= 4)
        {
            return AgentValidationResult.Fail(AgentValidationCodes.BadArg, "pid 非法");
        }

        var domain = AgentPathResolver.GetString(args, "domain");
        if (domain is not null && !DomainRegex.IsMatch(domain))
        {
            return AgentValidationResult.Fail(AgentValidationCodes.BadArg, "domain 格式非法");
        }

        var ip = AgentPathResolver.GetString(args, "ip");
        if (ip is not null && !IPAddress.TryParse(ip, out _))
        {
            return AgentValidationResult.Fail(AgentValidationCodes.BadArg, "ip 格式非法");
        }

        if (AgentPathResolver.TryGetInt(args, "sinceMinutes", out var minutes) && minutes is < 1 or > 1440)
        {
            return AgentValidationResult.Fail(AgentValidationCodes.BadArg, "sinceMinutes 超范围");
        }

        if (AgentPathResolver.TryGetInt(args, "maxRows", out var rows) && rows is < 1 or > 200)
        {
            return AgentValidationResult.Fail(AgentValidationCodes.BadArg, "maxRows 超范围");
        }

        return AgentValidationResult.Success(spec);
    }

    private static AgentValidationResult ValidateLockFile(AgentValidationContext ctx, JsonElement? args, AgentActionSpec spec)
    {
        return AgentPathResolver.TryResolve(ctx, args, out _, out var error)
            ? AgentValidationResult.Success(spec)
            : error!;
    }

    private static AgentValidationResult ValidateTerminateProcess(JsonElement? args, AgentActionSpec spec)
    {
        if (!AgentPathResolver.TryGetInt(args, "pid", out var pid) || pid <= 4)
        {
            return AgentValidationResult.Fail(AgentValidationCodes.BadArg, "pid 非法");
        }

        var expectedPath = AgentPathResolver.GetString(args, "expectedPath");
        if (expectedPath is null || !AgentPathRules.IsValidLocalPath(expectedPath, out _))
        {
            return AgentValidationResult.Fail(AgentValidationCodes.BadPath, "expectedPath 非法");
        }

        var startText = AgentPathResolver.GetString(args, "expectedStartTime");
        if (startText is null || !DateTimeOffset.TryParse(startText, out _))
        {
            return AgentValidationResult.Fail(AgentValidationCodes.BadArg, "expectedStartTime 非法");
        }

        return AgentValidationResult.Success(spec);
    }

    private static AgentValidationResult ValidateBlockNetwork(AgentValidationContext ctx, JsonElement? args, AgentActionSpec spec)
    {
        var ids = AgentPathResolver.GetArray(args, "indicatorIds");
        if (ids is null || ids.Value.GetArrayLength() is 0 or > 128)
        {
            return AgentValidationResult.Fail(AgentValidationCodes.BadArg, "indicatorIds 数量非法");
        }

        foreach (var id in ids.Value.EnumerateArray())
        {
            var text = id.ValueKind == JsonValueKind.String ? id.GetString() : null;
            if (text is null || !ctx.References.ContainsIndicator(text))
            {
                return AgentValidationResult.Fail(AgentValidationCodes.UnknownReference, "indicatorId 未签发");
            }
        }

        return AgentValidationResult.Success(spec);
    }

    private static AgentValidationResult ValidateP7bDecide(AgentValidationContext ctx, JsonElement? args, AgentActionSpec spec)
    {
        if (!AgentPathResolver.TryResolve(ctx, args, out _, out var error))
        {
            return error!;
        }

        var decision = AgentPathResolver.GetString(args, "decision");
        if (decision is not ("report" or "delete"))
        {
            return AgentValidationResult.Fail(AgentValidationCodes.BadArg, "decision 必须是 report/delete");
        }

        return AgentValidationResult.Success(spec);
    }

    private static AgentValidationResult ValidateVerdictAction(JsonElement? args, AgentActionSpec spec, bool requireSummary)
    {
        var verdict = AgentPathResolver.GetString(args, "verdict");
        if (verdict is null || !Verdicts.Contains(verdict, StringComparer.Ordinal))
        {
            return AgentValidationResult.Fail(AgentValidationCodes.BadArg, "verdict 非法");
        }

        if (AgentPathResolver.TryGetDouble(args, "confidence", out var confidence) && confidence is < 0 or > 1)
        {
            return AgentValidationResult.Fail(AgentValidationCodes.BadArg, "confidence 超范围");
        }

        if (requireSummary)
        {
            var summary = AgentPathResolver.GetString(args, "summary");
            if (summary is null || summary.Length > AgentProtocol.MaxReasonLength)
            {
                return AgentValidationResult.Fail(AgentValidationCodes.MissingArg, "summary 必填且不超长");
            }
        }

        return AgentValidationResult.Success(spec);
    }

    private static AgentValidationResult ValidateRecordIoc(JsonElement? args, AgentActionSpec spec)
    {
        var sha = AgentPathResolver.GetString(args, "sha256");
        var domain = AgentPathResolver.GetString(args, "domain");
        var ip = AgentPathResolver.GetString(args, "ip");
        if (sha is null && domain is null && ip is null)
        {
            return AgentValidationResult.Fail(AgentValidationCodes.MissingArg, "至少需要 sha256/domain/ip 之一");
        }

        if (sha is not null && !Sha256Regex.IsMatch(sha))
        {
            return AgentValidationResult.Fail(AgentValidationCodes.BadArg, "sha256 格式非法");
        }

        if (domain is not null && !DomainRegex.IsMatch(domain))
        {
            return AgentValidationResult.Fail(AgentValidationCodes.BadArg, "domain 格式非法");
        }

        if (ip is not null && !IPAddress.TryParse(ip, out _))
        {
            return AgentValidationResult.Fail(AgentValidationCodes.BadArg, "ip 格式非法");
        }

        var label = AgentPathResolver.GetString(args, "label");
        if (label is null || label.Length is 0 or > 128)
        {
            return AgentValidationResult.Fail(AgentValidationCodes.BadArg, "label 必填");
        }

        return AgentValidationResult.Success(spec);
    }
}
