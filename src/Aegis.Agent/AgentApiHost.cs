using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Aegis.Agent.Http;
using Aegis.Core.Infrastructure;
using Aegis.Core.Models;
using Aegis.Core.Scanning;
using Aegis.Hips;

namespace Aegis.Agent;

/// <summary>
/// Loopback-only automation API. It intentionally supports no CORS, no browser
/// origins, no chunked bodies and no HTTP/2. Every route requires the generated
/// Bearer key.
/// </summary>
public sealed class AgentApiHost : IAsyncDisposable
{
    private readonly AgentApiOptions _options;
    private readonly ScanCoordinator _coordinator;
    private readonly Func<AegisScanner?> _scannerProvider;
    private readonly Func<ScanOptions> _scanOptionsProvider;
    private readonly HipsService? _hips;
    private readonly object _lifecycleLock = new();
    private readonly object _keyLock = new();
    private AgentHttpServer? _server;
    private byte[]? _keyHash;
    private DateTimeOffset? _startedAt;
    private string? _lastError;

    public AgentApiHost(
        AgentApiOptions options,
        ScanCoordinator coordinator,
        Func<AegisScanner?> scannerProvider,
        Func<ScanOptions> scanOptionsProvider,
        HipsService? hips = null)
    {
        _options = options;
        _coordinator = coordinator;
        _scannerProvider = scannerProvider;
        _scanOptionsProvider = scanOptionsProvider;
        _hips = hips;
    }

    public bool IsRunning
    {
        get
        {
            lock (_lifecycleLock)
            {
                return _server?.IsRunning == true;
            }
        }
    }

    public int Port
    {
        get
        {
            lock (_lifecycleLock)
            {
                return _server?.Port ?? 0;
            }
        }
    }

    public string BaseUrl => IsRunning ? $"http://127.0.0.1:{Port}" : string.Empty;

    public string? LastError
    {
        get
        {
            lock (_lifecycleLock)
            {
                return _lastError;
            }
        }
    }

    public long RequestCount
    {
        get
        {
            lock (_lifecycleLock)
            {
                return _server?.RequestCount ?? 0;
            }
        }
    }

    public TimeSpan Uptime
    {
        get
        {
            lock (_lifecycleLock)
            {
                return _startedAt is null ? TimeSpan.Zero : DateTimeOffset.UtcNow - _startedAt.Value;
            }
        }
    }

    public event EventHandler? StateChanged;

    public void Start(string apiKey)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(apiKey);

        lock (_lifecycleLock)
        {
            if (_server?.IsRunning == true)
            {
                throw new InvalidOperationException("自动化接口已在运行。");
            }

            var newHash = HashApiKey(apiKey);
            var server = new AgentHttpServer(_options, HandleRequestAsync);
            try
            {
                lock (_keyLock)
                {
                    _keyHash = newHash;
                }

                server.Start(_options.Port);
                _server = server;
                _startedAt = DateTimeOffset.UtcNow;
                _lastError = null;
            }
            catch (Exception exception)
            {
                _lastError = DescribeStartFailure(exception);
                throw new InvalidOperationException(_lastError, exception);
            }
        }

        RaiseStateChanged();
    }

    public async Task StopAsync()
    {
        AgentHttpServer? server;
        lock (_lifecycleLock)
        {
            server = _server;
            _server = null;
            _startedAt = null;
        }

        if (server is not null)
        {
            await server.StopAsync().ConfigureAwait(false);
        }

        RaiseStateChanged();
    }

    public void UpdateKey(string apiKey)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(apiKey);
        var hash = HashApiKey(apiKey);
        lock (_keyLock)
        {
            _keyHash = hash;
        }
    }

    private async Task<AgentHttpResponse> HandleRequestAsync(AgentHttpRequest request, CancellationToken cancellationToken)
    {
        if (!IsAuthorized(request.Headers))
        {
            return new AgentHttpResponse(
                401,
                new { error = new { code = "unauthorized", message = "缺少或无效的 Bearer 密钥。" } },
                new Dictionary<string, string> { ["WWW-Authenticate"] = "Bearer realm=\"aegis-agent\"" });
        }

        var path = request.Path.TrimEnd('/');
        if (path.Equals("/api/v1/health", StringComparison.OrdinalIgnoreCase))
        {
            return RequireMethod(request.Method, "GET", () => new AgentHttpResponse(200, new
            {
                status = "ok",
                apiVersion = _options.ApiVersion,
                utc = DateTimeOffset.UtcNow
            }));
        }

        if (path.Equals("/api/v1/status", StringComparison.OrdinalIgnoreCase))
        {
            return RequireMethod(request.Method, "GET", BuildStatus);
        }

        if (path.Equals("/api/v1/hips/status", StringComparison.OrdinalIgnoreCase))
        {
            return RequireMethod(request.Method, "GET", BuildHipsStatus);
        }

        if (path.Equals("/api/v1/hips/events", StringComparison.OrdinalIgnoreCase))
        {
            return RequireMethod(request.Method, "GET", BuildHipsEvents);
        }

        if (path.Equals("/api/v1/scans", StringComparison.OrdinalIgnoreCase))
        {
            if (request.Method == "POST")
            {
                return CreateScan(request);
            }

            return RequireMethod(request.Method, "GET", BuildScanList);
        }

        var segments = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length is 4 or 5 &&
            segments[0].Equals("api", StringComparison.OrdinalIgnoreCase) &&
            segments[1].Equals("v1", StringComparison.OrdinalIgnoreCase) &&
            segments[2].Equals("scans", StringComparison.OrdinalIgnoreCase))
        {
            var id = segments[3];
            if (!IsJobId(id))
            {
                return Error(404, "not_found", "扫描任务不存在。");
            }

            if (segments.Length == 4)
            {
                return RequireMethod(request.Method, "GET", () => BuildJobResponse(id));
            }

            if (segments[4].Equals("cancel", StringComparison.OrdinalIgnoreCase))
            {
                return RequireMethod(request.Method, "POST", () => CancelJob(id));
            }
        }

        await Task.CompletedTask.ConfigureAwait(false);
        return Error(404, "not_found", "接口不存在。");
    }

    private AgentHttpResponse CreateScan(AgentHttpRequest request)
    {
        var contentType = request.Headers.TryGetValue("Content-Type", out var value) ? value : string.Empty;
        if (!contentType.StartsWith("application/json", StringComparison.OrdinalIgnoreCase) &&
            !contentType.Contains("+json", StringComparison.OrdinalIgnoreCase))
        {
            return Error(415, "unsupported_media_type", "请求体必须使用 application/json。");
        }

        if (request.Body.Length == 0)
        {
            return Error(400, "invalid_request", "请求体为空。");
        }

        AgentScanStartRequest? dto;
        try
        {
            dto = JsonSerializer.Deserialize<AgentScanStartRequest>(request.Body, JsonDefaults.Api);
        }
        catch (JsonException)
        {
            return Error(400, "invalid_json", "请求体不是有效的 JSON。");
        }

        if (dto is null)
        {
            return Error(400, "invalid_request", "请求体为空。");
        }

        var profileText = string.IsNullOrWhiteSpace(dto.Profile) ? "quick" : dto.Profile.Trim().ToLowerInvariant();
        var baseOptions = _scanOptionsProvider() ?? ScanOptions.Default;
        var maxFileSize = dto.MaxFileSizeBytes ?? baseOptions.MaxFileSizeBytes;
        if (maxFileSize is < 1024 * 1024 or > 2L * 1024 * 1024 * 1024)
        {
            return Error(400, "invalid_request", "maxFileSizeBytes 必须在 1 MiB 到 2 GiB 之间。");
        }

        CloudQueryPolicy policy;
        if (string.IsNullOrWhiteSpace(dto.CloudPolicy))
        {
            policy = baseOptions.CloudPolicy;
        }
        else
        {
            policy = dto.CloudPolicy.Trim().ToLowerInvariant() switch
            {
                "never" => CloudQueryPolicy.Never,
                "suspiciousonly" => CloudQueryPolicy.SuspiciousOnly,
                "executablesandscripts" => CloudQueryPolicy.ExecutablesAndScripts,
                "all" => CloudQueryPolicy.All,
                _ => (CloudQueryPolicy)(-1)
            };

            if ((int)policy < 0)
            {
                return Error(400, "invalid_request", "cloudPolicy 无效。");
            }
        }

        var options = new ScanOptions
        {
            MaxFileSizeBytes = maxFileSize,
            MaxDegreeOfParallelism = baseOptions.MaxDegreeOfParallelism,
            RunHeuristics = baseOptions.RunHeuristics,
            QueryCloud = dto.QueryCloud ?? baseOptions.QueryCloud,
            CloudPolicy = policy,
            UseDefaultExclusions = baseOptions.UseDefaultExclusions,
            UserExclusions = baseOptions.UserExclusions,
            IncludeHiddenFiles = baseOptions.IncludeHiddenFiles
        };

        ScanRequest scanRequest;
        try
        {
            switch (profileText)
            {
                case "quick":
                    scanRequest = ScanRequest.Quick(options);
                    break;
                case "full":
                    scanRequest = ScanRequest.Full(options);
                    break;
                case "custom":
                    if (string.IsNullOrWhiteSpace(dto.Path))
                    {
                        return Error(400, "invalid_request", "自定义扫描必须提供 path。");
                    }

                    var path = Path.GetFullPath(Environment.ExpandEnvironmentVariables(dto.Path.Trim()));
                    if (!File.Exists(path) && !Directory.Exists(path))
                    {
                        return Error(400, "path_not_found", "扫描路径不存在。");
                    }

                    scanRequest = ScanRequest.Custom(path, options);
                    break;
                default:
                    return Error(400, "invalid_request", "profile 必须是 quick、full 或 custom。");
            }
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return Error(400, "invalid_path", "扫描路径无效。");
        }

        var scanner = _scannerProvider();
        if (scanner is null)
        {
            return Error(503, "not_ready", "扫描引擎尚未初始化。");
        }

        try
        {
            var job = _coordinator.Start(scanner, scanRequest);
            return new AgentHttpResponse(
                202,
                ToJobEnvelope(job, includeSummary: false),
                new Dictionary<string, string> { ["Location"] = $"/api/v1/scans/{job.Id}" });
        }
        catch (InvalidOperationException)
        {
            return Error(429, "queue_full", "扫描队列已满，请稍后重试。");
        }
    }

    private AgentHttpResponse CancelJob(string id)
    {
        var job = _coordinator.Get(id);
        if (job is null)
        {
            return Error(404, "not_found", "扫描任务不存在。");
        }

        job.Cancel();
        return new AgentHttpResponse(202, ToJobEnvelope(job, includeSummary: false));
    }

    private AgentHttpResponse BuildJobResponse(string id)
    {
        var job = _coordinator.Get(id);
        return job is null
            ? Error(404, "not_found", "扫描任务不存在。")
            : new AgentHttpResponse(200, ToJobEnvelope(job, includeSummary: true));
    }

    private AgentHttpResponse BuildScanList()
    {
        var jobs = _coordinator.GetRecent(20).Select(job => ToJobEnvelope(job, includeSummary: false)).ToArray();
        return new AgentHttpResponse(200, new { jobs });
    }

    private AgentHttpResponse BuildHipsStatus()
    {
        return new AgentHttpResponse(200, new
        {
            running = _hips?.IsRunning == true,
            lastError = _hips?.LastError,
            blockCritical = _hips?.BlockCritical == true,
            processMonitoring = _hips?.ProcessMonitoringActive == true,
            fileMonitoring = _hips?.FileMonitoringActive == true,
            registryMonitoring = _hips?.RegistryMonitoringActive == true,
            eventCount = _hips?.EventCount ?? 0
        });
    }

    private AgentHttpResponse BuildHipsEvents()
    {
        var events = _hips?.GetRecent(100) ?? Array.Empty<HipsEvent>();
        return new AgentHttpResponse(200, new { events });
    }

    private AgentHttpResponse BuildStatus()
    {
        var scanner = _scannerProvider();
        if (scanner is null)
        {
            return Error(503, "not_ready", "扫描引擎尚未初始化。");
        }

        var active = _coordinator.ActiveJob;
        var running = _coordinator.GetRunning();
        return new AgentHttpResponse(200, new
        {
            apiVersion = _options.ApiVersion,
            engineVersion = AegisScanner.EngineVersion,
            signature = new
            {
                version = scanner.Signatures.Version,
                source = scanner.Signatures.Source,
                isSeed = scanner.Signatures.IsSeed,
                fetchedAt = scanner.Signatures.FetchedAt,
                hashes = scanner.Signatures.HashCount,
                domains = scanner.Signatures.DomainCount,
                ips = scanner.Signatures.IpCount,
                warningCount = scanner.Signatures.Warnings.Count
            },
            cloud = new
            {
                configured = scanner.Cloud.IsConfigured,
                policy = scanner.Cloud.QueryPolicy.ToString().ToLowerInvariant(),
                lastError = scanner.Cloud.LastError
            },
            agent = new
            {
                port = Port,
                baseUrl = BaseUrl,
                uptimeSeconds = (long)Uptime.TotalSeconds,
                requestCount = RequestCount
            },
            hips = new
            {
                running = _hips?.IsRunning == true,
                eventCount = _hips?.EventCount ?? 0,
                lastError = _hips?.LastError
            },
            scans = new
            {
                activeJobId = active?.Id,
                queuedOrRunning = running.Count,
                queued = running.Count(job => job.State == ScanJobState.Queued),
                running = running.Count(job => job.State == ScanJobState.Running)
            }
        });
    }

    private object ToJobEnvelope(ScanJob job, bool includeSummary)
    {
        return new
        {
            id = job.Id,
            state = job.State.ToString().ToLowerInvariant(),
            submittedAt = job.SubmittedAt,
            startedAt = job.StartedAt,
            completedAt = job.CompletedAt,
            cancelRequested = job.CancelRequested,
            error = job.Error,
            progress = job.Progress,
            summary = includeSummary ? job.Summary : null
        };
    }

    private static AgentHttpResponse RequireMethod(string actual, string expected, Func<AgentHttpResponse> action)
    {
        return actual.Equals(expected, StringComparison.OrdinalIgnoreCase)
            ? action()
            : new AgentHttpResponse(
                405,
                new { error = new { code = "method_not_allowed", message = $"此接口只支持 {expected}。" } },
                new Dictionary<string, string> { ["Allow"] = expected });
    }

    private bool IsAuthorized(IReadOnlyDictionary<string, string> headers)
    {
        if (!headers.TryGetValue("Authorization", out var authorization))
        {
            return false;
        }

        const string scheme = "Bearer ";
        if (!authorization.StartsWith(scheme, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var token = authorization[scheme.Length..].Trim();
        if (token.Length is < 16 or > 256)
        {
            return false;
        }

        byte[]? expected;
        lock (_keyLock)
        {
            expected = _keyHash;
        }

        if (expected is null)
        {
            return false;
        }

        var actual = SHA256.HashData(Encoding.UTF8.GetBytes(token));
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    private static byte[] HashApiKey(string apiKey) => SHA256.HashData(Encoding.UTF8.GetBytes(apiKey));

    private static bool IsJobId(string value)
    {
        return value.Length == 32 && value.All(Uri.IsHexDigit);
    }

    private static AgentHttpResponse Error(int status, string code, string message) =>
        new(status, new { error = new { code, message } });

    private string DescribeStartFailure(Exception exception) => exception switch
    {
        SocketException socketException when socketException.SocketErrorCode == SocketError.AddressAlreadyInUse =>
            $"本机端口 {_options.Port} 已被占用。",
        SocketException => "无法绑定本机回环端口。",
        UnauthorizedAccessException => "没有权限启动本机自动化接口。",
        _ => "自动化接口启动失败。"
    };

    private void RaiseStateChanged()
    {
        try
        {
            StateChanged?.Invoke(this, EventArgs.Empty);
        }
        catch
        {
            // UI subscribers must not affect the API lifecycle.
        }
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync().ConfigureAwait(false);
    }
}
