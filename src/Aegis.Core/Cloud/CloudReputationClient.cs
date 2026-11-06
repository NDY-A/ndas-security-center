using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Text.Json;
using Aegis.Core.Infrastructure;
using Aegis.Core.Models;

namespace Aegis.Core.Cloud;

public sealed class CloudReputationClient : ICloudReputationService, IDisposable
{
    private const int MaxResponseBytes = 64 * 1024;
    private const int CircuitFailureThreshold = 3;
    private static readonly TimeSpan CircuitOpenDuration = TimeSpan.FromSeconds(30);

    private readonly CloudOptions _options;
    private readonly HttpClient _httpClient;
    private readonly bool _ownsHttpClient;
    private readonly Uri? _baseUri;
    private readonly string? _configurationError;
    private readonly ConcurrentDictionary<string, CacheEntry> _cache = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _stateLock = new();
    private int _consecutiveFailures;
    private DateTimeOffset _circuitOpenUntil;
    private string? _lastError;

    public CloudReputationClient(CloudOptions options, HttpClient? httpClient = null)
    {
        _options = options;
        _ownsHttpClient = httpClient is null;
        _httpClient = httpClient ?? new HttpClient(new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate,
            ConnectTimeout = TimeSpan.FromSeconds(3),
            PooledConnectionLifetime = TimeSpan.FromMinutes(5)
        })
        {
            Timeout = Timeout.InfiniteTimeSpan
        };

        if (_httpClient.DefaultRequestHeaders.UserAgent.Count == 0)
        {
            _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("NDAS/0.1");
        }

        if (!options.Enabled)
        {
            _configurationError = "云安全查询未启用。";
            return;
        }

        if (!Uri.TryCreate(options.Endpoint.Trim(), UriKind.Absolute, out var baseUri) ||
            baseUri.Scheme is not ("https" or "http") ||
            !string.IsNullOrEmpty(baseUri.UserInfo) ||
            (baseUri.Scheme == "http" && !baseUri.IsLoopback))
        {
            _configurationError = "云端地址无效。必须使用 HTTPS，或仅本机回环地址的 HTTP。";
            return;
        }

        _baseUri = new Uri(baseUri.AbsoluteUri.TrimEnd('/') + "/");
    }

    public bool IsConfigured => _baseUri is not null;

    public CloudQueryPolicy QueryPolicy => _options.QueryPolicy;

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

    public async Task<CloudQueryResult?> QueryFileAsync(string sha256, long size, CancellationToken cancellationToken = default)
    {
        if (!IsConfigured || sha256.Length != 64)
        {
            return null;
        }

        if (_cache.TryGetValue(sha256, out var cached))
        {
            if (cached.ExpiresAt > DateTimeOffset.UtcNow)
            {
                return cached.Result;
            }

            _cache.TryRemove(sha256, out _);
        }

        lock (_stateLock)
        {
            if (_circuitOpenUntil > DateTimeOffset.UtcNow)
            {
                return null;
            }
        }

        try
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            linked.CancelAfter(_options.Timeout);
            using var request = CreateRequest(HttpMethod.Post, "v1/reputation/file");
            var payload = JsonSerializer.Serialize(new
            {
                schemaVersion = 1,
                sha256 = sha256.ToLowerInvariant(),
                size,
                engine = "aegis/0.1"
            }, JsonDefaults.Web);
            request.Content = new StringContent(payload, Encoding.UTF8, "application/json");

            using var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, linked.Token).ConfigureAwait(false);
            if (response.StatusCode != HttpStatusCode.OK)
            {
                RecordFailure($"云端返回 HTTP {(int)response.StatusCode}。");
                return null;
            }

            var json = await ReadLimitedAsync(response, linked.Token).ConfigureAwait(false);
            var dto = JsonSerializer.Deserialize<CloudResponseDto>(json, JsonDefaults.Web);
            if (dto is null)
            {
                RecordFailure("云端返回了空响应。");
                return null;
            }

            var verdict = ParseVerdict(dto.Verdict);
            if (verdict is null)
            {
                RecordFailure("云端返回了未知判定。");
                return null;
            }

            var ttl = Math.Clamp(dto.TtlSeconds <= 0 ? _options.DefaultCacheSeconds : dto.TtlSeconds, _options.MinCacheSeconds, _options.MaxCacheSeconds);
            var score = verdict switch
            {
                CloudVerdict.Malicious => Math.Max(90, Math.Clamp(dto.Score, 0, 100)),
                CloudVerdict.Pua => Math.Clamp(dto.Score < 80 ? 80 : dto.Score, 80, 89),
                CloudVerdict.Suspicious => Math.Clamp(dto.Score < 70 ? 70 : dto.Score, 70, 79),
                _ => 0
            };

            var result = new CloudQueryResult(
                verdict.Value,
                score,
                SanitizeThreatName(dto.ThreatName),
                Math.Clamp(dto.Confidence, 0, 1),
                ttl,
                SanitizeThreatName(dto.Provider));

            _cache[sha256] = new CacheEntry(result, DateTimeOffset.UtcNow.AddSeconds(ttl));
            RecordSuccess();
            return result;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            RecordFailure("云端查询超时。");
            return null;
        }
        catch (HttpRequestException)
        {
            RecordFailure("无法连接云安全服务。");
            return null;
        }
        catch (JsonException)
        {
            RecordFailure("云端返回的数据格式无效。");
            return null;
        }
        catch (InvalidDataException exception)
        {
            RecordFailure(exception.Message);
            return null;
        }
    }

    public async Task<CloudHealthResult> CheckHealthAsync(CancellationToken cancellationToken = default)
    {
        if (!IsConfigured)
        {
            return new CloudHealthResult(false, _configurationError ?? "云安全查询未配置。");
        }

        try
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            linked.CancelAfter(_options.Timeout);
            using var request = CreateRequest(HttpMethod.Get, "v1/health");
            using var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, linked.Token).ConfigureAwait(false);
            if (response.StatusCode == HttpStatusCode.OK)
            {
                return new CloudHealthResult(true, "云安全服务连接正常。");
            }

            return new CloudHealthResult(false, $"云安全服务返回 HTTP {(int)response.StatusCode}。");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            return new CloudHealthResult(false, "连接云安全服务超时。");
        }
        catch (HttpRequestException)
        {
            return new CloudHealthResult(false, "无法连接云安全服务。");
        }
    }

    private HttpRequestMessage CreateRequest(HttpMethod method, string relativePath)
    {
        var uri = new Uri(_baseUri!, relativePath);
        var request = new HttpRequestMessage(method, uri);
        request.Headers.Accept.ParseAdd("application/json");
        if (!string.IsNullOrWhiteSpace(_options.ApiKey))
        {
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", _options.ApiKey.Trim());
        }

        request.Headers.Add("X-NDAS-Client", "ndas/0.1");
        request.Headers.CacheControl = new System.Net.Http.Headers.CacheControlHeaderValue { NoStore = true };
        return request;
    }

    private static async Task<byte[]> ReadLimitedAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        if (response.Content.Headers.ContentLength is > MaxResponseBytes)
        {
            throw new InvalidDataException("云端响应过大。");
        }

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var buffer = new MemoryStream();
        var chunk = new byte[8 * 1024];
        while (true)
        {
            var read = await stream.ReadAsync(chunk, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            if (buffer.Length + read > MaxResponseBytes)
            {
                throw new InvalidDataException("云端响应超过大小限制。");
            }

            buffer.Write(chunk, 0, read);
        }

        return buffer.ToArray();
    }

    private void RecordFailure(string message)
    {
        lock (_stateLock)
        {
            _lastError = message;
            _consecutiveFailures++;
            if (_consecutiveFailures >= CircuitFailureThreshold)
            {
                _circuitOpenUntil = DateTimeOffset.UtcNow.Add(CircuitOpenDuration);
                _consecutiveFailures = 0;
            }
        }
    }

    private void RecordSuccess()
    {
        lock (_stateLock)
        {
            _lastError = null;
            _consecutiveFailures = 0;
            _circuitOpenUntil = default;
        }
    }

    private static CloudVerdict? ParseVerdict(string? value)
    {
        return value?.Trim().ToLowerInvariant() switch
        {
            "clean" => CloudVerdict.Clean,
            "unknown" => CloudVerdict.Unknown,
            "suspicious" => CloudVerdict.Suspicious,
            "malicious" => CloudVerdict.Malicious,
            "pua" => CloudVerdict.Pua,
            _ => null
        };
    }

    private static string? SanitizeThreatName(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var clean = new string(value.Where(character => !char.IsControl(character)).Take(160).ToArray()).Trim();
        return clean.Length == 0 ? null : clean;
    }

    public void Dispose()
    {
        if (_ownsHttpClient)
        {
            _httpClient.Dispose();
        }
    }

    private sealed record CacheEntry(CloudQueryResult Result, DateTimeOffset ExpiresAt);

    private sealed class CloudResponseDto
    {
        public string? Verdict { get; set; }
        public int Score { get; set; }
        public string? ThreatName { get; set; }
        public double Confidence { get; set; }
        public int TtlSeconds { get; set; }
        public string? Provider { get; set; }
    }
}
