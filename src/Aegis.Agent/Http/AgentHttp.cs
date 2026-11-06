using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Aegis.Core.Infrastructure;

namespace Aegis.Agent.Http;

internal sealed record AgentHttpRequest(
    string Method,
    string Path,
    string Query,
    IReadOnlyDictionary<string, string> Headers,
    byte[] Body);

internal sealed record AgentHttpResponse(
    int Status,
    object? Body,
    IReadOnlyDictionary<string, string>? Headers = null);

internal sealed class HttpProtocolException : Exception
{
    public HttpProtocolException(int status, string message) : base(message)
    {
        Status = status;
    }

    public int Status { get; }
}

internal sealed class AgentHttpServer
{
    private static readonly UTF8Encoding Utf8WithoutBom = new(false);
    private readonly AgentApiOptions _options;
    private readonly Func<AgentHttpRequest, CancellationToken, Task<AgentHttpResponse>> _handler;
    private readonly SemaphoreSlim _connectionSlots;
    private readonly object _lifecycleLock = new();
    private TcpListener? _listener;
    private CancellationTokenSource? _cancellation;
    private Task? _acceptLoop;
    private long _requestCount;

    public AgentHttpServer(
        AgentApiOptions options,
        Func<AgentHttpRequest, CancellationToken, Task<AgentHttpResponse>> handler)
    {
        _options = options;
        _handler = handler;
        _connectionSlots = new SemaphoreSlim(Math.Clamp(options.MaxConcurrentRequests, 1, 64));
    }

    public bool IsRunning
    {
        get
        {
            lock (_lifecycleLock)
            {
                return _listener is not null;
            }
        }
    }

    public int Port
    {
        get
        {
            lock (_lifecycleLock)
            {
                return _listener is null ? 0 : ((IPEndPoint)_listener.LocalEndpoint).Port;
            }
        }
    }

    public long RequestCount => Interlocked.Read(ref _requestCount);

    public void Start(int port)
    {
        lock (_lifecycleLock)
        {
            if (_listener is not null)
            {
                throw new InvalidOperationException("自动化 HTTP 服务已在运行。");
            }

            if (port is < 0 or > 65_535)
            {
                throw new ArgumentOutOfRangeException(nameof(port));
            }

            var listener = new TcpListener(IPAddress.Loopback, port);
            listener.Start(64);
            _listener = listener;
            _cancellation = new CancellationTokenSource();
            _acceptLoop = Task.Run(() => AcceptLoopAsync(listener, _cancellation.Token));
        }
    }

    public async Task StopAsync()
    {
        Task? acceptLoop;
        CancellationTokenSource? cancellation;
        lock (_lifecycleLock)
        {
            if (_listener is null)
            {
                return;
            }

            acceptLoop = _acceptLoop;
            cancellation = _cancellation;
            _acceptLoop = null;
            _cancellation = null;
            _listener.Stop();
            _listener = null;
        }

        cancellation?.Cancel();
        if (acceptLoop is not null)
        {
            try
            {
                await acceptLoop.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // Expected during shutdown.
            }
            catch (ObjectDisposedException)
            {
                // Listener was already closed.
            }
        }

        cancellation?.Dispose();
    }

    private async Task AcceptLoopAsync(TcpListener listener, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await listener.AcceptTcpClientAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (ObjectDisposedException)
            {
                break;
            }
            catch (SocketException)
            {
                break;
            }

            _ = HandleClientAsync(client, cancellationToken);
        }
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken serverToken)
    {
        if (!await _connectionSlots.WaitAsync(TimeSpan.Zero).ConfigureAwait(false))
        {
            client.Dispose();
            return;
        }

        try
        {
            using (client)
            using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(serverToken))
            {
                client.NoDelay = true;
                timeout.CancelAfter(_options.RequestTimeout);
                await using var stream = client.GetStream();
                await ProcessClientAsync(stream, timeout.Token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            // Timeout or server shutdown.
        }
        catch (IOException)
        {
            // Client disconnected.
        }
        catch (SocketException)
        {
            // Client disconnected.
        }
        catch
        {
            // Never let a single malformed client terminate the accept loop.
        }
        finally
        {
            _connectionSlots.Release();
        }
    }

    private async Task ProcessClientAsync(NetworkStream stream, CancellationToken cancellationToken)
    {
        var reader = new BufferedHttpReader(stream);
        AgentHttpRequest? request = null;
        try
        {
            request = await ReadRequestAsync(reader, stream, cancellationToken).ConfigureAwait(false);
        }
        catch (HttpProtocolException exception)
        {
            await WriteResponseAsync(stream, Error(exception.Status, "bad_request", exception.Message), cancellationToken).ConfigureAwait(false);
            return;
        }
        catch (InvalidDataException)
        {
            await WriteResponseAsync(stream, Error(400, "bad_request", "请求格式无效。"), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (request is null)
        {
            return;
        }

        Interlocked.Increment(ref _requestCount);
        AgentHttpResponse response;
        try
        {
            response = await _handler(request, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return;
        }
        catch
        {
            response = Error(500, "internal_error", "服务内部错误。");
        }

        await WriteResponseAsync(stream, response, cancellationToken).ConfigureAwait(false);
    }

    private async Task<AgentHttpRequest?> ReadRequestAsync(BufferedHttpReader reader, NetworkStream stream, CancellationToken cancellationToken)
    {
        string? requestLine;
        do
        {
            requestLine = await reader.ReadLineAsync(8 * 1024, cancellationToken).ConfigureAwait(false);
            if (requestLine is null)
            {
                return null;
            }
        }
        while (requestLine.Length == 0);

        var parts = requestLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 3)
        {
            throw new HttpProtocolException(400, "请求行格式无效。");
        }

        var method = parts[0].ToUpperInvariant();
        if (method is not ("GET" or "POST"))
        {
            throw new HttpProtocolException(405, "仅支持 GET 和 POST。");
        }

        if (!parts[2].Equals("HTTP/1.1", StringComparison.OrdinalIgnoreCase))
        {
            throw new HttpProtocolException(505, "仅支持 HTTP/1.1。");
        }

        var target = parts[1];
        if (!target.StartsWith('/') || target.Length > 4096)
        {
            throw new HttpProtocolException(400, "请求目标无效。");
        }

        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var headerBytes = requestLine.Length + 2;
        while (true)
        {
            var line = await reader.ReadLineAsync(8 * 1024, cancellationToken).ConfigureAwait(false);
            if (line is null)
            {
                throw new HttpProtocolException(400, "请求头不完整。");
            }

            if (line.Length == 0)
            {
                break;
            }

            headerBytes += line.Length + 2;
            if (headerBytes > _options.MaxHeaderBytes)
            {
                throw new HttpProtocolException(431, "请求头超过大小限制。");
            }

            if (line[0] is ' ' or '\t')
            {
                throw new HttpProtocolException(400, "不支持折叠请求头。");
            }

            var colon = line.IndexOf(':');
            if (colon <= 0)
            {
                throw new HttpProtocolException(400, "请求头格式无效。");
            }

            var name = line[..colon].Trim();
            var value = line[(colon + 1)..].Trim();
            if (!IsToken(name) || value.Any(character => (character < 0x20 && character != '\t') || character == 0x7F))
            {
                throw new HttpProtocolException(400, "请求头包含非法字符。");
            }

            if (!headers.TryAdd(name, value))
            {
                throw new HttpProtocolException(400, "不支持重复的请求头。");
            }

            if (headers.Count > 64)
            {
                throw new HttpProtocolException(431, "请求头数量过多。");
            }
        }

        if (!headers.TryGetValue("Host", out var host) || !IsAllowedHost(host))
        {
            throw new HttpProtocolException(400, "Host 请求头无效。");
        }

        if (headers.ContainsKey("Origin"))
        {
            throw new HttpProtocolException(403, "浏览器来源请求被拒绝。请使用原生 HTTP 客户端。");
        }

        if (headers.ContainsKey("Transfer-Encoding"))
        {
            throw new HttpProtocolException(400, "不支持分块传输。请提供 Content-Length。");
        }

        var bodyLength = 0;
        if (headers.TryGetValue("Content-Length", out var contentLengthText))
        {
            if (!long.TryParse(contentLengthText, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var parsedLength) || parsedLength < 0)
            {
                throw new HttpProtocolException(400, "Content-Length 无效。");
            }

            if (parsedLength > _options.MaxBodyBytes)
            {
                throw new HttpProtocolException(413, "请求体超过大小限制。");
            }

            bodyLength = (int)parsedLength;
        }

        if (bodyLength > 0 &&
            headers.TryGetValue("Expect", out var expect) &&
            expect.Contains("100-continue", StringComparison.OrdinalIgnoreCase))
        {
            var continueBytes = Encoding.ASCII.GetBytes("HTTP/1.1 100 Continue\r\n\r\n");
            await stream.WriteAsync(continueBytes, cancellationToken).ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }

        var body = bodyLength > 0
            ? await reader.ReadBodyAsync(bodyLength, cancellationToken).ConfigureAwait(false)
            : Array.Empty<byte>();

        var questionMark = target.IndexOf('?');
        var path = questionMark >= 0 ? target[..questionMark] : target;
        var query = questionMark >= 0 ? target[(questionMark + 1)..] : string.Empty;
        return new AgentHttpRequest(method, path, query, headers, body);
    }

    private bool IsAllowedHost(string host)
    {
        if (host.Length is 0 or > 255 || !Uri.TryCreate("http://" + host, UriKind.Absolute, out var uri))
        {
            return false;
        }

        return uri.Port == Port &&
               (uri.Host.Equals("127.0.0.1", StringComparison.OrdinalIgnoreCase) ||
                uri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsToken(string value)
    {
        if (value.Length == 0)
        {
            return false;
        }

        foreach (var character in value)
        {
            var valid = char.IsAsciiLetterOrDigit(character) ||
                        character is '!' or '#' or '$' or '%' or '&' or '\'' or '*' or '+' or '-' or '.' or '^' or '_' or '`' or '|' or '~';
            if (!valid)
            {
                return false;
            }
        }

        return true;
    }

    private static AgentHttpResponse Error(int status, string code, string message) =>
        new(status, new { error = new { code, message } });

    private async Task WriteResponseAsync(NetworkStream stream, AgentHttpResponse response, CancellationToken cancellationToken)
    {
        string json;
        try
        {
            json = response.Body is null ? "{}" : JsonSerializer.Serialize(response.Body, JsonDefaults.Api);
        }
        catch (JsonException)
        {
            response = Error(500, "serialization_error", "响应序列化失败。");
            json = JsonSerializer.Serialize(response.Body, JsonDefaults.Api);
        }

        var bodyBytes = Utf8WithoutBom.GetBytes(json);
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Content-Type"] = "application/json; charset=utf-8",
            ["Content-Length"] = bodyBytes.Length.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["Cache-Control"] = "no-store, max-age=0",
            ["Pragma"] = "no-cache",
            ["X-Content-Type-Options"] = "nosniff",
            ["Referrer-Policy"] = "no-referrer",
            ["Connection"] = "close"
        };

        if (response.Headers is not null)
        {
            foreach (var pair in response.Headers)
            {
                if (IsToken(pair.Key) && !pair.Value.Any(character => character is '\r' or '\n'))
                {
                    headers[pair.Key] = pair.Value;
                }
            }
        }

        var builder = new StringBuilder(256);
        builder.Append("HTTP/1.1 ").Append(response.Status).Append(' ').Append(ReasonPhrase(response.Status)).Append("\r\n");
        foreach (var pair in headers)
        {
            builder.Append(pair.Key).Append(": ").Append(pair.Value).Append("\r\n");
        }

        builder.Append("\r\n");
        var headBytes = Encoding.ASCII.GetBytes(builder.ToString());
        await stream.WriteAsync(headBytes, cancellationToken).ConfigureAwait(false);
        if (bodyBytes.Length > 0)
        {
            await stream.WriteAsync(bodyBytes, cancellationToken).ConfigureAwait(false);
        }

        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private static string ReasonPhrase(int status) => status switch
    {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        505 => "HTTP Version Not Supported",
        _ => "Error"
    };

    private sealed class BufferedHttpReader
    {
        private readonly Stream _stream;
        private readonly byte[] _buffer = new byte[8 * 1024];
        private int _start;
        private int _end;

        public BufferedHttpReader(Stream stream)
        {
            _stream = stream;
        }

        public async Task<string?> ReadLineAsync(int maxLength, CancellationToken cancellationToken)
        {
            var builder = new StringBuilder(128);
            while (true)
            {
                var next = await ReadByteAsync(cancellationToken).ConfigureAwait(false);
                if (next < 0)
                {
                    if (builder.Length == 0)
                    {
                        return null;
                    }

                    throw new HttpProtocolException(400, "连接在请求行结束前关闭。");
                }

                if (next == '\n')
                {
                    if (builder.Length > 0 && builder[^1] == '\r')
                    {
                        builder.Length--;
                    }

                    return builder.ToString();
                }

                if (builder.Length >= maxLength)
                {
                    throw new HttpProtocolException(431, "请求行或请求头过长。");
                }

                builder.Append((char)next);
            }
        }

        public async Task<byte[]> ReadBodyAsync(int length, CancellationToken cancellationToken)
        {
            var body = new byte[length];
            var copied = 0;
            if (_start < _end)
            {
                copied = Math.Min(length, _end - _start);
                Buffer.BlockCopy(_buffer, _start, body, 0, copied);
                _start += copied;
            }

            while (copied < length)
            {
                var read = await _stream.ReadAsync(body.AsMemory(copied, length - copied), cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    throw new HttpProtocolException(400, "请求体不完整。");
                }

                copied += read;
            }

            return body;
        }

        private async ValueTask<int> ReadByteAsync(CancellationToken cancellationToken)
        {
            if (_start >= _end)
            {
                _end = await _stream.ReadAsync(_buffer, cancellationToken).ConfigureAwait(false);
                _start = 0;
                if (_end == 0)
                {
                    return -1;
                }
            }

            return _buffer[_start++];
        }
    }
}
