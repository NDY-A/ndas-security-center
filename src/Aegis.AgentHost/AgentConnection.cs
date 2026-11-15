using System.Text;
using System.Text.Json;

namespace Aegis.AgentHost;

public enum AgentReadStatus
{
    Message,
    BadLine,
    EndOfStream,
}

public readonly record struct AgentReadResult(AgentReadStatus Status, AgentInboundMessage? Message, string? Error);

/// <summary>NDJSON duplex transport over the agent's stdio pipes.</summary>
public sealed class AgentConnection : IAsyncDisposable
{
    private readonly StreamReader _reader;
    private readonly StreamWriter _writer;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private bool _disposed;

    public AgentConnection(Stream stdin, Stream stdout)
    {
        _reader = new StreamReader(stdout, new UTF8Encoding(false), detectEncodingFromByteOrderMarks: false,
            bufferSize: 4096, leaveOpen: false);
        _writer = new StreamWriter(stdin, new UTF8Encoding(false), bufferSize: 4096, leaveOpen: false)
        {
            AutoFlush = false,
            NewLine = "\n",
        };
    }

    public async Task WriteAsync(AgentOutboundMessage message, CancellationToken cancellationToken)
    {
        var json = JsonSerializer.Serialize(message, AgentProtocol.JsonOptions);
        if (Encoding.UTF8.GetByteCount(json) > AgentProtocol.MaxLineBytes)
        {
            throw new InvalidDataException("出站协议消息超过大小限制");
        }

        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await _writer.WriteLineAsync(json).ConfigureAwait(false);
            await _writer.FlushAsync().ConfigureAwait(false);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public async Task<AgentReadResult> ReadAsync(CancellationToken cancellationToken)
    {
        string? line;
        try
        {
            line = await _reader.ReadLineAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception)
        {
            return new AgentReadResult(AgentReadStatus.EndOfStream, null, exception.Message);
        }

        if (line is null)
        {
            return new AgentReadResult(AgentReadStatus.EndOfStream, null, "agent stdout 已关闭");
        }

        if (Encoding.UTF8.GetByteCount(line) > AgentProtocol.MaxLineBytes)
        {
            return new AgentReadResult(AgentReadStatus.BadLine, null, "协议行超长");
        }

        try
        {
            var message = JsonSerializer.Deserialize<AgentInboundMessage>(line, AgentProtocol.JsonOptions);
            if (message is null)
            {
                return new AgentReadResult(AgentReadStatus.BadLine, null, "空消息");
            }

            return new AgentReadResult(AgentReadStatus.Message, message, null);
        }
        catch (Exception exception)
        {
            return new AgentReadResult(AgentReadStatus.BadLine, null, exception.Message);
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        try
        {
            await _writer.DisposeAsync().ConfigureAwait(false);
        }
        catch
        {
            // ignore
        }

        try
        {
            _reader.Dispose();
        }
        catch
        {
            // ignore
        }

        _writeLock.Dispose();
    }
}
