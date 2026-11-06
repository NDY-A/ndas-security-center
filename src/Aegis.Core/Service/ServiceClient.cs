using System.IO.Pipes;
using System.Text;
using System.Text.Json;

namespace Aegis.Core.Service;

public sealed class ServiceClient
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private static readonly UTF8Encoding Utf8 = new(encoderShouldEmitUTF8Identifier: false);

    public TimeSpan ConnectTimeout { get; set; } = TimeSpan.FromMilliseconds(1500);

    public Task<ServiceStatus?> GetStatusAsync(CancellationToken cancellationToken = default) =>
        SendAsync(new ServiceRequest { Command = "status" }, cancellationToken);

    public Task<ServiceStatus?> ConfigureAsync(ServiceConfiguration settings, CancellationToken cancellationToken = default) =>
        SendAsync(new ServiceRequest { Command = "configure", Settings = settings }, cancellationToken);

    public async Task<bool> PingAsync(CancellationToken cancellationToken = default) =>
        await GetStatusAsync(cancellationToken).ConfigureAwait(false) is not null;

    private async Task<ServiceStatus?> SendAsync(ServiceRequest request, CancellationToken cancellationToken)
    {
        try
        {
            using var pipe = new NamedPipeClientStream(".", ServiceProtocol.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(ConnectTimeout);
            await pipe.ConnectAsync(timeout.Token).ConfigureAwait(false);

            using var writer = new StreamWriter(pipe, Utf8, bufferSize: 4096, leaveOpen: true) { AutoFlush = true };
            using var reader = new StreamReader(pipe, Utf8, detectEncodingFromByteOrderMarks: false, bufferSize: 4096, leaveOpen: true);
            await writer.WriteLineAsync(JsonSerializer.Serialize(request, JsonOptions)).ConfigureAwait(false);
            var line = await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false);
            return string.IsNullOrWhiteSpace(line) ? null : JsonSerializer.Deserialize<ServiceStatus>(line, JsonOptions);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or TimeoutException or OperationCanceledException or JsonException or System.ComponentModel.Win32Exception)
        {
            return null;
        }
    }
}
