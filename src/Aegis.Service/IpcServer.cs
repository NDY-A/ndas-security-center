using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Aegis.Core.Service;
using Microsoft.Win32.SafeHandles;

namespace Aegis.Service;

public sealed class IpcServer
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private static readonly UTF8Encoding Utf8 = new(encoderShouldEmitUTF8Identifier: false);
    private readonly ProtectionHost _host;

    public IpcServer(ProtectionHost host)
    {
        _host = host;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                var pipe = CreatePipe();
                await pipe.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);
                _ = HandleAsync(pipe, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch
            {
                try
                {
                    await Task.Delay(250, cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }
    }

    private static NamedPipeServerStream CreatePipe()
    {
        var security = new PipeSecurity();
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var authenticatedUsers = new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null);
        security.AddAccessRule(new PipeAccessRule(system, PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(administrators, PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(authenticatedUsers, PipeAccessRights.ReadWrite, AccessControlType.Allow));

        return NamedPipeServerStreamAcl.Create(
            ServiceProtocol.PipeName,
            PipeDirection.InOut,
            NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous,
            64 * 1024,
            64 * 1024,
            security);
    }

    private async Task HandleAsync(NamedPipeServerStream pipe, CancellationToken cancellationToken)
    {
        await using (pipe.ConfigureAwait(false))
        {
            try
            {
                using var reader = new StreamReader(pipe, Utf8, detectEncodingFromByteOrderMarks: false, bufferSize: 4096, leaveOpen: true);
                using var writer = new StreamWriter(pipe, Utf8, bufferSize: 4096, leaveOpen: true) { AutoFlush = true };
                while (!cancellationToken.IsCancellationRequested && pipe.IsConnected)
                {
                    var line = await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false);
                    if (line is null)
                    {
                        break;
                    }

                    ServiceRequest? request;
                    try
                    {
                        request = JsonSerializer.Deserialize<ServiceRequest>(line, JsonOptions);
                    }
                    catch (JsonException)
                    {
                        continue;
                    }

                    ServiceStatus status;
                    if (request?.Command.Equals("block", StringComparison.OrdinalIgnoreCase) == true)
                    {
                        if (!TryAuthorizeWrite(pipe, "文件锁定", out var authError))
                        {
                            status = _host.GetStatus();
                            status.LastError = authError;
                        }
                        else if (string.IsNullOrWhiteSpace(request.Path) || !File.Exists(request.Path))
                        {
                            status = _host.GetStatus();
                            status.LastError = "锁定文件缺少有效路径。";
                        }
                        else
                        {
                            _host.Block(request.Path);
                            status = _host.GetStatus();
                        }
                    }
                    else if (request?.Command.Equals("unblock", StringComparison.OrdinalIgnoreCase) == true)
                    {
                        if (!TryAuthorizeWrite(pipe, "解除锁定", out var authError))
                        {
                            status = _host.GetStatus();
                            status.LastError = authError;
                        }
                        else if (string.IsNullOrWhiteSpace(request.Path))
                        {
                            status = _host.GetStatus();
                            status.LastError = "解除锁定缺少文件路径。";
                        }
                        else
                        {
                            _host.Unblock(request.Path);
                            status = _host.GetStatus();
                        }
                    }
                    else if (request?.Command.Equals("contain", StringComparison.OrdinalIgnoreCase) == true)
                    {
                        if (!TryAuthorizeWrite(pipe, "启动强力清除", out var authError))
                        {
                            status = _host.GetStatus();
                            status.LastError = authError;
                        }
                        else if (!TryGetClientSession(pipe, out var sessionId))
                        {
                            status = _host.GetStatus();
                            status.LastError = "无法识别发起强力清除的交互会话。";
                        }
                        else if (!_host.StartContainment(sessionId, out var error))
                        {
                            status = _host.GetStatus();
                            status.LastError = error;
                        }
                        else
                        {
                            status = _host.GetStatus();
                        }
                    }
                    else if (request?.Command.Equals("contain-abort", StringComparison.OrdinalIgnoreCase) == true)
                    {
                        if (!TryAuthorizeWrite(pipe, "取消强力清除", out var authError))
                        {
                            status = _host.GetStatus();
                            status.LastError = authError;
                        }
                        else if (!_host.AbortContainment(out var error))
                        {
                            status = _host.GetStatus();
                            status.LastError = error;
                        }
                        else
                        {
                            status = _host.GetStatus();
                        }
                    }
                    else if (request?.Command.Equals("configure", StringComparison.OrdinalIgnoreCase) == true)
                    {
                        if (request.Settings is null)
                        {
                            status = _host.GetStatus();
                            status.LastError = "配置内容为空。";
                        }
                        else if (!TryAuthorizeWrite(pipe, "修改防护设置", out var authError))
                        {
                            status = _host.GetStatus();
                            status.LastError = authError;
                        }
                        else
                        {
                            status = _host.ApplyConfiguration(request.Settings);
                        }
                    }
                    else if (request?.Command.Equals("agent-retry", StringComparison.OrdinalIgnoreCase) == true)
                    {
                        if (!TryAuthorizeWrite(pipe, "重新启动决策 agent", out var authError))
                        {
                            status = _host.GetStatus();
                            status.LastError = authError;
                        }
                        else if (!_host.RetryAgent(out var error))
                        {
                            status = _host.GetStatus();
                            status.LastError = error;
                        }
                        else
                        {
                            status = _host.GetStatus();
                        }
                    }
                    else
                    {
                        status = _host.GetStatus();
                    }

                    await writer.WriteLineAsync(JsonSerializer.Serialize(status, JsonOptions)).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException)
            {
                // Service shutdown.
            }
            catch
            {
                // A client disconnect must not affect other clients.
            }
        }
    }

    private static bool TryGetClientSession(NamedPipeServerStream pipe, out int sessionId)
    {
        sessionId = -1;
        try
        {
            if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle, out var processId))
            {
                return false;
            }

            using var process = Process.GetProcessById((int)processId);
            sessionId = process.SessionId;
            return sessionId > 0;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Write-command gate. Requires an interactive session (session 0 is always rejected,
    /// even for elevated System tokens) and refuses the decision agent process itself.
    /// This closes the hole where a restricted LocalSystem token could still call
    /// <c>configure</c> and slip hashes into the service allow list.
    /// </summary>
    private bool TryAuthorizeWrite(NamedPipeServerStream pipe, string action, out string? error)
    {
        error = null;
        if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle, out var processId))
        {
            error = "无法识别客户端进程。";
            return false;
        }

        var pid = (int)processId;
        if (_host.IsAgentProcess(pid))
        {
            error = "决策 agent 不允许修改防护设置。";
            return false;
        }

        int sessionId;
        try
        {
            using var process = Process.GetProcessById(pid);
            sessionId = process.SessionId;
        }
        catch
        {
            error = "无法识别客户端会话。";
            return false;
        }

        if (sessionId <= 0)
        {
            error = "服务会话中的客户端不能执行写操作。";
            return false;
        }

        if (!ClientIsElevated(pipe))
        {
            error = $"执行{action}需要管理员权限。";
            return false;
        }

        return true;
    }

    private static bool ClientIsElevated(NamedPipeServerStream pipe)
    {
        try
        {
            if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle, out var processId))
            {
                return false;
            }

            var process = OpenProcess(ProcessQueryLimitedInformation, false, processId);
            if (process == IntPtr.Zero)
            {
                return false;
            }

            try
            {
                if (!OpenProcessToken(process, TokenQuery, out var token))
                {
                    return false;
                }

                try
                {
                    return GetTokenInformation(token, TokenElevation, out var elevation, sizeof(int), out _) && elevation != 0;
                }
                finally
                {
                    CloseHandle(token);
                }
            }
            finally
            {
                CloseHandle(process);
            }
        }
        catch
        {
            return false;
        }
    }

    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const uint TokenQuery = 0x0008;
    private const int TokenElevation = 20;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inheritHandle, uint processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(IntPtr token, int informationClass, out int information, int length, out int returnLength);
}
