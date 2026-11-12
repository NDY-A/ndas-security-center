using Aegis.Core.Models;
using Aegis.Core.Signatures;

namespace Aegis.Sandbox;

public static class SandboxScorer
{
    private static readonly HashSet<string> InjectionApis = new(StringComparer.OrdinalIgnoreCase)
    {
        "WriteProcessMemory", "CreateRemoteThread", "CreateRemoteThreadEx", "NtCreateThreadEx",
        "QueueUserAPC", "SetThreadContext", "NtUnmapViewOfSection", "NtMapViewOfSection",
        "RtlCreateUserThread", "ZwWriteVirtualMemory"
    };

    private static readonly HashSet<string> CredentialApis = new(StringComparer.OrdinalIgnoreCase)
    {
        "MiniDumpWriteDump", "CredEnumerateW", "CredReadW", "LsaEnumerateLogonSessions",
        "CryptUnprotectData", "SamQueryInformationUser"
    };

    private static readonly HashSet<string> PersistenceApis = new(StringComparer.OrdinalIgnoreCase)
    {
        "CreateServiceW", "CreateServiceA", "StartServiceW", "StartServiceA",
        "RegSetValueExW", "RegSetValueExA", "RegCreateKeyExW", "RegCreateKeyExA", "SchTasks"
    };

    private static readonly HashSet<string> NetworkApis = new(StringComparer.OrdinalIgnoreCase)
    {
        "URLDownloadToFileW", "URLDownloadToFileA", "InternetOpenUrlW", "InternetOpenUrlA",
        "InternetOpenW", "InternetOpenA", "InternetConnectW", "InternetConnectA",
        "InternetReadFile", "WinHttpOpen", "WinHttpSendRequest", "HttpSendRequestW",
        "HttpSendRequestA", "WSAStartup", "WSAConnect", "connect", "send", "recv",
        "WSASend", "WSARecv", "GetAddrInfoW", "gethostbyname"
    };

    private static readonly HashSet<string> AntiAnalysisApis = new(StringComparer.OrdinalIgnoreCase)
    {
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
        "NtSetInformationThread", "OutputDebugStringW", "GetTickCount", "GetTickCount64"
    };

    private static readonly HashSet<string> ProcessCreateApis = new(StringComparer.OrdinalIgnoreCase)
    {
        "CreateProcessW", "CreateProcessA", "CreateProcessAsUserW", "CreateProcessAsUserA",
        "CreateProcessWithTokenW", "CreateProcessWithLogonW", "CreateProcessInternalW",
        "ShellExecuteW", "ShellExecuteA", "ShellExecuteExW", "WinExec"
    };

    private static readonly HashSet<string> FileWriteApis = new(StringComparer.OrdinalIgnoreCase)
    {
        "CreateFileW", "CreateFileA", "WriteFile", "NtWriteFile", "NtCreateFile",
        "CopyFileW", "CopyFileA", "MoveFileW", "MoveFileA", "MoveFileExW"
    };

    private static readonly string[] SuspiciousCommandPatterns =
    {
        "cmd.exe", "powershell", "pwsh", "mshta", "rundll32", "regsvr32", "certutil",
        "bitsadmin", "schtasks", "wscript", "cscript", "curl", "wget"
    };

    private static readonly string[] ExecutableExtensions =
    {
        ".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".ocx"
    };

    public static SandboxResult Score(
        ParsedSandboxReport report,
        SignatureSnapshot signatures,
        string fileName,
        string sha256,
        TimeSpan duration,
        string engineVersion)
    {
        var scores = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var details = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);

        void AddSignal(string category, int score, string detail)
        {
            if (!scores.TryGetValue(category, out var current) || score > current)
            {
                scores[category] = score;
            }

            if (!details.TryGetValue(category, out var list))
            {
                list = new List<string>();
                details[category] = list;
            }

            if (list.Count < 8 && !list.Contains(detail, StringComparer.OrdinalIgnoreCase))
            {
                list.Add(detail);
            }
        }

        var textParts = new List<string>();
        textParts.AddRange(report.Strings);
        textParts.AddRange(report.DroppedFiles);

        foreach (var item in report.Events)
        {
            var api = NormalizeApi(item.ApiName);
            if (api.Length > 0)
            {
                if (InjectionApis.Contains(api))
                {
                    AddSignal("注入", 35, api);
                }

                if (CredentialApis.Contains(api))
                {
                    AddSignal("凭据访问", 30, api);
                }

                if (PersistenceApis.Contains(api) && IsPersistenceUse(api, item))
                {
                    AddSignal("持久化", 30, api);
                }

                if (NetworkApis.Contains(api))
                {
                    AddSignal("网络行为", 10, api);
                }

                if (AntiAnalysisApis.Contains(api))
                {
                    AddSignal("反分析", 10, api);
                }

                if (ProcessCreateApis.Contains(api))
                {
                    var command = string.Join(' ', item.Arguments);
                    var suspicious = SuspiciousCommandPatterns.Any(pattern =>
                        command.Contains(pattern, StringComparison.OrdinalIgnoreCase));
                    AddSignal("进程创建", suspicious ? 20 : 10, Trim(command.Length > 0 ? command : api));
                }

                if (FileWriteApis.Contains(api))
                {
                    foreach (var argument in item.Arguments)
                    {
                        if (argument.Length > 0 && ExecutableExtensions.Any(ext =>
                                argument.EndsWith(ext, StringComparison.OrdinalIgnoreCase)))
                        {
                            AddSignal("落地文件", 25, Trim(argument));
                        }

                        if (IsStartupPath(argument))
                        {
                            AddSignal("持久化", 30, "启动目录落地：" + Trim(argument));
                        }
                    }
                }
            }

            if (item.WritableExecutable)
            {
                AddSignal("可写可执行内存", 15, "动态代码/可写可执行内存");
            }

            if (item.CrossProcess && item.Kind is "mem_alloc" or "mem_write")
            {
                AddSignal("注入", 25, "跨进程内存写入");
            }

            if (item.Kind == "process_create")
            {
                var command = item.CommandLine ?? item.Path ?? string.Empty;
                textParts.Add(command);
                var suspicious = SuspiciousCommandPatterns.Any(pattern =>
                    command.Contains(pattern, StringComparison.OrdinalIgnoreCase));
                AddSignal("进程创建", suspicious ? 20 : 10, Trim(command));
            }

            if (item.CommandLine is { Length: > 0 } commandLine)
            {
                textParts.Add(commandLine);
                if (commandLine.Contains("schtasks", StringComparison.OrdinalIgnoreCase) ||
                    commandLine.Contains("sc create", StringComparison.OrdinalIgnoreCase) ||
                    commandLine.Contains("reg add", StringComparison.OrdinalIgnoreCase))
                {
                    AddSignal("持久化", 30, Trim(commandLine));
                }
            }

            if (item.Arguments.Count > 0)
            {
                textParts.AddRange(item.Arguments);
            }

            if (item.Path is { Length: > 0 } path)
            {
                textParts.Add(path);
            }
        }

        foreach (var dropped in report.DroppedFiles)
        {
            var executable = ExecutableExtensions.Any(ext =>
                dropped.EndsWith(ext, StringComparison.OrdinalIgnoreCase));
            AddSignal("落地文件", executable ? 25 : 10, Trim(dropped));

            if (IsStartupPath(dropped))
            {
                AddSignal("持久化", 30, "启动目录落地：" + Trim(dropped));
            }
        }

        var indicators = NetworkIndicatorExtractor.Extract(
            string.Join('\n', textParts.Take(12_000)), signatures.Domains, signatures.IpAddresses);
        if (indicators.Count > 0)
        {
            AddSignal("已知网络 IOC", 25, string.Join(", ", indicators.Select(x => x.Value).Distinct().Take(5)));
        }
        else if (textParts.Any(part => part.Contains("http://", StringComparison.OrdinalIgnoreCase) ||
                                       part.Contains("https://", StringComparison.OrdinalIgnoreCase)))
        {
            AddSignal("网络行为", 10, "报告包含 URL 字符串");
        }

        var signals = scores
            .Select(pair => new SandboxSignal(pair.Key, string.Join("；", details[pair.Key]), pair.Value))
            .OrderByDescending(signal => signal.Score)
            .ToArray();
        var total = Math.Min(100, signals.Sum(signal => signal.Score));
        var critical = signals.Any(signal => signal.Category is "注入" or "凭据访问" or "已知网络 IOC");

        ThreatVerdict verdict;
        if (total >= 85 && signals.Length >= 3 && critical)
        {
            verdict = ThreatVerdict.Malicious;
        }
        else if (total >= 75)
        {
            verdict = ThreatVerdict.Pua;
        }
        else if (total >= 65)
        {
            verdict = ThreatVerdict.Attention;
        }
        else
        {
            verdict = ThreatVerdict.Clean;
        }

        var errors = report.SessionErrors.Concat(report.RunErrors).ToArray();
        var incomplete = errors.Any(error =>
            error.Contains("timeout", StringComparison.OrdinalIgnoreCase) ||
            error.Contains("unsupported_api", StringComparison.OrdinalIgnoreCase) ||
            error.Contains("internal_error", StringComparison.OrdinalIgnoreCase));
        var confidence = incomplete ? (total >= 85 ? "Medium" : "Low") : "High";

        var threatName = verdict switch
        {
            ThreatVerdict.Malicious => "Behavior:Win32/Speakeasy.HighEntropy",
            ThreatVerdict.Pua => "PUA:Win32/Speakeasy.HighEntropy",
            ThreatVerdict.Attention => "Behavior:Win32/Speakeasy.Suspicious",
            _ => null
        };

        var categoryText = signals.Length == 0
            ? "无行为信号"
            : string.Join("、", signals.Select(signal => signal.Category));
        var summary = $"沙箱分析：{VerdictText(verdict)}（评分 {total}/100），信号 {signals.Length} 类（{categoryText}）";
        if (report.Truncated)
        {
            summary += "，报告过大已截断";
        }

        if (incomplete)
        {
            summary += "，模拟不完整";
        }

        var effectiveDuration = duration > TimeSpan.Zero
            ? duration
            : TimeSpan.FromSeconds(report.RuntimeSeconds);

        return new SandboxResult
        {
            Sha256 = string.IsNullOrWhiteSpace(report.Sha256) ? sha256 : report.Sha256!,
            FileName = fileName,
            Verdict = verdict,
            Score = total,
            ThreatName = threatName,
            Summary = summary,
            Signals = signals,
            Indicators = indicators,
            Confidence = confidence,
            EngineVersion = engineVersion,
            Duration = effectiveDuration,
            CompletedAt = DateTimeOffset.Now,
            Error = errors.Length == 0 ? null : string.Join("; ", errors.Take(3))
        };
    }

    private static bool IsPersistenceUse(string api, ParsedSandboxEvent item)
    {
        if (api.StartsWith("CreateService", StringComparison.OrdinalIgnoreCase) ||
            api.StartsWith("StartService", StringComparison.OrdinalIgnoreCase) ||
            api.Equals("SchTasks", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var text = string.Join(' ', item.Arguments);
        return text.Contains("\\Run", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("RunOnce", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("Winlogon", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsStartupPath(string path) =>
        path.Contains("\\Start Menu\\Programs\\Startup", StringComparison.OrdinalIgnoreCase) ||
        path.Contains("\\StartUp\\", StringComparison.OrdinalIgnoreCase);

    private static string NormalizeApi(string? apiName)
    {
        if (string.IsNullOrWhiteSpace(apiName))
        {
            return string.Empty;
        }

        var index = apiName.LastIndexOf('.');
        return index >= 0 && index + 1 < apiName.Length ? apiName[(index + 1)..] : apiName;
    }

    private static string VerdictText(ThreatVerdict verdict) => verdict switch
    {
        ThreatVerdict.Malicious => "恶意",
        ThreatVerdict.Pua => "PUA",
        ThreatVerdict.Attention => "重点关注",
        ThreatVerdict.Suspicious => "可疑",
        _ => "未见异常"
    };

    private static string Trim(string value)
    {
        var cleaned = new string(value.Where(character => !char.IsControl(character)).ToArray()).Trim();
        return cleaned.Length <= 160 ? cleaned : cleaned[..160] + "…";
    }
}
