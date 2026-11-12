using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.Json;
using Aegis.Core.Models;
using Aegis.Core.Signatures;

namespace Aegis.Core.Network;

public sealed record NetworkBlockChange(int DomainsAdded, int IpsAdded)
{
    public int TotalAdded => DomainsAdded + IpsAdded;
}

/// <summary>
/// Writes malicious domains/IPs into the Windows hosts file and Windows Firewall.
/// Only entries recorded in the state file are ever removed, so user-created rules
/// with other names are never touched.
/// </summary>
public sealed class NetworkIocBlocker
{
    private const string HostsBeginMarker = "# BEGIN NDAS NETWORK IOC (managed by NDAS)";
    private const string HostsEndMarker = "# END NDAS NETWORK IOC (managed by NDAS)";
    private const string RulePrefix = "NDAS-IOC-";
    private const int MaxEntries = 4096;

    private readonly object _sync = new();
    private readonly string _statePath;
    private readonly string _hostsPath;
    private readonly Dictionary<string, BlockEntry> _entries = new(StringComparer.OrdinalIgnoreCase);
    private bool _loaded;

    public NetworkIocBlocker(string dataRoot, string? hostsPath = null)
    {
        _statePath = Path.Combine(dataRoot, "network-block.json");
        _hostsPath = hostsPath ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "System32", "drivers", "etc", "hosts");
    }

    public string? LastError { get; private set; }

    public int DomainCount
    {
        get
        {
            lock (_sync)
            {
                EnsureLoaded();
                return _entries.Values.Count(entry => entry.Kind == "domain");
            }
        }
    }

    public int IpCount
    {
        get
        {
            lock (_sync)
            {
                EnsureLoaded();
                return _entries.Values.Count(entry => entry.Kind == "ip");
            }
        }
    }

    /// <summary>
    /// Applies previously recorded entries when enabled; removes all managed entries
    /// when disabled so a crash cannot leave stale blocks behind after opting out.
    /// </summary>
    public void Restore(bool enabled)
    {
        lock (_sync)
        {
            EnsureLoaded();
            LastError = null;
            if (!enabled)
            {
                if (_entries.Count > 0)
                {
                    RemoveAllManagedCore();
                }

                return;
            }

            ApplyFirewallEntries(_entries.Values.Where(entry => entry.Kind == "ip"));
            WriteHostsBlock();
        }
    }

    public NetworkBlockChange Apply(IEnumerable<NetworkIndicator> indicators)
    {
        lock (_sync)
        {
            EnsureLoaded();
            LastError = null;

            var domains = new List<string>();
            var ips = new List<string>();
            foreach (var indicator in indicators)
            {
                if (indicator.Kind == IndicatorKind.Domain)
                {
                    if (DomainName.TryNormalize(indicator.Value, out var domain) &&
                        !_entries.ContainsKey(Key("domain", domain)))
                    {
                        domains.Add(domain);
                    }
                }
                else if (indicator.Kind == IndicatorKind.IpAddress)
                {
                    if (IPAddress.TryParse(indicator.Value, out var address) &&
                        address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork &&
                        !_entries.ContainsKey(Key("ip", address.ToString())))
                    {
                        ips.Add(address.ToString());
                    }
                }
            }

            var domainsAdded = 0;
            var ipsAdded = 0;
            foreach (var domain in domains.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                if (_entries.Count >= MaxEntries)
                {
                    LastError = $"网络封禁条目达到上限 {MaxEntries}，后续指标未处理。";
                    break;
                }

                _entries[Key("domain", domain)] = new BlockEntry
                {
                    Kind = "domain",
                    Value = domain,
                    AddedAt = DateTimeOffset.UtcNow
                };
                domainsAdded++;
            }

            foreach (var ip in ips.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                if (_entries.Count >= MaxEntries)
                {
                    LastError = $"网络封禁条目达到上限 {MaxEntries}，后续指标未处理。";
                    break;
                }

                if (EnsureFirewallRule(ip, "in") && EnsureFirewallRule(ip, "out"))
                {
                    _entries[Key("ip", ip)] = new BlockEntry
                    {
                        Kind = "ip",
                        Value = ip,
                        AddedAt = DateTimeOffset.UtcNow
                    };
                    ipsAdded++;
                }
            }

            if (domainsAdded > 0)
            {
                WriteHostsBlock();
            }

            SaveState();
            return new NetworkBlockChange(domainsAdded, ipsAdded);
        }
    }

    public void ClearManaged()
    {
        lock (_sync)
        {
            EnsureLoaded();
            LastError = null;
            RemoveAllManagedCore();
        }
    }

    private void RemoveAllManagedCore()
    {
        foreach (var entry in _entries.Values.Where(entry => entry.Kind == "ip").ToList())
        {
            RemoveFirewallRule(entry.Value, "in");
            RemoveFirewallRule(entry.Value, "out");
        }

        _entries.Clear();
        WriteHostsBlock();
        SaveState();
    }

    private void ApplyFirewallEntries(IEnumerable<BlockEntry> ips)
    {
        foreach (var entry in ips)
        {
            EnsureFirewallRule(entry.Value, "in");
            EnsureFirewallRule(entry.Value, "out");
        }
    }

    private void WriteHostsBlock()
    {
        try
        {
            var lines = File.Exists(_hostsPath)
                ? File.ReadAllLines(_hostsPath).ToList()
                : new List<string>();

            var kept = new List<string>(lines.Count);
            var inBlock = false;
            foreach (var line in lines)
            {
                var trimmed = line.Trim();
                if (trimmed.Equals(HostsBeginMarker, StringComparison.Ordinal))
                {
                    inBlock = true;
                    continue;
                }

                if (trimmed.Equals(HostsEndMarker, StringComparison.Ordinal))
                {
                    inBlock = false;
                    continue;
                }

                if (!inBlock)
                {
                    kept.Add(line);
                }
            }

            while (kept.Count > 0 && kept[^1].Trim().Length == 0)
            {
                kept.RemoveAt(kept.Count - 1);
            }

            var domains = _entries.Values
                .Where(entry => entry.Kind == "domain")
                .Select(entry => entry.Value)
                .OrderBy(value => value, StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (domains.Count > 0)
            {
                kept.Add(string.Empty);
                kept.Add(HostsBeginMarker);
                foreach (var domain in domains)
                {
                    kept.Add("127.0.0.1 " + domain);
                    kept.Add("::1 " + domain);
                }

                kept.Add(HostsEndMarker);
            }

            var directory = Path.GetDirectoryName(_hostsPath);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            var temporary = _hostsPath + ".ndas.tmp";
            File.WriteAllText(temporary, string.Join("\r\n", kept) + "\r\n", new UTF8Encoding(false));
            File.Move(temporary, _hostsPath, overwrite: true);
        }
        catch (Exception exception)
        {
            LastError = "写入 hosts 失败：" + exception.Message;
        }
    }

    private bool EnsureFirewallRule(string ip, string direction)
    {
        var name = RulePrefix + ip + "-" + direction;
        if (FirewallRuleExists(name))
        {
            return true;
        }

        var result = RunNetsh(
            $"advfirewall firewall add rule name=\"{name}\" dir={direction} action=block " +
            $"remoteip={ip} profile=any protocol=any");
        if (result.ExitCode == 0)
        {
            return true;
        }

        LastError = $"添加防火墙规则失败（{ip} {direction}）：{FirstLine(result.Output)}";
        return false;
    }

    private void RemoveFirewallRule(string ip, string direction)
    {
        var name = RulePrefix + ip + "-" + direction;
        RunNetsh($"advfirewall firewall delete rule name=\"{name}\"");
    }

    private static bool FirewallRuleExists(string name)
    {
        var result = RunNetsh($"advfirewall firewall show rule name=\"{name}\"");
        return result.ExitCode == 0 && result.Output.Contains(name, StringComparison.OrdinalIgnoreCase);
    }

    private static (int ExitCode, string Output) RunNetsh(string arguments)
    {
        try
        {
            var startInfo = new ProcessStartInfo("netsh.exe", arguments)
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using var process = Process.Start(startInfo);
            if (process is null)
            {
                return (-1, "无法启动 netsh.exe");
            }

            var output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
            if (!process.WaitForExit(15_000))
            {
                try
                {
                    process.Kill(entireProcessTree: true);
                }
                catch
                {
                    // Best effort.
                }

                return (-1, "netsh 超时");
            }

            return (process.ExitCode, output);
        }
        catch (Exception exception)
        {
            return (-1, exception.Message);
        }
    }

    private static string FirstLine(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return "未知错误";
        }

        var line = text.Split('\n').FirstOrDefault(value => value.Trim().Length > 0);
        return line?.Trim() ?? text.Trim();
    }

    private void EnsureLoaded()
    {
        if (_loaded)
        {
            return;
        }

        _loaded = true;
        try
        {
            if (!File.Exists(_statePath))
            {
                return;
            }

            var state = JsonSerializer.Deserialize<BlockerState>(File.ReadAllText(_statePath), JsonDefaults);
            if (state?.Entries is null)
            {
                return;
            }

            foreach (var entry in state.Entries)
            {
                if (entry.Kind is not ("domain" or "ip") ||
                    string.IsNullOrWhiteSpace(entry.Value))
                {
                    continue;
                }

                _entries[Key(entry.Kind, entry.Value)] = entry;
            }
        }
        catch (Exception exception)
        {
            LastError = "读取网络封禁状态失败：" + exception.Message;
        }
    }

    private void SaveState()
    {
        try
        {
            var directory = Path.GetDirectoryName(_statePath);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            var state = new BlockerState { Entries = _entries.Values.ToList() };
            var temporary = _statePath + ".tmp";
            File.WriteAllText(temporary, JsonSerializer.Serialize(state, JsonDefaults));
            File.Move(temporary, _statePath, overwrite: true);
        }
        catch (Exception exception)
        {
            LastError = "保存网络封禁状态失败：" + exception.Message;
        }
    }

    private static string Key(string kind, string value) => kind + ":" + value.ToLowerInvariant();

    private static readonly JsonSerializerOptions JsonDefaults = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true
    };

    private sealed class BlockerState
    {
        public List<BlockEntry> Entries { get; set; } = new();
    }

    private sealed class BlockEntry
    {
        public string Kind { get; set; } = string.Empty;
        public string Value { get; set; } = string.Empty;
        public DateTimeOffset AddedAt { get; set; }
    }
}
