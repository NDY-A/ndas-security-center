using Microsoft.Win32;

namespace Aegis.App.Services;

public sealed record SecurityProviderInfo(string Name, string State);

public static class SecurityProviderReader
{
    private const string ProviderRoot = @"SOFTWARE\Microsoft\Security Center\Provider";

    public static IReadOnlyList<SecurityProviderInfo> ReadAntivirusProviders() => ReadCategory("Av");

    public static IReadOnlyList<SecurityProviderInfo> ReadFirewallProviders()
    {
        var providers = ReadCategory("Fw");
        if (providers.Count == 0)
        {
            providers.Add(ReadWindowsFirewall());
        }

        return providers;
    }

    private static List<SecurityProviderInfo> ReadCategory(string category)
    {
        var providers = new List<SecurityProviderInfo>();
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var categoryKey = baseKey.OpenSubKey(ProviderRoot + "\\" + category);
            if (categoryKey is null)
            {
                return providers;
            }

            foreach (var subKeyName in categoryKey.GetSubKeyNames())
            {
                using var providerKey = categoryKey.OpenSubKey(subKeyName);
                if (providerKey?.GetValue("DISPLAYNAME") is not string displayName ||
                    string.IsNullOrWhiteSpace(displayName))
                {
                    continue;
                }

                providers.Add(new SecurityProviderInfo(displayName.Trim(), DescribeState(providerKey.GetValue("STATE"))));
            }
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            // Unreadable hive: report whatever was collected.
        }

        return providers;
    }

    private static string DescribeState(object? rawValue)
    {
        // Windows 安全中心的 STATE 是未公开位图；社区共识是十六进制第三位为 1 表示已启用
        // （例如 Defender 0x061100 已打开、360 0x050000 已关闭）。
        if (rawValue is not int value || value == 0)
        {
            return "已打开。";
        }

        return ((value >> 12) & 0xF) != 0 ? "已打开。" : "已关闭。";
    }

    private static SecurityProviderInfo ReadWindowsFirewall()
    {
        var enabled = false;
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var policyKey = baseKey.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy");
            foreach (var profile in new[] { "DomainProfile", "StandardProfile", "PublicProfile" })
            {
                using var profileKey = policyKey?.OpenSubKey(profile);
                if (profileKey?.GetValue("EnableFirewall") is int value && value != 0)
                {
                    enabled = true;
                }
            }
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            // Fall through to the disabled label.
        }

        return new SecurityProviderInfo("Windows 防火墙", enabled ? "已打开。" : "已关闭。");
    }
}
