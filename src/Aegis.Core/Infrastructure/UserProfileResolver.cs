using System.Runtime.Versioning;
using Microsoft.Win32;

namespace Aegis.Core.Infrastructure;

public sealed record UserProfileFolders(string Sid, string ProfilePath, string? Desktop, string? Downloads);

[SupportedOSPlatform("windows")]
public static class UserProfileResolver
{
    private static readonly object CacheLock = new();
    private static IReadOnlyList<UserProfileFolders> _cache = Array.Empty<UserProfileFolders>();
    private static DateTimeOffset _cacheAt = DateTimeOffset.MinValue;

    public static IReadOnlyList<UserProfileFolders> GetCached(TimeSpan maxAge)
    {
        lock (CacheLock)
        {
            if (DateTimeOffset.UtcNow - _cacheAt <= maxAge)
            {
                return _cache;
            }
        }

        var fresh = Resolve();
        lock (CacheLock)
        {
            _cache = fresh;
            _cacheAt = DateTimeOffset.UtcNow;
        }

        return fresh;
    }

    public static IReadOnlyList<UserProfileFolders> Resolve()
    {
        var results = new List<UserProfileFolders>();
        try
        {
            using var profileList = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList");
            if (profileList is null)
            {
                return results;
            }

            foreach (var sid in profileList.GetSubKeyNames())
            {
                if (!sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                try
                {
                    string? profilePath;
                    using (var key = profileList.OpenSubKey(sid))
                    {
                        profilePath = key?.GetValue("ProfileImagePath") as string;
                    }

                    if (string.IsNullOrWhiteSpace(profilePath))
                    {
                        continue;
                    }

                    profilePath = Environment.ExpandEnvironmentVariables(profilePath).TrimEnd('\\');
                    if (!Directory.Exists(profilePath))
                    {
                        continue;
                    }

                    RegistryKey? userKey = null;
                    try
                    {
                        userKey = Registry.Users.OpenSubKey(sid);
                    }
                    catch
                    {
                        // A hive can be inaccessible during logon/logoff; fall back below.
                    }

                    using (userKey)
                    {
                        RegistryKey? shellKey = null;
                        if (userKey is not null)
                        {
                            try
                            {
                                shellKey = userKey.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")
                                           ?? userKey.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders");
                            }
                            catch
                            {
                                // Fall back to profile-relative folders.
                            }
                        }

                        using (shellKey)
                        {
                            var desktop = ExistingOrNull(ReadAndExpand(shellKey, "Desktop", profilePath))
                                          ?? ExistingOrNull(Path.Combine(profilePath, "Desktop"));
                            var downloads = ExistingOrNull(ReadAndExpand(shellKey, "{374DE290-123F-4565-9164-39C4925E467B}", profilePath))
                                            ?? ExistingOrNull(Path.Combine(profilePath, "Downloads"));

                            results.Add(new UserProfileFolders(sid, profilePath, desktop, downloads));
                        }
                    }
                }
                catch
                {
                    // A profile can disappear between enumeration and inspection.
                }
            }
        }
        catch
        {
            // Profile enumeration is best-effort.
        }

        return results;
    }

    private static string? ReadAndExpand(RegistryKey? key, string valueName, string profilePath)
    {
        if (key?.GetValue(valueName) is not string value || string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var root = Path.GetPathRoot(profilePath)?.TrimEnd('\\') ?? "C:";
        var homePath = profilePath.Length > root.Length ? profilePath[root.Length..] : string.Empty;
        var expanded = value
            .Replace("%USERPROFILE%", profilePath, StringComparison.OrdinalIgnoreCase)
            .Replace("%HOMEDRIVE%", root, StringComparison.OrdinalIgnoreCase)
            .Replace("%HOMEPATH%", homePath, StringComparison.OrdinalIgnoreCase)
            .Replace("%SYSTEMDRIVE%", root, StringComparison.OrdinalIgnoreCase)
            .Replace("%SYSTEMROOT%", Environment.GetFolderPath(Environment.SpecialFolder.Windows), StringComparison.OrdinalIgnoreCase)
            .Replace("%WINDIR%", Environment.GetFolderPath(Environment.SpecialFolder.Windows), StringComparison.OrdinalIgnoreCase)
            .Replace("%PUBLIC%", Environment.GetEnvironmentVariable("PUBLIC") ?? @"C:\Users\Public", StringComparison.OrdinalIgnoreCase);
        return Environment.ExpandEnvironmentVariables(expanded).TrimEnd('\\');
    }

    private static string? ExistingOrNull(string? path)
    {
        return !string.IsNullOrWhiteSpace(path) && Directory.Exists(path) ? path : null;
    }
}
