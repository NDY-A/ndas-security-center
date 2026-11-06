using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using Aegis.Core.Service;

namespace Aegis.Service;

public sealed class FileBlocker : IDisposable
{
    private const string StoreFileName = "blocked-files.json";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web) { WriteIndented = true };
    private readonly object _lock = new();
    private readonly Dictionary<string, BlockRecord> _records = new(StringComparer.OrdinalIgnoreCase);
    private readonly string _storePath;
    private bool _disposed;

    public FileBlocker(string dataRoot)
    {
        Directory.CreateDirectory(dataRoot);
        _storePath = Path.Combine(dataRoot, StoreFileName);
        Load();
    }

    public IReadOnlyList<ServiceBlockedFile> Snapshot()
    {
        lock (_lock)
        {
            return _records.Values
                .OrderBy(record => record.BlockedAt)
                .Select(ToServiceBlockedFile)
                .ToArray();
        }
    }

    public ServiceBlockedFile Block(string path, string reason)
    {
        var fullPath = Path.GetFullPath(path);
        lock (_lock)
        {
            if (_records.TryGetValue(fullPath, out var existing))
            {
                existing.Reason = reason;
                existing.Handle ??= TryOpenExclusive(fullPath);
                Save();
                return ToServiceBlockedFile(existing);
            }

            var sddl = TryReadSddl(fullPath);
            var aclApplied = TryApplyDeny(fullPath);
            var handle = TryOpenExclusive(fullPath);
            var record = new BlockRecord(fullPath, reason, DateTimeOffset.UtcNow, sddl, aclApplied, handle);
            _records[fullPath] = record;
            Save();
            return ToServiceBlockedFile(record);
        }
    }

    public bool Unblock(string path)
    {
        var fullPath = Path.GetFullPath(path);
        lock (_lock)
        {
            if (!_records.TryGetValue(fullPath, out var record))
            {
                return false;
            }

            record.Handle?.Dispose();
            record.Handle = null;
            TryRestore(fullPath, record.Sddl);
            _records.Remove(fullPath);
            Save();
            return true;
        }
    }

    private void Load()
    {
        try
        {
            if (!File.Exists(_storePath))
            {
                return;
            }

            var entries = JsonSerializer.Deserialize<List<StoredEntry>>(File.ReadAllText(_storePath), JsonOptions);
            foreach (var entry in entries ?? new List<StoredEntry>())
            {
                if (string.IsNullOrWhiteSpace(entry.Path) || !File.Exists(entry.Path))
                {
                    continue;
                }

                var aclApplied = entry.AclApplied && TryApplyDeny(entry.Path);
                var handle = TryOpenExclusive(entry.Path);
                _records[entry.Path] = new BlockRecord(entry.Path, entry.Reason ?? "Malicious",
                    entry.BlockedAt, entry.Sddl, aclApplied, handle);
            }
        }
        catch
        {
            // A corrupt block store must not prevent the service from starting.
        }
    }

    private void Save()
    {
        try
        {
            var entries = _records.Values.Select(record => new StoredEntry
            {
                Path = record.Path,
                Reason = record.Reason,
                BlockedAt = record.BlockedAt,
                Sddl = record.Sddl,
                AclApplied = record.AclApplied
            }).ToList();
            var temporary = _storePath + ".tmp";
            File.WriteAllText(temporary, JsonSerializer.Serialize(entries, JsonOptions));
            File.Move(temporary, _storePath, overwrite: true);
        }
        catch
        {
            // Persistence is best-effort; the in-memory locks still hold.
        }
    }

    private static string? TryReadSddl(string path)
    {
        try
        {
            var file = new FileInfo(path);
            var security = file.GetAccessControl(AccessControlSections.Access);
            return security.GetSecurityDescriptorSddlForm(AccessControlSections.Access);
        }
        catch
        {
            return null;
        }
    }

    private static bool TryApplyDeny(string path)
    {
        try
        {
            // ACL denial is only applied by the LocalSystem service; a developer console
            // running as the file owner would otherwise lock itself out.
            if (!WindowsIdentity.GetCurrent().IsSystem)
            {
                return false;
            }

            var file = new FileInfo(path);
            var security = file.GetAccessControl(AccessControlSections.Access);
            var interactive = new SecurityIdentifier(WellKnownSidType.InteractiveSid, null);
            var identities = new HashSet<SecurityIdentifier> { interactive };

            SecurityIdentifier? owner = null;
            try
            {
                owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
            }
            catch
            {
                // The owner is not required to apply the interactive deny.
            }

            if (owner is not null && ShouldLockIdentity(owner))
            {
                identities.Add(owner);
            }

            foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                if (rule.AccessControlType == AccessControlType.Deny &&
                    rule.FileSystemRights == FileSystemRights.FullControl &&
                    rule.IdentityReference is SecurityIdentifier sid &&
                    identities.Contains(sid))
                {
                    return true;
                }
            }

            foreach (var identity in identities)
            {
                security.AddAccessRule(new FileSystemAccessRule(identity, FileSystemRights.FullControl, AccessControlType.Deny));
            }

            file.SetAccessControl(security);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static bool ShouldLockIdentity(SecurityIdentifier sid)
    {
        return !sid.IsWellKnown(WellKnownSidType.LocalSystemSid) &&
               !sid.IsWellKnown(WellKnownSidType.LocalServiceSid) &&
               !sid.IsWellKnown(WellKnownSidType.NetworkServiceSid) &&
               !sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid) &&
               !sid.IsWellKnown(WellKnownSidType.BuiltinUsersSid) &&
               !sid.IsWellKnown(WellKnownSidType.AuthenticatedUserSid) &&
               !sid.IsWellKnown(WellKnownSidType.InteractiveSid);
    }

    private static void TryRestore(string path, string? sddl)
    {
        try
        {
            if (!File.Exists(path))
            {
                return;
            }

            var file = new FileInfo(path);
            if (!string.IsNullOrWhiteSpace(sddl))
            {
                var original = new FileSecurity();
                original.SetSecurityDescriptorSddlForm(sddl, AccessControlSections.Access);
                file.SetAccessControl(original);
                return;
            }

            var security = file.GetAccessControl(AccessControlSections.Access);
            var identities = new HashSet<SecurityIdentifier>
            {
                new(WellKnownSidType.InteractiveSid, null)
            };
            try
            {
                if (security.GetOwner(typeof(SecurityIdentifier)) is SecurityIdentifier owner && ShouldLockIdentity(owner))
                {
                    identities.Add(owner);
                }
            }
            catch
            {
                // Best effort.
            }

            foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToArray())
            {
                if (rule.AccessControlType == AccessControlType.Deny &&
                    rule.FileSystemRights == FileSystemRights.FullControl &&
                    rule.IdentityReference is SecurityIdentifier sid &&
                    identities.Contains(sid))
                {
                    security.RemoveAccessRuleSpecific(rule);
                }
            }

            file.SetAccessControl(security);
        }
        catch
        {
            // Restoring the original ACL is best-effort.
        }
    }

    private static FileStream? TryOpenExclusive(string path)
    {
        try
        {
            return new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.None, 1,
                FileOptions.None);
        }
        catch
        {
            return null;
        }
    }

    private static ServiceBlockedFile ToServiceBlockedFile(BlockRecord record) => new()
    {
        Path = record.Path,
        Reason = record.Reason,
        BlockedAt = record.BlockedAt,
        AclApplied = record.AclApplied,
        HandleHeld = record.Handle is not null
    };

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        lock (_lock)
        {
            foreach (var record in _records.Values)
            {
                record.Handle?.Dispose();
                record.Handle = null;
            }
        }
    }

    private sealed class BlockRecord
    {
        public BlockRecord(string path, string reason, DateTimeOffset blockedAt, string? sddl, bool aclApplied, FileStream? handle)
        {
            Path = path;
            Reason = reason;
            BlockedAt = blockedAt;
            Sddl = sddl;
            AclApplied = aclApplied;
            Handle = handle;
        }

        public string Path { get; }
        public string Reason { get; set; }
        public DateTimeOffset BlockedAt { get; }
        public string? Sddl { get; }
        public bool AclApplied { get; }
        public FileStream? Handle { get; set; }
    }

    private sealed class StoredEntry
    {
        public string? Path { get; set; }
        public string? Reason { get; set; }
        public DateTimeOffset BlockedAt { get; set; }
        public string? Sddl { get; set; }
        public bool AclApplied { get; set; }
    }
}
