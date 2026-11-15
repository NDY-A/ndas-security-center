using System.Text.Json;

namespace Aegis.AgentHost;

public sealed class AgentPersistedState
{
    public int ConsecutiveFailures { get; set; }
    public string LastState { get; set; } = "unavailable";
    public string? AgentVersion { get; set; }
    public DateTimeOffset? UpdatedAt { get; set; }
}

/// <summary>Small atomic JSON store so restart budgets survive service restarts.</summary>
public sealed class AgentStateStore
{
    private static readonly JsonSerializerOptions JsonDefaults = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
    };

    private readonly string _path;
    private readonly object _lock = new();

    public AgentStateStore(string path) => _path = path;

    public AgentPersistedState Load()
    {
        lock (_lock)
        {
            try
            {
                if (File.Exists(_path))
                {
                    var state = JsonSerializer.Deserialize<AgentPersistedState>(File.ReadAllText(_path), JsonDefaults);
                    if (state is not null)
                    {
                        return state;
                    }
                }
            }
            catch
            {
                // Corrupt state falls back to defaults.
            }

            return new AgentPersistedState();
        }
    }

    public void Save(AgentPersistedState state)
    {
        lock (_lock)
        {
            try
            {
                state.UpdatedAt = DateTimeOffset.UtcNow;
                var directory = Path.GetDirectoryName(_path);
                if (!string.IsNullOrEmpty(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                var temporary = _path + ".tmp";
                File.WriteAllText(temporary, JsonSerializer.Serialize(state, JsonDefaults));
                File.Move(temporary, _path, overwrite: true);
            }
            catch
            {
                // Persistence is advisory; in-memory state remains authoritative.
            }
        }
    }
}
