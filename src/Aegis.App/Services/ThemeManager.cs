using Microsoft.UI.Xaml;

namespace Aegis.App.Services;

public static class ThemeManager
{
    private const string DefenderSource = "ms-appx:///Themes/Defender.xaml";

    private static ResourceDictionary? _defenderResources;
    private static readonly Dictionary<object, object> SavedAegisResources = new();
    private static readonly HashSet<object> OverriddenFrameworkResources = new();

    public static void ApplyDefenderPalette(bool enabled)
    {
        if (Application.Current is null)
        {
            return;
        }

        var resources = Application.Current.Resources;
        if (enabled)
        {
            _defenderResources ??= new ResourceDictionary { Source = new Uri(DefenderSource) };
            foreach (var key in _defenderResources.Keys)
            {
                if (key is string name && name.StartsWith("Aegis", StringComparison.Ordinal))
                {
                    if (!SavedAegisResources.ContainsKey(key) && resources.TryGetValue(key, out var original))
                    {
                        SavedAegisResources[key] = original;
                    }
                }
                else
                {
                    OverriddenFrameworkResources.Add(key);
                }

                resources[key] = _defenderResources[key];
            }
        }
        else
        {
            foreach (var pair in SavedAegisResources)
            {
                resources[pair.Key] = pair.Value;
            }

            SavedAegisResources.Clear();

            foreach (var key in OverriddenFrameworkResources)
            {
                resources.Remove(key);
            }

            OverriddenFrameworkResources.Clear();
        }
    }
}
