using Aegis.App.Services;
using Microsoft.UI.Text;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Windows.UI;

namespace Aegis.App.Views;

public sealed partial class ProvidersPage : Page
{
    public ProvidersPage()
    {
        InitializeComponent();
        Loaded += (_, _) => Reload();
    }

    private void Reload()
    {
        Fill(AntivirusProviderList, SecurityProviderReader.ReadAntivirusProviders());
        Fill(FirewallProviderList, SecurityProviderReader.ReadFirewallProviders());
    }

    private void Fill(StackPanel target, IReadOnlyList<SecurityProviderInfo> providers)
    {
        target.Children.Clear();
        if (providers.Count == 0)
        {
            target.Children.Add(CreateEmptyRow("未检测到已注册的安全提供程序。"));
            return;
        }

        foreach (var provider in providers)
        {
            target.Children.Add(CreateProviderRow(provider));
        }
    }

    private static Border CreateProviderRow(SecurityProviderInfo provider)
    {
        var grid = new Grid { ColumnSpacing = 8 };
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        var text = new StackPanel { Spacing = 2 };
        text.Children.Add(new TextBlock
        {
            Text = provider.Name,
            FontSize = 14,
            FontWeight = FontWeights.SemiBold,
            TextWrapping = TextWrapping.Wrap
        });
        var stateText = new TextBlock
        {
            Text = provider.Name + " " + provider.State,
            FontSize = 12,
            TextWrapping = TextWrapping.Wrap
        };
        if (Application.Current.Resources.TryGetValue("TextFillColorSecondaryBrush", out var secondary) &&
            secondary is Brush secondaryBrush)
        {
            stateText.Foreground = secondaryBrush;
        }

        text.Children.Add(stateText);
        grid.Children.Add(text);

        if (!string.Equals(provider.State, "已打开。", StringComparison.Ordinal))
        {
            var chevron = new FontIcon
            {
                Glyph = "",
                FontSize = 12,
                HorizontalAlignment = HorizontalAlignment.Right,
                VerticalAlignment = VerticalAlignment.Center
            };
            Grid.SetColumn(chevron, 1);
            grid.Children.Add(chevron);
        }

        return new Border
        {
            Background = Application.Current.Resources.TryGetValue("SubtleFillColorSecondaryBrush", out var subtle) &&
                         subtle is Brush subtleBrush
                ? subtleBrush
                : new SolidColorBrush(Color.FromArgb(255, 47, 47, 47)),
            CornerRadius = new CornerRadius(6),
            Padding = new Thickness(14, 12, 14, 12),
            Child = grid
        };
    }

    private static Border CreateEmptyRow(string message)
    {
        var text = new TextBlock
        {
            Text = message,
            FontSize = 12,
            TextWrapping = TextWrapping.Wrap
        };
        if (Application.Current.Resources.TryGetValue("TextFillColorSecondaryBrush", out var secondary) &&
            secondary is Brush secondaryBrush)
        {
            text.Foreground = secondaryBrush;
        }

        return new Border
        {
            Background = Application.Current.Resources.TryGetValue("SubtleFillColorSecondaryBrush", out var subtle) &&
                         subtle is Brush subtleBrush
                ? subtleBrush
                : new SolidColorBrush(Color.FromArgb(255, 47, 47, 47)),
            CornerRadius = new CornerRadius(6),
            Padding = new Thickness(14, 12, 14, 12),
            Child = text
        };
    }

    private void BreadcrumbSettings_Click(object sender, RoutedEventArgs e) => App.MainWindow?.NavigateTo("hips");

    private async void OpenStore_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            await Windows.System.Launcher.LaunchUriAsync(new Uri("ms-windows-store://search/?query=antivirus"));
        }
        catch
        {
            // Store may be unavailable; the link is best-effort.
        }
    }
}
