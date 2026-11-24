using Aegis.Hips;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Media;
using Windows.UI;

namespace Aegis.App.Views;

public sealed class HipsEventRow
{
    public required string SeverityText { get; init; }
    public required string Title { get; init; }
    public required string Detail { get; init; }
    public required string RuleId { get; init; }
    public required string TimeText { get; init; }
    public required Brush BadgeBackground { get; init; }
    public required Brush BadgeForeground { get; init; }

    public static HipsEventRow From(HipsEvent hipsEvent)
    {
        var (backgroundKey, foregroundKey, fallbackBackground, fallbackForeground) = hipsEvent.Severity switch
        {
            HipsSeverity.Critical => ("AegisDangerSoftBrush", "AegisDangerTextBrush",
                Color.FromArgb(255, 253, 231, 233), Color.FromArgb(255, 138, 28, 16)),
            HipsSeverity.High => ("AegisWarningSoftBrush", "AegisWarningTextBrush",
                Color.FromArgb(255, 255, 244, 206), Color.FromArgb(255, 107, 64, 0)),
            HipsSeverity.Medium => ("AegisWarningSoftBrush", "AegisWarningTextBrush",
                Color.FromArgb(255, 255, 244, 206), Color.FromArgb(255, 107, 64, 0)),
            _ => ("AegisAccentSoftBrush", "AegisAccentTextBrush",
                Color.FromArgb(255, 232, 241, 251), Color.FromArgb(255, 15, 108, 189))
        };

        var detail = hipsEvent.Detail;
        if (!string.IsNullOrWhiteSpace(hipsEvent.CommandLine))
        {
            detail += " 命令行：" + hipsEvent.CommandLine;
        }
        else if (!string.IsNullOrWhiteSpace(hipsEvent.ProcessPath))
        {
            detail += " 进程：" + hipsEvent.ProcessPath;
        }

        if (hipsEvent.Blocked)
        {
            detail += " · 已拦截";
        }

        return new HipsEventRow
        {
            SeverityText = hipsEvent.Severity switch
            {
                HipsSeverity.Critical => "严重",
                HipsSeverity.High => "高危",
                HipsSeverity.Medium => "中危",
                HipsSeverity.Low => "低危",
                _ => "信息"
            },
            Title = hipsEvent.Title,
            Detail = detail,
            RuleId = hipsEvent.RuleId,
            TimeText = hipsEvent.Timestamp.ToLocalTime().ToString("HH:mm:ss"),
            BadgeBackground = BrushResource(backgroundKey, fallbackBackground),
            BadgeForeground = BrushResource(foregroundKey, fallbackForeground)
        };
    }

    private static Brush BrushResource(string key, Color fallback)
    {
        if (Application.Current.Resources.TryGetValue(key, out var value) && value is Brush brush)
        {
            return brush;
        }

        return new SolidColorBrush(fallback);
    }
}
