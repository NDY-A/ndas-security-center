using System.ComponentModel;
using Aegis.Core.Models;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Media;
using Windows.UI;

namespace Aegis.App.Views;

public sealed class ScanResultRow : INotifyPropertyChanged
{
    private string? _actionStatus;

    public required FileScanResult Result { get; init; }
    public required string VerdictText { get; init; }
    public required string Title { get; init; }
    public required string FilePath { get; init; }
    public required string Detail { get; init; }
    public required string ScoreText { get; init; }
    public string TimeText { get; init; } = string.Empty;
    public required Brush BadgeBackground { get; init; }
    public required Brush BadgeForeground { get; init; }

    public string ActionStatus => _actionStatus ?? string.Empty;

    public Visibility ActionsVisibility => _actionStatus is null ? Visibility.Visible : Visibility.Collapsed;

    public Visibility StatusVisibility => _actionStatus is null ? Visibility.Collapsed : Visibility.Visible;

    public event PropertyChangedEventHandler? PropertyChanged;

    public void MarkHandled(string status)
    {
        _actionStatus = status;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(ActionStatus)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(ActionsVisibility)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(StatusVisibility)));
    }

    public static ScanResultRow From(FileScanResult finding, DateTimeOffset? completedAt = null)
    {
        var detection = finding.Detections.FirstOrDefault();
        var malicious = finding.Verdict == ThreatVerdict.Malicious;
        var attention = finding.Verdict == ThreatVerdict.Attention;
        return new ScanResultRow
        {
            Result = finding,
            VerdictText = finding.VerdictText,
            Title = finding.ThreatName ?? detection?.Name ?? "启发式发现",
            FilePath = finding.FilePath,
            Detail = detection is null
                ? string.Join(" · ", finding.Notes.Take(2))
                : $"{detection.RuleId} · {detection.Description}",
            ScoreText = $"评分 {finding.Score}",
            TimeText = completedAt is { } time ? time.ToLocalTime().ToString("MM-dd HH:mm") : string.Empty,
            BadgeBackground = malicious
                ? BrushResource("AegisDangerSoftBrush", Color.FromArgb(255, 253, 231, 233))
                : attention
                    ? BrushResource("AegisAccentSoftBrush", Color.FromArgb(255, 232, 241, 251))
                    : BrushResource("AegisWarningSoftBrush", Color.FromArgb(255, 255, 244, 206)),
            BadgeForeground = malicious
                ? BrushResource("AegisDangerTextBrush", Color.FromArgb(255, 138, 28, 16))
                : attention
                    ? BrushResource("AegisAccentTextBrush", Color.FromArgb(255, 15, 108, 189))
                    : BrushResource("AegisWarningTextBrush", Color.FromArgb(255, 107, 64, 0))
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
