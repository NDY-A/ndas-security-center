using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.Foundation;

namespace Aegis.App.Controls;

/// <summary>按可用宽度自动排列等宽卡片，窄窗口时减少列数。</summary>
public sealed class CardWrapPanel : Panel
{
    public static readonly DependencyProperty MinItemWidthProperty =
        DependencyProperty.Register(nameof(MinItemWidth), typeof(double), typeof(CardWrapPanel),
            new PropertyMetadata(260d, OnLayoutPropertyChanged));

    public static readonly DependencyProperty MaxColumnsProperty =
        DependencyProperty.Register(nameof(MaxColumns), typeof(int), typeof(CardWrapPanel),
            new PropertyMetadata(4, OnLayoutPropertyChanged));

    public static readonly DependencyProperty SpacingProperty =
        DependencyProperty.Register(nameof(Spacing), typeof(double), typeof(CardWrapPanel),
            new PropertyMetadata(16d, OnLayoutPropertyChanged));

    public double MinItemWidth
    {
        get => (double)GetValue(MinItemWidthProperty);
        set => SetValue(MinItemWidthProperty, value);
    }

    public int MaxColumns
    {
        get => (int)GetValue(MaxColumnsProperty);
        set => SetValue(MaxColumnsProperty, value);
    }

    public double Spacing
    {
        get => (double)GetValue(SpacingProperty);
        set => SetValue(SpacingProperty, value);
    }

    private static void OnLayoutPropertyChanged(DependencyObject d, DependencyPropertyChangedEventArgs e) =>
        ((CardWrapPanel)d).InvalidateMeasure();

    private int GetColumnCount(double width)
    {
        var spacing = Math.Max(0, Spacing);
        var minWidth = Math.Max(1, MinItemWidth);
        var columns = (int)Math.Floor((width + spacing) / (minWidth + spacing));
        return Math.Clamp(columns, 1, Math.Max(1, MaxColumns));
    }

    protected override Size MeasureOverride(Size availableSize)
    {
        var children = Children;
        if (children.Count == 0)
        {
            return new Size(0, 0);
        }

        var spacing = Math.Max(0, Spacing);
        var width = availableSize.Width;
        if (double.IsInfinity(width) || double.IsNaN(width) || width <= 0)
        {
            width = MaxColumns * MinItemWidth + Math.Max(0, MaxColumns - 1) * spacing;
        }

        var columns = GetColumnCount(width);
        var cellWidth = Math.Max(0, (width - (columns - 1) * spacing) / columns);

        double totalHeight = 0;
        double rowHeight = 0;
        var index = 0;
        foreach (var child in children)
        {
            child.Measure(new Size(cellWidth, double.PositiveInfinity));
            rowHeight = Math.Max(rowHeight, child.DesiredSize.Height);
            index++;
            if (index == columns)
            {
                totalHeight += rowHeight + spacing;
                rowHeight = 0;
                index = 0;
            }
        }

        if (index > 0)
        {
            totalHeight += rowHeight;
        }
        else if (totalHeight > 0)
        {
            totalHeight -= spacing;
        }

        return new Size(width, totalHeight);
    }

    protected override Size ArrangeOverride(Size finalSize)
    {
        var children = Children;
        if (children.Count == 0)
        {
            return finalSize;
        }

        var spacing = Math.Max(0, Spacing);
        var columns = GetColumnCount(finalSize.Width);
        var cellWidth = Math.Max(0, (finalSize.Width - (columns - 1) * spacing) / columns);

        double y = 0;
        for (var start = 0; start < children.Count; start += columns)
        {
            var end = Math.Min(start + columns, children.Count);
            var rowHeight = 0d;
            for (var i = start; i < end; i++)
            {
                rowHeight = Math.Max(rowHeight, children[i].DesiredSize.Height);
            }

            for (var i = start; i < end; i++)
            {
                var column = i - start;
                children[i].Arrange(new Rect(column * (cellWidth + spacing), y, cellWidth, rowHeight));
            }

            y += rowHeight + spacing;
        }

        return new Size(finalSize.Width, Math.Max(0, y - spacing));
    }
}
