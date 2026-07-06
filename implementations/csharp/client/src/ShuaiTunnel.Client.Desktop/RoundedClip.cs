using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace ShuaiTunnel.Client.Desktop;

/// <summary>
/// 让 Border 的内容（例如 DataGrid 的方角表头）跟随外层圆角。
/// 裁剪必须加在 Child 而不是 Border 自身：直接裁剪 Border 时，描边与裁剪
/// 边缘在圆角处叠加抗锯齿，会出现锯齿与漏色。内容裁剪半径按描边与内边距
/// 向内收缩，保证描边完整可见、内容不越界。
/// </summary>
public static class RoundedClip
{
    public static readonly DependencyProperty CornerRadiusProperty =
        DependencyProperty.RegisterAttached(
            "CornerRadius",
            typeof(CornerRadius),
            typeof(RoundedClip),
            new PropertyMetadata(default(CornerRadius), OnCornerRadiusChanged));

    public static CornerRadius GetCornerRadius(DependencyObject element)
    {
        return (CornerRadius)element.GetValue(CornerRadiusProperty);
    }

    public static void SetCornerRadius(DependencyObject element, CornerRadius value)
    {
        element.SetValue(CornerRadiusProperty, value);
    }

    private static void OnCornerRadiusChanged(DependencyObject dependencyObject, DependencyPropertyChangedEventArgs e)
    {
        if (dependencyObject is not Border border)
        {
            return;
        }

        border.SizeChanged -= Border_SizeChanged;
        border.SizeChanged += Border_SizeChanged;
        border.Loaded -= Border_Loaded;
        border.Loaded += Border_Loaded;
        ApplyClip(border);
    }

    private static void Border_Loaded(object sender, RoutedEventArgs e)
    {
        if (sender is Border border)
        {
            ApplyClip(border);
        }
    }

    private static void Border_SizeChanged(object sender, SizeChangedEventArgs e)
    {
        if (sender is Border border)
        {
            ApplyClip(border);
        }
    }

    private static void ApplyClip(Border border)
    {
        if (border.Child is not FrameworkElement child)
        {
            return;
        }

        var outerRadius = GetCornerRadius(border).TopLeft;
        var inset = border.BorderThickness.Left + border.Padding.Left;
        var innerRadius = Math.Max(0, outerRadius - inset);
        var width = child.ActualWidth;
        var height = child.ActualHeight;
        if (width <= 0 || height <= 0 || innerRadius <= 0)
        {
            child.Clip = null;
            return;
        }

        child.Clip = new RectangleGeometry(new Rect(0, 0, width, height), innerRadius, innerRadius);
    }
}
