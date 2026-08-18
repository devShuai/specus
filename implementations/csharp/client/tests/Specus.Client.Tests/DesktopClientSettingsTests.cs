using Specus.Client.Configuration;
using Specus.Client.Desktop;

namespace Specus.Client.Tests;

public sealed class DesktopClientSettingsTests
{
    [Fact]
    public void DefaultsEnableDailyChecksWithoutAutomaticInstall()
    {
        var settings = DesktopClientSettings.Default();

        Assert.True(settings.UpdateCheckEnabled);
        Assert.Equal(24, settings.UpdateCheckIntervalHours);
        Assert.False(settings.AutoUpdate);
    }

    [Theory]
    [InlineData(-1, 24)]
    [InlineData(0, 24)]
    [InlineData(1, 1)]
    [InlineData(169, 168)]
    public void IntervalIsNormalizedToSharedContract(int input, int expected)
    {
        var settings = new DesktopClientSettings { UpdateCheckIntervalHours = input };

        Assert.Equal(expected, settings.Normalize().UpdateCheckIntervalHours);
        Assert.InRange(settings.UpdateCheckIntervalHours,
            SpecusClientConfig.MinUpdateCheckIntervalHours,
            SpecusClientConfig.MaxUpdateCheckIntervalHours);
    }
}
