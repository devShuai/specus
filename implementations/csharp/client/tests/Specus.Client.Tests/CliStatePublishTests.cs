using Specus.Client.Cli;
using Xunit;

namespace Specus.Client.Tests;

public sealed class CliStatePublishTests
{
    /// <summary>
    /// A failed write must not end publication: the next tick writes again, and the failure and the
    /// recovery are each said once rather than once a second.
    /// </summary>
    [Fact]
    public void PublicationKeepsWritingAfterAFailure()
    {
        var results = new[] { true, false, false, true, true };
        var calls = 0;
        var report = new StringWriter();
        var failing = false;
        foreach (var _ in results)
        {
            failing = CliState.PublishOnce(() =>
            {
                var ok = results[calls++];
                if (!ok) throw new UnauthorizedAccessException("access denied");
            }, failing, report);
        }

        Assert.Equal(results.Length, calls);
        Assert.False(failing);
        Assert.Equal(new[]
        {
            "State publication failed (UnauthorizedAccessException: access denied); retrying every second, so status may be stale meanwhile.",
            "State publication recovered.",
        }, report.ToString().Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries));
    }
}
