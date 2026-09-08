using Microsoft.Extensions.Logging.Abstractions;
using Specus.Client.Configuration;
using Specus.Client.Control;
using Specus.Client.DirectHttp;

namespace Specus.Client.Cli;

internal sealed class UiRuntime
{
    private readonly object _gate = new();
    private Task? _task;
    private CancellationTokenSource? _stop;
    private CliState? _state;
    private string _revision = "", _detail = "尚未连接；保存配置不会自动连接";
    internal Dictionary<string, object> Snapshot()
    {
        lock (_gate)
        {
            bool running = _task is { IsCompleted: false };
            var data = _state?.Snapshot() ?? new() { ["phase"] = running ? "http-login" : "stopped", ["controlAuthenticated"] = false,
                ["businessReady"] = false, ["peers"] = Array.Empty<object>(), ["services"] = Array.Empty<object>() };
            data["processRunning"] = running; data["runningRevision"] = _revision; data["pid"] = Environment.ProcessId;
            data["detail"] = running ? (string)data["phase"] switch {
                "ready" => "转发通道就绪；目录不代表目标服务已通过连通性探测",
                "control-authenticated" => "控制通道已认证，等待转发通道就绪",
                "connecting" => "正在建立控制通道", _ => "正在进行 HTTP 登录" } : _detail;
            return data;
        }
    }
    internal void Start(SpecusClientConfig config, string path, string revision, int timeout)
    {
        lock (_gate)
        {
            if (_task is { IsCompleted: false }) throw new LocalUi.Failure(409, "本页已有连接正在运行");
            _stop?.Dispose(); _stop = new(); var cancellation = _stop.Token;
            _state = new(path); var state = _state; _revision = revision;
            _task = Task.Run(async () => {
                try
                {
                    using var authHttp = ClientAuthService.BuildDefaultClient(); using var forwardingHttp = DirectHttpForwarder.BuildDefaultClient();
                    var auth = new ClientAuthService(config, authHttp, NullLogger<ClientAuthService>.Instance) { InitialLoginTimeout = TimeSpan.FromSeconds(timeout) };
                    await using var client = new SpecusControlClient(config, auth, new DirectHttpForwarder(forwardingHttp), NullLoggerFactory.Instance, state);
                    await client.RunAsync(cancellation);
                    lock (_gate) _detail = "连接已结束，请检查权限和服务端状态后重试";
                }
                catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { }
                catch (Exception error) { lock (_gate) _detail = error is HttpLoginFailure ? error.Message : "连接失败，请检查配置、网络及服务端状态"; }
                finally { try { state.Dispose(); } finally { lock (_gate) _state = null; } }
            });
        }
    }
    internal async Task StopAsync()
    {
        Task? task;
        lock (_gate) { _stop?.Cancel(); task = _task; }
        if (task is not null)
        {
            try { await task.WaitAsync(TimeSpan.FromSeconds(8)); }
            catch (TimeoutException) { throw new LocalUi.Failure(409, "连接仍在退出，请稍后再试"); }
        }
        lock (_gate) _detail = "连接已断开；页面仍可管理配置";
    }
}
