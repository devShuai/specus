using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Specus.Client.Configuration;
using Specus.Client.Updates;

namespace Specus.Client.Cli;

/// <summary>
/// Deliberately narrow HTTP/1.1 endpoint: one request per connection, fixed-length JSON only,
/// no upgrades, chunking, proxies or filesystem routing. Uses loopback sockets, not HTTP.sys
/// (which would require a Windows URL reservation) or an extra ASP.NET shared runtime.
/// </summary>
internal sealed class LocalUi(ClientCliOptions options, string configPath)
{
    internal sealed class Failure(int status, string message) : Exception(message) { internal int Status => status; }
    private readonly UiRuntime _runtime = new();
    private readonly SemaphoreSlim _operations = new(1);
    private readonly object _authGate = new();
    private readonly Dictionary<string, DateTimeOffset> _sessions = [];
    private string _code = "", _origin = "";
    private DateTimeOffset _codeExpiry;
    private static string Random() => Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
    private void PrintCode()
    {
        lock (_authGate) { _code = Random(); _codeExpiry = DateTimeOffset.UtcNow.AddMinutes(5);
            Console.WriteLine("一次性连接码（5 分钟有效；按 Enter 生成新码）：\n" + _code); }
    }
    private object Session(JsonObject body)
    {
        lock (_authGate)
        {
            var now = DateTimeOffset.UtcNow;
            if (_code == "" || now >= _codeExpiry || body["code"]?.GetValue<string>() != _code) throw new Failure(401, "连接码无效或已过期，请在终端按 Enter 获取新码");
            foreach (var expired in _sessions.Where(s => s.Value <= now).Select(s => s.Key).ToArray()) _sessions.Remove(expired);
            if (_sessions.Count >= 8) throw new Failure(429, "会话数已达上限，请重启本地页面服务");
            _code = ""; var token = Random(); _sessions[token] = now.AddHours(8); return new { schemaVersion = 1, token };
        }
    }
    private void Authenticate(string bearer)
    {
        lock (_authGate)
            if (!bearer.StartsWith("Bearer ", StringComparison.Ordinal) || !_sessions.TryGetValue(bearer[7..], out var expiry) || expiry <= DateTimeOffset.UtcNow)
                throw new Failure(401, "请使用终端中的一次性连接码打开工作台");
    }
    private List<object> Others()
    {
        CliState.CheckPrivate(CliState.Root);
        var result = new List<object>(); int count = 0;
        foreach (var path in Directory.EnumerateFiles(CliState.Root, "*.json"))
        {
            if (++count > 256) throw new Failure(409, "本地状态文件过多，请检查状态目录");
            try
            {
                CliState.CheckPrivate(path); if (new FileInfo(path).Length > 1024 * 1024) continue;
                var data = JsonNode.Parse(File.ReadAllText(path))!;
                int pid = data["pid"]!.GetValue<int>(); long age = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - data["updatedAtUnixMs"]!.GetValue<long>();
                if (pid == Environment.ProcessId || age is < 0 or > 5000 || data["schemaVersion"]!.GetValue<int>() != 1 || !string.Equals(data["configPath"]!.GetValue<string>(), configPath,
                    OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal)) continue;
                using var process = Process.GetProcessById(pid); if (process.HasExited) continue;
                result.Add(new { pid, phase = data["phase"]!.GetValue<string>(), controlAuthenticated = data["controlAuthenticated"]!.GetValue<bool>(), businessReady = data["businessReady"]!.GetValue<bool>(), readOnly = true });
            }
            catch (Exception e) when (e is FileNotFoundException or JsonException or ArgumentException or InvalidOperationException or NullReferenceException) { }
        }
        return result;
    }
    private async Task<object> ApiAsync(string path, string method, JsonObject body, CancellationToken cancellation)
    {
        await _operations.WaitAsync(cancellation);
        try
        {
            if (path == "/api/config" && method == "GET") return UiConfig.View(configPath);
            if (path == "/api/status" && method == "GET")
            {
                List<object> others = []; string warning = "";
                try { others = Others(); } catch (Exception) { warning = "无法安全读取其他实例状态，连接操作已禁用"; }
                return new { schemaVersion = 1, implementation = "dotnet", version = ClientVersion.Current, configPath,
                    runtime = _runtime.Snapshot(), otherInstances = others, instanceWarning = warning };
            }
            if ((path is "/api/config/save" or "/api/config/validate") && method == "POST")
            {
                var warnings = new List<string>(); var bytes = UiConfig.Prepare(configPath, body, warnings);
                bool save = path.EndsWith("/save", StringComparison.Ordinal); if (save) UiConfig.Save(configPath, body["revision"]!.GetValue<string>(), bytes);
                return new { schemaVersion = 1, saved = save, offline = true, warnings };
            }
            if (path == "/api/connection" && method == "POST")
            {
                string action = body["action"]?.GetValue<string>() ?? "";
                if (action is not ("start" or "stop" or "restart")) throw new Failure(400, "未知连接操作");
                if (action == "stop") await _runtime.StopAsync();
                else
                {
                    if (Others().Count > 0) throw new Failure(409, "已有其他 CLI 实例运行，本页只读展示且不会接管");
                    var snapshot = UiConfig.Read(configPath); UiConfig.CheckRevision(snapshot, body["revision"]?.GetValue<string>() ?? ""); UiConfig.Parse(snapshot.Bytes);
                    var config = SpecusClientConfigLoader.Parse(new UTF8Encoding(false, true).GetString(snapshot.Bytes), configPath);
                    config.AutoUpdate = false; config.UpdateEnabled = false;
                    if (action == "restart") await _runtime.StopAsync();
                    _runtime.Start(config, configPath, snapshot.Revision, options.LoginTimeout);
                }
                return new { schemaVersion = 1, accepted = true };
            }
            if (path is "/api/config" or "/api/status" or "/api/config/save" or "/api/config/validate" or "/api/connection") throw new Failure(405, "此接口不支持该方法");
            throw new Failure(404, "接口不存在");
        }
        finally { _operations.Release(); }
    }
    private async Task HandleAsync(TcpClient socket, CancellationToken shutdown)
    {
        using (socket)
        using (var deadline = CancellationTokenSource.CreateLinkedTokenSource(shutdown))
        {
            deadline.CancelAfter(TimeSpan.FromSeconds(25)); var ct = deadline.Token; var stream = socket.GetStream();
            int status = 200; string type = "application/json; charset=utf-8"; byte[] result;
            try
            {
                // A separate total read budget prevents slow headers/bodies from retaining a slot.
                using var readDeadline = CancellationTokenSource.CreateLinkedTokenSource(ct); readDeadline.CancelAfter(TimeSpan.FromSeconds(10));
                byte[] header = new byte[16384], single = new byte[1]; int size = 0;
                while (true)
                {
                    if (size == header.Length) throw new Failure(400, "请求头过大");
                    if (await stream.ReadAsync(single, readDeadline.Token) == 0) return;
                    byte b = single[0]; if (b > 126 || b < 32 && b is not (9 or 10 or 13)) throw new Failure(400, "无效请求头");
                    header[size++] = b;
                    if (size >= 4 && header.AsSpan(size - 4, 4).SequenceEqual("\r\n\r\n"u8)) break;
                }
                string[] lines = Encoding.ASCII.GetString(header, 0, size - 4).Split("\r\n");
                string[] first = lines[0].Split(' ');
                if (first.Length != 3 || first[2] != "HTTP/1.1") throw new Failure(400, "仅支持 HTTP/1.1 请求");
                var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach (string line in lines.Skip(1))
                {
                    int colon = line.IndexOf(':'); if (colon <= 0) throw new Failure(400, "无效请求头");
                    string name = line[..colon];
                    if (name.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '-')) throw new Failure(400, "无效请求头");
                    if (!headers.TryAdd(name, line[(colon + 1)..].Trim(' ', '\t'))) throw new Failure(400, "重复请求头");
                }
                string Get(string key) => headers.GetValueOrDefault(key, "");
                string method = first[0], path = first[1];
                if (Get("Host") != _origin[7..]) throw new Failure(403, "Host 不匹配");
                if (headers.ContainsKey("Origin") && Get("Origin") != _origin || Get("Sec-Fetch-Site") == "cross-site") throw new Failure(403, "仅允许本地页面访问");
                if (method is not ("GET" or "POST")) throw new Failure(405, "不支持该方法");
                if (path.Contains('?') || path.Contains('%') || !path.StartsWith('/')) throw new Failure(400, "不支持查询参数或编码路径");
                if (headers.ContainsKey("Transfer-Encoding") || headers.ContainsKey("Expect") || headers.ContainsKey("Upgrade")) throw new Failure(400, "不支持流式请求或协议升级");
                int length = 0;
                if (headers.TryGetValue("Content-Length", out var rawLength) && (rawLength.Length == 0 || rawLength.Any(c => c is < '0' or > '9') || !int.TryParse(rawLength, out length) || length > 65536)) throw new Failure(400, "请求体过大或长度无效");
                if (method == "POST")
                {
                    if (Get("Origin") != _origin || Get("X-Specus-UI") != "1") throw new Failure(403, "写入操作必须来自本地页面");
                    if (!Get("Content-Type").Split(';')[0].Trim().Equals("application/json", StringComparison.OrdinalIgnoreCase)) throw new Failure(415, "请求必须是 JSON");
                }
                byte[] bytes = new byte[length]; await stream.ReadExactlyAsync(bytes, readDeadline.Token);
                if (method == "GET" && path is "/" or "/app.js" or "/app.css")
                {
                    string name = path == "/" ? "index.html" : path[1..];
                    using var asset = typeof(LocalUi).Assembly.GetManifestResourceStream("local-ui." + name) ?? throw new Failure(404, "页面资源缺失");
                    using var output = new MemoryStream(); await asset.CopyToAsync(output, ct); result = output.ToArray();
                    type = path.EndsWith(".js") ? "text/javascript; charset=utf-8" : path.EndsWith(".css") ? "text/css; charset=utf-8" : "text/html; charset=utf-8";
                }
                else
                {
                    JsonObject body = [];
                    if (method == "POST")
                    { try { body = JsonNode.Parse(bytes) as JsonObject ?? throw new JsonException(); } catch (JsonException) { throw new Failure(400, "无效 JSON 请求"); } }
                    object data;
                    if (path == "/api/session" && method == "POST") data = Session(body);
                    else { Authenticate(Get("Authorization")); data = await ApiAsync(path, method, body, ct); }
                    result = JsonSerializer.SerializeToUtf8Bytes(data);
                }
            }
            catch (OperationCanceledException) { return; }
            catch (Exception error)
            {
                status = error is Failure failure ? failure.Status : 422;
                result = JsonSerializer.SerializeToUtf8Bytes(new { schemaVersion = 1, error = error is Failure ? error.Message : "操作失败，请检查配置、权限和本地状态；原始诊断不会返回浏览器" });
            }
            string response = $"HTTP/1.1 {status} Response\r\nContent-Type: {type}\r\nContent-Length: {result.Length}\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nX-Frame-Options: DENY\r\nPermissions-Policy: camera=(), microphone=(), geolocation=()\r\nContent-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'\r\n\r\n";
            try
            {
                await stream.WriteAsync(Encoding.ASCII.GetBytes(response), ct); await stream.WriteAsync(result, ct);
                socket.Client.Shutdown(SocketShutdown.Send);
                // On Windows, closing with unread rejected request bytes resets the socket and
                // can discard the error response. Drain only a small bounded tail after FIN.
                using var drain = CancellationTokenSource.CreateLinkedTokenSource(ct); drain.CancelAfter(TimeSpan.FromMilliseconds(200));
                byte[] tail = new byte[8192]; int remaining = 65537;
                while (remaining > 0)
                { int read = await stream.ReadAsync(tail.AsMemory(0, Math.Min(tail.Length, remaining)), drain.Token); if (read == 0) break; remaining -= read; }
            }
            catch (Exception error) when (error is IOException or OperationCanceledException) { }
        }
    }
    internal static async Task<int> RunAsync(ClientCliOptions options, string configPath)
    {
        Console.OutputEncoding = new UTF8Encoding(false);
        string? ownedLock = null; string stage = "私有状态目录"; var ui = new LocalUi(options, configPath);
        using var shutdown = new CancellationTokenSource(); var listener = new TcpListener(IPAddress.Loopback, options.UiPort);
        using var slots = new SemaphoreSlim(16); var pending = new List<Task>();
        ConsoleCancelEventHandler cancel = (_, e) => { e.Cancel = true; shutdown.Cancel(); };
        try
        {
            string path = Path.Combine(CliState.EnsureRoot(), CliState.Prefix(configPath)[7..] + "ui.lock");
            stage = "同配置管理锁（先确认原管理进程已退出，再清理遗留锁）";
            using (var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read))
            { ownedLock = path; file.Write(Encoding.ASCII.GetBytes(Environment.ProcessId.ToString())); }
            stage = "本机端口（检查 --port 是否被占用，或使用 --port 0）";
            listener.Start(32); ui._origin = "http://127.0.0.1:" + ((IPEndPoint)listener.LocalEndpoint).Port;
            stage = "管理服务";
            Console.CancelKeyPress += cancel;
            Console.WriteLine("本地管理页面：" + ui._origin + "\n配置：" + configPath + "\nCtrl+C 退出管理服务及本页连接。"); ui.PrintCode();
            if (!options.NoOpen)
            {
                try
                {
                    var start = new ProcessStartInfo(OperatingSystem.IsWindows() ? "rundll32" : OperatingSystem.IsMacOS() ? "open" : "xdg-open") { UseShellExecute = false, CreateNoWindow = true, WindowStyle = ProcessWindowStyle.Hidden, RedirectStandardOutput = true, RedirectStandardError = true };
                    if (OperatingSystem.IsWindows()) start.ArgumentList.Add("url.dll,FileProtocolHandler");
                    start.ArgumentList.Add(ui._origin + "/#" + ui._code); using var browser = Process.Start(start);
                }
                catch (Exception) { Console.Error.WriteLine("未能打开浏览器，请手动打开本地地址并输入连接码。"); }
            }
            _ = Task.Run(() => { while (Console.ReadLine() is not null && !shutdown.IsCancellationRequested) ui.PrintCode(); });
            while (!shutdown.IsCancellationRequested)
            {
                var socket = await listener.AcceptTcpClientAsync(shutdown.Token);
                if (!slots.Wait(0)) { socket.Dispose(); continue; }
                pending.RemoveAll(task => task.IsCompleted);
                pending.Add(Task.Run(async () => { try { await ui.HandleAsync(socket, shutdown.Token); } finally { slots.Release(); } }));
            }
            return 0;
        }
        catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { return 0; }
        catch (Exception) { Console.Error.WriteLine("无法启动本地页面：" + stage + "。请检查对应资源及当前用户权限。"); return 2; }
        finally
        {
            shutdown.Cancel(); listener.Stop(); Console.CancelKeyPress -= cancel;
            try { await Task.WhenAll(pending); await ui._runtime.StopAsync(); }
            catch (Exception) { Console.Error.WriteLine("连接清理未能按时完成，请确认客户端进程已退出。"); }
            if (ownedLock is not null) File.Delete(ownedLock);
        }
    }
}
