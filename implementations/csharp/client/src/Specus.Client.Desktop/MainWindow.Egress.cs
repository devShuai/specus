using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using Microsoft.Extensions.Logging;
using Specus.Client.Cli;
using Specus.Client.Configuration;
using Specus.Client.Runtime;
using Specus.Protocol.PeerEgress;

namespace Specus.Client.Desktop;

/// <summary>
/// The egress page: the rules, the takeover switch, a rule tester and what the running client says
/// about them.
/// </summary>
/// <remarks>
/// Every edit goes through the same plan as the egress commands and the local page, so a rule one of
/// them refuses is refused here with the same code; the words are the local page's. The rules live in
/// this app's own settings rather than a configuration file, and a running client reads them when it
/// connects, as the other two entries say too.
/// </remarks>
public partial class MainWindow
{
    /// <summary>Why a rule is not in force, in the words the local page uses.</summary>
    private static readonly IReadOnlyDictionary<string, string> EgressRuleReasons = new Dictionary<string, string>
    {
        [PeerEgressCodes.RuleDefaultRoute] = "一期不接管默认路由",
        [PeerEgressCodes.RuleMeshOverlap] = "与组网虚拟网段重叠",
        [PeerEgressCodes.RuleMalformed] = "规则格式不正确（含主机位非零）",
        [PeerEgressCodes.RuleMissingTarget] = "没有指定出口设备",
        [PeerEgressCodes.RuleDomainUnsupported] = "域名规则需要二期的 DNS 接管，目前不支持",
        [PeerEgressCodes.RuleIpv6Unsupported] = "一期不支持 IPv6 规则",
        [PeerEgressCodes.RulePortUnsupported] = "消费端规则不支持端口字段",
        [PeerEgressCodes.RuleDisabled] = "规则已停用",
        [PeerEgressCodes.ConsumerDisabled] = "系统接管未开启",
    };

    private const string EgressEnableNotice =
        "开启系统接管：\n\n"
        + "· 需要创建虚拟网卡与安装路由的权限（以管理员运行；虚拟网卡模式不能是 noop）\n"
        + "· 只接管规则命中的目标，其余流量保持本地直连\n"
        + "· 命中「经出口设备」规则而出口不可用时，这些目标被阻断，不会改走本机\n\n"
        + "确认开启？";

    private bool _egressEnabled;
    private List<PeerEgressRule> _egressRules = [];
    private DispatcherTimer? _egressTimer;

    public ObservableCollection<EgressRuleRow> EgressRules { get; } = new();

    public ObservableCollection<EgressIssueRow> EgressIssues { get; } = new();

    private void InitializeEgressPage()
    {
        // Half the status is live (flows, paths, peers going offline), so it is read while the page
        // is open rather than pushed; three seconds is what the local page polls at.
        _egressTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(3) };
        _egressTimer.Tick += (_, _) => RefreshEgressStatus();
        _egressTimer.Start();
        SyncEgressTargetBox();
        RenderEgressRules();
        RefreshEgressStatus();
    }

    private void StopEgressPage() => _egressTimer?.Stop();

    /// <summary>The configuration the rules are judged against, as the next connection will read it.</summary>
    private SpecusClientConfig EgressConfig() => new()
    {
        PeerEgressEnabled = _egressEnabled,
        PeerEgressRules = _egressRules.ToList(),
        PeerMeshDevice = string.IsNullOrWhiteSpace(PeerMeshDeviceBox.Text) ? "auto" : PeerMeshDeviceBox.Text.Trim(),
    };

    private void ApplyEgressChange(EgressEdit.Change change, string done)
    {
        List<PeerEgressRule> edited;
        try
        {
            edited = EgressEdit.ApplyRules(_egressRules, change);
        }
        catch (EgressEdit.PlanFailure failure)
        {
            ShowEgressNotice(EgressFailureText(failure.Message), warning: true);
            return;
        }
        var previous = _egressRules;
        _egressRules = edited;
        if (!PersistEgress(done, []))
        {
            _egressRules = previous;
        }
    }

    /// <summary>Writes the settings and says when the change applies; false when nothing was written.</summary>
    private bool PersistEgress(string done, IEnumerable<string> warnings)
    {
        try
        {
            SaveSettingsFromForm(validateConnection: false);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            ShowEgressNotice("未保存：" + ex.Message, warning: true);
            return false;
        }
        RenderEgressRules();
        var applies = _running ? "运行中的连接需断开后重新连接才会应用。" : "下次连接时生效。";
        ShowEgressNotice(done + "已保存；" + applies + string.Concat(warnings.Select(line => " " + line)),
            warning: warnings.Any());
        return true;
    }

    /// <summary>A plan's refusal carries the rule code the CLI prints; the reason is given in words with the code beside it.</summary>
    private static string EgressFailureText(string message)
    {
        var start = message.IndexOf("EGRESS_", StringComparison.Ordinal);
        if (start >= 0)
        {
            var end = start;
            while (end < message.Length && (char.IsAsciiLetterUpper(message[end]) || char.IsAsciiDigit(message[end]) || message[end] == '_'))
            {
                end++;
            }
            var code = message[start..end];
            if (EgressRuleReasons.TryGetValue(code, out var reason))
            {
                return "未添加：" + reason + "（" + code + "）";
            }
        }
        return message;
    }

    private void ShowEgressNotice(string text, bool warning = false)
    {
        EgressNoticeText.Text = text;
        EgressNoticeText.SetResourceReference(TextBlock.ForegroundProperty, warning ? "WarningBrush" : "TextSecondaryBrush");
        EgressNoticeText.Visibility = Visibility.Visible;
        AppendLog(warning ? LogLevel.Warning : LogLevel.Information, "egress", text, null);
    }

    /// <summary>A device's name where the mesh knows it, and its ID either way.</summary>
    private string EgressDeviceLabel(long clientId)
    {
        var peer = PeerRoutes.FirstOrDefault(route => route.ClientId == clientId);
        return peer is { ClientName: { Length: > 0 } name } ? $"{name}（{clientId}）" : clientId.ToString(System.Globalization.CultureInfo.InvariantCulture);
    }

    private string EgressTargetText(string action, long? egressClientId) => action switch
    {
        PeerEgressRules.ActionEgress => "经出口设备 " + EgressDeviceLabel(egressClientId ?? 0),
        PeerEgressRules.ActionBlock => "阻断",
        PeerEgressRules.ActionDirect => "本地直连",
        _ => "未知动作 " + (action.Length > 0 ? action : "—"),
    };

    private void RenderEgressRules()
    {
        var on = _egressEnabled;
        var count = _egressRules.Count;
        EgressTakeoverStateText.Text = on ? "已开启" : "已关闭";
        EgressTakeoverStateText.SetResourceReference(TextBlock.ForegroundProperty, on ? "SuccessBrush" : "TextSecondaryBrush");
        EgressTakeoverDetailText.Text = on
            ? "命中规则的目标由系统接管；出口不可用时这些目标被阻断，不会改走本机。"
            : count > 0
                ? count + " 条规则已保存，均未生效：流量照常从本机出去。"
                : "尚未配置规则；流量照常从本机出去。添加规则后仍需开启系统接管才会生效。";
        EgressTakeoverButton.Content = on ? "关闭接管" : "开启接管";

        EgressRules.Clear();
        for (var index = 0; index < count; index++)
        {
            var rule = _egressRules[index];
            // The rule's own problem, told apart from being off: worth fixing before takeover is on.
            var refusal = EgressEdit.RuleCode(rule with { Enabled = null });
            var state = refusal is not null
                ? "不会生效：" + (EgressRuleReasons.TryGetValue(refusal, out var reason) ? reason : "规则被拒绝")
                : rule.SwitchedOff ? "已停用" : on ? "已启用，按配置生效" : "已启用，开启系统接管后生效";
            EgressRules.Add(new EgressRuleRow
            {
                Index = index,
                Match = rule.Match.Trim(),
                Target = EgressTargetText(rule.Action.Trim(), rule.EgressClientId),
                State = state,
                Code = refusal ?? string.Empty,
                SwitchedOff = rule.SwitchedOff,
                ToggleLabel = rule.SwitchedOff ? "启用" : "停用",
                CanMoveUp = index > 0,
                CanMoveDown = index < count - 1,
            });
        }
    }

    private void SyncEgressTargetBox()
    {
        EgressTargetBox.IsEnabled = SelectedEgressAction() == PeerEgressRules.ActionEgress;
    }

    private string SelectedEgressAction() =>
        (EgressActionBox.SelectedItem as ComboBoxItem)?.Tag as string ?? PeerEgressRules.ActionEgress;

    private void EgressActionBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (EgressTargetBox is not null) SyncEgressTargetBox();
    }

    private void EgressAddButton_Click(object sender, RoutedEventArgs e)
    {
        var action = SelectedEgressAction();
        long egressClientId = 0;
        if (action == PeerEgressRules.ActionEgress)
        {
            if (EgressTargetBox.SelectedItem is PeerRouteSnapshot peer && EgressTargetBox.Text == peer.ClientName)
            {
                egressClientId = peer.ClientId;
            }
            else if (!long.TryParse(EgressTargetBox.Text.Trim(), out egressClientId) || egressClientId <= 0)
            {
                ShowEgressNotice("请选择出口设备，或填写设备 ID（正整数）。", warning: true);
                return;
            }
        }
        if (AddEgressRule(EgressMatchBox.Text.Trim(), action, egressClientId,
                EgressAddFirstBox.IsChecked == true, EgressAddDisabledBox.IsChecked == true))
        {
            EgressMatchBox.Clear();
            EgressAddDisabledBox.IsChecked = false;
        }
    }

    /// <summary>Adds a rule through the shared plan; false when it was refused or not saved.</summary>
    internal bool AddEgressRule(string match, string action, long egressClientId, bool first, bool disabled)
    {
        var before = _egressRules.Count;
        ApplyEgressChange(new EgressEdit.Change("add", match, action, egressClientId,
            At: first ? 0 : -1, Disabled: disabled), "规则已添加，");
        return _egressRules.Count > before;
    }

    private static EgressRuleRow? RowOf(object sender) => (sender as FrameworkElement)?.Tag as EgressRuleRow;

    private void EgressToggleRule_Click(object sender, RoutedEventArgs e)
    {
        if (RowOf(sender) is not { } row) return;
        ApplyEgressChange(new EgressEdit.Change(row.SwitchedOff ? "enable" : "disable", Index: row.Index),
            "规则 #" + row.Index + (row.SwitchedOff ? " 已启用，" : " 已停用，"));
    }

    private void EgressMoveUp_Click(object sender, RoutedEventArgs e)
    {
        if (RowOf(sender) is not { } row) return;
        ApplyEgressChange(new EgressEdit.Change("move", Index: row.Index, To: row.Index - 1), "规则已上移，");
    }

    private void EgressMoveDown_Click(object sender, RoutedEventArgs e)
    {
        if (RowOf(sender) is not { } row) return;
        ApplyEgressChange(new EgressEdit.Change("move", Index: row.Index, To: row.Index + 1), "规则已下移，");
    }

    private void EgressRemoveRule_Click(object sender, RoutedEventArgs e)
    {
        if (RowOf(sender) is not { } row) return;
        if (MessageBox.Show(this, "删除规则 #" + row.Index + "「" + row.Match + "」？", "删除出口规则",
                MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
        ApplyEgressChange(new EgressEdit.Change("remove", Index: row.Index), "规则已删除，");
    }

    private void EgressTakeoverButton_Click(object sender, RoutedEventArgs e)
    {
        if (_egressEnabled)
        {
            if (MessageBox.Show(this, "关闭系统接管？规则保留，但不再接管任何流量。", "关闭系统接管",
                    MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
            _egressEnabled = false;
            if (!PersistEgress("系统接管已关闭，", [])) _egressEnabled = true;
            return;
        }
        // Asked every time it is turned on, the way egress enable asks for --yes.
        if (MessageBox.Show(this, EgressEnableNotice, "开启系统接管",
                MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        var planned = EgressEdit.Plan(EgressConfig(), new EgressEdit.Change("takeover", Enabled: true, Confirmed: true));
        var warnings = planned.Preface.Any(line => line.Contains("peerMeshDevice is noop", StringComparison.Ordinal))
            ? new[] { "注意：虚拟网卡模式为 noop，没有可接管路由的网卡；请在「连接设置」改为私有组网（auto）。" }
            : [];
        _egressEnabled = true;
        if (!PersistEgress("系统接管已开启，", warnings)) _egressEnabled = false;
    }

    private string? EgressTestAddress()
    {
        var address = EgressTestAddressBox.Text.Trim();
        if (EgressEdit.AddressProblem(address) is not { } problem) return address;
        EgressTestResultText.Text = problem.Contains("domain name", StringComparison.Ordinal)
            ? "这是域名；规则目前只匹配 IPv4 地址，请填写它解析到的地址。"
            : "请填写一个 IPv4 地址。";
        return null;
    }

    private void EgressPreviewButton_Click(object sender, RoutedEventArgs e)
    {
        if (EgressTestAddress() is not { } address) return;
        var data = EgressEdit.Preview(string.Empty, EgressConfig(), address, []);
        var matched = data["matchedRuleIndex"] is int index ? index : -1;
        var egress = data.TryGetValue("egressClientId", out var id) && id is long value ? value : 0L;
        string Outcome(object? result) => (result as string) switch
        {
            "egress" => "经出口设备 " + EgressDeviceLabel(egress),
            "block" => "阻断",
            _ => "本地直连",
        };
        var rule = matched >= 0 ? "命中规则 #" + matched : "未被任何规则覆盖";
        var result = data.TryGetValue("resultWithTakeover", out var withTakeover)
            ? "系统接管未开启，当前本地直连；开启后" + Outcome(withTakeover)
            : matched < 0 ? "将本地直连" : Outcome(data["result"]);
        EgressTestResultText.Text = address + "：" + rule + "，" + result + "。仅按已保存的规则判断，未建立连接。";
    }

    private async void EgressConnectButton_Click(object sender, RoutedEventArgs e)
    {
        if (EgressTestAddress() is not { } address) return;
        if (!int.TryParse(EgressTestPortBox.Text.Trim(), out var port) || port is < 1 or > 65535)
        {
            EgressTestResultText.Text = "请填写 1–65535 之间的端口。";
            return;
        }
        var target = address + ":" + port;
        EgressConnectButton.IsEnabled = false;
        EgressTestResultText.Text = "正在连接 " + target + "…";
        var watch = Stopwatch.StartNew();
        try
        {
            using var client = new TcpClient();
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await client.ConnectAsync(IPAddress.Parse(address), port, timeout.Token);
            EgressTestResultText.Text = $"连通测试：{target} 在 {watch.ElapsedMilliseconds} ms 内连上。这只说明能连上，不说明走了哪条路径；去向请用预演查看。";
        }
        catch (OperationCanceledException)
        {
            EgressTestResultText.Text = $"连通测试：{target} 5 秒内没有连上（超时）。";
        }
        catch (SocketException error)
        {
            EgressTestResultText.Text = $"连通测试：{target} 连接失败（{error.Message}）。";
        }
        finally
        {
            EgressConnectButton.IsEnabled = true;
        }
    }

    private void RefreshEgressStatus()
    {
        JsonObject? section = null;
        if (_running && _client is not null)
        {
            try
            {
                section = JsonSerializer.SerializeToNode(_client.EgressStatus()) as JsonObject;
            }
            catch (Exception ex) when (ex is InvalidOperationException or ObjectDisposedException or NotSupportedException)
            {
                section = null;
            }
        }
        RenderEgressStatus(section);
    }

    // Field readers that tolerate a status shaped differently: a wrong type reads as absent.
    private static JsonObject EgressObject(JsonNode? node) => node as JsonObject ?? new JsonObject();

    private static List<JsonObject> EgressList(JsonNode? node) =>
        node is JsonArray array ? array.OfType<JsonObject>().ToList() : [];

    private static long EgressNumber(JsonNode? node) =>
        node is JsonValue value && value.TryGetValue<long>(out var number) ? number : 0;

    private static bool EgressTrue(JsonNode? node) =>
        node is JsonValue value && value.TryGetValue<bool>(out var flag) && flag;

    private static string EgressText(JsonNode? node) =>
        node is JsonValue value && value.TryGetValue<string>(out var text) ? text : string.Empty;

    private static string EgressCounters(JsonNode? node) =>
        node is JsonObject counts
            ? string.Join("，", counts.Where(entry => EgressNumber(entry.Value) != 0)
                .OrderBy(entry => entry.Key, StringComparer.Ordinal)
                .Select(entry => entry.Key + "=" + EgressNumber(entry.Value)))
            : string.Empty;

    /// <summary>
    /// The status the local page shows, the same way: what is not working is listed one by one and
    /// the rest is counted, because a rule not in force, a route not installed and an egress offline
    /// are the three ways this feature does nothing while everything else looks healthy.
    /// </summary>
    internal void RenderEgressStatus(JsonObject? section)
    {
        EgressIssues.Clear();
        if (section is null)
        {
            EgressProblemsText.Text = "—";
            EgressProblemsText.SetResourceReference(TextBlock.ForegroundProperty, "TextSecondaryBrush");
            EgressSummaryText.Text = _running
                ? "客户端正在启动，尚无分流状态。"
                : "连接后显示本机分流规则是否生效；未连接时不读取路由表。";
            EgressRoleText.Text = string.Empty;
            return;
        }
        var consumer = EgressObject(section["consumer"]);
        var egress = EgressObject(section["egress"]);
        var problems = 0;
        var rules = EgressList(consumer["rules"]);
        if (consumer["enabled"] is JsonValue enabled && enabled.TryGetValue<bool>(out var on) && !on && rules.Count > 0)
        {
            EgressSummaryText.Text = "系统接管未开启：" + rules.Count + " 条规则已保存，均未生效，流量照常从本机出去。在上方开启。";
        }
        else if (!EgressTrue(consumer["active"]))
        {
            EgressSummaryText.Text = "未配置分流规则：所有流量照常从本机出去。";
        }
        else
        {
            var routes = EgressList(consumer["routes"]);
            var peers = EgressList(consumer["peers"]);
            var refused = rules.Where(rule => !EgressTrue(rule["inForce"])).ToList();
            var missing = routes.Where(route => !EgressTrue(route["installed"])).ToList();
            var offline = peers.Where(peer => !EgressTrue(peer["online"])).ToList();
            var relayed = peers.Where(peer => EgressText(peer["path"]) == "relay").ToList();
            var pathless = peers.Where(peer => EgressTrue(peer["online"]) && EgressText(peer["path"]) == "none").ToList();
            EgressSummaryText.Text = $"{rules.Count} 条规则，{refused.Count} 条未生效 · {routes.Count} 条路由，{missing.Count} 条未安装 · "
                + $"{EgressNumber(consumer["flows"])} 个流 · {peers.Count} 个出口设备，{offline.Count} 个离线，{relayed.Count} 个经中继";
            foreach (var rule in refused)
            {
                var code = EgressText(rule["code"]);
                var match = EgressText(rule["match"]);
                EgressIssues.Add(new EgressIssueRow("规则 #" + EgressNumber(rule["index"]) + "「" + (match.Length > 0 ? match : "—") + "」未生效",
                    (EgressRuleReasons.TryGetValue(code, out var reason) ? reason : "规则被拒绝") + "；这条规则现在不引导任何流量。", code));
            }
            foreach (var route in missing)
            {
                EgressIssues.Add(new EgressIssueRow("路由 " + EgressText(route["cidr"]) + " 未安装",
                    "该前缀已被本功能之外的路由占用，本该进隧道的流量正从物理网卡出去：" + EgressText(route["conflict"])
                    + "。处理：删除或缩小那条路由，或修改规则；客户端每 60 秒重试一次。", EgressText(route["origin"])));
            }
            foreach (var peer in offline)
            {
                EgressIssues.Add(new EgressIssueRow("出口设备 " + EgressDeviceLabel(EgressNumber(peer["clientId"])) + " 离线",
                    "指向它的规则已经生效，但流量没有出口可发，会被阻断而不是改走本机。处理：启动该设备或恢复它的网络连接。", ""));
            }
            foreach (var peer in pathless)
            {
                EgressIssues.Add(new EgressIssueRow("出口设备 " + EgressDeviceLabel(EgressNumber(peer["clientId"])) + " 在线但尚无路径",
                    "直连与中继路径都还没建立，指向它的流量暂时发不出去。处理：稍候；持续如此时检查两台设备到服务端的 UDP 是否可达。", ""));
            }
            var routeError = EgressText(consumer["routeError"]);
            if (routeError.Length > 0)
            {
                var permission = System.Text.RegularExpressions.Regex.IsMatch(routeError, "permission|denied|not permitted|elevat|access",
                    System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                EgressIssues.Add(new EgressIssueRow("路由下发失败",
                    routeError + (EgressTrue(consumer["rolledBack"]) ? "（本次下发已整体回滚）" : "") + "。处理："
                    + (permission ? "以管理员身份运行桌面端，并把虚拟网卡模式设为私有组网（auto）。" : "运行日志里记录了失败的路由命令，按其提示修正后重新连接。"), ""));
            }
            foreach (var peer in relayed)
            {
                EgressIssues.Add(new EgressIssueRow("出口设备 " + EgressDeviceLabel(EgressNumber(peer["clientId"])) + " 经中继连接",
                    "可用，但比直连慢；" + EgressNumber(peer["flows"]) + " 个流。直连需要两台设备之间的 UDP 可达。", ""));
            }
            // The system DNS takeover, when the configuration asks for one and it is not in place:
            // domain rules depend on it, and nothing else on this page would say why they do nothing.
            var dns = consumer["dns"] as JsonObject;
            var dnsCode = dns is null ? string.Empty : EgressText(dns["code"]);
            if (dnsCode.Length > 0 && !EgressTrue(dns!["takeover"]))
            {
                var why = EgressText(dns["reason"]) is { Length: > 0 } reason ? reason : EgressText(dns["error"]);
                EgressIssues.Add(new EgressIssueRow("系统 DNS 未接管",
                    "域名规则要靠系统 DNS 指向本功能才生效；" + (why.Length > 0 ? "原因：" + why + "。" : "") + "按地址写的规则不受影响。", dnsCode));
            }
            problems = refused.Count + missing.Count + offline.Count + pathless.Count + (routeError.Length > 0 ? 1 : 0)
                + (dnsCode.Length > 0 && !EgressTrue(dns!["takeover"]) ? 1 : 0);
            if (problems == 0)
            {
                EgressIssues.Add(new EgressIssueRow("规则均已生效", "路由均已安装，指向的出口设备均在线。", ""));
            }
            var blocked = EgressCounters(consumer["blocked"]);
            if (blocked.Length > 0)
            {
                EgressIssues.Add(new EgressIssueRow("拦截计数",
                    "被丢弃、没有放行的包，按原因分别计数：rule 为阻断规则，unsupported-protocol 为不承载的协议（如 ICMP），egress-unavailable 为出口不可用，rejected- 开头为出口拒绝。", blocked));
            }
        }
        EgressProblemsText.Text = problems > 0 ? problems + " 个问题" : "正常";
        EgressProblemsText.SetResourceReference(TextBlock.ForegroundProperty, problems > 0 ? "WarningBrush" : "SuccessBrush");
        var refusedByEgress = EgressCounters(egress["refused"]);
        EgressRoleText.Text = EgressTrue(egress["active"])
            ? "本机正在作为出口 · " + EgressNumber(egress["flows"]) + " 个流 · 累计 " + EgressNumber(egress["totalFlows"]) + " 个"
              + (refusedByEgress.Length > 0 ? " · 拒绝：" + refusedByEgress : "")
            : "本机未作为出口（尚无策略启用）";
    }
}

/// <summary>One rule as the page lists it.</summary>
public sealed class EgressRuleRow
{
    public int Index { get; init; }

    public string Match { get; init; } = "";

    public string Target { get; init; } = "";

    public string State { get; init; } = "";

    /// <summary>The code of the rule's own problem, empty when it has none.</summary>
    public string Code { get; init; } = "";

    /// <summary>The state in full, with the code a person can search for.</summary>
    public string StateTip => Code.Length > 0 ? State + "（" + Code + "）" : State;

    public bool SwitchedOff { get; init; }

    public string ToggleLabel { get; init; } = "";

    public bool CanMoveUp { get; init; }

    public bool CanMoveDown { get; init; }
}

/// <summary>One thing the status says is wrong, or a count worth seeing.</summary>
public sealed class EgressIssueRow(string title, string detail, string code)
{
    public string Title { get; } = title;

    public string Detail { get; } = detail;

    public string Code { get; } = code;

    public Visibility CodeVisibility => Code.Length > 0 ? Visibility.Visible : Visibility.Collapsed;
}
