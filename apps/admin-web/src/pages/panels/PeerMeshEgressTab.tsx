import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Button } from "@heroui/react";
import { adminApi } from "../../api/client";
import type { PeerEgressActivity, PeerEgressPolicy, PeerEgressSwitch, PeerMeshDevice } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { ConfirmModal } from "../../components/ConfirmModal";
import { Alert, Card, CardBody, Empty, Icon, RelativeTime, Section, TableWrap, Tag } from "../../components/ui";
import { notify, notifyError } from "../../components/toast";
import { formatBytes } from "../../lib/format";
import {
  checkPolicyDraft,
  consumerNote,
  draftFromPolicy,
  emptyDomainRuleDraft,
  emptyPolicyDraft,
  emptyRuleDraft,
  formatPorts,
  MAX_DESTINATION_RULES,
  MAX_DOMAIN_RULES,
  policyState,
  scopeLabel,
  storedDomainRuleProblem,
  storedRuleProblem,
  switchSummary,
  type EgressPolicyDraft,
} from "./peerEgressModel";
import { PeerMeshOperationLocks } from "./peerMeshServicesModel";
import { Check, CheckGroup, InlineCode, ModelTag, RadioCards, SelectField, SettingRow, TextField, Toggle } from "./meshSystemParts";

const DEFAULT_MESH_CIDR = "100.96.0.0/11";

type ConfirmState = {
  title: string;
  description: string;
  confirmLabel: string;
  danger?: boolean;
  action: () => Promise<void>;
};

/**
 * The tenant's peer egress: the switch, which devices act as an egress for whom and to where, and
 * what the egresses report.
 *
 * A device forwards for others only when the switch is on, its policy is enabled, the consumer is
 * both listed and allowed by the Peer ACL, and the destination is in a rule the forced-deny list does
 * not cover: a destination rule containing the address, or, for a flow the consumer sent by name, a
 * domain rule covering the name. Each of those can silently make a policy do nothing, so each is shown
 * where it applies.
 */
export function PeerMeshEgressTab({ devices }: { devices: PeerMeshDevice[] }) {
  const { profile } = useAuth();
  const isAdmin = Boolean(profile?.admin);
  const [egressSwitch, setEgressSwitch] = useState<PeerEgressSwitch | null>(null);
  const [policies, setPolicies] = useState<PeerEgressPolicy[]>([]);
  const [activity, setActivity] = useState<PeerEgressActivity[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [updatingSwitch, setUpdatingSwitch] = useState(false);
  const [busyPolicies, setBusyPolicies] = useState<ReadonlySet<number>>(new Set());
  const [draft, setDraft] = useState<EgressPolicyDraft | null>(null);
  const [editingExisting, setEditingExisting] = useState(false);
  const [saving, setSaving] = useState(false);
  const [confirm, setConfirm] = useState<ConfirmState | null>(null);
  const loadInFlight = useRef<Promise<void> | null>(null);
  const locks = useRef(new PeerMeshOperationLocks());

  const meshCidr = devices.find((device) => device.cidr)?.cidr ?? DEFAULT_MESH_CIDR;
  const deviceById = useMemo(() => new Map(devices.map((device) => [device.clientId, device])), [devices]);
  const deviceName = useCallback(
    (clientId: number) => deviceById.get(clientId)?.clientName ?? `客户端 #${clientId}`,
    [deviceById],
  );

  const load = useCallback((silent = false): Promise<void> => {
    if (loadInFlight.current) {
      return loadInFlight.current;
    }
    if (!silent) {
      setLoading(true);
    }
    const pending = (async () => {
      try {
        const [nextSwitch, nextPolicies, nextActivity] = await Promise.all([
          adminApi.peerEgressSwitch(),
          adminApi.listPeerEgressPolicies(),
          adminApi.listPeerEgressActivity().catch(() => []),
        ]);
        setEgressSwitch(nextSwitch);
        setPolicies(nextPolicies);
        setActivity(nextActivity);
        setLoadError(null);
      } catch (error) {
        setLoadError(error instanceof Error ? error.message : "无法读取出口分流状态");
        if (!silent) {
          notifyError(error, "加载出口分流失败");
        }
      } finally {
        if (!silent) {
          setLoading(false);
        }
      }
    })();
    loadInFlight.current = pending;
    void pending.finally(() => {
      if (loadInFlight.current === pending) {
        loadInFlight.current = null;
      }
    });
    return pending;
  }, []);

  useEffect(() => {
    void load();
    const timer = window.setInterval(() => void load(true), 5_000);
    return () => window.clearInterval(timer);
  }, [load]);

  const setBusy = (id: number, busy: boolean) =>
    setBusyPolicies((current) => {
      const next = new Set(current);
      if (busy) {
        next.add(id);
      } else {
        next.delete(id);
      }
      return next;
    });

  const setSwitchEnabled = (enabled: boolean) => {
    if (!egressSwitch || updatingSwitch || confirm) {
      return;
    }
    setConfirm({
      title: enabled ? "开启出口分流" : "关闭出口分流",
      description: enabled
        ? `已启用的 ${egressSwitch.enabledPolicyCount} 条策略将开始生效：出口设备为获授权、且 Peer ACL 允许的消费设备转发到规则内的目标。回环、链路本地、云元数据与组网网段始终被拒绝。`
        : "所有出口立即停止转发，已建立的经出口连接会被切断；消费端命中规则的流量会被阻断，不会改走本机。策略保留。",
      confirmLabel: enabled ? "开启" : "关闭",
      danger: !enabled,
      action: async () => {
        if (!locks.current.acquire("switch")) {
          return;
        }
        setUpdatingSwitch(true);
        try {
          setEgressSwitch(await adminApi.updatePeerEgressSwitch(enabled));
          await load(true);
          notify(enabled ? "已开启出口分流" : "已关闭出口分流");
        } catch (error) {
          notifyError(error, "更新出口分流开关失败");
          throw error;
        } finally {
          setUpdatingSwitch(false);
          locks.current.release("switch");
        }
      },
    });
  };

  const togglePolicy = async (policy: PeerEgressPolicy, enabled: boolean) => {
    const key = `policy:${policy.id}`;
    if (!locks.current.acquire(key)) {
      return;
    }
    setBusy(policy.id, true);
    setPolicies((items) => items.map((item) => (item.id === policy.id ? { ...item, enabled } : item)));
    try {
      const saved = await adminApi.savePeerEgressPolicy({ egressClientId: policy.egressClientId, enabled });
      setPolicies((items) => items.map((item) => (item.id === saved.id ? saved : item)));
      await load(true);
    } catch (error) {
      setPolicies((items) => items.map((item) => (item.id === policy.id ? policy : item)));
      notifyError(error, "更新出口策略失败");
    } finally {
      setBusy(policy.id, false);
      locks.current.release(key);
    }
  };

  const removePolicy = (policy: PeerEgressPolicy) => {
    setConfirm({
      title: "删除出口策略",
      description: `${deviceName(policy.egressClientId)} 将不再作为出口，经它的连接会被切断，消费端指向它的规则会阻断流量。`,
      confirmLabel: "删除",
      danger: true,
      action: async () => {
        const key = `policy:${policy.id}`;
        if (!locks.current.acquire(key)) {
          return;
        }
        setBusy(policy.id, true);
        try {
          await adminApi.deletePeerEgressPolicy(policy.id);
          setPolicies((items) => items.filter((item) => item.id !== policy.id));
          notify("出口策略已删除");
          await load(true);
        } catch (error) {
          notifyError(error, "删除出口策略失败");
          throw error;
        } finally {
          setBusy(policy.id, false);
          locks.current.release(key);
        }
      },
    });
  };

  const check = useMemo(() => (draft ? checkPolicyDraft(draft, meshCidr) : null), [draft, meshCidr]);

  const save = async () => {
    if (!draft || !check?.mutation || !locks.current.acquire("save")) {
      return;
    }
    setSaving(true);
    try {
      const saved = await adminApi.savePeerEgressPolicy(check.mutation);
      setPolicies((items) => [saved, ...items.filter((item) => item.id !== saved.id)]);
      setDraft(null);
      notify(editingExisting ? "出口策略已保存" : saved.enabled ? "出口策略已创建并启用" : "出口策略已创建（未启用）");
      // A server that predates domain rules ignores the field and leaves it out of its answer.
      if (saved.domainRules === undefined && (check.mutation.domainRules ?? []).length > 0) {
        notify("服务端未返回域名规则，可能还不支持：域名规则没有保存", "error");
      }
      await load(true);
    } catch (error) {
      notifyError(error, "保存出口策略失败");
    } finally {
      setSaving(false);
      locks.current.release("save");
    }
  };

  const edit = (policy: PeerEgressPolicy) => {
    setEditingExisting(true);
    setDraft(draftFromPolicy(policy));
  };

  const startNew = () => {
    setEditingExisting(false);
    setDraft(emptyPolicyDraft());
  };

  const updateRule = (index: number, patch: Partial<EgressPolicyDraft["rules"][number]>) =>
    setDraft((current) => current && {
      ...current,
      rules: current.rules.map((rule, position) => (position === index ? { ...rule, ...patch } : rule)),
    });

  const updateDomainRule = (index: number, patch: Partial<EgressPolicyDraft["domainRules"][number]>) =>
    setDraft((current) => current && {
      ...current,
      domainRules: current.domainRules.map((rule, position) => (position === index ? { ...rule, ...patch } : rule)),
    });

  const takenEgresses = new Set(policies.map((policy) => String(policy.egressClientId)));
  const switchSelected = Boolean(egressSwitch?.configuredEnabled);
  const switchDisabled = !isAdmin || loading || updatingSwitch || loadError != null || !egressSwitch?.deploymentEnabled;

  return (
    <div className="ms-tab" aria-busy={loading || updatingSwitch}>
      <Alert tone="info" title="出口在什么条件下转发" className="ms-block">
        出口分流让一台设备作为其他设备访问指定目标的网络出口。只有总开关开启、策略启用、消费设备既被授权又被 Peer ACL 允许，并且目标在目的规则内（消费端按域名发出的流，也可以由覆盖该域名的域名规则放行）时才会转发；回环、链路本地、云元数据与组网网段始终被拒绝。消费端需在客户端里写规则并开启系统接管。
      </Alert>
      {loadError && (
        <Alert
          tone="danger"
          role="alert"
          title="出口分流状态未知"
          className="ms-block"
          actions={<Button size="sm" color="danger" variant="flat" startContent={<Icon name="refresh" />} onPress={() => void load()}>重新加载</Button>}
        >
          {loadError}。检查后台连接后重新加载；在此之前策略状态都按未知处理。
        </Alert>
      )}

      <Section title="总开关" description="立即生效；关闭时策略保留，所有出口停止转发。">
        <Card className="ms-settings">
          <SettingRow
            title="出口分流总开关"
            descriptionId="peer-egress-switch-help"
            description={<>
              {switchSummary(egressSwitch, loading)}
              {egressSwitch?.updatedAt ? (
                <> · <RelativeTime value={egressSwitch.updatedAt} />{egressSwitch.updatedBy ? ` 由 ${egressSwitch.updatedBy} 修改` : ""}</>
              ) : null}
            </>}
            control={(
              <Toggle
                label="出口分流总开关"
                describedBy="peer-egress-switch-help"
                busy={updatingSwitch}
                checked={switchSelected}
                disabled={switchDisabled}
                onChange={setSwitchEnabled}
              />
            )}
          />
        </Card>
      </Section>

      {isAdmin && draft && (
        <Section
          title={editingExisting ? `编辑 ${deviceName(Number(draft.egressClientId))} 的出口策略` : "新增出口设备"}
          description="保存前会检查规则；出错的地方会在下面列出原因。"
        >
          <Card aria-label="出口策略编辑" role="group">
            <CardBody className="ms-egress-form">
              <div className="bd-form-grid">
                <SelectField
                  label="出口设备"
                  value={draft.egressClientId}
                  placeholder="选择出口设备"
                  disabled={editingExisting}
                  onChange={(egressClientId) => setDraft((current) => current && {
                    ...current,
                    egressClientId,
                    consumers: current.consumers.filter((id) => id !== egressClientId),
                  })}
                  options={devices
                    .filter((device) => editingExisting || !takenEgresses.has(String(device.clientId)))
                    .map((device) => ({
                      value: String(device.clientId),
                      label: `${device.clientName}${device.online ? "" : "（离线）"}`,
                    }))}
                  help={editingExisting ? "出口设备保存后不能更换；要换设备就新增一条策略。" : "每台设备只能有一条出口策略。"}
                />
                <div className="bd-col-full">
                  <RadioCards
                    legend="目标范围"
                    value={draft.scope === "LAN" ? "LAN" : "PUBLIC"}
                    onChange={(scope) => setDraft((current) => current && { ...current, scope })}
                    help="公网与局域网互不包含"
                    options={[
                      { value: "PUBLIC", title: "公网", description: "出口替消费设备访问互联网上的地址" },
                      { value: "LAN", title: "局域网", description: "10/8、172.16/12、192.168/16、100.64/10" },
                    ]}
                  />
                </div>
                <div className="bd-col-full">
                  <CheckGroup
                    legend="授权的消费设备"
                    values={draft.consumers}
                    onChange={(consumers) => setDraft((current) => current && { ...current, consumers })}
                    help="还需 Peer ACL 允许它们与出口设备通信"
                    empty="除出口设备外没有其他组网设备"
                    options={devices
                      .filter((device) => String(device.clientId) !== draft.egressClientId)
                      .map((device) => ({ value: String(device.clientId), label: device.clientName }))}
                  />
                </div>
              </div>

              <fieldset className="jd-fieldset ms-rule-block">
                <legend className="bd-label">目的规则</legend>
                {draft.rules.length === 0 && (
                  <p className="bd-help">没有目的规则时所有目标都会被拒绝。</p>
                )}
                {draft.rules.map((rule, index) => (
                  <div key={index} className="ms-rule-row">
                    <input
                      className="bd-input ms-mono"
                      aria-label={`目的规则 ${index + 1} 网段`}
                      placeholder="203.0.113.0/24"
                      value={rule.cidr}
                      onChange={(event) => updateRule(index, { cidr: event.target.value })}
                    />
                    <Check checked={rule.tcp} onChange={(tcp) => updateRule(index, { tcp })}>TCP</Check>
                    <Check checked={rule.udp} onChange={(udp) => updateRule(index, { udp })}>UDP</Check>
                    <input
                      className="bd-input"
                      aria-label={`目的规则 ${index + 1} 端口`}
                      placeholder="443, 8000-8100 或 全部"
                      value={rule.ports}
                      onChange={(event) => updateRule(index, { ports: event.target.value })}
                    />
                    <Button
                      size="sm"
                      variant="light"
                      color="danger"
                      onPress={() => setDraft((current) => current && { ...current, rules: current.rules.filter((_, position) => position !== index) })}
                    >
                      移除
                    </Button>
                  </div>
                ))}
                <div>
                  <Button
                    size="sm"
                    variant="flat"
                    startContent={<Icon name="plus" size={14} />}
                    isDisabled={draft.rules.length >= MAX_DESTINATION_RULES}
                    onPress={() => setDraft((current) => current && { ...current, rules: [...current.rules, emptyRuleDraft()] })}
                  >
                    添加目的规则
                  </Button>
                </div>
              </fieldset>

              <fieldset className="jd-fieldset ms-rule-block">
                <legend className="bd-label">域名规则</legend>
                <ul className="ms-notes">
                  <li>只对消费端按域名规则发出的流（二期，开启系统 DNS 接管）起作用；只按地址发出的流不看域名规则，即使地址恰好是某个已授权域名的解析结果。</li>
                  <li><InlineCode>example.com</InlineCode> 只覆盖这个名字；<InlineCode>*.example.com</InlineCode> 覆盖它的所有子域，不含 <InlineCode>example.com</InlineCode> 本身。</li>
                  <li>出口自己解析名字，解析出的地址仍要先过始终拒绝的地址与目标范围：解析到回环、云元数据、组网网段或（范围为公网时）局域网地址的名字照样被拒绝。</li>
                  <li>站点用 CDN、地址不固定时用它，不必为此放行 <InlineCode>0.0.0.0/0</InlineCode>。按地址授权写在上面的目的规则里。</li>
                </ul>
                {draft.domainRules.map((rule, index) => (
                  <div key={index} className="ms-rule-row">
                    <input
                      className="bd-input ms-mono"
                      aria-label={`域名规则 ${index + 1} 域名`}
                      placeholder="*.example.com"
                      value={rule.match}
                      onChange={(event) => updateDomainRule(index, { match: event.target.value })}
                    />
                    <Check checked={rule.tcp} onChange={(tcp) => updateDomainRule(index, { tcp })}>TCP</Check>
                    <Check checked={rule.udp} onChange={(udp) => updateDomainRule(index, { udp })}>UDP</Check>
                    <input
                      className="bd-input"
                      aria-label={`域名规则 ${index + 1} 端口`}
                      placeholder="443, 8000-8100 或 全部"
                      value={rule.ports}
                      onChange={(event) => updateDomainRule(index, { ports: event.target.value })}
                    />
                    <Button
                      size="sm"
                      variant="light"
                      color="danger"
                      onPress={() => setDraft((current) => current && { ...current, domainRules: current.domainRules.filter((_, position) => position !== index) })}
                    >
                      移除
                    </Button>
                  </div>
                ))}
                <div>
                  <Button
                    size="sm"
                    variant="flat"
                    startContent={<Icon name="plus" size={14} />}
                    isDisabled={draft.domainRules.length >= MAX_DOMAIN_RULES}
                    onPress={() => setDraft((current) => current && { ...current, domainRules: [...current.domainRules, emptyDomainRuleDraft()] })}
                  >
                    添加域名规则
                  </Button>
                </div>
              </fieldset>

              <div className="bd-form-grid ms-limits">
                <TextField
                  label="最大并发流"
                  inputMode="numeric"
                  value={draft.maxConcurrentFlows}
                  onChange={(maxConcurrentFlows) => setDraft((current) => current && { ...current, maxConcurrentFlows })}
                />
                <TextField
                  label="每台消费设备最大流数"
                  inputMode="numeric"
                  value={draft.maxFlowsPerConsumer}
                  onChange={(maxFlowsPerConsumer) => setDraft((current) => current && { ...current, maxFlowsPerConsumer })}
                />
                <TextField
                  label="空闲超时"
                  inputMode="numeric"
                  unit="秒"
                  value={draft.idleTimeoutSeconds}
                  onChange={(idleTimeoutSeconds) => setDraft((current) => current && { ...current, idleTimeoutSeconds })}
                />
              </div>

              <Toggle
                checked={draft.enabled}
                onChange={(enabled) => setDraft((current) => current && { ...current, enabled })}
              >
                启用这条策略
              </Toggle>

              {check && check.errors.length > 0 && (
                <Alert tone="danger" role="alert" title="还不能保存">
                  <ul className="ms-alert-list">
                    {check.errors.map((error) => <li key={error}>{error}</li>)}
                  </ul>
                </Alert>
              )}
              {check && check.warnings.length > 0 && (
                <Alert tone="warning" title="保存前确认">
                  <ul className="ms-alert-list">
                    {check.warnings.map((warning) => <li key={warning}>{warning}</li>)}
                  </ul>
                </Alert>
              )}
            </CardBody>
            <div className="bd-card-footer">
              <Button variant="light" isDisabled={saving} onPress={() => setDraft(null)}>取消</Button>
              <Button color="primary" isLoading={saving} isDisabled={saving || !check?.mutation} onPress={() => void save()}>
                {editingExisting ? "保存更改" : "创建"}
              </Button>
            </div>
          </Card>
        </Section>
      )}

      <Section
        title="出口策略"
        description="一台出口设备一条策略；启用后才为授权的消费设备转发。"
        actions={isAdmin && !draft ? (
          <Button color="primary" variant="flat" startContent={<Icon name="plus" />} isDisabled={loadError != null} onPress={startNew}>
            新增出口设备
          </Button>
        ) : null}
      >
        {policies.length === 0 ? (
          <Card>
            <Empty
              icon="globe"
              title="尚无出口设备"
              description="选择一台设备作为出口，授权消费设备与可达的目标后启用。"
            />
          </Card>
        ) : (
          <TableWrap>
            <table className="bd-table jd-stack ms-table ms-egress-table" aria-label="出口策略">
              <thead>
                <tr>
                  <th scope="col">出口设备</th>
                  <th scope="col">状态</th>
                  <th scope="col">范围</th>
                  <th scope="col">消费设备</th>
                  <th scope="col">目的规则</th>
                  <th scope="col">域名规则</th>
                  <th scope="col">限额</th>
                  <th scope="col" className="ms-col-actions">操作</th>
                </tr>
              </thead>
              <tbody>
                {policies.map((policy) => {
                  const state = loadError ? { label: "状态未知", color: "default" as const, detail: "" } : policyState(policy, egressSwitch, deviceById);
                  const device = deviceById.get(policy.egressClientId);
                  const allowed = policy.allowedConsumerClientIds ?? [];
                  const busy = busyPolicies.has(policy.id);
                  return (
                    <tr key={policy.id} aria-busy={busy}>
                      <td>
                        <div className="ms-cell-main">
                          <span className="ms-cell-title">{policy.egressClientName || deviceName(policy.egressClientId)}</span>
                          <span className="ms-cell-sub bd-num">
                            #{policy.egressClientId} · {device ? (device.online ? "在线" : "离线") : "不在组网设备中"}
                          </span>
                        </div>
                      </td>
                      <td className="ms-wrap">
                        <div className="ms-cell-main">
                          <ModelTag color={state.color}>{state.label}</ModelTag>
                          {state.detail && <span className="ms-cell-sub">{state.detail}</span>}
                        </div>
                      </td>
                      <td data-label="范围">{scopeLabel(policy.scope)}</td>
                      <td data-label="消费设备" className="ms-wrap">
                        {allowed.length === 0 ? (
                          <span className="ms-cell-warn">未授权</span>
                        ) : (
                          <ul className="ms-plain-list">
                            {allowed.map((id) => {
                              const note = consumerNote(id, policy, deviceById);
                              return (
                                <li key={id}>
                                  {deviceName(id)}
                                  {note && <span className="ms-cell-warn"> {note}</span>}
                                </li>
                              );
                            })}
                          </ul>
                        )}
                      </td>
                      <td data-label="目的规则" className="ms-wrap">
                        {(policy.destinationRules ?? []).length === 0 ? (
                          <span className="ms-cell-warn">无（拒绝所有目标）</span>
                        ) : (
                          <ul className="ms-plain-list ms-rule-list">
                            {(policy.destinationRules ?? []).map((rule, index) => {
                              const problem = storedRuleProblem(rule);
                              return (
                                <li key={`${rule.cidr}-${index}`} className={problem ? "ms-cell-warn" : undefined}>
                                  <span className="ms-mono">{rule.cidr}</span> · {(rule.protocols ?? []).join("/") || "无协议"} · {formatPorts(rule.portRanges)}
                                  {problem && <span className="ms-rule-problem">{problem}</span>}
                                </li>
                              );
                            })}
                          </ul>
                        )}
                      </td>
                      <td data-label="域名规则" className={(policy.domainRules ?? []).length === 0 ? "is-empty" : "ms-wrap"}>
                        {(policy.domainRules ?? []).length === 0 ? (
                          <span className="ms-cell-sub">无</span>
                        ) : (
                          <ul className="ms-plain-list ms-rule-list">
                            {(policy.domainRules ?? []).map((rule, index) => {
                              const problem = storedDomainRuleProblem(rule);
                              return (
                                <li key={`${rule.match}-${index}`} className={problem ? "ms-cell-warn" : undefined}>
                                  <span className="ms-mono">{rule.match}</span> · {(rule.protocols ?? []).join("/") || "无协议"} · {formatPorts(rule.portRanges)}
                                  {problem && <span className="ms-rule-problem">{problem}</span>}
                                </li>
                              );
                            })}
                          </ul>
                        )}
                      </td>
                      <td data-label="限额" className="ms-wrap">
                        <span className="ms-cell-sub bd-num">
                          并发 {policy.maxConcurrentFlows} · 每设备 {policy.maxFlowsPerConsumer} · 空闲 {policy.idleTimeoutSeconds} 秒
                        </span>
                      </td>
                      <td className="jd-cell-actions ms-col-actions">
                        <div className="ms-row-actions">
                          {isAdmin && (
                            <Toggle
                              label={`启用 ${policy.egressClientName} 的出口策略`}
                              checked={policy.enabled}
                              disabled={busy || loadError != null}
                              busy={busy}
                              onChange={(enabled) => void togglePolicy(policy, enabled)}
                            />
                          )}
                          {isAdmin && (
                            <Button size="sm" variant="light" isDisabled={busy || draft != null} onPress={() => edit(policy)}>编辑</Button>
                          )}
                          {isAdmin && (
                            <Button size="sm" variant="light" color="danger" isLoading={busy} isDisabled={busy} onPress={() => removePolicy(policy)}>删除</Button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </TableWrap>
        )}
      </Section>

      <Section title="出口活动" description="出口运行后每 60 秒检查一次、有变化才上报；出口是否在线以组网在线状态为准。">
        {activity.length === 0 ? (
          <Card>
            <Empty icon="activity" title="尚无出口上报的活动" description="启用策略并让出口设备上线后，这里会显示它的活动流、流量和拒绝原因。" />
          </Card>
        ) : (
          <TableWrap>
            <table className="bd-table jd-stack ms-table" aria-label="出口活动">
              <thead>
                <tr>
                  <th scope="col">出口设备</th>
                  <th scope="col">状态</th>
                  <th scope="col" className="bd-col-num">活动流</th>
                  <th scope="col" className="bd-col-num">累计</th>
                  <th scope="col" className="bd-col-num">收 / 发</th>
                  <th scope="col">拒绝</th>
                  <th scope="col">上报</th>
                </tr>
              </thead>
              <tbody>
                {activity.map((item) => {
                  const rejected = Object.entries(item.rejectedFlows ?? {}).filter(([, count]) => count > 0);
                  return (
                    <tr key={item.egressClientId}>
                      <td><span className="ms-cell-title">{item.egressClientName || deviceName(item.egressClientId)}</span></td>
                      <td><Tag tone={item.online ? "success" : "neutral"}>{item.online ? "在线" : "离线"}</Tag></td>
                      <td className="bd-col-num" data-label="活动流">{item.activeFlows}</td>
                      <td className="bd-col-num" data-label="累计">{item.totalFlows}</td>
                      <td className="bd-col-num" data-label="收 / 发">{formatBytes(item.bytesIn)} / {formatBytes(item.bytesOut)}</td>
                      <td data-label="拒绝" className={rejected.length > 0 ? "ms-wrap" : "is-empty"}>
                        {rejected.length > 0 ? (
                          <span className="ms-tags">
                            {rejected.map(([code, count]) => <Tag key={code} tone="warning" plain><span className="ms-mono">{code}</span> {count}</Tag>)}
                          </span>
                        ) : <span className="ms-cell-sub">无</span>}
                      </td>
                      <td data-label="上报" className={item.reportedAt ? undefined : "is-empty"}>
                        {item.reportedAt ? <RelativeTime value={item.reportedAt} /> : "—"}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </TableWrap>
        )}
      </Section>

      <ConfirmModal
        isOpen={confirm != null}
        onClose={() => setConfirm(null)}
        title={confirm?.title ?? ""}
        description={confirm?.description}
        confirmLabel={confirm?.confirmLabel}
        danger={confirm?.danger}
        onConfirm={async () => {
          if (confirm) {
            await confirm.action();
          }
        }}
      />
    </div>
  );
}
