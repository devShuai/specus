import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Button,
  Checkbox,
  Chip,
  Input,
  Select,
  SelectItem,
  Switch,
  Table,
  TableBody,
  TableCell,
  TableColumn,
  TableHeader,
  TableRow,
} from "@heroui/react";
import { adminApi } from "../../api/client";
import type { PeerEgressActivity, PeerEgressPolicy, PeerEgressSwitch, PeerMeshDevice } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { ConfirmModal } from "../../components/ConfirmModal";
import { EmptyState } from "../../components/EmptyState";
import { notify, notifyError } from "../../components/toast";
import { formatBytes, formatDateTime } from "../../lib/format";
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
    <section className="space-y-4" aria-busy={loading || updatingSwitch}>
      <p className="rounded-md border border-default-200 bg-default-50 p-3 text-small text-default-600">
        出口分流让一台设备作为其他设备访问指定目标的网络出口。只有总开关开启、策略启用、消费设备既被授权又被 Peer ACL 允许，并且目标在目的规则内（消费端按域名发出的流，也可以由覆盖该域名的域名规则放行）时才会转发；回环、链路本地、云元数据与组网网段始终被拒绝。消费端需在客户端里写规则并开启系统接管。
      </p>
      {loadError && (
        <div role="alert" className="flex flex-wrap items-center justify-between gap-3 rounded-md border border-danger-200 bg-danger-50 p-3 text-small text-danger-700">
          <span>出口分流状态未知：{loadError}</span>
          <Button size="sm" color="danger" variant="flat" onPress={() => void load()}>重新加载</Button>
        </div>
      )}

      <div className="flex flex-wrap items-center justify-between gap-3 rounded-md border border-default-200 p-3">
        <div>
          <h3 className="text-base font-semibold">出口分流总开关</h3>
          <p id="peer-egress-switch-help" className="text-small text-default-500">
            {switchSummary(egressSwitch, loading)}
            {egressSwitch?.updatedAt ? ` · ${formatDateTime(egressSwitch.updatedAt)}${egressSwitch.updatedBy ? ` 由 ${egressSwitch.updatedBy} 修改` : ""}` : ""}
          </p>
        </div>
        <Switch
          aria-label="出口分流总开关"
          aria-describedby="peer-egress-switch-help"
          aria-busy={updatingSwitch}
          isSelected={switchSelected}
          isDisabled={switchDisabled}
          onValueChange={setSwitchEnabled}
        />
      </div>

      {isAdmin && !draft && (
        <div className="flex justify-end">
          <Button color="primary" variant="flat" isDisabled={loadError != null} onPress={startNew}>
            新增出口设备
          </Button>
        </div>
      )}

      {isAdmin && draft && (
        <div className="space-y-3 rounded-md border border-primary-200 p-3" aria-label="出口策略编辑">
          <h3 className="text-base font-semibold">{editingExisting ? `编辑 ${deviceName(Number(draft.egressClientId))} 的出口策略` : "新增出口设备"}</h3>
          <div className="grid grid-cols-1 gap-2 md:grid-cols-3">
            <Select
              label="出口设备"
              aria-label="出口设备"
              isDisabled={editingExisting}
              selectedKeys={draft.egressClientId ? [draft.egressClientId] : []}
              onSelectionChange={(keys) => setDraft((current) => current && {
                ...current,
                egressClientId: String([...keys][0] ?? ""),
                consumers: current.consumers.filter((id) => id !== String([...keys][0] ?? "")),
              })}
            >
              {devices
                .filter((device) => editingExisting || !takenEgresses.has(String(device.clientId)))
                .map((device) => (
                  <SelectItem key={String(device.clientId)} textValue={device.clientName}>
                    {device.clientName}{device.online ? "" : "（离线）"}
                  </SelectItem>
                ))}
            </Select>
            <Select
              label="目标范围"
              aria-label="目标范围"
              description="公网与局域网互不包含"
              selectedKeys={[draft.scope]}
              onSelectionChange={(keys) => setDraft((current) => current && {
                ...current, scope: String([...keys][0] ?? "PUBLIC") === "LAN" ? "LAN" : "PUBLIC",
              })}
            >
              <SelectItem key="PUBLIC">公网</SelectItem>
              <SelectItem key="LAN">局域网（10/8、172.16/12、192.168/16、100.64/10）</SelectItem>
            </Select>
            <Select
              label="授权的消费设备"
              aria-label="授权的消费设备"
              selectionMode="multiple"
              description="还需 Peer ACL 允许它们与出口设备通信"
              selectedKeys={new Set(draft.consumers)}
              onSelectionChange={(keys) => setDraft((current) => current && { ...current, consumers: [...keys].map(String) })}
            >
              {devices
                .filter((device) => String(device.clientId) !== draft.egressClientId)
                .map((device) => (
                  <SelectItem key={String(device.clientId)} textValue={device.clientName}>{device.clientName}</SelectItem>
                ))}
            </Select>
          </div>

          <div className="space-y-2">
            <p className="text-small font-semibold text-default-700">目的规则</p>
            {draft.rules.length === 0 && (
              <p className="text-small text-default-500">没有目的规则时所有目标都会被拒绝。</p>
            )}
            {draft.rules.map((rule, index) => (
              <div key={index} className="grid grid-cols-1 items-center gap-2 md:grid-cols-[2fr_auto_auto_2fr_auto]">
                <Input
                  size="sm"
                  aria-label={`目的规则 ${index + 1} 网段`}
                  placeholder="203.0.113.0/24"
                  value={rule.cidr}
                  onValueChange={(cidr) => updateRule(index, { cidr })}
                />
                <Checkbox size="sm" isSelected={rule.tcp} onValueChange={(tcp) => updateRule(index, { tcp })}>TCP</Checkbox>
                <Checkbox size="sm" isSelected={rule.udp} onValueChange={(udp) => updateRule(index, { udp })}>UDP</Checkbox>
                <Input
                  size="sm"
                  aria-label={`目的规则 ${index + 1} 端口`}
                  placeholder="443, 8000-8100 或 全部"
                  value={rule.ports}
                  onValueChange={(ports) => updateRule(index, { ports })}
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
            <Button
              size="sm"
              variant="flat"
              isDisabled={draft.rules.length >= MAX_DESTINATION_RULES}
              onPress={() => setDraft((current) => current && { ...current, rules: [...current.rules, emptyRuleDraft()] })}
            >
              添加目的规则
            </Button>
          </div>

          <div className="space-y-2">
            <p className="text-small font-semibold text-default-700">域名规则</p>
            <ul className="list-disc space-y-0.5 pl-5 text-tiny text-default-500">
              <li>只对消费端按域名规则发出的流（二期，开启系统 DNS 接管）起作用；只按地址发出的流不看域名规则，即使地址恰好是某个已授权域名的解析结果。</li>
              <li><code>example.com</code> 只覆盖这个名字；<code>*.example.com</code> 覆盖它的所有子域，不含 <code>example.com</code> 本身。</li>
              <li>出口自己解析名字，解析出的地址仍要先过始终拒绝的地址与目标范围：解析到回环、云元数据、组网网段或（范围为公网时）局域网地址的名字照样被拒绝。</li>
              <li>站点用 CDN、地址不固定时用它，不必为此放行 <code>0.0.0.0/0</code>。按地址授权请写在上面的目的规则里。</li>
            </ul>
            {draft.domainRules.map((rule, index) => (
              <div key={index} className="grid grid-cols-1 items-center gap-2 md:grid-cols-[2fr_auto_auto_2fr_auto]">
                <Input
                  size="sm"
                  aria-label={`域名规则 ${index + 1} 域名`}
                  placeholder="*.example.com"
                  value={rule.match}
                  onValueChange={(match) => updateDomainRule(index, { match })}
                />
                <Checkbox size="sm" isSelected={rule.tcp} onValueChange={(tcp) => updateDomainRule(index, { tcp })}>TCP</Checkbox>
                <Checkbox size="sm" isSelected={rule.udp} onValueChange={(udp) => updateDomainRule(index, { udp })}>UDP</Checkbox>
                <Input
                  size="sm"
                  aria-label={`域名规则 ${index + 1} 端口`}
                  placeholder="443, 8000-8100 或 全部"
                  value={rule.ports}
                  onValueChange={(ports) => updateDomainRule(index, { ports })}
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
            <Button
              size="sm"
              variant="flat"
              isDisabled={draft.domainRules.length >= MAX_DOMAIN_RULES}
              onPress={() => setDraft((current) => current && { ...current, domainRules: [...current.domainRules, emptyDomainRuleDraft()] })}
            >
              添加域名规则
            </Button>
          </div>

          <div className="grid grid-cols-1 gap-2 md:grid-cols-3">
            <Input
              label="最大并发流"
              value={draft.maxConcurrentFlows}
              onValueChange={(maxConcurrentFlows) => setDraft((current) => current && { ...current, maxConcurrentFlows })}
            />
            <Input
              label="每台消费设备最大流数"
              value={draft.maxFlowsPerConsumer}
              onValueChange={(maxFlowsPerConsumer) => setDraft((current) => current && { ...current, maxFlowsPerConsumer })}
            />
            <Input
              label="空闲超时（秒）"
              value={draft.idleTimeoutSeconds}
              onValueChange={(idleTimeoutSeconds) => setDraft((current) => current && { ...current, idleTimeoutSeconds })}
            />
          </div>

          {/* The switch is inline-level; in a block of its own, space-y's gap no longer eats its line's
              descender space, now that Tailwind 4 puts that gap in the bottom margin. */}
          <div>
            <Switch
              isSelected={draft.enabled}
              onValueChange={(enabled) => setDraft((current) => current && { ...current, enabled })}
            >
              启用这条策略
            </Switch>
          </div>

          {check && check.errors.length > 0 && (
            <ul role="alert" className="list-disc space-y-1 rounded-md border border-danger-200 bg-danger-50 p-3 pl-6 text-small text-danger-700">
              {check.errors.map((error) => <li key={error}>{error}</li>)}
            </ul>
          )}
          {check && check.warnings.length > 0 && (
            <ul className="list-disc space-y-1 rounded-md border border-warning-200 bg-warning-50 p-3 pl-6 text-small text-warning-700">
              {check.warnings.map((warning) => <li key={warning}>{warning}</li>)}
            </ul>
          )}
          <div className="flex gap-2">
            <Button color="primary" isLoading={saving} isDisabled={saving || !check?.mutation} onPress={() => void save()}>
              {editingExisting ? "保存更改" : "创建"}
            </Button>
            <Button variant="light" isDisabled={saving} onPress={() => setDraft(null)}>取消</Button>
          </div>
        </div>
      )}

      {policies.length === 0 ? (
        <EmptyState
          icon="peer"
          title="尚无出口设备"
          description="选择一台设备作为出口，授权消费设备与可达的目标后启用。"
        />
      ) : (
        <div className="overflow-x-auto">
          <Table aria-label="出口策略" removeWrapper>
            <TableHeader>
              <TableColumn>出口设备</TableColumn>
              <TableColumn>状态</TableColumn>
              <TableColumn>范围</TableColumn>
              <TableColumn>消费设备</TableColumn>
              <TableColumn>目的规则</TableColumn>
              <TableColumn>域名规则</TableColumn>
              <TableColumn>限额</TableColumn>
              <TableColumn>操作</TableColumn>
            </TableHeader>
            <TableBody>
              {policies.map((policy) => {
                const state = loadError ? { label: "状态未知", color: "default" as const, detail: "" } : policyState(policy, egressSwitch, deviceById);
                const device = deviceById.get(policy.egressClientId);
                const allowed = policy.allowedConsumerClientIds ?? [];
                const busy = busyPolicies.has(policy.id);
                return (
                  <TableRow key={policy.id} aria-busy={busy}>
                    <TableCell>
                      <div className="flex flex-col">
                        <span>{policy.egressClientName || deviceName(policy.egressClientId)}</span>
                        <span className="text-tiny text-default-400">
                          #{policy.egressClientId} · {device ? (device.online ? "在线" : "离线") : "不在组网设备中"}
                        </span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Chip size="sm" variant="flat" color={state.color} className="whitespace-nowrap">{state.label}</Chip>
                      {state.detail && <p className="mt-1 max-w-56 text-tiny text-default-500">{state.detail}</p>}
                    </TableCell>
                    <TableCell className="whitespace-nowrap">{scopeLabel(policy.scope)}</TableCell>
                    <TableCell>
                      {allowed.length === 0 ? (
                        <span className="text-tiny text-warning-600">未授权</span>
                      ) : (
                        <ul className="space-y-0.5 text-small">
                          {allowed.map((id) => {
                            const note = consumerNote(id, policy, deviceById);
                            return (
                              <li key={id}>
                                {deviceName(id)}
                                {note && <span className="ml-1 text-tiny text-warning-600">{note}</span>}
                              </li>
                            );
                          })}
                        </ul>
                      )}
                    </TableCell>
                    <TableCell>
                      {(policy.destinationRules ?? []).length === 0 ? (
                        <span className="text-tiny text-warning-600">无（拒绝所有目标）</span>
                      ) : (
                        <ul className="space-y-0.5 font-mono text-tiny">
                          {(policy.destinationRules ?? []).map((rule, index) => {
                            const problem = storedRuleProblem(rule);
                            return (
                              <li key={`${rule.cidr}-${index}`} className={problem ? "text-warning-600" : undefined}>
                                {rule.cidr} · {(rule.protocols ?? []).join("/") || "无协议"} · {formatPorts(rule.portRanges)}
                                {problem && <span className="block font-sans">{problem}</span>}
                              </li>
                            );
                          })}
                        </ul>
                      )}
                    </TableCell>
                    <TableCell>
                      {(policy.domainRules ?? []).length === 0 ? (
                        <span className="text-tiny text-default-400">无</span>
                      ) : (
                        <ul className="space-y-0.5 font-mono text-tiny">
                          {(policy.domainRules ?? []).map((rule, index) => {
                            const problem = storedDomainRuleProblem(rule);
                            return (
                              <li key={`${rule.match}-${index}`} className={problem ? "text-warning-600" : undefined}>
                                {rule.match} · {(rule.protocols ?? []).join("/") || "无协议"} · {formatPorts(rule.portRanges)}
                                {problem && <span className="block font-sans">{problem}</span>}
                              </li>
                            );
                          })}
                        </ul>
                      )}
                    </TableCell>
                    <TableCell>
                      <span className="text-tiny text-default-500">
                        并发 {policy.maxConcurrentFlows} · 每设备 {policy.maxFlowsPerConsumer} · 空闲 {policy.idleTimeoutSeconds} 秒
                      </span>
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap items-center gap-2">
                        {isAdmin && (
                          <Switch
                            size="sm"
                            aria-label={`启用 ${policy.egressClientName} 的出口策略`}
                            isSelected={policy.enabled}
                            isDisabled={busy || loadError != null}
                            onValueChange={(enabled) => void togglePolicy(policy, enabled)}
                          />
                        )}
                        {isAdmin && (
                          <Button size="sm" variant="light" isDisabled={busy || draft != null} onPress={() => edit(policy)}>编辑</Button>
                        )}
                        {isAdmin && (
                          <Button size="sm" variant="light" color="danger" isLoading={busy} isDisabled={busy} onPress={() => removePolicy(policy)}>删除</Button>
                        )}
                      </div>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </div>
      )}

      <div className="rounded-md border border-default-200 p-3">
        <h4 className="mb-2 text-small font-semibold text-default-600">出口活动</h4>
        {activity.length === 0 ? (
          <p className="text-tiny text-default-500">尚无出口上报的活动。客户端目前不上报出口计数，出口是否在线以组网在线状态为准。</p>
        ) : (
          <ul className="space-y-1 text-tiny text-default-600">
            {activity.map((item) => {
              const rejected = Object.entries(item.rejectedFlows ?? {}).filter(([, count]) => count > 0);
              return (
                <li key={item.egressClientId}>
                  {item.egressClientName || deviceName(item.egressClientId)} · {item.online ? "在线" : "离线"} · {item.activeFlows} 个活动流 · 累计 {item.totalFlows} · 收 {formatBytes(item.bytesIn)} / 发 {formatBytes(item.bytesOut)}
                  {rejected.length > 0 ? ` · 拒绝：${rejected.map(([code, count]) => `${code}=${count}`).join("，")}` : ""}
                  {item.reportedAt ? ` · ${formatDateTime(item.reportedAt)}` : ""}
                </li>
              );
            })}
          </ul>
        )}
      </div>

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
    </section>
  );
}
