import { ButtonLink } from "../../components/ButtonLink";
import { Pager } from "../../components/Pager";
import { AutoSizeTextArea } from "../../components/AutoSizeTextArea";
import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { Button, Chip, Input, Modal, Switch, Table, TableBody, TableCell, TableColumn, TableHeader, TableRow, Tooltip, Spinner, Label, TooltipTrigger, TooltipContent, useOverlayState, TextField, Description, FieldError, TableContent } from "@heroui/react";
import { adminApi } from "../../api/client";
import type { Client, ClientCredential } from "../../api/types";
import { formatBytes, formatDateTime, formatSince } from "../../lib/format";
import { copyTextWithFeedback } from "../../lib/clipboard";
import { notify, notifyError } from "../../components/toast";
import { useNowTick } from "../../hooks/useNowTick";
import { MobileListCard, MobileListCardList } from "../../components/MobileListCard";
import { ClientDetailDrawer } from "../../components/ClientDetailDrawer";
import { ConfirmModal } from "../../components/ConfirmModal";
import { EmptyState } from "../../components/EmptyState";
import { StatusChip, enabledTone, onlineTone } from "../../components/StatusChip";
import { ClientOnboardingGuide } from "../../components/ClientOnboardingGuide";
import { buildClientStartupConfig } from "../../lib/clientOnboarding";
import { useAuth } from "../../auth/AuthContext";
import { OwnerTransferDialog } from "../../components/OwnerTransferDialog";
import { countOwnedResources, sameOwner, type TransferResource } from "../../lib/ownerTransfer";
import { publishOwnershipChange, watchOwnershipChanges } from "../../lib/ownershipChanges";

const PAGE_SIZE = 10;

/** 在线时长自 tick 的小组件，避免整表每秒重挂载。 */
function SinceText({ sinceMs }: { sinceMs: number }) {
  const now = useNowTick(1000);
  return <>{formatSince(sinceMs, now)}</>;
}

interface ConfirmState {
  title: string;
  description?: string;
  confirmLabel?: string;
  action: () => Promise<void>;
}

/** 本地分页：返回当前页切片与分页器（单页时不渲染分页器）。 */
function useLocalPagination<T>(items: T[], pageSize = PAGE_SIZE) {
  const [page, setPage] = useState(1);
  const totalPages = Math.max(1, Math.ceil(items.length / pageSize));
  const safePage = Math.min(page, totalPages);
  const paged = items.slice((safePage - 1) * pageSize, safePage * pageSize);
  const pager = totalPages > 1 ? (
    <div className="flex justify-end">
      <Pager page={safePage} total={totalPages} onChange={setPage}  />
    </div>
  ) : null;
  return { paged, pager };
}

export function ClientsPanel() {
  const clientRead = useRef(0), credentialRead = useRef(0);
  const { profile } = useAuth();
  const [transferResource, setTransferResource] = useState<TransferResource | null>(null);
  const [ownerFilter, setOwnerFilter] = useState(() => new URLSearchParams(window.location.hash.split("?")[1] ?? "").get("owner") ?? "");
  const [clients, setClients] = useState<Client[]>([]);
  const [credentials, setCredentials] = useState<ClientCredential[]>([]);
  const [loadingClients, setLoadingClients] = useState(true);
  const [loadingCredentials, setLoadingCredentials] = useState(true);
  const [apiKey, setApiKey] = useState("");
  const [secret, setSecret] = useState("");
  const [maxOnline, setMaxOnline] = useState("2");
  const [creating, setCreating] = useState(false);
  const [editingClient, setEditingClient] = useState<Client | null>(null);
  const [editingCredential, setEditingCredential] = useState<ClientCredential | null>(null);
  const [revealedSecret, setRevealedSecret] = useState("");
  const [revealedApiKey, setRevealedApiKey] = useState("");
  const [serverBaseUrl, setServerBaseUrl] = useState(window.location.origin);
  const [clientsLoadError, setClientsLoadError] = useState(false);
  const [credentialsLoadError, setCredentialsLoadError] = useState(false);
  const clientModal = useOverlayState();
  const credentialModal = useOverlayState();
  const secretModal = useOverlayState();
  const [detailClient, setDetailClient] = useState<Client | null>(null);
  const detailOpenerRef = useRef<HTMLButtonElement | null>(null);
  const [confirm, setConfirm] = useState<ConfirmState | null>(null);

  const loadClients = useCallback(async () => {
    const read = ++clientRead.current;
    setLoadingClients(true);
    try {
      const next = await adminApi.listClients();
      if (read !== clientRead.current) return true;
      setClients(next);
      setDetailClient(current => current ? next.find(client => client.id === current.id) ?? null : null);
      setClientsLoadError(false);
      return true;
    } catch (error) {
      if (read !== clientRead.current) return true;
      setClientsLoadError(true);
      notifyError(error, "加载客户端失败");
      return false;
    } finally {
      if (read === clientRead.current) setLoadingClients(false);
    }
  }, []);

  const loadCredentials = useCallback(async () => {
    const read = ++credentialRead.current;
    setLoadingCredentials(true);
    try {
      const next = await adminApi.listClientCredentials();
      if (read !== credentialRead.current) return true;
      setCredentials(next);
      setCredentialsLoadError(false);
      return true;
    } catch (error) {
      if (read !== credentialRead.current) return true;
      setCredentialsLoadError(true);
      notifyError(error, "加载接入凭证失败");
      return false;
    } finally {
      if (read === credentialRead.current) setLoadingCredentials(false);
    }
  }, []);

  const load = useCallback(async () => {
    return (await Promise.all([loadCredentials(), loadClients()])).every(Boolean);
  }, [loadClients, loadCredentials]);

  useEffect(() => {
    void load();
  }, [load]);
  useEffect(() => watchOwnershipChanges(() => { void load(); }, false), [load]);
  useEffect(() => {
    const sync = () => {
      const query = new URLSearchParams(window.location.hash.split("?")[1] ?? "");
      setOwnerFilter(query.get("owner") ?? "");
      const section = query.get("section");
      if (section === "clients" || section === "credentials") document.getElementById(`owner-${section}`)?.scrollIntoView({ block: "start" });
    };
    window.addEventListener("hashchange", sync); sync();
    return () => window.removeEventListener("hashchange", sync);
  }, []);
  const openTransfer = (resource: TransferResource) => {
    if (!profile?.admin) return;
    setDetailClient(null); credentialModal.close(); setTransferResource(resource);
  };
  const openDetails = (client: Client, target: Element) => {
    detailOpenerRef.current = target.closest<HTMLButtonElement>("button");
    setDetailClient(client);
  };
  const closeDetails = () => {
    const opener = detailOpenerRef.current;
    setDetailClient(null);
    window.requestAnimationFrame(() => { if (opener?.isConnected) opener.focus({ preventScroll: true }); });
  };

  const showSecret = (value?: string, credentialApiKey = "") => {
    if (!value) {
      return;
    }
    setRevealedSecret(value);
    setRevealedApiKey(credentialApiKey);
    setServerBaseUrl(window.location.origin);
    secretModal.open();
  };

  const closeSecret = () => {
    secretModal.close();
    setRevealedSecret("");
    setRevealedApiKey("");
  };
  let startupConfig = "";
  let startupConfigError = "";
  if (revealedSecret) {
    try { startupConfig = buildClientStartupConfig(serverBaseUrl, revealedApiKey, revealedSecret); }
    catch (error) { startupConfigError = error instanceof Error ? error.message : "请检查服务端地址"; }
  }
  const downloadStartupConfig = () => {
    if (!startupConfig) return;
    const url = URL.createObjectURL(new Blob([startupConfig], { type: "application/json" }));
    const link = document.createElement("a");
    link.href = url; link.download = "client.jsonc";
    document.body.appendChild(link); link.click(); link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    notify("已开始下载 client.jsonc；文件含凭证，请妥善保管");
  };

  const maxOnlineNumber = Number(maxOnline);
  const maxOnlineError = !maxOnline.trim()
    ? "请输入在线实例上限"
    : !Number.isInteger(maxOnlineNumber) || maxOnlineNumber < 1 || maxOnlineNumber > 10000
      ? "请输入 1-10000 的整数"
      : "";

  const createCredential = async (event: FormEvent) => {
    event.preventDefault();
    if (maxOnlineError) {
      notify(maxOnlineError, "error");
      return;
    }
    setCreating(true);
    try {
      const result = await adminApi.createClientCredential({
        apiKey: apiKey.trim() || undefined,
        secret: secret.trim() || null,
        maxOnlineInstances: maxOnlineNumber,
        enabled: true,
      });
      setApiKey("");
      setSecret("");
      setMaxOnline("2");
      showSecret(result.secret, result.credential.apiKey);
      notify("接入凭证已创建");
      await loadCredentials();
    } catch (error) {
      notifyError(error, "创建失败");
    } finally {
      setCreating(false);
    }
  };

  const openClientEdit = (client: Client) => {
    setEditingClient(client);
    clientModal.open();
  };

  const openCredentialEdit = (credential: ClientCredential) => {
    setEditingCredential(credential);
    credentialModal.open();
  };

  const pushNat = async (client: Client) => {
    try {
      const result = await adminApi.pushNatControl(client.id);
      const http = result.httpRoutes < 0 ? "-" : String(result.httpRoutes);
      notify(`已下发：TCP ${result.specusMappings} 条 / HTTP ${http} 条`);
    } catch (error) {
      notifyError(error, "下发失败");
    }
  };

  const removeClient = (client: Client) => {
    setConfirm({
      title: "删除客户端实例",
      description: `确定删除客户端实例「${client.clientName}」吗？历史连接和流量记录会保留。`,
      confirmLabel: "删除",
      action: async () => {
        try {
          await adminApi.deleteClient(client.id);
          notify("客户端实例已删除");
          await loadClients();
        } catch (error) {
          notifyError(error, "删除失败");
        }
      },
    });
  };

  const removeCredential = (credential: ClientCredential) => {
    setConfirm({
      title: "删除接入凭证",
      description: `确定删除接入凭证「${credential.apiKey}」吗？使用它的客户端将无法继续登录。`,
      confirmLabel: "删除",
      action: async () => {
        try {
          await adminApi.deleteClientCredential(credential.id);
          notify("接入凭证已删除");
          await loadCredentials();
        } catch (error) {
          notifyError(error, "删除失败");
        }
      },
    });
  };

  const statusChip = (client: Client) => {
    const tooltip = client.online && client.connectedSinceMs
      ? `登录于 ${formatDateTime(new Date(client.connectedSinceMs).toISOString())}`
      : undefined;
    const chip = (
      <StatusChip tone={onlineTone(client.online, !client.enabled)}>
        {!client.enabled ? "停用" : client.online ? "在线" : "离线"}
        {client.online && client.connectedSinceMs ? (
          <>
            {" · "}
            <SinceText sinceMs={client.connectedSinceMs} />
          </>
        ) : null}
      </StatusChip>
    );
    return tooltip ? <Tooltip>
      <TooltipTrigger role="group" tabIndex={0}>{chip}</TooltipTrigger>
      <TooltipContent>{tooltip}</TooltipContent>
    </Tooltip> : chip;
  };

  const messageCapabilityChip = (client: Client) => (
    <Tooltip
    >
      <TooltipTrigger role="group" tabIndex={0}><Chip size="sm" color={client.messageReceiveCapable ? "success" : "default"} variant="soft">
        {client.messageReceiveCapable ? "可聊天" : "不可聊天"}
      </Chip></TooltipTrigger>
      <TooltipContent>{client.messageReceiveCapable
          ? `附件 ${client.messageAttachmentsCapable ? "支持" : "不支持"} · 预览 ${client.messageMediaPreviewCapable ? "支持" : "不支持"}`
          : "该客户端未上报消息能力"}</TooltipContent>
    </Tooltip>
  );

  const visibleCredentials = ownerFilter ? credentials.filter(row => sameOwner(row.ownerUsername, ownerFilter)) : credentials;
  const visibleClients = ownerFilter ? clients.filter(row => sameOwner(row.ownerUsername, ownerFilter)) : clients;
  const credentialPagination = useLocalPagination(visibleCredentials);
  const clientPagination = useLocalPagination(visibleClients);
  const ownerCounts = countOwnedResources(ownerFilter, clients, credentials);

  return (
    <div className="mt-3 flex min-w-0 flex-col gap-5">
      {ownerFilter && <div className="space-y-2 rounded-md border border-primary-200 bg-primary-50 p-4" role="status">
        <p className="break-all font-medium">正在处理「{ownerFilter}」的资源</p>
        <p className="text-small">{loadingClients || loadingCredentials ? "正在重新读取归属…" : clientsLoadError || credentialsLoadError ? "部分列表读取失败，请刷新后核对计数。" : `${ownerCounts.clients} 个客户端、${ownerCounts.credentials} 个接入凭证。零设备凭证也需要单独处理。`}</p>
        <div className="flex flex-wrap gap-2"><ButtonLink href="#/clients" size="sm" variant={"secondary"}>查看全部资源</ButtonLink><ButtonLink href="#/system" size="sm" variant={"secondary"}>返回账号管理</ButtonLink></div>
      </div>}
      <ClientOnboardingGuide loading={loadingClients || loadingCredentials} error={clientsLoadError || credentialsLoadError}
        online={clients.filter((client) => client.enabled && client.online).length} registered={clients.length} credentials={credentials.length}
        onRefresh={() => void load()} />
      <section className="flex min-w-0 flex-col gap-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 id="owner-credentials" className="scroll-mt-20 text-lg font-semibold text-foreground">接入凭证</h2>
            <p className="text-small text-default-500">客户端启动只需要 serverBaseUrl、apiKey 和 secret；名称首次连接时自动生成，之后可在实例列表中修改。</p>
          </div>
          <Button className="w-full sm:w-auto" variant="secondary" onPress={() => void load()} isDisabled={loadingClients || loadingCredentials}>{loadingClients || loadingCredentials ? <Spinner size="sm" /> : null}
            刷新
          </Button>
        </div>

        <form className="flex flex-wrap items-end gap-3" onSubmit={createCredential}>
          <TextField value={apiKey} onChange={setApiKey} className={[("w-full sm:w-64")].filter(Boolean).join(" ")}><Label>{"apiKey"}</Label><Input placeholder="留空自动生成" /></TextField>
          <TextField value={secret} onChange={setSecret} className={[("w-full sm:w-56")].filter(Boolean).join(" ")}><Label>{"secret"}</Label><Input type="password" autoComplete="new-password" placeholder="留空自动生成" /></TextField>
          <TextField value={maxOnline} isInvalid={Boolean(maxOnlineError)} onChange={setMaxOnline} className={[("w-full sm:w-44")].filter(Boolean).join(" ")}><Label>{"在线实例上限"}</Label><Input type="number" min={1} max={10000} /><FieldError>{maxOnlineError}</FieldError></TextField>
          <Button className="h-14 w-full sm:w-auto" type="submit" isPending={creating} variant={"primary"}>{(creating) ? <Spinner size="sm" aria-hidden="true" /> : null}
            新建接入凭证
          </Button>
        </form>

        {/* mobile: 卡片 */}
        <div className="lg:hidden">
          <MobileListCardList
            items={credentialPagination.paged}
            isLoading={loadingCredentials}
            emptyContent={<EmptyState icon="clients" title="暂无接入凭证" description="创建凭证后客户端即可接入" />}
            renderCard={(raw) => {
              const credential = raw as ClientCredential;
              return (
                <MobileListCard
                  key={credential.id}
                  title={<span className="break-all font-mono">{credential.apiKey}</span>}
                  subtitle={`${credential.ownerUsername || "-"} · #${credential.id}`}
                  badges={
                    <StatusChip tone={enabledTone(credential.enabled)}>
                      {credential.enabled ? "启用" : "停用"}
                    </StatusChip>
                  }
                  fields={[
                    { label: "实例上限", value: credential.maxOnlineInstances },
                    { label: "创建时间", value: formatDateTime(credential.createdAt) },
                  ]}
                  actions={
                    <>
                      <Button size="sm" variant="secondary" onPress={() => openCredentialEdit(credential)}>
                        编辑
                      </Button>
                      {profile?.admin && <Button size="sm" variant={"secondary"} onPress={() => openTransfer({ kind: "credential", id: credential.id })}>转移管理归属</Button>}
                      <Button size="sm" variant={"danger-soft"} onPress={() => void removeCredential(credential)}>
                        删除
                      </Button>
                    </>
                  }
                />
              );
            }}
          />
        </div>

        {/* desktop: 表格 */}
        <div className="hidden min-w-0 overflow-x-auto lg:block">
        <Table>{(loadingCredentials) && <div role="status" className="flex items-center gap-2 p-3 text-small text-default-500"><Spinner size="sm" aria-hidden="true" /><span>正在加载…</span></div>}<Table.ScrollContainer><TableContent aria-label={"接入凭证列表"} aria-busy={loadingCredentials}>
          <TableHeader className={"sticky top-0 z-10"}>
            <TableColumn isRowHeader={true}>ID</TableColumn>
            <TableColumn>apiKey</TableColumn>
            <TableColumn>归属</TableColumn>
            <TableColumn>状态</TableColumn>
            <TableColumn>在线实例上限</TableColumn>
            <TableColumn>创建时间</TableColumn>
            <TableColumn>操作</TableColumn>
          </TableHeader>
          <TableBody items={credentialPagination.paged} renderEmptyState={() => (loadingCredentials) ? null : (<EmptyState icon="clients" title="暂无接入凭证" description="创建凭证后客户端即可接入" />)}>
            {(credential) => (
              <TableRow key={credential.id} id={credential.id}>
                <TableCell>{credential.id}</TableCell>
                <TableCell className="font-mono">{credential.apiKey}</TableCell>
                <TableCell>{credential.ownerUsername || "-"}</TableCell>
                <TableCell>
                  <StatusChip tone={enabledTone(credential.enabled)}>
                    {credential.enabled ? "启用" : "停用"}
                  </StatusChip>
                </TableCell>
                <TableCell>{credential.maxOnlineInstances}</TableCell>
                <TableCell>{formatDateTime(credential.createdAt)}</TableCell>
                <TableCell>
                  <div className="flex gap-2">
                    <Button size="sm" variant={"secondary"} onPress={() => openCredentialEdit(credential)}>
                      编辑
                    </Button>
                    {profile?.admin && <Button size="sm" variant={"secondary"} onPress={() => openTransfer({ kind: "credential", id: credential.id })}>转移管理归属</Button>}
                    <Button size="sm" variant={"danger-soft"} onPress={() => removeCredential(credential)}>
                      删除
                    </Button>
                  </div>
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </TableContent></Table.ScrollContainer></Table>
        </div>
        {credentialPagination.pager}
      </section>

      <section className="flex min-w-0 flex-col gap-3">
        <div>
          <h2 id="owner-clients" className="scroll-mt-20 text-lg font-semibold text-foreground">客户端实例</h2>
          <p className="text-small text-default-500">实例首次登录后自动注册并生成名称；可在编辑窗口中自定义，名称在全局范围内不可重复。</p>
        </div>

        {/* mobile: 卡片 */}
        <div className="lg:hidden">
          <MobileListCardList
            items={clientPagination.paged}
            isLoading={loadingClients}
            emptyContent={<EmptyState icon="clients" title="暂无客户端实例" description="客户端首次登录后自动注册" />}
            renderCard={(raw) => {
              const client = raw as Client;
              return (
                <MobileListCard
                  key={client.id}
                  title={<span className="break-all">{client.clientName}</span>}
                  subtitle={`${client.ownerUsername || "-"} · #${client.id}`}
                  badges={statusChip(client)}
                  fields={[
                    { label: "版本", value: client.clientVersion || "未上报" },
                    { label: "每分钟上限", value: client.connectionRateLimitPerMinute || "不限" },
                    { label: "消息", value: messageCapabilityChip(client) },
                    { label: "上传", value: formatBytes(client.uploadBytes) },
                    { label: "下载", value: formatBytes(client.downloadBytes) },
                    { label: "创建时间", value: formatDateTime(client.createdAt) },
                  ]}
                  actions={
                    <>
                      <Button size="sm" variant="secondary" onPress={(event) => openDetails(client, event.target)}>
                        详情
                      </Button>
                      <Button size="sm" variant="secondary" onPress={() => openClientEdit(client)}>
                        编辑
                      </Button>
                      {profile?.admin && <Button size="sm" variant={"secondary"} onPress={() => openTransfer({ kind: "client", id: client.id })}>转移管理归属</Button>}
                      <Button size="sm" variant={"secondary"} onPress={() => void pushNat(client)}>
                        下发映射
                      </Button>
                      <Button size="sm" variant="danger-soft" onPress={() => removeClient(client)}>
                        删除
                      </Button>
                    </>
                  }
                />
              );
            }}
          />
        </div>

        {/* desktop: 表格 */}
        <div className="hidden min-w-0 overflow-x-auto lg:block">
        <Table>{(loadingClients) && <div role="status" className="flex items-center gap-2 p-3 text-small text-default-500"><Spinner size="sm" aria-hidden="true" /><span>正在加载…</span></div>}<Table.ScrollContainer><TableContent aria-label={"客户端实例列表"} aria-busy={loadingClients}>
          <TableHeader className={"sticky top-0 z-10"}>
            <TableColumn isRowHeader={true}>ID</TableColumn>
            <TableColumn>客户端</TableColumn>
            <TableColumn>归属</TableColumn>
            <TableColumn>状态</TableColumn>
            <TableColumn>版本</TableColumn>
            <TableColumn>消息</TableColumn>
            <TableColumn>每分钟上限</TableColumn>
            <TableColumn>上传</TableColumn>
            <TableColumn>下载</TableColumn>
            <TableColumn>创建时间</TableColumn>
            <TableColumn>操作</TableColumn>
          </TableHeader>
          <TableBody items={clientPagination.paged} renderEmptyState={() => (loadingClients) ? null : (<EmptyState icon="clients" title="暂无客户端实例" description="客户端首次登录后自动注册" />)}>
            {(client) => (
              <TableRow key={client.id} id={client.id}>
                <TableCell>{client.id}</TableCell>
                <TableCell>{client.clientName}</TableCell>
                <TableCell>{client.ownerUsername || "-"}</TableCell>
                <TableCell>{statusChip(client)}</TableCell>
                <TableCell><span className="whitespace-nowrap font-mono text-tiny">{client.clientVersion || "未上报"}</span></TableCell>
                <TableCell>{messageCapabilityChip(client)}</TableCell>
                <TableCell>{client.connectionRateLimitPerMinute || "不限"}</TableCell>
                <TableCell>{formatBytes(client.uploadBytes)}</TableCell>
                <TableCell>{formatBytes(client.downloadBytes)}</TableCell>
                <TableCell>{formatDateTime(client.createdAt)}</TableCell>
                <TableCell>
                  <div className="flex gap-2">
                    <Button size="sm" variant={"secondary"} onPress={(event) => openDetails(client, event.target)}>
                      详情
                    </Button>
                    <Button size="sm" variant={"secondary"} onPress={() => openClientEdit(client)}>
                      编辑
                    </Button>
                    {profile?.admin && <Button size="sm" variant={"secondary"} onPress={() => openTransfer({ kind: "client", id: client.id })}>转移管理归属</Button>}
                    <Button size="sm" variant={"secondary"} onPress={() => void pushNat(client)}>
                      下发映射
                    </Button>
                    <Button size="sm" variant={"danger-soft"} onPress={() => removeClient(client)}>
                      删除
                    </Button>
                  </div>
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </TableContent></Table.ScrollContainer></Table>
        </div>
        {clientPagination.pager}
      </section>

      <EditCredentialModal disclosure={credentialModal} credential={editingCredential} onSaved={(value, currentApiKey) => {
        showSecret(value, currentApiKey);
        void loadCredentials();
      }} onTransfer={profile?.admin && editingCredential ? () => openTransfer({ kind: "credential", id: editingCredential.id }) : undefined} />

      <EditClientModal disclosure={clientModal} client={editingClient} onSaved={() => void loadClients()} />

      <Modal.Root isOpen={secretModal.isOpen} onOpenChange={(open) => { if (!open) (closeSecret)?.(); }}>
        <Modal.Backdrop><Modal.Container scroll={"inside"} size={"lg"}><Modal.Dialog className={"max-w-2xl"}>
          {() => (
            <><Modal.CloseTrigger />
              <Modal.Header><Modal.Heading>保存接入配置（凭证仅显示一次）</Modal.Heading></Modal.Header>
              <Modal.Body className="gap-3">
                <p className="text-small text-warning">配置包含接入凭证，请只交给要接入的设备。关闭后本页不再保留；不要上传到仓库或发送给他人。</p>
                <TextField value={serverBaseUrl} isInvalid={Boolean(startupConfigError)} onChange={setServerBaseUrl}><Label>{"服务端地址"}</Label><Input  /><Description>{"需能从客户端设备访问；前端与服务端分开部署时，请改为实际服务端地址。"}</Description><FieldError>{startupConfigError}</FieldError></TextField>
                <TextField value={revealedApiKey} isReadOnly><Label>{"apiKey"}</Label><Input  /></TextField>
                <TextField value={startupConfig} isReadOnly><Label>client.jsonc（含敏感凭证）</Label><AutoSizeTextArea value={startupConfig} minRows={5} className="font-mono text-tiny" /></TextField>
                <p className="text-small text-default-500">保存为 client.jsonc 后，按所选客户端的启动说明运行。实例首次登录后才会出现在列表中。</p>
              </Modal.Body>
              <Modal.Footer className="flex-wrap">
                <Button variant={"secondary"} isDisabled={!startupConfig} onPress={() => void copyTextWithFeedback(startupConfig, "接入配置已复制，请妥善保存")}
                >
                  复制配置
                </Button>
                <Button variant={"secondary"} isDisabled={!startupConfig} onPress={downloadStartupConfig}>下载配置</Button>
                <Button onPress={closeSecret} variant={"primary"}>
                  关闭配置
                </Button>
              </Modal.Footer>
            </>
          )}
        </Modal.Dialog></Modal.Container></Modal.Backdrop>
      </Modal.Root>
      <ClientDetailDrawer client={detailClient} open={detailClient != null} onClose={closeDetails}
        onTransfer={profile?.admin && detailClient ? () => openTransfer({ kind: "client", id: detailClient.id }) : undefined} />
      {profile?.admin && transferResource && <OwnerTransferDialog key={`${transferResource.kind}:${transferResource.id}`}
        resource={transferResource} onClose={() => setTransferResource(null)} onTransferred={async () => { publishOwnershipChange(); if (!await load()) throw new Error("列表刷新失败"); }} />}
      <ConfirmModal
        isOpen={confirm != null}
        onClose={() => setConfirm(null)}
        onConfirm={() => confirm?.action()}
        title={confirm?.title ?? ""}
        description={confirm?.description}
        confirmLabel={confirm?.confirmLabel}
        danger
      />
    </div>
  );
}

interface EditCredentialModalProps {
  disclosure: ReturnType<typeof useOverlayState>;
  credential: ClientCredential | null;
  onSaved: (secret?: string, apiKey?: string) => void;
  onTransfer?: () => void;
}

function EditCredentialModal({ disclosure, credential, onSaved, onTransfer }: EditCredentialModalProps) {
  const [apiKey, setApiKey] = useState("");
  const [secret, setSecret] = useState("");
  const [enabled, setEnabled] = useState(true);
  const [maxOnline, setMaxOnline] = useState("2");
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (credential) {
      setApiKey(credential.apiKey);
      setSecret("");
      setEnabled(credential.enabled);
      setMaxOnline(String(credential.maxOnlineInstances));
    }
  }, [credential, disclosure.isOpen]);

  const maxOnlineNumber = Number(maxOnline);
  const maxOnlineError = !maxOnline.trim()
    ? "请输入在线实例上限"
    : !Number.isInteger(maxOnlineNumber) || maxOnlineNumber < 1 || maxOnlineNumber > 10000
      ? "请输入 1-10000 的整数"
      : "";

  const save = async () => {
    if (!credential || maxOnlineError) {
      return;
    }
    setSaving(true);
    try {
      const result = await adminApi.updateClientCredential(credential.id, {
        apiKey: apiKey.trim(),
        secret: secret.trim() || null,
        enabled,
        maxOnlineInstances: maxOnlineNumber,
      });
      notify("接入凭证已更新");
      disclosure.close();
      setSecret("");
      onSaved(result.secret, result.credential.apiKey);
    } catch (error) {
      notifyError(error, "更新失败");
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal.Root isOpen={disclosure.isOpen} onOpenChange={disclosure.setOpen}>
      <Modal.Backdrop><Modal.Container><Modal.Dialog>
        {({ close: onClose }) => (
          <><Modal.CloseTrigger />
            <Modal.Header><Modal.Heading>编辑接入凭证「{credential?.apiKey}」</Modal.Heading></Modal.Header>
            <Modal.Body className="gap-3">
              <TextField value={apiKey} isRequired onChange={setApiKey}><Label>{"apiKey"}</Label><Input  /></TextField>
              <TextField value={secret} onChange={setSecret}><Label>{"secret"}</Label><Input type="password" autoComplete="new-password" placeholder="留空保留原 secret" /></TextField>
              <TextField value={maxOnline} isInvalid={Boolean(maxOnlineError)} onChange={setMaxOnline}><Label>{"在线实例上限"}</Label><Input type="number" min={1} max={10000} /><FieldError>{maxOnlineError}</FieldError></TextField>
              <Switch isSelected={enabled} onChange={setEnabled}><Switch.Content><Switch.Control><Switch.Thumb /></Switch.Control><Label>
                启用
              </Label></Switch.Content></Switch>
            </Modal.Body>
            <Modal.Footer>
              {onTransfer && <Button variant={"secondary"} isDisabled={saving} onPress={onTransfer}>转移管理归属</Button>}
              <Button variant={"secondary"} onPress={onClose}>
                取消
              </Button>
              <Button variant="primary" isDisabled={Boolean(maxOnlineError) || saving} onPress={() => void save()}>{saving ? <Spinner size="sm" /> : null}
                保存
              </Button>
            </Modal.Footer>
            </>
            )}

          </Modal.Dialog>
        </Modal.Container>
      </Modal.Backdrop>
    </Modal.Root>
  );
}

interface EditClientModalProps {
  disclosure: ReturnType<typeof useOverlayState>;
  client: Client | null;
  onSaved: () => void;
}

function EditClientModal({ disclosure, client, onSaved }: EditClientModalProps) {
  const [clientName, setClientName] = useState("");
  const [nameStatus, setNameStatus] = useState<"idle" | "checking" | "available" | "unavailable" | "error">("idle");
  const [rate, setRate] = useState("30");
  const [enabled, setEnabled] = useState(true);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (client) {
      setClientName(client.clientName);
      setNameStatus("available");
      setRate(String(client.connectionRateLimitPerMinute));
      setEnabled(client.enabled);
    }
  }, [client]);

  const normalizedClientName = clientName.trim();
  const localNameError = !normalizedClientName
    ? "客户端名称不能为空"
    : normalizedClientName.length > 120
      ? "客户端名称不能超过 120 个字符"
      : "";
  const nameError = localNameError
    || (nameStatus === "unavailable" ? "该名称已被其他客户端使用" : "")
    || (nameStatus === "error" ? "暂时无法校验名称，请稍后重试" : "");

  useEffect(() => {
    if (!client || localNameError) {
      setNameStatus("idle");
      return;
    }
    if (normalizedClientName === client.clientName) {
      setNameStatus("available");
      return;
    }

    let active = true;
    setNameStatus("checking");
    const timer = window.setTimeout(() => {
      void adminApi.checkClientNameAvailability(normalizedClientName, client.id)
        .then((result) => {
          if (active) {
            setNameStatus(result.available ? "available" : "unavailable");
          }
        })
        .catch(() => {
          if (active) {
            setNameStatus("error");
          }
        });
    }, 300);
    return () => {
      active = false;
      window.clearTimeout(timer);
    };
  }, [client, localNameError, normalizedClientName]);

  const rateNumber = Number(rate);
  const rateError = !rate.trim()
    ? "请输入每分钟连接上限"
    : !Number.isInteger(rateNumber) || rateNumber < 0 || rateNumber > 10000
      ? "请输入 0-10000 的整数（0 = 不限）"
      : "";

  const save = async () => {
    if (!client || localNameError || rateError) {
      return;
    }
    setSaving(true);
    try {
      const availability = await adminApi.checkClientNameAvailability(normalizedClientName, client.id);
      if (!availability.available) {
        setNameStatus("unavailable");
        return;
      }
      const renamed = normalizedClientName !== client.clientName;
      await adminApi.updateClient(client.id, {
        clientName: normalizedClientName,
        enabled,
        connectionRateLimitPerMinute: rateNumber,
      });
      notify(renamed ? "客户端名称已更新，在线实例将自动重连" : "客户端实例已更新");
      disclosure.close();
      onSaved();
    } catch (error) {
      notifyError(error, "更新失败");
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal.Root isOpen={disclosure.isOpen} onOpenChange={disclosure.setOpen}>
      <Modal.Backdrop>
        <Modal.Container>
          <Modal.Dialog>
            {({ close: onClose }) => (
            <><Modal.CloseTrigger />
            <Modal.Header><Modal.Heading>编辑客户端实例「{client?.clientName}」</Modal.Heading></Modal.Header>
            <Modal.Body className="gap-3">
              <TextField value={clientName} onChange={setClientName} isRequired isInvalid={Boolean(nameError)}>
                <Label>客户端名称</Label>
                <Input maxLength={120}   />
                <Description>{nameStatus === "checking"
                  ? "正在检查全局唯一性…"
                  : nameStatus === "available" && !localNameError
                    ? "名称可用；修改后在线实例会重新连接"
                    : "所有租户和用户之间不可重名"}</Description>
                <FieldError>{nameError}</FieldError>
              </TextField>
            <TextField value={rate} onChange={setRate} isInvalid={Boolean(rateError)} type="number">
              <Label>每分钟连接上限（0 = 不限）</Label>
              <Input min={0}
              max={10000}  />
              <FieldError>{rateError}</FieldError>
            </TextField>
            <Switch isSelected={enabled} onChange={setEnabled}><Switch.Content><Switch.Control><Switch.Thumb /></Switch.Control><Label>
              启用
            </Label></Switch.Content></Switch>
            </Modal.Body>
            <Modal.Footer>
              <Button variant="secondary" onPress={onClose}>
                取消
              </Button>
              <Button variant="primary" isDisabled={Boolean(localNameError) || Boolean(rateError) || nameStatus === "checking" || nameStatus === "unavailable" || saving} onPress={() => void save()}
              >{saving ? <Spinner size="sm" /> : null}
            保存
            </Button>
            </Modal.Footer>
            </>
            )}

          </Modal.Dialog>
        </Modal.Container>
      </Modal.Backdrop>
    </Modal.Root>
  );
}
