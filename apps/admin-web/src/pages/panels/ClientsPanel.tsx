import { useCallback, useEffect, useState, type FormEvent } from "react";
import { PageHeader } from "../../components/PageHeader";
import {
  Button,
  Input,
  Modal,
  ModalBody,
  ModalContent,
  ModalFooter,
  ModalHeader,
  Pagination,
  Textarea,
  useDisclosure,
} from "@heroui/react";
import { adminApi } from "../../api/client";
import type { Client, ClientCredential } from "../../api/types";
import { formatAbsoluteTime, formatBytes, formatElapsed } from "../../lib/format";
import { copyTextWithFeedback } from "../../lib/clipboard";
import { notify, notifyError } from "../../components/toast";
import { useNowTick } from "../../hooks/useNowTick";
import { ClientDetailDrawer } from "../../components/ClientDetailDrawer";
import { ConfirmModal } from "../../components/ConfirmModal";
import { ClientOnboardingGuide } from "../../components/ClientOnboardingGuide";
import { Alert, Empty, Icon, Section, TableWrap, Tag } from "../../components/ui";
import { buildClientStartupConfig } from "../../lib/clientOnboarding";
import { DesignSwitch, EmptyCell, ListLoading, TimeText } from "./accessUi";

const PAGE_SIZE = 10;

/** 在线时长自 tick 的小组件，避免整表每秒重挂载。 */
function SinceText({ sinceMs }: { sinceMs: number }) {
  const now = useNowTick(1000);
  return <>{formatElapsed(Math.max(0, (now - sinceMs) / 1000))}</>;
}

/** Online state of an instance: a Tag (disabled before online), and how long it has been online. */
function ClientStatus({ client }: { client: Client }) {
  const title = client.online && client.connectedSinceMs ? `登录于 ${formatAbsoluteTime(client.connectedSinceMs)}` : undefined;
  return (
    <div className="acc-status-cell">
      <Tag tone={client.enabled && client.online ? "success" : "neutral"} plain={!client.enabled} title={title}>
        {!client.enabled ? "停用" : client.online ? "在线" : "离线"}
      </Tag>
      {client.enabled && client.online && client.connectedSinceMs ? (
        <span className="jd-table-sub bd-num" title={title}>已在线 <SinceText sinceMs={client.connectedSinceMs} /></span>
      ) : null}
    </div>
  );
}

function MessageCapability({ client }: { client: Client }) {
  const title = client.messageReceiveCapable
    ? `附件 ${client.messageAttachmentsCapable ? "支持" : "不支持"} · 预览 ${client.messageMediaPreviewCapable ? "支持" : "不支持"}`
    : "该客户端未上报消息能力";
  return (
    <Tag tone={client.messageReceiveCapable ? "info" : "neutral"} plain title={title}>
      {client.messageReceiveCapable ? "可聊天" : "不可聊天"}
    </Tag>
  );
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
    <div className="acc-pager">
      <span className="bd-num">共 {items.length} 条</span>
      <Pagination showControls size="sm" page={safePage} total={totalPages} onChange={setPage} />
    </div>
  ) : null;
  return { paged, pager };
}

export function ClientsPanel() {
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
  const clientModal = useDisclosure();
  const credentialModal = useDisclosure();
  const secretModal = useDisclosure();
  const [detailClient, setDetailClient] = useState<Client | null>(null);
  const [confirm, setConfirm] = useState<ConfirmState | null>(null);

  const loadClients = useCallback(async () => {
    setLoadingClients(true);
    try {
      setClients(await adminApi.listClients());
      setClientsLoadError(false);
    } catch (error) {
      setClientsLoadError(true);
      notifyError(error, "加载客户端失败");
    } finally {
      setLoadingClients(false);
    }
  }, []);

  const loadCredentials = useCallback(async () => {
    setLoadingCredentials(true);
    try {
      setCredentials(await adminApi.listClientCredentials());
      setCredentialsLoadError(false);
    } catch (error) {
      setCredentialsLoadError(true);
      notifyError(error, "加载接入凭证失败");
    } finally {
      setLoadingCredentials(false);
    }
  }, []);

  const load = useCallback(async () => {
    await Promise.all([loadCredentials(), loadClients()]);
  }, [loadClients, loadCredentials]);

  useEffect(() => {
    void load();
  }, [load]);

  const showSecret = (value?: string, credentialApiKey = "") => {
    if (!value) {
      return;
    }
    setRevealedSecret(value);
    setRevealedApiKey(credentialApiKey);
    setServerBaseUrl(window.location.origin);
    secretModal.onOpen();
  };

  const closeSecret = () => {
    secretModal.onClose();
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
    clientModal.onOpen();
  };

  const openCredentialEdit = (credential: ClientCredential) => {
    setEditingCredential(credential);
    credentialModal.onOpen();
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

  const credentialPagination = useLocalPagination(credentials);
  const clientPagination = useLocalPagination(clients);
  const onlineCount = clients.filter((client) => client.enabled && client.online).length;

  return (
    <div className="acc-page">
      <PageHeader
        title="客户端"
        description="创建接入凭证、管理客户端实例，确认设备上线后再发布服务。"
        actions={<Button variant="flat" isLoading={loadingClients || loadingCredentials} startContent={loadingClients || loadingCredentials ? null : <Icon name="refresh" />} onPress={() => void load()}>刷新</Button>}
      />
      <ClientOnboardingGuide loading={loadingClients || loadingCredentials} error={clientsLoadError || credentialsLoadError}
        online={onlineCount} registered={clients.length} credentials={credentials.length}
        onRefresh={() => void load()} />

      <Section
        title="接入凭证"
        description="客户端启动只需要 serverBaseUrl、apiKey 和 secret；名称首次连接时自动生成，之后可在实例列表中修改。"
        actions={credentialsLoadError ? <Tag tone="danger">读取失败</Tag> : !loadingCredentials ? <span className="acc-head-count bd-num">{credentials.length} 个</span> : null}
      >
        <form className="bd-card acc-inline-form" onSubmit={createCredential} aria-label="新建接入凭证">
          <Input label="apiKey" placeholder="team-laptop" description="留空自动生成" value={apiKey} onValueChange={setApiKey} />
          <Input label="secret" type="password" autoComplete="new-password" description="留空自动生成；只在创建后显示一次" value={secret} onValueChange={setSecret} />
          <Input
            type="number"
            label="在线实例上限"
            min={1}
            max={10000}
            value={maxOnline}
            onValueChange={setMaxOnline}
            isInvalid={Boolean(maxOnlineError)}
            errorMessage={maxOnlineError}
            description="同一凭证同时在线的实例数，1–10000"
          />
          <div className="acc-inline-form-submit">
            <Button type="submit" color="primary" isLoading={creating} startContent={creating ? null : <Icon name="plus" />}>
              新建接入凭证
            </Button>
          </div>
        </form>

        {loadingCredentials && credentials.length === 0 ? <ListLoading label="正在读取接入凭证…" /> : credentials.length === 0 ? (
          <div className="bd-card"><Empty icon="key" title="还没有接入凭证" description="在上面新建一个接入凭证，保存配置后客户端就能接入。" /></div>
        ) : (
          <TableWrap className={loadingCredentials ? "bd-refetching" : undefined}>
            <table className="bd-table jd-stack" aria-label="接入凭证列表">
              <thead>
                <tr>
                  <th>apiKey</th>
                  <th>归属</th>
                  <th>状态</th>
                  <th className="bd-col-num">在线实例上限</th>
                  <th>创建时间</th>
                  <th className="jd-col-actions"><span className="jd-sr-only">操作</span></th>
                </tr>
              </thead>
              <tbody>
                {credentialPagination.paged.map((credential) => (
                  <tr key={credential.id}>
                    <td>
                      <div className="jd-table-title">
                        <span className="font-mono">{credential.apiKey}</span>
                        <span className="jd-table-sub bd-num">#{credential.id}</span>
                      </div>
                    </td>
                    <td data-label="归属" className={credential.ownerUsername ? undefined : "is-empty"}>{credential.ownerUsername || <EmptyCell />}</td>
                    <td><Tag tone={credential.enabled ? "success" : "neutral"} plain={!credential.enabled}>{credential.enabled ? "启用" : "停用"}</Tag></td>
                    <td className="bd-col-num" data-label="实例上限">{credential.maxOnlineInstances}</td>
                    <td data-label="创建"><TimeText value={credential.createdAt} /></td>
                    <td className="jd-cell-actions">
                      <div className="jd-row-actions">
                        <Button size="sm" variant="flat" startContent={<Icon name="edit" size={14} />} onPress={() => openCredentialEdit(credential)}>
                          编辑
                        </Button>
                        <Button size="sm" color="danger" variant="flat" startContent={<Icon name="trash" size={14} />} onPress={() => removeCredential(credential)}>
                          删除
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
        )}
        {credentialPagination.pager}
      </Section>

      <Section
        title="客户端实例"
        description="实例首次登录后自动注册并生成名称；可在编辑窗口中自定义，名称在全局范围内不可重复。"
        actions={clientsLoadError ? <Tag tone="danger">读取失败</Tag> : !loadingClients ? (
          <>
            {onlineCount > 0 ? <Tag tone="success">{onlineCount} 台在线</Tag> : null}
            <span className="acc-head-count bd-num">共 {clients.length} 台</span>
          </>
        ) : null}
      >
        {loadingClients && clients.length === 0 ? <ListLoading label="正在读取客户端实例…" /> : clients.length === 0 ? (
          <div className="bd-card"><Empty icon="monitor" title="还没有客户端实例" description="客户端用接入凭证首次登录后自动注册，会出现在这里。" /></div>
        ) : (
          <TableWrap className={loadingClients ? "bd-refetching" : undefined}>
            <table className="bd-table jd-stack acc-instances" aria-label="客户端实例列表">
              <thead>
                <tr>
                  <th>客户端</th>
                  <th>归属</th>
                  <th>状态</th>
                  <th>消息</th>
                  <th className="bd-col-num">每分钟上限</th>
                  <th className="bd-col-num">上传</th>
                  <th className="bd-col-num">下载</th>
                  <th>创建时间</th>
                  <th className="jd-col-actions"><span className="jd-sr-only">操作</span></th>
                </tr>
              </thead>
              <tbody>
                {clientPagination.paged.map((client) => (
                  <tr key={client.id}>
                    <td>
                      <div className="jd-table-title">
                        <span className="font-medium">{client.clientName}</span>
                        <span className="jd-table-sub bd-num">#{client.id}{client.clientVersion ? ` · v${client.clientVersion.replace(/^v/, "")}` : ""}</span>
                      </div>
                    </td>
                    <td data-label="归属" className={client.ownerUsername ? undefined : "is-empty"}>{client.ownerUsername || <EmptyCell />}</td>
                    <td><ClientStatus client={client} /></td>
                    <td><MessageCapability client={client} /></td>
                    <td className="bd-col-num" data-label="每分钟上限">{client.connectionRateLimitPerMinute || "不限"}</td>
                    <td className="bd-col-num" data-label="上传">{formatBytes(client.uploadBytes)}</td>
                    <td className="bd-col-num" data-label="下载">{formatBytes(client.downloadBytes)}</td>
                    <td data-label="创建"><TimeText value={client.createdAt} /></td>
                    <td className="jd-cell-actions">
                      <div className="jd-row-actions">
                        <Button size="sm" variant="flat" onPress={() => setDetailClient(client)}>
                          详情
                        </Button>
                        <Button size="sm" variant="flat" onPress={() => openClientEdit(client)}>
                          编辑
                        </Button>
                        <Button size="sm" variant="flat" onPress={() => void pushNat(client)}>
                          下发映射
                        </Button>
                        <Button size="sm" color="danger" variant="flat" onPress={() => removeClient(client)}>
                          删除
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
        )}
        {clientPagination.pager}
      </Section>

      <EditCredentialModal disclosure={credentialModal} credential={editingCredential} onSaved={(value, currentApiKey) => {
        showSecret(value, currentApiKey);
        void loadCredentials();
      }} />

      <EditClientModal disclosure={clientModal} client={editingClient} onSaved={() => void loadClients()} />

      <Modal isOpen={secretModal.isOpen} onClose={closeSecret} size="2xl" scrollBehavior="inside">
        <ModalContent>
          {() => (
            <>
              <ModalHeader>保存接入配置（凭证仅显示一次）</ModalHeader>
              <ModalBody className="acc-dialog-body">
                <Alert tone="warning" title="配置包含接入凭证">
                  只交给要接入的设备。关闭后本页不再保留；不要上传到仓库或发送给他人。
                </Alert>
                <Input label="服务端地址" description="需能从客户端设备访问；前端与服务端分开部署时，改为实际服务端地址。" value={serverBaseUrl} onValueChange={setServerBaseUrl} isInvalid={Boolean(startupConfigError)} errorMessage={startupConfigError} />
                <Input label="apiKey" value={revealedApiKey} isReadOnly classNames={{ input: "font-mono" }} />
                <Textarea label="client.jsonc（含敏感凭证）" value={startupConfig} isReadOnly minRows={5} classNames={{ input: "font-mono text-tiny" }} />
                <p className="bd-help">保存为 client.jsonc 后，按所选客户端的启动说明运行。实例首次登录后才会出现在列表中。</p>
              </ModalBody>
              <ModalFooter className="flex-wrap">
                <Button
                  variant="flat"
                  isDisabled={!startupConfig}
                  startContent={<Icon name="copy" />}
                  onPress={() => void copyTextWithFeedback(startupConfig, "接入配置已复制，请妥善保存")}
                >
                  复制配置
                </Button>
                <Button variant="flat" isDisabled={!startupConfig} startContent={<Icon name="download" />} onPress={downloadStartupConfig}>下载配置</Button>
                <Button color="primary" onPress={closeSecret}>
                  关闭配置
                </Button>
              </ModalFooter>
            </>
          )}
        </ModalContent>
      </Modal>
      <ClientDetailDrawer client={detailClient} open={detailClient != null} onClose={() => setDetailClient(null)} />
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
  disclosure: ReturnType<typeof useDisclosure>;
  credential: ClientCredential | null;
  onSaved: (secret?: string, apiKey?: string) => void;
}

function EditCredentialModal({ disclosure, credential, onSaved }: EditCredentialModalProps) {
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
      disclosure.onClose();
      setSecret("");
      onSaved(result.secret, result.credential.apiKey);
    } catch (error) {
      notifyError(error, "更新失败");
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal isOpen={disclosure.isOpen} onOpenChange={disclosure.onOpenChange}>
      <ModalContent>
        {(onClose) => (
          <>
            <ModalHeader>编辑接入凭证「{credential?.apiKey}」</ModalHeader>
            <ModalBody className="acc-dialog-body">
              <Input label="apiKey" value={apiKey} onValueChange={setApiKey} isRequired />
              <Input label="secret" type="password" autoComplete="new-password" placeholder="留空保留原 secret" value={secret} onValueChange={setSecret} />
              <Input
                type="number"
                label="在线实例上限"
                min={1}
                max={10000}
                value={maxOnline}
                onValueChange={setMaxOnline}
                isInvalid={Boolean(maxOnlineError)}
                errorMessage={maxOnlineError}
              />
              <DesignSwitch checked={enabled} onChange={setEnabled} label="启用" />
            </ModalBody>
            <ModalFooter>
              <Button variant="flat" onPress={onClose}>
                取消
              </Button>
              <Button color="primary" isDisabled={Boolean(maxOnlineError)} isLoading={saving} onPress={() => void save()}>
                保存
              </Button>
            </ModalFooter>
          </>
        )}
      </ModalContent>
    </Modal>
  );
}

interface EditClientModalProps {
  disclosure: ReturnType<typeof useDisclosure>;
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
      disclosure.onClose();
      onSaved();
    } catch (error) {
      notifyError(error, "更新失败");
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal isOpen={disclosure.isOpen} onOpenChange={disclosure.onOpenChange}>
      <ModalContent>
        {(onClose) => (
          <>
            <ModalHeader>编辑客户端实例「{client?.clientName}」</ModalHeader>
            <ModalBody className="acc-dialog-body">
              <Input
                label="客户端名称"
                value={clientName}
                onValueChange={setClientName}
                maxLength={120}
                isRequired
                isInvalid={Boolean(nameError)}
                errorMessage={nameError}
                description={nameStatus === "checking"
                  ? "正在检查全局唯一性…"
                  : nameStatus === "available" && !localNameError
                    ? "名称可用；修改后在线实例会重新连接"
                    : "所有租户和用户之间不可重名"}
              />
              <Input
                type="number"
                label="每分钟连接上限（0 = 不限）"
                value={rate}
                onValueChange={setRate}
                min={0}
                max={10000}
                isInvalid={Boolean(rateError)}
                errorMessage={rateError}
              />
              <DesignSwitch checked={enabled} onChange={setEnabled} label="启用" />
            </ModalBody>
            <ModalFooter>
              <Button variant="flat" onPress={onClose}>
                取消
              </Button>
              <Button
                color="primary"
                isDisabled={Boolean(localNameError) || Boolean(rateError) || nameStatus === "checking" || nameStatus === "unavailable"}
                isLoading={saving}
                onPress={() => void save()}
              >
                保存
              </Button>
            </ModalFooter>
          </>
        )}
      </ModalContent>
    </Modal>
  );
}
