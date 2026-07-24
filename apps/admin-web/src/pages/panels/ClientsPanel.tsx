import { useCallback, useEffect, useState, type FormEvent } from "react";
import {
  Button,
  Chip,
  Input,
  Modal,
  ModalBody,
  ModalContent,
  ModalFooter,
  ModalHeader,
  Pagination,
  Switch,
  Table,
  TableBody,
  TableCell,
  TableColumn,
  TableHeader,
  TableRow,
  Tooltip,
  useDisclosure,
} from "@heroui/react";
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
      <Pagination showControls page={safePage} total={totalPages} onChange={setPage} />
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
  const clientModal = useDisclosure();
  const credentialModal = useDisclosure();
  const secretModal = useDisclosure();
  const [detailClient, setDetailClient] = useState<Client | null>(null);
  const [confirm, setConfirm] = useState<ConfirmState | null>(null);

  const loadClients = useCallback(async () => {
    setLoadingClients(true);
    try {
      setClients(await adminApi.listClients());
    } catch (error) {
      notifyError(error, "加载客户端失败");
    } finally {
      setLoadingClients(false);
    }
  }, []);

  const loadCredentials = useCallback(async () => {
    setLoadingCredentials(true);
    try {
      setCredentials(await adminApi.listClientCredentials());
    } catch (error) {
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

  const showSecret = (value?: string) => {
    if (!value) {
      return;
    }
    setRevealedSecret(value);
    secretModal.onOpen();
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
      showSecret(result.secret);
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
      notify(`已下发：TCP ${result.tunnels} 条 / HTTP ${http} 条`);
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
    return tooltip ? <Tooltip content={tooltip}>{chip}</Tooltip> : chip;
  };

  const messageCapabilityChip = (client: Client) => (
    <Tooltip
      content={
        client.messageReceiveCapable
          ? `附件 ${client.messageAttachmentsCapable ? "支持" : "不支持"} · 预览 ${client.messageMediaPreviewCapable ? "支持" : "不支持"}`
          : "该客户端未上报消息能力"
      }
    >
      <Chip size="sm" color={client.messageReceiveCapable ? "success" : "default"} variant="flat">
        {client.messageReceiveCapable ? "可聊天" : "不可聊天"}
      </Chip>
    </Tooltip>
  );

  const credentialPagination = useLocalPagination(credentials);
  const clientPagination = useLocalPagination(clients);

  return (
    <div className="mt-3 flex min-w-0 flex-col gap-5">
      <section className="min-w-0 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-lg font-semibold text-foreground">接入凭证</h2>
            <p className="text-small text-default-500">客户端启动只需要 serverBaseUrl、apiKey 和 secret；名称首次连接时自动生成，之后可在实例列表中修改。</p>
          </div>
          <Button className="w-full sm:w-auto" variant="flat" isLoading={loadingClients || loadingCredentials} onPress={() => void load()}>
            刷新
          </Button>
        </div>

        <form className="flex flex-wrap items-end gap-3" onSubmit={createCredential}>
          <Input className="w-full sm:w-64" label="apiKey" placeholder="留空自动生成" value={apiKey} onValueChange={setApiKey} />
          <Input className="w-full sm:w-56" label="secret" placeholder="留空自动生成" value={secret} onValueChange={setSecret} />
          <Input
            className="w-full sm:w-44"
            type="number"
            label="在线实例上限"
            min={1}
            max={10000}
            value={maxOnline}
            onValueChange={setMaxOnline}
            isInvalid={Boolean(maxOnlineError)}
            errorMessage={maxOnlineError}
          />
          <Button className="h-14 w-full sm:w-auto" type="submit" color="primary" isLoading={creating}>
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
                      <Button size="sm" variant="flat" onPress={() => openCredentialEdit(credential)}>
                        编辑
                      </Button>
                      <Button size="sm" color="danger" variant="flat" onPress={() => void removeCredential(credential)}>
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
        <Table aria-label="接入凭证列表" isHeaderSticky removeWrapper>
          <TableHeader>
            <TableColumn>ID</TableColumn>
            <TableColumn>apiKey</TableColumn>
            <TableColumn>归属</TableColumn>
            <TableColumn>状态</TableColumn>
            <TableColumn>在线实例上限</TableColumn>
            <TableColumn>创建时间</TableColumn>
            <TableColumn>操作</TableColumn>
          </TableHeader>
          <TableBody items={credentialPagination.paged} isLoading={loadingCredentials} emptyContent={<EmptyState icon="clients" title="暂无接入凭证" description="创建凭证后客户端即可接入" />}>
            {(credential) => (
              <TableRow key={credential.id}>
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
                    <Button size="sm" variant="flat" onPress={() => openCredentialEdit(credential)}>
                      编辑
                    </Button>
                    <Button size="sm" color="danger" variant="flat" onPress={() => removeCredential(credential)}>
                      删除
                    </Button>
                  </div>
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
        </div>
        {credentialPagination.pager}
      </section>

      <section className="min-w-0 space-y-3">
        <div>
          <h2 className="text-lg font-semibold text-foreground">客户端实例</h2>
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
                    { label: "每分钟上限", value: client.connectionRateLimitPerMinute || "不限" },
                    { label: "消息", value: messageCapabilityChip(client) },
                    { label: "上传", value: formatBytes(client.uploadBytes) },
                    { label: "下载", value: formatBytes(client.downloadBytes) },
                    { label: "创建时间", value: formatDateTime(client.createdAt) },
                  ]}
                  actions={
                    <>
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
                    </>
                  }
                />
              );
            }}
          />
        </div>

        {/* desktop: 表格 */}
        <div className="hidden min-w-0 overflow-x-auto lg:block">
        <Table aria-label="客户端实例列表" isHeaderSticky removeWrapper>
          <TableHeader>
            <TableColumn>ID</TableColumn>
            <TableColumn>客户端</TableColumn>
            <TableColumn>归属</TableColumn>
            <TableColumn>状态</TableColumn>
            <TableColumn>消息</TableColumn>
            <TableColumn>每分钟上限</TableColumn>
            <TableColumn>上传</TableColumn>
            <TableColumn>下载</TableColumn>
            <TableColumn>创建时间</TableColumn>
            <TableColumn>操作</TableColumn>
          </TableHeader>
          <TableBody items={clientPagination.paged} isLoading={loadingClients} emptyContent={<EmptyState icon="clients" title="暂无客户端实例" description="客户端首次登录后自动注册" />}>
            {(client) => (
              <TableRow key={client.id}>
                <TableCell>{client.id}</TableCell>
                <TableCell>{client.clientName}</TableCell>
                <TableCell>{client.ownerUsername || "-"}</TableCell>
                <TableCell>{statusChip(client)}</TableCell>
                <TableCell>{messageCapabilityChip(client)}</TableCell>
                <TableCell>{client.connectionRateLimitPerMinute || "不限"}</TableCell>
                <TableCell>{formatBytes(client.uploadBytes)}</TableCell>
                <TableCell>{formatBytes(client.downloadBytes)}</TableCell>
                <TableCell>{formatDateTime(client.createdAt)}</TableCell>
                <TableCell>
                  <div className="flex gap-2">
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
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
        </div>
        {clientPagination.pager}
      </section>

      <EditCredentialModal disclosure={credentialModal} credential={editingCredential} onSaved={(value) => {
        showSecret(value);
        void loadCredentials();
      }} />

      <EditClientModal disclosure={clientModal} client={editingClient} onSaved={() => void loadClients()} />

      <Modal isOpen={secretModal.isOpen} onOpenChange={secretModal.onOpenChange}>
        <ModalContent>
          {(onClose) => (
            <>
              <ModalHeader>客户端 secret（仅显示一次）</ModalHeader>
              <ModalBody>
                <Input value={revealedSecret} isReadOnly onFocus={(event) => event.target.select()} />
              </ModalBody>
              <ModalFooter>
                <Button
                  variant="flat"
                  onPress={() => void copyTextWithFeedback(revealedSecret)}
                >
                  复制
                </Button>
                <Button color="primary" onPress={onClose}>
                  我已保存
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
  onSaved: (secret?: string) => void;
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
  }, [credential]);

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
      onSaved(result.secret);
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
            <ModalBody className="gap-3">
              <Input label="apiKey" value={apiKey} onValueChange={setApiKey} isRequired />
              <Input label="secret" placeholder="留空保留原 secret" value={secret} onValueChange={setSecret} />
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
              <Switch isSelected={enabled} onValueChange={setEnabled}>
                启用
              </Switch>
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
            <ModalBody className="gap-3">
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
              <Switch isSelected={enabled} onValueChange={setEnabled}>
                启用
              </Switch>
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
