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
import { notify, notifyError } from "../../components/toast";
import { useNowTick } from "../../hooks/useNowTick";
import { MobileListCard, MobileListCardList } from "../../components/MobileListCard";

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
  const now = useNowTick(1000);
  const durationTick = Math.floor(now / 1000);

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

  const createCredential = async (event: FormEvent) => {
    event.preventDefault();
    setCreating(true);
    try {
      const result = await adminApi.createClientCredential({
        apiKey: apiKey.trim() || undefined,
        secret: secret.trim() || null,
        maxOnlineInstances: Number(maxOnline) || 2,
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

  const removeClient = async (client: Client) => {
    if (!window.confirm(`确定删除客户端实例「${client.clientName}」吗？历史连接和流量记录会保留。`)) {
      return;
    }
    try {
      await adminApi.deleteClient(client.id);
      notify("客户端实例已删除");
      await loadClients();
    } catch (error) {
      notifyError(error, "删除失败");
    }
  };

  const removeCredential = async (credential: ClientCredential) => {
    if (!window.confirm(`确定删除接入凭证「${credential.apiKey}」吗？使用它的客户端将无法继续登录。`)) {
      return;
    }
    try {
      await adminApi.deleteClientCredential(credential.id);
      notify("接入凭证已删除");
      await loadCredentials();
    } catch (error) {
      notifyError(error, "删除失败");
    }
  };

  const statusChip = (client: Client) => {
    const since = client.online && client.connectedSinceMs ? formatSince(client.connectedSinceMs, now) : "";
    const text = `${client.online ? "在线" : "离线"} / ${client.enabled ? "启用" : "停用"}${since ? ` · ${since}` : ""}`;
    const tooltip = client.online && client.connectedSinceMs
      ? `登录于 ${formatDateTime(new Date(client.connectedSinceMs).toISOString())}`
      : undefined;
    const chip = (
      <Chip size="sm" color={client.online ? "success" : "default"} variant="flat">
        {text}
      </Chip>
    );
    return tooltip ? <Tooltip content={tooltip}>{chip}</Tooltip> : chip;
  };

  return (
    <div className="mt-3 flex min-w-0 flex-col gap-5">
      <section className="min-w-0 space-y-3">
        <div className="flex flex-wrap items-end justify-between gap-3">
          <div>
            <h2 className="text-lg font-semibold text-foreground">接入凭证</h2>
            <p className="text-small text-default-500">客户端启动只需要 serverBaseUrl、apiKey 和 secret，clientName 由服务端按机器自动分配。</p>
          </div>
          <Button className="w-full sm:w-auto" variant="flat" onPress={() => void load()}>
            刷新
          </Button>
        </div>

        <form className="flex flex-wrap items-end gap-3" onSubmit={createCredential}>
          <Input className="w-full sm:w-64" label="apiKey" placeholder="留空自动生成" value={apiKey} onValueChange={setApiKey} />
          <Input className="w-full sm:w-56" label="secret" placeholder="留空自动生成" value={secret} onValueChange={setSecret} />
          <Input className="w-full sm:w-44" type="number" label="在线实例上限" min={1} max={10000} value={maxOnline} onValueChange={setMaxOnline} />
          <Button className="w-full sm:w-auto" type="submit" color="primary" isLoading={creating}>
            新建接入凭证
          </Button>
        </form>

        {/* mobile: 卡片 */}
        <div className="lg:hidden">
          <MobileListCardList
            items={credentials}
            isLoading={loadingCredentials}
            emptyContent="暂无接入凭证"
            renderCard={(raw) => {
              const credential = raw as ClientCredential;
              return (
                <MobileListCard
                  key={credential.id}
                  title={<span className="break-all font-mono">{credential.apiKey}</span>}
                  subtitle={`${credential.ownerUsername || "-"} · #${credential.id}`}
                  badges={
                    <Chip size="sm" variant="flat" color={credential.enabled ? "success" : "default"}>
                      {credential.enabled ? "启用" : "停用"}
                    </Chip>
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
          <TableBody items={credentials} isLoading={loadingCredentials} emptyContent="暂无接入凭证">
            {(credential) => (
              <TableRow key={credential.id}>
                <TableCell>{credential.id}</TableCell>
                <TableCell className="font-mono">{credential.apiKey}</TableCell>
                <TableCell>{credential.ownerUsername || "-"}</TableCell>
                <TableCell>
                  <Chip size="sm" color={credential.enabled ? "success" : "default"} variant="flat">
                    {credential.enabled ? "启用" : "停用"}
                  </Chip>
                </TableCell>
                <TableCell>{credential.maxOnlineInstances}</TableCell>
                <TableCell>{formatDateTime(credential.createdAt)}</TableCell>
                <TableCell>
                  <div className="flex gap-2">
                    <Button size="sm" variant="flat" onPress={() => openCredentialEdit(credential)}>
                      编辑
                    </Button>
                    <Button size="sm" color="danger" variant="flat" onPress={() => void removeCredential(credential)}>
                      删除
                    </Button>
                  </div>
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
        </div>
      </section>

      <section className="min-w-0 space-y-3">
        <div>
          <h2 className="text-lg font-semibold text-foreground">客户端实例</h2>
          <p className="text-small text-default-500">实例由客户端首次登录后注册，名称由机器指纹和系统用户生成。</p>
        </div>

        {/* mobile: 卡片 */}
        <div className="lg:hidden">
          <MobileListCardList
            items={clients}
            isLoading={loadingClients}
            emptyContent="暂无客户端实例"
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
                    { label: "上传", value: formatBytes(client.uploadBytes) },
                    { label: "下载", value: formatBytes(client.downloadBytes) },
                    { label: "创建时间", value: formatDateTime(client.createdAt) },
                  ]}
                  actions={
                    <>
                      <Button size="sm" variant="flat" onPress={() => openClientEdit(client)}>
                        编辑
                      </Button>
                      <Button size="sm" variant="flat" onPress={() => void pushNat(client)}>
                        下发映射
                      </Button>
                      <Button size="sm" color="danger" variant="flat" onPress={() => void removeClient(client)}>
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
        <Table key={`clients-${durationTick}`} aria-label="客户端实例列表" isHeaderSticky removeWrapper>
          <TableHeader>
            <TableColumn>ID</TableColumn>
            <TableColumn>客户端</TableColumn>
            <TableColumn>归属</TableColumn>
            <TableColumn>状态</TableColumn>
            <TableColumn>每分钟上限</TableColumn>
            <TableColumn>上传</TableColumn>
            <TableColumn>下载</TableColumn>
            <TableColumn>创建时间</TableColumn>
            <TableColumn>操作</TableColumn>
          </TableHeader>
          <TableBody items={clients} isLoading={loadingClients} emptyContent="暂无客户端实例">
            {(client) => (
              <TableRow key={client.id}>
                <TableCell>{client.id}</TableCell>
                <TableCell>{client.clientName}</TableCell>
                <TableCell>{client.ownerUsername || "-"}</TableCell>
                <TableCell>{statusChip(client)}</TableCell>
                <TableCell>{client.connectionRateLimitPerMinute || "不限"}</TableCell>
                <TableCell>{formatBytes(client.uploadBytes)}</TableCell>
                <TableCell>{formatBytes(client.downloadBytes)}</TableCell>
                <TableCell>{formatDateTime(client.createdAt)}</TableCell>
                <TableCell>
                  <div className="flex gap-2">
                    <Button size="sm" variant="flat" onPress={() => openClientEdit(client)}>
                      编辑
                    </Button>
                    <Button size="sm" variant="flat" onPress={() => void pushNat(client)}>
                      下发映射
                    </Button>
                    <Button size="sm" color="danger" variant="flat" onPress={() => void removeClient(client)}>
                      删除
                    </Button>
                  </div>
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
        </div>
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
                <Input value={revealedSecret} isReadOnly />
              </ModalBody>
              <ModalFooter>
                <Button
                  variant="flat"
                  onPress={() => {
                    void navigator.clipboard?.writeText(revealedSecret);
                    notify("已复制");
                  }}
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

  const save = async () => {
    if (!credential) {
      return;
    }
    setSaving(true);
    try {
      const result = await adminApi.updateClientCredential(credential.id, {
        apiKey: apiKey.trim(),
        secret: secret.trim() || null,
        enabled,
        maxOnlineInstances: Number(maxOnline) || 2,
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
              <Input type="number" label="在线实例上限" min={1} max={10000} value={maxOnline} onValueChange={setMaxOnline} />
              <Switch isSelected={enabled} onValueChange={setEnabled}>
                启用
              </Switch>
            </ModalBody>
            <ModalFooter>
              <Button variant="flat" onPress={onClose}>
                取消
              </Button>
              <Button color="primary" isLoading={saving} onPress={() => void save()}>
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
  const [rate, setRate] = useState("30");
  const [enabled, setEnabled] = useState(true);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (client) {
      setRate(String(client.connectionRateLimitPerMinute));
      setEnabled(client.enabled);
    }
  }, [client]);

  const save = async () => {
    if (!client) {
      return;
    }
    setSaving(true);
    try {
      await adminApi.updateClient(client.id, {
        enabled,
        connectionRateLimitPerMinute: Number(rate) || 0,
      });
      notify("客户端实例已更新");
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
                type="number"
                label="每分钟连接上限（0 = 不限）"
                value={rate}
                onValueChange={setRate}
                min={0}
                max={10000}
              />
              <Switch isSelected={enabled} onValueChange={setEnabled}>
                启用
              </Switch>
            </ModalBody>
            <ModalFooter>
              <Button variant="flat" onPress={onClose}>
                取消
              </Button>
              <Button color="primary" isLoading={saving} onPress={() => void save()}>
                保存
              </Button>
            </ModalFooter>
          </>
        )}
      </ModalContent>
    </Modal>
  );
}
