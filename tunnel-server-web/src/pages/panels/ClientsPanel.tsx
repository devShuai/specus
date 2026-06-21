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
import type { Client } from "../../api/types";
import { formatBytes, formatDateTime, formatSince } from "../../lib/format";
import { notify, notifyError } from "../../components/toast";
import { useNowTick } from "../../hooks/useNowTick";

export function ClientsPanel() {
  const [clients, setClients] = useState<Client[]>([]);
  const [loading, setLoading] = useState(true);
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [rate, setRate] = useState("30");
  const [creating, setCreating] = useState(false);

  const [editing, setEditing] = useState<Client | null>(null);
  const editModal = useDisclosure();
  const [revealed, setRevealed] = useState<string | null>(null);
  const passwordModal = useDisclosure();

  useNowTick(1000); // refresh online durations once per second

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setClients(await adminApi.listClients());
    } catch (error) {
      notifyError(error, "加载客户端失败");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const showPassword = (value: string) => {
    setRevealed(value);
    passwordModal.onOpen();
  };

  const onCreate = async (event: FormEvent) => {
    event.preventDefault();
    if (!name.trim()) {
      notify("请填写客户端名称", "error");
      return;
    }
    setCreating(true);
    try {
      const result = await adminApi.createClient({
        clientName: name.trim(),
        password: password.trim() || null,
        connectionRateLimitPerMinute: Number(rate) || 0,
        enabled: true,
      });
      setName("");
      setPassword("");
      setRate("30");
      if (result.password) {
        showPassword(result.password);
      }
      notify("客户端已创建");
      await load();
    } catch (error) {
      notifyError(error, "创建失败");
    } finally {
      setCreating(false);
    }
  };

  const openEdit = (client: Client) => {
    setEditing(client);
    editModal.onOpen();
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

  const remove = async (client: Client) => {
    if (!window.confirm(`确定删除客户端「${client.clientName}」吗？历史连接和流量记录会保留。`)) {
      return;
    }
    try {
      await adminApi.deleteClient(client.id);
      notify("客户端已删除");
      await load();
    } catch (error) {
      notifyError(error, "删除失败");
    }
  };

  const statusChip = (client: Client) => {
    const online = client.online;
    const since = online && client.connectedSinceMs ? formatSince(client.connectedSinceMs) : "";
    const text = `${online ? "在线" : "离线"} / ${client.enabled ? "启用" : "停用"}${since ? ` · ${since}` : ""}`;
    const tooltip = online && client.connectedSinceMs ? `登录于 ${formatDateTime(new Date(client.connectedSinceMs).toISOString())}` : undefined;
    const chip = (
      <Chip size="sm" color={online ? "success" : "default"} variant="flat">
        {text}
      </Chip>
    );
    return tooltip ? <Tooltip content={tooltip}>{chip}</Tooltip> : chip;
  };

  return (
    <div className="mt-4 flex flex-col gap-4">
      <form className="flex flex-wrap items-end gap-3" onSubmit={onCreate}>
        <Input className="w-48" label="客户端名称" value={name} onValueChange={setName} isRequired />
        <Input
          className="w-48"
          label="密码"
          placeholder="留空自动生成"
          value={password}
          onValueChange={setPassword}
        />
        <Input
          className="w-40"
          type="number"
          label="每分钟连接上限"
          value={rate}
          onValueChange={setRate}
          min={0}
          max={10000}
        />
        <Button type="submit" color="primary" isLoading={creating}>
          新建客户端
        </Button>
        <Button variant="flat" onPress={() => void load()}>
          刷新
        </Button>
      </form>

      <Table aria-label="客户端列表" isHeaderSticky removeWrapper>
        <TableHeader>
          <TableColumn>ID</TableColumn>
          <TableColumn>客户端</TableColumn>
          <TableColumn>状态</TableColumn>
          <TableColumn>每分钟上限</TableColumn>
          <TableColumn>上传</TableColumn>
          <TableColumn>下载</TableColumn>
          <TableColumn>创建时间</TableColumn>
          <TableColumn>操作</TableColumn>
        </TableHeader>
        <TableBody
          items={clients}
          isLoading={loading}
          emptyContent="暂无数据"
        >
          {(client) => (
            <TableRow key={client.id}>
              <TableCell>{client.id}</TableCell>
              <TableCell>{client.clientName}</TableCell>
              <TableCell>{statusChip(client)}</TableCell>
              <TableCell>{client.connectionRateLimitPerMinute || "不限"}</TableCell>
              <TableCell>{formatBytes(client.uploadBytes)}</TableCell>
              <TableCell>{formatBytes(client.downloadBytes)}</TableCell>
              <TableCell>{formatDateTime(client.createdAt)}</TableCell>
              <TableCell>
                <div className="flex gap-2">
                  <Button size="sm" variant="flat" onPress={() => openEdit(client)}>
                    编辑
                  </Button>
                  <Button size="sm" variant="flat" onPress={() => void pushNat(client)}>
                    下发映射
                  </Button>
                  <Button size="sm" color="danger" variant="flat" onPress={() => void remove(client)}>
                    删除
                  </Button>
                </div>
              </TableCell>
            </TableRow>
          )}
        </TableBody>
      </Table>

      <EditClientModal
        disclosure={editModal}
        client={editing}
        onSaved={(pwd) => {
          if (pwd) {
            showPassword(pwd);
          }
          void load();
        }}
      />

      <Modal isOpen={passwordModal.isOpen} onOpenChange={passwordModal.onOpenChange}>
        <ModalContent>
          {(onClose) => (
            <>
              <ModalHeader>客户端密码（仅显示一次）</ModalHeader>
              <ModalBody>
                <Input value={revealed ?? ""} isReadOnly />
              </ModalBody>
              <ModalFooter>
                <Button
                  variant="flat"
                  onPress={() => {
                    if (revealed) {
                      void navigator.clipboard?.writeText(revealed);
                      notify("已复制");
                    }
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

interface EditClientModalProps {
  disclosure: ReturnType<typeof useDisclosure>;
  client: Client | null;
  onSaved: (password?: string) => void;
}

function EditClientModal({ disclosure, client, onSaved }: EditClientModalProps) {
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [rate, setRate] = useState("30");
  const [enabled, setEnabled] = useState(true);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (client) {
      setName(client.clientName);
      setPassword("");
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
      const result = await adminApi.updateClient(client.id, {
        clientName: name.trim(),
        password: password.trim() || null,
        connectionRateLimitPerMinute: Number(rate) || 0,
        enabled,
      });
      notify("客户端已更新");
      disclosure.onClose();
      onSaved(result.password);
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
            <ModalHeader>编辑客户端「{client?.clientName}」</ModalHeader>
            <ModalBody className="gap-3">
              <Input label="客户端名称" value={name} onValueChange={setName} maxLength={64} isRequired />
              <Input
                label="密码"
                placeholder="留空保留原密码"
                value={password}
                onValueChange={setPassword}
              />
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
