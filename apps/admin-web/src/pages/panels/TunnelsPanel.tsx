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
  Select,
  SelectItem,
  Switch,
  Table,
  TableBody,
  TableCell,
  TableColumn,
  TableHeader,
  TableRow,
  useDisclosure,
} from "@heroui/react";
import { adminApi } from "../../api/client";
import type { Tunnel } from "../../api/types";
import { formatDateTime } from "../../lib/format";
import { notify, notifyError } from "../../components/toast";
import { MobileListCard, MobileListCardList } from "../../components/MobileListCard";
import { useClients } from "../../hooks/useClients";

export function TunnelsPanel() {
  const { clients } = useClients();
  const [tunnels, setTunnels] = useState<Tunnel[]>([]);
  const [loading, setLoading] = useState(true);
  const [clientId, setClientId] = useState("");
  const [listenPort, setListenPort] = useState("");
  const [targetAddress, setTargetAddress] = useState("");
  const [targetPort, setTargetPort] = useState("");
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<Tunnel | null>(null);
  const editModal = useDisclosure();

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setTunnels(await adminApi.listTunnels());
    } catch (error) {
      notifyError(error, "加载端口映射失败");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const onCreate = async (event: FormEvent) => {
    event.preventDefault();
    if (!clientId) {
      notify("请先选择客户端", "error");
      return;
    }
    setCreating(true);
    try {
      await adminApi.createTunnel(Number(clientId), {
        listenPort: Number(listenPort),
        targetAddress: targetAddress.trim(),
        targetPort: Number(targetPort),
        enabled: true,
        detailCaptureEnabled: false,
      });
      setListenPort("");
      setTargetAddress("");
      setTargetPort("");
      notify("端口映射已创建");
      await load();
    } catch (error) {
      notifyError(error, "创建失败");
    } finally {
      setCreating(false);
    }
  };

  const toggle = async (tunnel: Tunnel) => {
    try {
      await adminApi.updateTunnel(tunnel.id, {
        listenPort: tunnel.listenPort,
        targetAddress: tunnel.targetAddress,
        targetPort: tunnel.targetPort,
        enabled: !tunnel.enabled,
        detailCaptureEnabled: Boolean(tunnel.detailCaptureEnabled),
      });
      await load();
    } catch (error) {
      notifyError(error, "切换状态失败");
    }
  };

  const toggleDetailCapture = async (tunnel: Tunnel) => {
    try {
      await adminApi.updateTunnel(tunnel.id, {
        listenPort: tunnel.listenPort,
        targetAddress: tunnel.targetAddress,
        targetPort: tunnel.targetPort,
        enabled: tunnel.enabled,
        detailCaptureEnabled: !Boolean(tunnel.detailCaptureEnabled),
      });
      await load();
    } catch (error) {
      notifyError(error, "切换明细采集失败");
    }
  };

  const remove = async (tunnel: Tunnel) => {
    if (!window.confirm("确定删除该端口映射？")) {
      return;
    }
    try {
      await adminApi.deleteTunnel(tunnel.id);
      notify("端口映射已删除");
      await load();
    } catch (error) {
      notifyError(error, "删除失败");
    }
  };

  return (
    <div className="mt-4 flex min-w-0 flex-col gap-4">
      <form className="flex flex-wrap items-end gap-3" onSubmit={onCreate}>
        <Select
          className="w-full sm:w-48"
          label="客户端"
          selectedKeys={clientId ? [clientId] : []}
          onChange={(event) => setClientId(event.target.value)}
          isRequired
        >
          {clients.map((client) => (
            <SelectItem key={String(client.id)}>{client.clientName}</SelectItem>
          ))}
        </Select>
        <Input className="w-full sm:w-32" type="number" label="公网端口" value={listenPort} onValueChange={setListenPort} min={1} max={65535} isRequired />
        <Input className="w-full sm:w-44" label="内网目标地址" placeholder="127.0.0.1" value={targetAddress} onValueChange={setTargetAddress} isRequired />
        <Input className="w-full sm:w-32" type="number" label="内网端口" value={targetPort} onValueChange={setTargetPort} min={1} max={65535} isRequired />
        <Button className="h-14 w-full sm:w-auto" type="submit" color="primary" isLoading={creating}>
          新建映射
        </Button>
        <Button className="h-14 w-full sm:w-auto" variant="flat" onPress={() => void load()}>
          刷新
        </Button>
      </form>

      {/* mobile: 卡片 */}
      <div className="lg:hidden">
        <MobileListCardList
          items={tunnels}
          isLoading={loading}
          emptyContent="暂无数据"
          renderCard={(raw) => {
            const tunnel = raw as Tunnel;
            return (
              <MobileListCard
                key={tunnel.id}
                title={
                  <div className="flex items-center gap-2">
                    <code className="break-all">:{tunnel.listenPort} → {tunnel.targetAddress}:{tunnel.targetPort}</code>
                  </div>
                }
                subtitle={`${tunnel.clientName} · #${tunnel.id}`}
                badges={
                  <>
                    <Chip
                      size="sm"
                      variant="flat"
                      color={tunnel.enabled ? "success" : "warning"}
                      className="cursor-pointer"
                      onClick={() => void toggle(tunnel)}
                    >
                      {tunnel.enabled ? "启用" : "停用"}
                    </Chip>
                    <Chip
                      size="sm"
                      variant="flat"
                      color={tunnel.detailCaptureEnabled ? "primary" : "default"}
                      className="cursor-pointer"
                      onClick={() => void toggleDetailCapture(tunnel)}
                    >
                      {tunnel.detailCaptureEnabled ? "采集" : "采集关"}
                    </Chip>
                  </>
                }
                fields={[
                  { label: "更新时间", value: formatDateTime(tunnel.updatedAt || tunnel.createdAt) },
                ]}
                actions={
                  <>
                    <Button size="sm" variant="flat" onPress={() => { setEditing(tunnel); editModal.onOpen(); }}>
                      编辑
                    </Button>
                    <Button size="sm" color="danger" variant="flat" onPress={() => void remove(tunnel)}>
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
      <Table aria-label="端口映射列表" isHeaderSticky removeWrapper>
        <TableHeader>
          <TableColumn>ID</TableColumn>
          <TableColumn>客户端</TableColumn>
          <TableColumn>公网端口</TableColumn>
          <TableColumn>内网目标</TableColumn>
          <TableColumn>状态</TableColumn>
          <TableColumn>明细采集</TableColumn>
          <TableColumn>更新时间</TableColumn>
          <TableColumn>操作</TableColumn>
        </TableHeader>
        <TableBody items={tunnels} isLoading={loading} emptyContent="暂无数据">
          {(tunnel) => (
            <TableRow key={tunnel.id}>
              <TableCell>{tunnel.id}</TableCell>
              <TableCell>{tunnel.clientName}</TableCell>
              <TableCell>{tunnel.listenPort}</TableCell>
              <TableCell>
                <code>{tunnel.targetAddress}:{tunnel.targetPort}</code>
              </TableCell>
              <TableCell>
                <Chip
                  size="sm"
                  variant="flat"
                  color={tunnel.enabled ? "success" : "warning"}
                  className="cursor-pointer"
                  onClick={() => void toggle(tunnel)}
                >
                  {tunnel.enabled ? "启用" : "停用"}
                </Chip>
              </TableCell>
              <TableCell>
                <Chip
                  size="sm"
                  variant="flat"
                  color={tunnel.detailCaptureEnabled ? "primary" : "default"}
                  className="cursor-pointer"
                  onClick={() => void toggleDetailCapture(tunnel)}
                >
                  {tunnel.detailCaptureEnabled ? "采集" : "关闭"}
                </Chip>
              </TableCell>
              <TableCell>{formatDateTime(tunnel.updatedAt || tunnel.createdAt)}</TableCell>
              <TableCell>
                <div className="flex gap-2">
                  <Button size="sm" variant="flat" onPress={() => { setEditing(tunnel); editModal.onOpen(); }}>
                    编辑
                  </Button>
                  <Button size="sm" color="danger" variant="flat" onPress={() => void remove(tunnel)}>
                    删除
                  </Button>
                </div>
              </TableCell>
            </TableRow>
          )}
        </TableBody>
      </Table>
      </div>

      <EditTunnelModal disclosure={editModal} tunnel={editing} onSaved={() => void load()} />
    </div>
  );
}

interface EditTunnelModalProps {
  disclosure: ReturnType<typeof useDisclosure>;
  tunnel: Tunnel | null;
  onSaved: () => void;
}

function EditTunnelModal({ disclosure, tunnel, onSaved }: EditTunnelModalProps) {
  const [listenPort, setListenPort] = useState("");
  const [targetAddress, setTargetAddress] = useState("");
  const [targetPort, setTargetPort] = useState("");
  const [enabled, setEnabled] = useState(true);
  const [detailCaptureEnabled, setDetailCaptureEnabled] = useState(false);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (tunnel) {
      setListenPort(String(tunnel.listenPort));
      setTargetAddress(tunnel.targetAddress);
      setTargetPort(String(tunnel.targetPort));
      setEnabled(tunnel.enabled);
      setDetailCaptureEnabled(Boolean(tunnel.detailCaptureEnabled));
    }
  }, [tunnel]);

  const save = async () => {
    if (!tunnel) {
      return;
    }
    setSaving(true);
    try {
      await adminApi.updateTunnel(tunnel.id, {
        listenPort: Number(listenPort),
        targetAddress: targetAddress.trim(),
        targetPort: Number(targetPort),
        enabled,
        detailCaptureEnabled,
      });
      notify("端口映射已更新");
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
            <ModalHeader>编辑端口映射 #{tunnel?.id}</ModalHeader>
            <ModalBody className="gap-3">
              <Input type="number" label="公网端口" value={listenPort} onValueChange={setListenPort} min={1} max={65535} isRequired />
              <Input label="内网目标地址" value={targetAddress} onValueChange={setTargetAddress} maxLength={255} isRequired />
              <Input type="number" label="内网端口" value={targetPort} onValueChange={setTargetPort} min={1} max={65535} isRequired />
              <Switch isSelected={enabled} onValueChange={setEnabled}>
                启用
              </Switch>
              <Switch isSelected={detailCaptureEnabled} onValueChange={setDetailCaptureEnabled}>
                明细采集
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
