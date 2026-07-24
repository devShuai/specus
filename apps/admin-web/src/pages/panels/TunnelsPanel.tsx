import { useCallback, useEffect, useState, type FormEvent } from "react";
import {
  Button,
  Input,
  Modal,
  ModalBody,
  ModalContent,
  ModalFooter,
  ModalHeader,
  Pagination,
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
import { ConfirmModal } from "../../components/ConfirmModal";
import { EmptyState } from "../../components/EmptyState";
import { useClients } from "../../hooks/useClients";

const PAGE_SIZE = 10;

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
  const [pendingIds, setPendingIds] = useState<Set<number>>(new Set());
  const [confirm, setConfirm] = useState<{ title: string; description: string; action: () => Promise<void> } | null>(null);
  const [page, setPage] = useState(1);
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

  /** 乐观更新 + 失败回滚；切换期间该行开关禁用，避免整表刷新与连点竞态。 */
  const patchTunnel = async (tunnel: Tunnel, patch: Partial<Pick<Tunnel, "enabled" | "detailCaptureEnabled">>, errorMessage: string) => {
    if (pendingIds.has(tunnel.id)) {
      return;
    }
    setPendingIds((prev) => new Set(prev).add(tunnel.id));
    setTunnels((prev) => prev.map((item) => (item.id === tunnel.id ? { ...item, ...patch } : item)));
    try {
      await adminApi.updateTunnel(tunnel.id, {
        listenPort: tunnel.listenPort,
        targetAddress: tunnel.targetAddress,
        targetPort: tunnel.targetPort,
        enabled: patch.enabled ?? tunnel.enabled,
        detailCaptureEnabled: patch.detailCaptureEnabled ?? Boolean(tunnel.detailCaptureEnabled),
      });
    } catch (error) {
      setTunnels((prev) => prev.map((item) => (item.id === tunnel.id ? tunnel : item)));
      notifyError(error, errorMessage);
    } finally {
      setPendingIds((prev) => {
        const next = new Set(prev);
        next.delete(tunnel.id);
        return next;
      });
    }
  };

  const toggle = (tunnel: Tunnel) => patchTunnel(tunnel, { enabled: !tunnel.enabled }, "切换状态失败");

  const toggleDetailCapture = (tunnel: Tunnel) =>
    patchTunnel(tunnel, { detailCaptureEnabled: !Boolean(tunnel.detailCaptureEnabled) }, "切换明细采集失败");

  const remove = (tunnel: Tunnel) => {
    setConfirm({
      title: "删除端口映射",
      description: `确定删除端口映射 :${tunnel.listenPort} → ${tunnel.targetAddress}:${tunnel.targetPort} 吗？删除后立即停止转发。`,
      action: async () => {
        try {
          await adminApi.deleteTunnel(tunnel.id);
          notify("端口映射已删除");
          await load();
        } catch (error) {
          notifyError(error, "删除失败");
        }
      },
    });
  };

  const totalPages = Math.max(1, Math.ceil(tunnels.length / PAGE_SIZE));
  const safePage = Math.min(page, totalPages);
  const pagedTunnels = tunnels.slice((safePage - 1) * PAGE_SIZE, safePage * PAGE_SIZE);

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
        <Button className="h-14 w-full sm:w-auto" variant="flat" isLoading={loading} onPress={() => void load()}>
          刷新
        </Button>
      </form>

      {/* mobile: 卡片 */}
      <div className="lg:hidden">
        <MobileListCardList
          items={pagedTunnels}
          isLoading={loading}
          emptyContent={<EmptyState icon="connections" title="暂无端口映射" description="创建映射后公网端口将转发到内网目标" />}
          renderCard={(raw) => {
            const tunnel = raw as Tunnel;
            const pending = pendingIds.has(tunnel.id);
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
                    <Switch
                      size="sm"
                      isSelected={tunnel.enabled}
                      isDisabled={pending}
                      onValueChange={() => void toggle(tunnel)}
                    >
                      启用
                    </Switch>
                    <Switch
                      size="sm"
                      isSelected={Boolean(tunnel.detailCaptureEnabled)}
                      isDisabled={pending}
                      onValueChange={() => void toggleDetailCapture(tunnel)}
                    >
                      明细采集
                    </Switch>
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
                    <Button size="sm" color="danger" variant="flat" onPress={() => remove(tunnel)}>
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
          <TableColumn>启用</TableColumn>
          <TableColumn>明细采集</TableColumn>
          <TableColumn>更新时间</TableColumn>
          <TableColumn>操作</TableColumn>
        </TableHeader>
        <TableBody items={pagedTunnels} isLoading={loading} emptyContent={<EmptyState icon="connections" title="暂无端口映射" description="创建映射后公网端口将转发到内网目标" />}>
          {(tunnel) => {
            const pending = pendingIds.has(tunnel.id);
            return (
            <TableRow key={tunnel.id}>
              <TableCell>{tunnel.id}</TableCell>
              <TableCell>{tunnel.clientName}</TableCell>
              <TableCell>{tunnel.listenPort}</TableCell>
              <TableCell>
                <code>{tunnel.targetAddress}:{tunnel.targetPort}</code>
              </TableCell>
              <TableCell>
                <Switch
                  aria-label="启用"
                  size="sm"
                  isSelected={tunnel.enabled}
                  isDisabled={pending}
                  onValueChange={() => void toggle(tunnel)}
                />
              </TableCell>
              <TableCell>
                <Switch
                  aria-label="明细采集"
                  size="sm"
                  isSelected={Boolean(tunnel.detailCaptureEnabled)}
                  isDisabled={pending}
                  onValueChange={() => void toggleDetailCapture(tunnel)}
                />
              </TableCell>
              <TableCell>{formatDateTime(tunnel.updatedAt || tunnel.createdAt)}</TableCell>
              <TableCell>
                <div className="flex gap-2">
                  <Button size="sm" variant="flat" onPress={() => { setEditing(tunnel); editModal.onOpen(); }}>
                    编辑
                  </Button>
                  <Button size="sm" color="danger" variant="flat" onPress={() => remove(tunnel)}>
                    删除
                  </Button>
                </div>
              </TableCell>
            </TableRow>
            );
          }}
        </TableBody>
      </Table>
      </div>

      {totalPages > 1 ? (
        <div className="flex justify-end">
          <Pagination showControls page={safePage} total={totalPages} onChange={setPage} />
        </div>
      ) : null}

      <EditTunnelModal disclosure={editModal} tunnel={editing} onSaved={() => void load()} />
      <ConfirmModal
        isOpen={confirm != null}
        onClose={() => setConfirm(null)}
        onConfirm={() => confirm?.action()}
        title={confirm?.title ?? ""}
        description={confirm?.description}
        confirmLabel="删除"
        danger
      />
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
