import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Button, Input, Label, ListBox, ListBoxItem, Modal, Select, SelectIndicator, SelectPopover, SelectTrigger, SelectValue, Spinner, Switch, Table, TableBody, TableCell, TableColumn, TableContent, TableHeader, TableRow, TextField, useOverlayState } from "@heroui/react";
import { Pager } from "../../components/Pager";
import { adminApi } from "../../api/client";
import type { Specus } from "../../api/types";
import { formatDateTime } from "../../lib/format";
import { notify, notifyError } from "../../components/toast";
import { MobileListCard, MobileListCardList } from "../../components/MobileListCard";
import { ConfirmModal } from "../../components/ConfirmModal";
import { EmptyState } from "../../components/EmptyState";
import { useClients } from "../../hooks/useClients";

const PAGE_SIZE = 10;

export function SpecusMappingsPanel() {
  const { clients } = useClients();
  const [specusMappings, setSpecusMappings] = useState<Specus[]>([]);
  const [loading, setLoading] = useState(true);
  const [clientId, setClientId] = useState("");
  const [listenPort, setListenPort] = useState("");
  const [targetAddress, setTargetAddress] = useState("");
  const [targetPort, setTargetPort] = useState("");
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<Specus | null>(null);
  const [pendingIds, setPendingIds] = useState<Set<number>>(new Set());
  const [confirm, setConfirm] = useState<{ title: string; description: string; action: () => Promise<void> } | null>(null);
  const [page, setPage] = useState(1);
  const editModal = useOverlayState();

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setSpecusMappings(await adminApi.listSpecusMappings());
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
      await adminApi.createSpecus(Number(clientId), {
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
  const patchSpecus = async (specus: Specus, patch: Partial<Pick<Specus, "enabled" | "detailCaptureEnabled">>, errorMessage: string) => {
    if (pendingIds.has(specus.id)) {
      return;
    }
    setPendingIds((prev) => new Set(prev).add(specus.id));
    setSpecusMappings((prev) => prev.map((item) => (item.id === specus.id ? { ...item, ...patch } : item)));
    try {
      await adminApi.updateSpecus(specus.id, {
        listenPort: specus.listenPort,
        targetAddress: specus.targetAddress,
        targetPort: specus.targetPort,
        enabled: patch.enabled ?? specus.enabled,
        detailCaptureEnabled: patch.detailCaptureEnabled ?? Boolean(specus.detailCaptureEnabled),
      });
    } catch (error) {
      setSpecusMappings((prev) => prev.map((item) => (item.id === specus.id ? specus : item)));
      notifyError(error, errorMessage);
    } finally {
      setPendingIds((prev) => {
        const next = new Set(prev);
        next.delete(specus.id);
        return next;
      });
    }
  };

  const toggle = (specus: Specus) => patchSpecus(specus, { enabled: !specus.enabled }, "切换状态失败");

  const toggleDetailCapture = (specus: Specus) =>
    patchSpecus(specus, { detailCaptureEnabled: !Boolean(specus.detailCaptureEnabled) }, "切换明细采集失败");

  const remove = (specus: Specus) => {
    setConfirm({
      title: "删除端口映射",
      description: `确定删除端口映射 :${specus.listenPort} → ${specus.targetAddress}:${specus.targetPort} 吗？删除后立即停止转发。`,
      action: async () => {
        try {
          await adminApi.deleteSpecus(specus.id);
          notify("端口映射已删除");
          await load();
        } catch (error) {
          notifyError(error, "删除失败");
        }
      },
    });
  };

  const totalPages = Math.max(1, Math.ceil(specusMappings.length / PAGE_SIZE));
  const safePage = Math.min(page, totalPages);
  const pagedSpecusMappings = specusMappings.slice((safePage - 1) * PAGE_SIZE, safePage * PAGE_SIZE);

  return (
    <div className="mt-4 flex min-w-0 flex-col gap-4">
      <form className="flex flex-wrap items-end gap-3" onSubmit={onCreate}>
        <Select
          className="w-full sm:w-48"
          isRequired selectedKey={clientId || null} onSelectionChange={(event) => setClientId(String(event ?? ""))}>
          <Label>客户端</Label>
          <SelectTrigger>
            <SelectValue />
            <SelectIndicator />
          </SelectTrigger>
          <SelectPopover>
            <ListBox>
              {clients.map((client) => (
            <ListBoxItem key={String(client.id)} id={String(client.id)}>{client.clientName}</ListBoxItem>
          ))}
            </ListBox>
          </SelectPopover>
        </Select>
        <TextField value={listenPort} onChange={setListenPort} isRequired type="number" className="w-full sm:w-32">
          <Label>公网端口</Label>
          <Input min={1} max={65535} />
        </TextField>
        <TextField value={targetAddress} onChange={setTargetAddress} isRequired className="w-full sm:w-44">
          <Label>内网目标地址</Label>
          <Input placeholder="127.0.0.1" />
        </TextField>
        <TextField value={targetPort} onChange={setTargetPort} isRequired type="number" className="w-full sm:w-32">
          <Label>内网端口</Label>
          <Input min={1} max={65535} />
        </TextField>
        <Button variant="primary" className="h-14 w-full sm:w-auto" type="submit" isDisabled={creating}>{creating ? <Spinner size="sm" /> : null}
          新建映射
        </Button>
        <Button className="h-14 w-full sm:w-auto" variant="secondary" onPress={() => void load()} isDisabled={loading}>{loading ? <Spinner size="sm" /> : null}
          刷新
        </Button>
      </form>

      {/* mobile: 卡片 */}
      <div className="lg:hidden">
        <MobileListCardList
          items={pagedSpecusMappings}
          isLoading={loading}
          emptyContent={<EmptyState icon="connections" title="暂无端口映射" description="创建映射后公网端口将转发到内网目标" />}
          renderCard={(raw) => {
            const specus = raw as Specus;
            const pending = pendingIds.has(specus.id);
            return (
              <MobileListCard
                key={specus.id}
                title={
                  <div className="flex items-center gap-2">
                    <code className="break-all">:{specus.listenPort} → {specus.targetAddress}:{specus.targetPort}</code>
                  </div>
                }
                subtitle={`${specus.clientName} · #${specus.id}`}
                badges={
                  <>
                    <Switch
                      isSelected={specus.enabled}
                      isDisabled={pending}
                      onChange={() => void toggle(specus)}
                    >
                      启用
                    </Switch>
                    <Switch
                      isSelected={Boolean(specus.detailCaptureEnabled)}
                      isDisabled={pending}
                      onChange={() => void toggleDetailCapture(specus)}
                    >
                      明细采集
                    </Switch>
                  </>
                }
                fields={[
                  { label: "更新时间", value: formatDateTime(specus.updatedAt || specus.createdAt) },
                ]}
                actions={
                  <>
                    <Button size="sm" variant="secondary" onPress={() => { setEditing(specus); editModal.open(); }}>
                      编辑
                    </Button>
                    <Button size="sm" variant="danger-soft" onPress={() => remove(specus)}>
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
      <Table>
        <TableContent aria-label="端口映射列表">
          <TableHeader>
            <TableColumn isRowHeader>ID</TableColumn>
            <TableColumn>客户端</TableColumn>
            <TableColumn>公网端口</TableColumn>
            <TableColumn>内网目标</TableColumn>
            <TableColumn>启用</TableColumn>
            <TableColumn>明细采集</TableColumn>
            <TableColumn>更新时间</TableColumn>
            <TableColumn>操作</TableColumn>
          </TableHeader>
          <TableBody items={pagedSpecusMappings} renderEmptyState={() => (loading ? <Spinner size="sm" /> : <EmptyState icon="connections" title="暂无端口映射" description="创建映射后公网端口将转发到内网目标" />)}>
            {(specus) => {
              const pending = pendingIds.has(specus.id);
              return (
              <TableRow key={specus.id}>
                <TableCell>{specus.id}</TableCell>
                <TableCell>{specus.clientName}</TableCell>
                <TableCell>{specus.listenPort}</TableCell>
                <TableCell>
                  <code>{specus.targetAddress}:{specus.targetPort}</code>
                </TableCell>
                <TableCell>
                  <Switch
                    aria-label="启用"
                    isSelected={specus.enabled}
                    isDisabled={pending}
                    onChange={() => void toggle(specus)}
                  />
                </TableCell>
                <TableCell>
                  <Switch
                    aria-label="明细采集"
                    isSelected={Boolean(specus.detailCaptureEnabled)}
                    isDisabled={pending}
                    onChange={() => void toggleDetailCapture(specus)}
                  />
                </TableCell>
                <TableCell>{formatDateTime(specus.updatedAt || specus.createdAt)}</TableCell>
                <TableCell>
                  <div className="flex gap-2">
                    <Button size="sm" variant="secondary" onPress={() => { setEditing(specus); editModal.open(); }}>
                      编辑
                    </Button>
                    <Button size="sm" variant="danger-soft" onPress={() => remove(specus)}>
                      删除
                    </Button>
                  </div>
                </TableCell>
              </TableRow>
              );
            }}
          </TableBody>
      
        </TableContent>
      </Table>
      </div>

      {totalPages > 1 ? (
        <div className="flex justify-end">
          <Pager page={safePage} total={totalPages} onChange={setPage}  />
        </div>
      ) : null}

      <EditSpecusModal disclosure={editModal} specus={editing} onSaved={() => void load()} />
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

interface EditSpecusModalProps {
  disclosure: ReturnType<typeof useOverlayState>;
  specus: Specus | null;
  onSaved: () => void;
}

function EditSpecusModal({ disclosure, specus, onSaved }: EditSpecusModalProps) {
  const [listenPort, setListenPort] = useState("");
  const [targetAddress, setTargetAddress] = useState("");
  const [targetPort, setTargetPort] = useState("");
  const [enabled, setEnabled] = useState(true);
  const [detailCaptureEnabled, setDetailCaptureEnabled] = useState(false);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (specus) {
      setListenPort(String(specus.listenPort));
      setTargetAddress(specus.targetAddress);
      setTargetPort(String(specus.targetPort));
      setEnabled(specus.enabled);
      setDetailCaptureEnabled(Boolean(specus.detailCaptureEnabled));
    }
  }, [specus]);

  const save = async () => {
    if (!specus) {
      return;
    }
    setSaving(true);
    try {
      await adminApi.updateSpecus(specus.id, {
        listenPort: Number(listenPort),
        targetAddress: targetAddress.trim(),
        targetPort: Number(targetPort),
        enabled,
        detailCaptureEnabled,
      });
      notify("端口映射已更新");
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
            <>
            <Modal.Header>编辑端口映射 #{specus?.id}</Modal.Header>
            <Modal.Body className="gap-3">
              <TextField value={listenPort} onChange={setListenPort} isRequired type="number">
                <Label>公网端口</Label>
                <Input min={1} max={65535} />
              </TextField>
            <TextField value={targetAddress} onChange={setTargetAddress} isRequired>
              <Label>内网目标地址</Label>
              <Input maxLength={255} />
            </TextField>
            <TextField value={targetPort} onChange={setTargetPort} isRequired type="number">
              <Label>内网端口</Label>
              <Input min={1} max={65535} />
            </TextField>
            <Switch isSelected={enabled} onChange={setEnabled}>
              启用
            </Switch>
            <Switch isSelected={detailCaptureEnabled} onChange={setDetailCaptureEnabled}>
              明细采集
            </Switch>
            </Modal.Body>
            <Modal.Footer>
              <Button variant="secondary" onPress={onClose}>
                取消
              </Button>
              <Button variant="primary" onPress={() => void save()} isDisabled={saving}>{saving ? <Spinner size="sm" /> : null}
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
