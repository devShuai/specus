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
  Select,
  SelectItem,
  useDisclosure,
} from "@heroui/react";
import { adminApi } from "../../api/client";
import type { Specus } from "../../api/types";
import { notify, notifyError } from "../../components/toast";
import { ConfirmModal } from "../../components/ConfirmModal";
import { Empty, Icon, Section, TableWrap, Tag } from "../../components/ui";
import { useClients } from "../../hooks/useClients";
import { DesignSwitch, ListLoading, TimeText } from "./accessUi";

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
  const editModal = useDisclosure();

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
  const enabledCount = specusMappings.filter((item) => item.enabled).length;

  return (
    <div className="acc-page">
      <PageHeader
        title="端口映射"
        description="把客户端所在网络里的 TCP 服务映射到服务端的公网端口。"
        actions={<Button variant="flat" isLoading={loading} startContent={loading ? null : <Icon name="refresh" />} onPress={() => void load()}>刷新</Button>}
      />

      <Section title="新建映射" description="公网端口收到的 TCP 连接，经所选客户端转发到它所在网络里的目标地址和端口。">
        <form className="bd-card acc-inline-form acc-mapping-form" onSubmit={onCreate} aria-label="新建端口映射">
          <Select
            label="客户端"
            selectedKeys={clientId ? [clientId] : []}
            onChange={(event) => setClientId(event.target.value)}
            description="转发经过的设备"
            isRequired
          >
            {clients.map((client) => (
              <SelectItem key={String(client.id)}>{client.clientName}</SelectItem>
            ))}
          </Select>
          <Input type="number" label="公网端口" value={listenPort} onValueChange={setListenPort} min={1} max={65535} description="1–65535，在服务端监听" isRequired />
          <Input label="内网目标地址" placeholder="127.0.0.1" value={targetAddress} onValueChange={setTargetAddress} description="从客户端能访问到的地址" isRequired />
          <Input type="number" label="内网端口" placeholder="22" value={targetPort} onValueChange={setTargetPort} min={1} max={65535} description="1–65535" isRequired />
          <div className="acc-inline-form-submit">
            <Button type="submit" color="primary" isLoading={creating} startContent={creating ? null : <Icon name="plus" />}>
              新建映射
            </Button>
          </div>
        </form>
      </Section>

      <Section
        title="映射列表"
        description="开关立即生效：关掉“启用”会停止转发，“明细采集”记录每条连接的内容。"
        actions={!loading || specusMappings.length > 0 ? (
          <>
            {enabledCount > 0 ? <Tag tone="success">{enabledCount} 条转发中</Tag> : null}
            <span className="acc-head-count bd-num">共 {specusMappings.length} 条</span>
          </>
        ) : null}
      >
        {loading && specusMappings.length === 0 ? <ListLoading label="正在读取端口映射…" /> : specusMappings.length === 0 ? (
          <div className="bd-card"><Empty icon="shuffle" title="还没有端口映射" description="在上面选好客户端和目标，新建映射后公网端口就会转发到内网目标。" /></div>
        ) : (
          <TableWrap className={loading ? "bd-refetching" : undefined}>
            <table className="bd-table jd-stack" aria-label="端口映射列表">
              <thead>
                <tr>
                  <th>公网端口 → 内网目标</th>
                  <th>客户端</th>
                  <th>启用</th>
                  <th>明细采集</th>
                  <th>更新时间</th>
                  <th className="jd-col-actions"><span className="jd-sr-only">操作</span></th>
                </tr>
              </thead>
              <tbody>
                {pagedSpecusMappings.map((specus) => {
                  const pending = pendingIds.has(specus.id);
                  const client = clients.find((item) => item.id === specus.clientId);
                  return (
                    <tr key={specus.id}>
                      <td>
                        <div className="jd-table-title">
                          <span className="font-mono bd-num"><span className="font-semibold">:{specus.listenPort}</span> <span className="acc-mapping-arrow">→</span> {specus.targetAddress}:{specus.targetPort}</span>
                          <span className="jd-table-sub bd-num">#{specus.id}</span>
                        </div>
                      </td>
                      <td>
                        <div className="acc-client-cell">
                          <span>{specus.clientName}</span>
                          {client ? (
                            <Tag tone={client.enabled && client.online ? "success" : "neutral"} plain={!client.enabled}>
                              {!client.enabled ? "停用" : client.online ? "在线" : "离线"}
                            </Tag>
                          ) : null}
                        </div>
                      </td>
                      <td>
                        <DesignSwitch
                          ariaLabel="启用"
                          label={<span className="acc-stack-only">启用</span>}
                          checked={specus.enabled}
                          disabled={pending}
                          onChange={() => void toggle(specus)}
                        />
                      </td>
                      <td>
                        <DesignSwitch
                          ariaLabel="明细采集"
                          label={<span className="acc-stack-only">明细采集</span>}
                          checked={Boolean(specus.detailCaptureEnabled)}
                          disabled={pending}
                          onChange={() => void toggleDetailCapture(specus)}
                        />
                      </td>
                      <td data-label="更新"><TimeText value={specus.updatedAt || specus.createdAt} /></td>
                      <td className="jd-cell-actions">
                        <div className="jd-row-actions">
                          <Button size="sm" variant="flat" startContent={<Icon name="edit" size={14} />} onPress={() => { setEditing(specus); editModal.onOpen(); }}>
                            编辑
                          </Button>
                          <Button size="sm" color="danger" variant="flat" startContent={<Icon name="trash" size={14} />} onPress={() => remove(specus)}>
                            删除
                          </Button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </TableWrap>
        )}

        {totalPages > 1 ? (
          <div className="acc-pager">
            <span className="bd-num">共 {specusMappings.length} 条</span>
            <Pagination showControls size="sm" page={safePage} total={totalPages} onChange={setPage} />
          </div>
        ) : null}
      </Section>

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
  disclosure: ReturnType<typeof useDisclosure>;
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
            <ModalHeader>编辑端口映射 #{specus?.id}</ModalHeader>
            <ModalBody className="acc-dialog-body">
              <Input type="number" label="公网端口" value={listenPort} onValueChange={setListenPort} min={1} max={65535} description="1–65535，在服务端监听" isRequired />
              <div className="acc-field-pair">
                <Input label="内网目标地址" value={targetAddress} onValueChange={setTargetAddress} maxLength={255} isRequired />
                <Input type="number" label="内网端口" value={targetPort} onValueChange={setTargetPort} min={1} max={65535} isRequired />
              </div>
              <div className="acc-switch-list">
                <DesignSwitch checked={enabled} onChange={setEnabled} label="启用" />
                <DesignSwitch checked={detailCaptureEnabled} onChange={setDetailCaptureEnabled} label="明细采集" />
              </div>
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
