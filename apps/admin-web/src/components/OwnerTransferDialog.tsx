import { useEffect, useMemo, useRef, useState, useSyncExternalStore } from "react";
import { Button, Checkbox, Chip, Modal, ModalBody, ModalContent, ModalFooter, ModalHeader, Pagination, Select, SelectItem, Spinner } from "@heroui/react";
import { adminApi } from "../api/client";
import type { OwnerTransferResult } from "../api/types";
import { OWNER_TRANSFER_WARNING, OwnerTransferController, ownerResourcesHash, transferCanSubmit, type TransferResource } from "../lib/ownerTransfer";
import { watchOwnershipChanges } from "../lib/ownershipChanges";

interface Props {
  resource: TransferResource;
  onClose: () => void;
  onTransferred: (result: OwnerTransferResult) => Promise<void>;
}

/** Mounted only by administrator entrypoints. Backend remains authoritative for every request. */
export function OwnerTransferDialog({ resource, onClose, onTransferred }: Props) {
  const controller = useMemo(() => new OwnerTransferController({
    preview: item => item.kind === "client" ? adminApi.previewClientOwnerTransfer(item.id) : adminApi.previewCredentialOwnerTransfer(item.id),
    users: adminApi.listUsers,
    submit: (item, body) => item.kind === "client" ? adminApi.transferClientOwner(item.id, body) : adminApi.transferCredentialOwner(item.id, body),
  }), []);
  const state = useSyncExternalStore(controller.subscribe, controller.snapshot, controller.snapshot);
  const [page, setPage] = useState(1);
  const [refreshError, setRefreshError] = useState(false);
  const bodyRef = useRef<HTMLDivElement>(null);
  useEffect(() => { void controller.load(resource); return () => controller.dispose(); }, [controller, resource]);
  useEffect(() => watchOwnershipChanges(() => { if (controller.snapshot().phase === "review") void controller.refresh(); }), [controller]);
  useEffect(() => { setPage(1); }, [state.preview]);
  const busy = state.phase === "submitting";
  const preview = state.preview;
  const group = state.resource?.kind === "credential";
  const targetMissing = !!state.target && !state.users.some(user => user.username === state.target);
  const targets = state.users.map(user => ({ key: user.username, name: user.username }));
  if (targetMissing) targets.push({ key: state.target, name: `${state.target}（当前不可用）` });
  const pages = Math.max(1, Math.ceil((preview?.affectedClientCount ?? 0) / 10));
  const currentPage = Math.min(page, pages);
  const submit = async () => {
    const result = await controller.submit();
    if (!result) return;
    try { await onTransferred(result); } catch { setRefreshError(true); }
  };
  const close = () => { if (controller.snapshot().phase !== "submitting") onClose(); };
  return <Modal isOpen onClose={close} isDismissable={!busy} isKeyboardDismissDisabled={busy} hideCloseButton={busy}
    size="2xl" scrollBehavior="inside" placement="center" classNames={{ base: "max-h-[90dvh] mx-3", footer: "flex-wrap" }}>
    <ModalContent>
      <ModalHeader className="flex-col gap-1">
        <span>转移管理归属</span>
        <span className="text-small font-normal text-default-500">{group ? "完整凭证组" : "单台客户端"} · 资源 <span className="font-mono">#{state.resource?.id ?? resource.id}</span></span>
      </ModalHeader>
      <ModalBody ref={bodyRef} className="gap-4">
        {state.phase === "loading" && <div role="status" className="py-8 text-center"><Spinner label="读取完整影响清单与可用账号…" /></div>}
        {state.message && <div role={state.phase === "unknown" || state.phase === "error" ? "alert" : "status"}
          className="rounded-md border border-warning-300 bg-warning-50 p-3 text-small text-warning-800">{state.message}</div>}
        {state.phase === "success" && state.result ? <div role="status" className="space-y-3">
          <h3 className="text-lg font-semibold">{state.result.changed ? "管理归属已转移" : "管理归属已确认，无需更改"}</h3>
          <p className="text-small">目标账号：<strong>{state.result.targetUsername}</strong>。已核对 {state.result.affectedClientIds.length} 台设备{state.result.credentialId !== null ? "及其接入凭证" : ""}。</p>
          <p className="text-small text-default-600">原接入能力保留。若还需删除原管理账号，请返回账号管理重新确认删除。</p>
          {refreshError && <p role="alert" className="text-small text-warning-700">转移已成功，但列表刷新失败。请手动刷新列表，不要重复提交。</p>}
          <Button as="a" role="link" href={ownerResourcesHash(state.result.targetUsername, group ? "credentials" : "clients")} variant="flat" onPress={onClose}>查看新归属资源</Button>
        </div> : preview && <>
          <div className="grid gap-3 rounded-md border border-default-200 bg-default-50 p-3 sm:grid-cols-2">
            <div><p className="text-tiny text-default-500">预览时归属</p><p className="break-all text-small font-medium">{Array.from(new Set([
              ...(preview.credentialId !== null ? [preview.credentialOwnerUsername || "未记录归属"] : []),
              ...preview.affectedClients.map(client => client.ownerUsername || "未记录归属"),
            ])).join("、")}</p></div>
            <Select label="目标账号" placeholder="选择当前租户已启用的账号" selectedKeys={state.target ? [state.target] : []}
              // Keep the nested overlay in the modal's accessibility tree instead of an aria-hidden body sibling.
              popoverProps={{ portalContainer: bodyRef.current ?? undefined }}
              disabledKeys={targetMissing ? [state.target] : []} isDisabled={state.phase !== "review"}
              isInvalid={targetMissing} errorMessage={targetMissing ? "请重新选择已启用账号" : undefined}
              onSelectionChange={keys => controller.setTarget(Array.from(keys)[0]?.toString() ?? "")}>
              {targets.map(user => <SelectItem key={user.key} textValue={user.name}>{user.name}</SelectItem>)}
            </Select>
          </div>
          <section aria-label="转移影响清单" className="space-y-2">
            <div className="flex flex-wrap items-center justify-between gap-2"><h3 className="font-semibold">{group ? "整组影响清单" : "影响清单"}</h3><span className="text-small text-default-600">{preview.affectedClientCount} 台设备 · {preview.credentialId === null ? "无关联凭证" : `凭证 #${preview.credentialId}`}</span></div>
            {preview.credentialId !== null && <p className="text-small text-default-600">凭证原归属：{preview.credentialOwnerUsername || "未记录归属"} · {preview.credentialEnabled ? "启用" : "停用（转移后仍停用）"}</p>}
            {preview.affectedClientCount === 0 ? <p className="rounded-md border border-default-200 p-3 text-small">此凭证尚无设备。仍会转移凭证归属，以后派生的设备归目标账号。</p>
              : <ul className="divide-y divide-default-200 rounded-md border border-default-200">
                {preview.affectedClients.slice((currentPage - 1) * 10, currentPage * 10).map(client => <li key={client.id} className="flex items-center justify-between gap-3 px-3 py-2">
                  <div className="min-w-0"><p className="break-all text-small font-medium">{client.clientName}</p><p className="text-tiny text-default-500"><span className="font-mono">#{client.id}</span> · {client.ownerUsername || "未记录归属"}</p></div>
                  <Chip size="sm" variant="flat">{client.enabled ? "启用" : "停用"}</Chip>
                </li>)}
              </ul>}
            {pages > 1 && <div className="flex flex-wrap items-center justify-between gap-2"><span className="text-tiny text-default-500">仅分页展示；确认绑定全部 {preview.affectedClientCount} 台设备，不只本页。</span><Pagination aria-label="影响清单分页" page={currentPage} total={pages} onChange={setPage} isDisabled={busy} /></div>}
          </section>
          {preview.conflictCode === "CREDENTIAL_SHARED" && <div className="space-y-2 rounded-md border border-warning-300 bg-warning-50 p-3">
            <p className="text-small">此凭证还关联其他设备，不能只转移这一台。整组操作需要重新预览并显式确认。</p>
            <Button variant="flat" onPress={() => void controller.group()} isDisabled={state.phase !== "review"}>查看凭证整组预览</Button>
          </div>}
          <div className="rounded-md border border-warning-300 bg-warning-50 p-3 text-small text-warning-800">{OWNER_TRANSFER_WARNING}</div>
          <Checkbox isSelected={state.confirmed} onValueChange={value => controller.confirm(value)}
            isDisabled={state.phase !== "review" || !preview.canTransfer || !state.target || targetMissing}>
            我已核对完整清单与目标账号，并知晓原接入能力保留
          </Checkbox>
        </>}
      </ModalBody>
      <ModalFooter>
        <Button variant="flat" onPress={close} isDisabled={busy}>{state.phase === "success" ? "完成" : "取消"}</Button>
        {state.phase !== "success" && <Button variant="flat" isDisabled={busy || state.phase === "loading"} onPress={() => void controller.refresh()}>{state.phase === "unknown" ? "重新读取当前归属" : "刷新预览"}</Button>}
        {state.phase !== "success" && <Button color="primary" className="h-auto whitespace-normal py-2" isDisabled={!transferCanSubmit(state)} isLoading={busy} onPress={() => void submit()}>
          {group ? preview ? `转移此凭证及 ${preview.affectedClientCount} 台设备` : "等待完整凭证组清单" : "确认转移这台客户端"}
        </Button>}
      </ModalFooter>
    </ModalContent>
  </Modal>;
}
