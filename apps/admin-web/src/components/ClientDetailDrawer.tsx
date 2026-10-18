import { useEffect, useState } from "react";
import { Button, Chip, Modal, Spinner } from "@heroui/react";
import { adminApi } from "../api/client";
import type { Client, ClientDetail, Specus, HttpRoute } from "../api/types";
import { formatBytes, formatDateTime, formatSince } from "../lib/format";
import { notifyError, notify } from "./toast";

export function ClientDetailDrawer({ client, open, onClose, onTransfer }: { client: Client | null; open: boolean; onClose: () => void; onTransfer?: () => void }) {
  const [detail, setDetail] = useState<ClientDetail | null>(null);
  const [loading, setLoading] = useState(false);
  useEffect(() => {
    const clientId = client?.id;
    let current = true;
    setDetail(null);
    if (!open || clientId == null) { setLoading(false); return; }
    setLoading(true);
    void adminApi.getClient(clientId).then(value => {
      if (current) setDetail(value);
    }).catch(error => {
      if (current) notifyError(error, "加载详情失败");
    }).finally(() => {
      if (current) setLoading(false);
    });
    return () => { current = false; };
  }, [open, client]);

  return (
    <Modal.Root isOpen={open} onOpenChange={(isOpen) => { if (!isOpen) onClose(); }}>
      <Modal.Backdrop className="bg-black/40 backdrop-blur-xs">
      <Modal.Container className="w-full items-end justify-start p-0 sm:w-full sm:p-0" scroll="inside">
      <Modal.Dialog className="m-0 flex h-dvh max-h-none w-full max-w-md flex-col overflow-hidden rounded-none border-l border-divider bg-background p-0 shadow-2xl">
        <Modal.Header className="flex-row items-center justify-between gap-2 border-b border-divider px-4 py-3">
          <Modal.Heading className="text-base font-semibold">{detail?.client.clientName ?? client?.clientName ?? "客户端详情"}</Modal.Heading>
          <Button isIconOnly aria-label="关闭客户端详情" className="h-9 w-9 min-w-9" variant="ghost" onPress={onClose}><svg className="h-5 w-5" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24" aria-hidden="true"><path strokeLinecap="round" strokeLinejoin="round" d="M6 6l12 12M6 18L18 6" /></svg></Button>
        </Modal.Header>
        <Modal.Body className="m-0 flex-1 overflow-y-auto p-4 text-foreground">
          {loading ? <div role="status" className="flex items-center justify-center py-12"><span className="inline-flex items-center gap-2"><Spinner aria-hidden="true" /><span className="text-sm text-default-500">加载中…</span></span></div> : detail ? (
            <div className="flex flex-col gap-5">
              {onTransfer && <Button variant={"secondary"} onPress={onTransfer}>转移管理归属</Button>}
              <Sec t="基本信息"><F l="ID" v={String(detail.client.id)} /><F l="名称" v={detail.client.clientName} /><F l="归属" v={detail.client.ownerUsername || "-"} /><F l="创建" v={formatDateTime(detail.client.createdAt)} /></Sec>
              <Sec t="在线状态">
                <div className="flex items-center gap-2"><Chip size="sm" variant="soft" color={detail.client.online ? "success" : "default"}>{detail.client.online ? "在线" : "离线"}</Chip><Chip size="sm" variant="soft" color={detail.client.enabled ? "success" : "default"}>{detail.client.enabled ? "已启用" : "已停用"}</Chip></div>
                {detail.client.online && detail.client.connectedSinceMs && <F l="在线时长" v={formatSince(detail.client.connectedSinceMs, Date.now())} />}
                <F l="每分钟上限" v={String(detail.client.connectionRateLimitPerMinute)} />
              </Sec>
              <Sec t="流量"><F l="上传" v={formatBytes(detail.client.uploadBytes)} /><F l="下载" v={formatBytes(detail.client.downloadBytes)} /></Sec>
              <Sec t={`端口映射 · ${detail.specusMappings.length + detail.httpRoutes.length} 项`}>
                {detail.specusMappings.map((t: Specus) => <div key={t.id} className="flex items-center justify-between rounded-md bg-default-50 px-3 py-1.5 text-tiny"><span className="font-mono">{t.listenPort} {"→"} {t.targetAddress}:{t.targetPort}</span><Chip size="sm" variant="soft" color={t.enabled ? "success" : "default"}>{t.enabled ? "启用" : "停用"}</Chip></div>)}
                {detail.httpRoutes.map((r: HttpRoute) => (
                  <div key={r.id} className="flex items-center justify-between gap-2 rounded-md bg-default-50 px-3 py-1.5 text-tiny">
                    <span className="min-w-0 truncate font-mono" title={`${r.route} → ${r.targetBaseUrl}`}>
                      {r.route} {"→"} {r.targetBaseUrl}
                    </span>
                    <div className="flex shrink-0 items-center gap-1">
                      <Chip size="sm" variant="soft" color={r.authEnabled ? "accent" : "default"}>
                        {r.authEnabled ? "Basic" : "公开"}
                      </Chip>
                      <Chip size="sm" variant="soft" color={r.enabled ? "success" : "default"}>{r.enabled ? "启用" : "停用"}</Chip>
                    </div>
                  </div>
                ))}
                {detail.specusMappings.length === 0 && detail.httpRoutes.length === 0 && <div className="text-tiny text-default-400">暂无端口映射</div>}
              </Sec>
              <Button size="sm" variant="secondary" onPress={async () => { if (!client) return; try { const r = await adminApi.forceRefreshPortMapping(client.id); notify(`已推送：${r.specusMappings} 个端口映射`); } catch (e) { notifyError(e, "刷新失败"); } }}>强制刷新端口映射</Button>
            </div>
          ) : <div className="py-12 text-center text-small text-default-400">无数据</div>}
        </Modal.Body>
      </Modal.Dialog>
      </Modal.Container>
      </Modal.Backdrop>
    </Modal.Root>
  );
}
function Sec({ t, children }: { t: string; children: React.ReactNode }) { return <div><h3 className="mb-2 text-small font-semibold">{t}</h3><div className="space-y-2 rounded-md border border-default-200 bg-default-50 p-3 text-small">{children}</div></div>; }
function F({ l, v }: { l: string; v: string }) { return <div className="flex justify-between gap-3"><span className="text-default-500">{l}</span><span className="truncate text-right font-medium" title={v}>{v}</span></div>; }
