import { useEffect, useState, useCallback } from "react";
import { Button, Chip, Spinner } from "@heroui/react";
import { adminApi } from "../api/client";
import type { Client, ClientDetail, Tunnel, HttpRoute } from "../api/types";
import { formatBytes, formatDateTime, formatSince } from "../lib/format";
import { notifyError, notify } from "./toast";

export function ClientDetailDrawer({ client, open, onClose }: { client: Client | null; open: boolean; onClose: () => void }) {
  const [detail, setDetail] = useState<ClientDetail | null>(null);
  const [loading, setLoading] = useState(false);
  const load = useCallback(async () => { if (!client) return; setLoading(true); try { setDetail(await adminApi.getClient(client.id)); } catch (e) { notifyError(e, "加载详情失败"); } finally { setLoading(false); } }, [client]);
  useEffect(() => { if (open && client) void load(); if (!open) setDetail(null); }, [open, client, load]);
  useEffect(() => { if (!open) return; const p = document.body.style.overflow; document.body.style.overflow = "hidden"; return () => { document.body.style.overflow = p; }; }, [open]);

  return (
    <>
      <div aria-hidden="true" className={`fixed inset-0 z-40 bg-black/40 backdrop-blur-sm transition-opacity duration-200 ${open ? "opacity-100" : "pointer-events-none opacity-0"}`} onClick={onClose} />
      <aside className={`fixed inset-y-0 right-0 z-50 flex w-full max-w-md flex-col border-l border-divider bg-background shadow-2xl transition-transform duration-200 ${open ? "translate-x-0" : "translate-x-full"}`}>
        <div className="flex items-center justify-between gap-2 border-b border-divider px-4 py-3">
          <h2 className="text-base font-semibold">{client?.clientName ?? "\u5BA2\u6237\u7AEF\u8BE6\u60C5"}</h2>
          <Button isIconOnly aria-label="\u5173\u95ED" className="h-9 w-9 min-w-9" radius="sm" variant="light" onPress={onClose}><svg className="h-5 w-5" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M6 6l12 12M6 18L18 6" /></svg></Button>
        </div>
        <div className="flex-1 overflow-y-auto p-4">
          {loading ? <div className="flex items-center justify-center py-12"><Spinner label="\u52A0\u8F7D\u4E2D\u2026" /></div> : detail ? (
            <div className="flex flex-col gap-5">
              <Sec t="\u57FA\u672C\u4FE1\u606F"><F l="ID" v={String(detail.client.id)} /><F l="\u540D\u79F0" v={detail.client.clientName} /><F l="\u5F52\u5C5E" v={detail.client.ownerUsername || "-"} /><F l="\u521B\u5EFA" v={formatDateTime(detail.client.createdAt)} /></Sec>
              <Sec t="\u5728\u7EBF\u72B6\u6001">
                <div className="flex items-center gap-2"><Chip size="sm" variant="flat" color={detail.client.online ? "success" : "default"}>{detail.client.online ? "\u5728\u7EBF" : "\u79BB\u7EBF"}</Chip><Chip size="sm" variant="flat" color={detail.client.enabled ? "success" : "default"}>{detail.client.enabled ? "\u5DF2\u542F\u7528" : "\u5DF2\u505C\u7528"}</Chip></div>
                {detail.client.online && detail.client.connectedSinceMs && <F l="\u5728\u7EBF\u65F6\u957F" v={formatSince(detail.client.connectedSinceMs, Date.now())} />}
                <F l="\u6BCF\u5206\u949F\u4E0A\u9650" v={String(detail.client.connectionRateLimitPerMinute)} />
              </Sec>
              <Sec t="\u6D41\u91CF"><F l="\u4E0A\u4F20" v={formatBytes(detail.client.uploadBytes)} /><F l="\u4E0B\u8F7D" v={formatBytes(detail.client.downloadBytes)} /></Sec>
              <Sec t={`\u7AEF\u53E3\u6620\u5C04 \u00B7 ${detail.tunnels.length + detail.httpRoutes.length} \u9879`}>
                {detail.tunnels.map((t: Tunnel) => <div key={t.id} className="flex items-center justify-between rounded-md bg-default-50 px-3 py-1.5 text-tiny"><span className="font-mono">{t.listenPort} {"\u2192"} {t.targetAddress}:{t.targetPort}</span><Chip size="sm" variant="flat" color={t.enabled ? "success" : "default"}>{t.enabled ? "\u542F\u7528" : "\u505C\u7528"}</Chip></div>)}
                {detail.httpRoutes.map((r: HttpRoute) => <div key={r.id} className="flex items-center justify-between rounded-md bg-default-50 px-3 py-1.5 text-tiny"><span className="font-mono">{r.route} {"\u2192"} {r.targetBaseUrl}</span><Chip size="sm" variant="flat" color={r.enabled ? "success" : "default"}>{r.enabled ? "\u542F\u7528" : "\u505C\u7528"}</Chip></div>)}
                {detail.tunnels.length === 0 && detail.httpRoutes.length === 0 && <div className="text-tiny text-default-400">\u6682\u65E0\u7AEF\u53E3\u6620\u5C04</div>}
              </Sec>
              <Button size="sm" variant="flat" onPress={async () => { if (!client) return; try { const r = await adminApi.forceRefreshPortMapping(client.id); notify(`\u5DF2\u63A8\u9001\uFF1A${r.tunnels} \u4E2A\u7AEF\u53E3\u6620\u5C04`); } catch (e) { notifyError(e, "\u5237\u65B0\u5931\u8D25"); } }}>\u5F3A\u5236\u5237\u65B0\u7AEF\u53E3\u6620\u5C04</Button>
            </div>
          ) : <div className="py-12 text-center text-small text-default-400">\u65E0\u6570\u636E</div>}
        </div>
      </aside>
    </>
  );
}
function Sec({ t, children }: { t: string; children: React.ReactNode }) { return <div><h3 className="mb-2 text-small font-semibold">{t}</h3><div className="space-y-2 rounded-md border border-default-200 bg-default-50 p-3 text-small">{children}</div></div>; }
function F({ l, v }: { l: string; v: string }) { return <div className="flex justify-between gap-3"><span className="text-default-500">{l}</span><span className="truncate text-right font-medium" title={v}>{v}</span></div>; }
