import { useEffect, useState, useCallback } from "react";
import { Button, Chip, Spinner } from "@heroui/react";
import { adminApi } from "../api/client";
import type { Client, ClientDetail, Tunnel, HttpRoute } from "../api/types";
import { formatBytes, formatDateTime, formatSince } from "../lib/format";
import { notifyError, notify } from "./toast";

export interface ClientDetailDrawerProps {
  client: Client | null;
  open: boolean;
  onClose: () => void;
}

export function ClientDetailDrawer({ client, open, onClose }: ClientDetailDrawerProps) {
  const [detail, setDetail] = useState<ClientDetail | null>(null);
  const [loading, setLoading] = useState(false);

  const load = useCallback(async () => {
    if (!client) return;
    setLoading(true);
    try {
      setDetail(await adminApi.getClient(client.id));
    } catch (error) {
      notifyError(error, "加载客户端详情失败");
    } finally {
      setLoading(false);
    }
  }, [client]);

  useEffect(() => {
    if (open && client) {
      void load();
    }
    if (!open) {
      setDetail(null);
    }
  }, [open, client, load]);

  // Lock body scroll
  useEffect(() => {
    if (!open) return;
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const handleEscape = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", handleEscape);
    return () => {
      document.body.style.overflow = prev;
      window.removeEventListener("keydown", handleEscape);
    };
  }, [open, onClose]);

  const handleForceRefresh = async () => {
    if (!client) return;
    try {
      const result = await adminApi.forceRefreshPortMapping(client.id);
      notify(`已推送端口映射刷新：${result.tunnels} 个 TCP`);
    } catch (error) {
      notifyError(error, "刷新失败");
    }
  };

  return (
    <>
      <div
        aria-hidden="true"
        className={`fixed inset-0 z-40 bg-black/40 backdrop-blur-sm transition-opacity duration-200 ${
          open ? "opacity-100" : "pointer-events-none opacity-0"
        }`}
        onClick={onClose}
      />
      <aside
        aria-label="客户端详情"
        className={`fixed inset-y-0 right-0 z-50 flex w-full max-w-md flex-col border-l border-divider bg-background shadow-2xl transition-transform duration-200 ${
          open ? "translate-x-0" : "translate-x-full"
        }`}
      >
        <div className="flex items-center justify-between gap-2 border-b border-divider px-4 py-3">
          <h2 className="text-base font-semibold text-foreground">
            {client?.clientName ?? "客户端详情"}
          </h2>
          <Button isIconOnly aria-label="关闭" className="h-9 w-9 min-w-9" radius="sm" variant="light" onPress={onClose}>
            <svg className="h-5 w-5" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 6l12 12M6 18L18 6" />
            </svg>
          </Button>
        </div>

        <div className="flex-1 overflow-y-auto p-4">
          {loading ? (
            <div className="flex items-center justify-center py-12">
              <Spinner label="加载中…" />
            </div>
          ) : detail ? (
            <div className="flex flex-col gap-5">
              <Section title="基本信息">
                <Field label="客户端 ID" value={String(detail.client.id)} />
                <Field label="名称" value={detail.client.clientName} />
                <Field label="归属" value={detail.client.ownerUsername || "-"} />
                <Field label="创建时间" value={formatDateTime(detail.client.createdAt)} />
              </Section>

              <Section title="在线状态">
                <div className="flex items-center gap-2">
                  <Chip size="sm" variant="flat" color={detail.client.online ? "success" : "default"}>
                    {detail.client.online ? "在线" : "离线"}
                  </Chip>
                  <Chip size="sm" variant="flat" color={detail.client.enabled ? "success" : "default"}>
                    {detail.client.enabled ? "已启用" : "已停用"}
                  </Chip>
                </div>
                {detail.client.online && detail.client.connectedSinceMs && (
                  <Field label="在线时长" value={formatSince(detail.client.connectedSinceMs, Date.now())} />
                )}
                <Field label="每分钟上限" value={String(detail.client.connectionRateLimitPerMinute)} />
              </Section>

              <Section title="流量统计">
                <Field label="上传" value={formatBytes(detail.client.uploadBytes)} />
                <Field label="下载" value={formatBytes(detail.client.downloadBytes)} />
              </Section>

              <Section title={`端口映射 · ${detail.tunnels.length + detail.httpRoutes.length} 项`}>
                {detail.tunnels.length > 0 && (
                  <div className="mb-2">
                    <h4 className="text-tiny font-semibold text-default-500 mb-1">TCP 端口映射</h4>
                    {detail.tunnels.map((t: Tunnel) => (
                      <div key={t.id} className="flex items-center justify-between rounded-md bg-default-50 px-3 py-1.5 text-tiny">
                        <span className="font-mono">{t.listenPort} → {t.targetAddress}:{t.targetPort}</span>
                        <Chip size="sm" variant="flat" color={t.enabled ? "success" : "default"}>
                          {t.enabled ? "启用" : "停用"}
                        </Chip>
                      </div>
                    ))}
                  </div>
                )}
                {detail.httpRoutes.length > 0 && (
                  <div>
                    <h4 className="text-tiny font-semibold text-default-500 mb-1">HTTP 路由</h4>
                    {detail.httpRoutes.map((r: HttpRoute) => (
                      <div key={r.id} className="flex items-center justify-between rounded-md bg-default-50 px-3 py-1.5 text-tiny">
                        <span className="font-mono">{r.route} → {r.targetBaseUrl}</span>
                        <Chip size="sm" variant="flat" color={r.enabled ? "success" : "default"}>
                          {r.enabled ? "启用" : "停用"}
                        </Chip>
                      </div>
                    ))}
                  </div>
                )}
                {detail.tunnels.length === 0 && detail.httpRoutes.length === 0 && (
                  <div className="text-tiny text-default-400">暂无端口映射</div>
                )}
              </Section>

              <div className="flex flex-col gap-2 pt-1">
                <Button size="sm" variant="flat" onPress={handleForceRefresh}>
                  强制刷新端口映射
                </Button>
              </div>
            </div>
          ) : (
            <div className="py-12 text-center text-small text-default-400">无数据</div>
          )}
        </div>
      </aside>
    </>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <h3 className="mb-2 text-small font-semibold text-foreground">{title}</h3>
      <div className="space-y-2 rounded-md border border-default-200 bg-default-50 p-3 text-small">
        {children}
      </div>
    </div>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between gap-3">
      <span className="text-default-500">{label}</span>
      <span className="truncate text-right font-medium">{value}</span>
    </div>
  );
}