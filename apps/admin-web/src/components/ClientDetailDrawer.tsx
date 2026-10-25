import { useEffect, useState, useCallback, type ReactNode } from "react";
import { Button } from "@heroui/react";
import { adminApi } from "../api/client";
import type { Client, ClientDetail, Specus, HttpRoute } from "../api/types";
import { formatAbsoluteTime, formatBytes, formatElapsed } from "../lib/format";
import { notifyError, notify } from "./toast";
import { Icon, Tag } from "./ui";

export function ClientDetailDrawer({ client, open, onClose }: { client: Client | null; open: boolean; onClose: () => void }) {
  const [detail, setDetail] = useState<ClientDetail | null>(null);
  const [loading, setLoading] = useState(false);
  const load = useCallback(async () => { if (!client) return; setLoading(true); try { setDetail(await adminApi.getClient(client.id)); } catch (e) { notifyError(e, "加载详情失败"); } finally { setLoading(false); } }, [client]);
  useEffect(() => { if (open && client) void load(); if (!open) setDetail(null); }, [open, client, load]);
  useEffect(() => { if (!open) return; const p = document.body.style.overflow; document.body.style.overflow = "hidden"; return () => { document.body.style.overflow = p; }; }, [open]);

  const info = detail?.client;
  const mappingCount = detail ? detail.specusMappings.length + detail.httpRoutes.length : 0;
  return (
    <>
      <div aria-hidden="true" className={`acc-drawer-scrim${open ? " is-open" : ""}`} onClick={onClose} />
      <aside className={`acc-drawer${open ? " is-open" : ""}`} aria-label={client?.clientName ?? "客户端详情"}>
        <div className="acc-drawer-head">
          <div className="min-w-0">
            <h2 className="acc-drawer-title">{client?.clientName ?? "客户端详情"}</h2>
            {client ? <p className="acc-drawer-sub bd-num">#{client.id}{client.ownerUsername ? ` · ${client.ownerUsername}` : ""}</p> : null}
          </div>
          <button type="button" className="bd-icon-btn" aria-label="关闭" onClick={onClose}><Icon name="x" size={18} /></button>
        </div>
        <div className="acc-drawer-body">
          {loading ? (
            <div className="acc-loading" role="status">
              <span className="bd-skeleton" /><span className="bd-skeleton" /><span className="bd-skeleton" />
              <span className="bd-skeleton-note">正在读取详情…</span>
            </div>
          ) : detail && info ? (
            <>
              <DrawerSection title="状态">
                <div className="bd-row">
                  <Tag tone={info.enabled && info.online ? "success" : "neutral"}>{info.online ? "在线" : "离线"}</Tag>
                  <Tag tone={info.enabled ? "success" : "neutral"} plain={!info.enabled}>{info.enabled ? "已启用" : "已停用"}</Tag>
                </div>
                <dl className="bd-desc acc-desc">
                  {info.online && info.connectedSinceMs ? <Field label="已在线" value={formatElapsed((Date.now() - info.connectedSinceMs) / 1000)} /> : null}
                  <Field label="每分钟上限" value={info.connectionRateLimitPerMinute ? `${info.connectionRateLimitPerMinute} 次` : "不限"} />
                  {info.clientVersion ? <Field label="版本" value={info.clientVersion} /> : null}
                  <Field label="创建" value={formatAbsoluteTime(info.createdAt)} />
                </dl>
              </DrawerSection>
              <DrawerSection title="流量">
                <dl className="bd-desc acc-desc">
                  <Field label="上传" value={formatBytes(info.uploadBytes)} />
                  <Field label="下载" value={formatBytes(info.downloadBytes)} />
                </dl>
              </DrawerSection>
              <DrawerSection title="端口映射" meta={`${mappingCount} 项`}>
                {mappingCount === 0 ? <p className="jd-muted acc-drawer-empty">这台设备还没有端口映射或 HTTP 路由。</p> : (
                  <ul className="acc-drawer-list">
                    {detail.specusMappings.map((t: Specus) => (
                      <li key={`t${t.id}`}>
                        <Icon name="shuffle" size={14} />
                        <span className="acc-drawer-item-text font-mono bd-num" title={`${t.listenPort} → ${t.targetAddress}:${t.targetPort}`}>:{t.listenPort} → {t.targetAddress}:{t.targetPort}</span>
                        <Tag tone={t.enabled ? "success" : "neutral"}>{t.enabled ? "启用" : "停用"}</Tag>
                      </li>
                    ))}
                    {detail.httpRoutes.map((r: HttpRoute) => (
                      <li key={`r${r.id}`}>
                        <Icon name="globe" size={14} />
                        <span className="acc-drawer-item-text font-mono" title={`${r.route} → ${r.targetBaseUrl}`}>{r.route} → {r.targetBaseUrl}</span>
                        <Tag tone={r.authEnabled ? "info" : "warning"} plain>{r.authEnabled ? "Basic" : "公开"}</Tag>
                        <Tag tone={r.enabled ? "success" : "neutral"}>{r.enabled ? "启用" : "停用"}</Tag>
                      </li>
                    ))}
                  </ul>
                )}
              </DrawerSection>
            </>
          ) : <p className="jd-muted acc-drawer-empty">没有读到这台设备的详情，关闭后重新打开再试。</p>}
        </div>
        {detail ? (
          <div className="acc-drawer-foot">
            <Button size="sm" variant="flat" startContent={<Icon name="refresh" size={14} />} onPress={async () => { if (!client) return; try { const r = await adminApi.forceRefreshPortMapping(client.id); notify(`已推送：${r.specusMappings} 个端口映射`); } catch (e) { notifyError(e, "刷新失败"); } }}>强制刷新端口映射</Button>
          </div>
        ) : null}
      </aside>
    </>
  );
}

function DrawerSection({ title, meta, children }: { title: string; meta?: string; children: ReactNode }) {
  return (
    <section className="acc-drawer-section">
      <h3 className="acc-drawer-section-title">{title}{meta ? <span className="bd-num">{meta}</span> : null}</h3>
      {children}
    </section>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return <div><dt>{label}</dt><dd className="bd-num" title={value}>{value}</dd></div>;
}
