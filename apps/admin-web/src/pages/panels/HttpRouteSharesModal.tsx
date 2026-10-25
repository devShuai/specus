import { useCallback, useEffect, useState } from "react";
import {
  Button,
  Input,
  Modal,
  ModalBody,
  ModalContent,
  ModalFooter,
  ModalHeader,
  Select,
  SelectItem,
} from "@heroui/react";
import { adminApi } from "../../api/client";
import type { HttpRoute } from "../../api/types";
import { copyTextWithFeedback } from "../../lib/clipboard";
import { formatAbsoluteTime } from "../../lib/format";
import { Alert, Icon, RelativeTime, TableWrap, Tag } from "../../components/ui";
import { DesignCheck, DesignRadioRow, RadioCards } from "./accessUi";
import {
  buildCreateShareBody,
  describeAuditEntry,
  emptyShareDraft,
  routeShareBlocker,
  SHARE_EXPIRY_PRESETS,
  SHARE_LABEL_MAX,
  shareLink,
  shareRemaining,
  shareStatusLabel,
  sharingAvailability,
  type HttpAccessAuditEntry,
  type HttpShare,
  type ShareDraft,
  type ShareExpiryUnit,
} from "../../lib/httpShare";
import { notify, notifyError } from "../../components/toast";
import { ConfirmModal } from "../../components/ConfirmModal";

export interface HttpRouteSharesModalProps {
  route: HttpRoute | null;
  clientEnabled: boolean | undefined;
  isOpen: boolean;
  onClose: () => void;
}

/**
 * Temporary shares of one protected route: create (expiry chosen explicitly, read-only by
 * default), show the link once, list and revoke, and the route's access audit.
 */
export function HttpRouteSharesModal({ route, clientEnabled, isOpen, onClose }: HttpRouteSharesModalProps) {
  const [shares, setShares] = useState<HttpShare[]>([]);
  const [loading, setLoading] = useState(false);
  const [draft, setDraft] = useState<ShareDraft>(emptyShareDraft);
  const [creating, setCreating] = useState(false);
  // The link is shown once, kept in component state only and dropped when the dialog closes.
  const [createdLink, setCreatedLink] = useState("");
  const [revoking, setRevoking] = useState<HttpShare | null>(null);
  const [audit, setAudit] = useState<HttpAccessAuditEntry[] | null>(null);
  const [now, setNow] = useState(() => Date.now());

  const availability = typeof window === "undefined"
    ? { available: false, reason: "" }
    : sharingAvailability(window.location);
  const blocker = route ? routeShareBlocker(route, clientEnabled) : "";

  const load = useCallback(async () => {
    if (!route) return;
    setLoading(true);
    try {
      setShares(await adminApi.listHttpShares(route.id));
    } catch (error) {
      notifyError(error, "加载分享失败");
    } finally {
      setLoading(false);
    }
  }, [route]);

  useEffect(() => {
    if (!isOpen) {
      setCreatedLink("");
      setDraft(emptyShareDraft());
      setAudit(null);
      return;
    }
    void load();
    const timer = window.setInterval(() => setNow(Date.now()), 30_000);
    return () => window.clearInterval(timer);
  }, [isOpen, load]);

  const update = (patch: Partial<ShareDraft>) => setDraft((current) => ({ ...current, ...patch }));
  const validation = buildCreateShareBody(draft);
  const canCreate = Boolean(route) && availability.available && !blocker && typeof validation !== "string";

  const create = async () => {
    if (!route || typeof validation === "string") {
      if (typeof validation === "string") notify(validation, "error");
      return;
    }
    setCreating(true);
    try {
      const created = await adminApi.createHttpShare(route.id, validation);
      setCreatedLink(shareLink(window.location.origin, created.linkPath));
      setDraft(emptyShareDraft());
      notify("分享已创建，链接只显示这一次");
      await load();
    } catch (error) {
      notifyError(error, "创建分享失败");
    } finally {
      setCreating(false);
    }
  };

  const revoke = async (share: HttpShare) => {
    if (!route) return;
    try {
      await adminApi.revokeHttpShare(route.id, share.shareId);
      notify("分享已撤销");
      await load();
    } catch (error) {
      notifyError(error, "撤销失败");
    }
  };

  const loadAudit = async () => {
    if (!route) return;
    try {
      setAudit((await adminApi.listHttpRouteAccessAudit(route.id, 50)).entries);
    } catch (error) {
      notifyError(error, "加载审计失败");
    }
  };

  const close = () => {
    setCreatedLink("");
    onClose();
  };

  return (
    <>
      <Modal isOpen={isOpen} onOpenChange={(open) => (open ? undefined : close())} scrollBehavior="inside" size="3xl">
        <ModalContent>
          <ModalHeader className="flex flex-col gap-1">
            <span>临时分享</span>
            <span className="acc-dialog-sub">
              路由 <code className="font-mono">{route?.route}</code>（{route?.clientName}）
            </span>
          </ModalHeader>
          <ModalBody className="acc-dialog-body">
            <Alert tone="info" title="分享不会改变路由的访问认证">
              <p>路由自己的访问链接仍需用户名和密码，访客也拿不到这组密码。</p>
              <p>路由被停用、改为公开或删除，客户端被停用，或创建者失去管理权时，分享立即失效且不会恢复。</p>
            </Alert>
            {!availability.available ? (
              <Alert tone="warning" role="alert">{availability.reason}</Alert>
            ) : blocker ? (
              <Alert tone="info" role="status">{blocker}</Alert>
            ) : (
              <ShareCreateForm
                draft={draft}
                update={update}
                validation={typeof validation === "string" ? validation : ""}
                detailCaptureEnabled={Boolean(route?.detailCaptureEnabled)}
              />
            )}
            {createdLink ? (
              <div className="bd-alert bd-alert--success acc-share-created" role="status">
                <Icon name="circle-check" />
                <div className="min-w-0 flex-1">
                  <div className="bd-alert-title">分享链接（只显示这一次，关闭后无法再次查看）</div>
                  <code className="acc-code-line font-mono">{createdLink}</code>
                </div>
                <Button size="sm" variant="flat" startContent={<Icon name="copy" size={14} />} onPress={() => void copyTextWithFeedback(createdLink, "分享链接已复制")}>
                  复制链接
                </Button>
              </div>
            ) : null}
            <section aria-label="分享列表" className="acc-dialog-section">
              <div className="acc-dialog-section-head">
                <h3>分享列表</h3>
                <span className="acc-head-count bd-num">{shares.length ? `${shares.length} 个` : ""}</span>
                <Button size="sm" variant="light" isLoading={loading} startContent={loading ? null : <Icon name="refresh" size={14} />} onPress={() => void load()}>
                  刷新
                </Button>
              </div>
              {shares.length === 0 ? (
                <p className="acc-dialog-empty">{loading ? "正在读取分享…" : "还没有分享；在上面选好有效期后创建。"}</p>
              ) : (
                <TableWrap>
                  <table className="bd-table bd-table--compact jd-stack acc-share-table">
                    <thead>
                      <tr>
                        <th>备注</th>
                        <th>访问</th>
                        <th>路径</th>
                        <th>到期</th>
                        <th>状态</th>
                        <th className="jd-col-actions"><span className="jd-sr-only">操作</span></th>
                      </tr>
                    </thead>
                    <tbody>
                      {shares.map((share) => (
                        <tr key={share.shareId}>
                          <td>
                            <div className="jd-table-title">
                              <span className={share.label ? "font-medium" : "jd-subtle"}>{share.label || "（无备注）"}</span>
                              <span className="jd-table-sub">创建者 {share.createdBy}</span>
                            </div>
                          </td>
                          <td><Tag tone={share.access === "full" ? "warning" : "neutral"} plain>{share.access === "full" ? "完整访问" : "只读"}</Tag></td>
                          <td data-label="路径"><code className="font-mono">{share.pathPrefix}</code></td>
                          <td data-label="到期">
                            <span className="bd-num" title={share.expiresAt}>
                              {formatAbsoluteTime(share.expiresAt)}
                              {share.status === "active" ? <span className="jd-subtle"> · {shareRemaining(share.expiresAt, now)}</span> : null}
                            </span>
                          </td>
                          <td><Tag tone={share.status === "active" ? "success" : "neutral"}>{shareStatusLabel(share)}</Tag></td>
                          <td className="jd-cell-actions">
                            {share.status === "active" ? (
                              <Button size="sm" color="danger" variant="flat" onPress={() => setRevoking(share)}>
                                撤销
                              </Button>
                            ) : null}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </TableWrap>
              )}
            </section>
            <section aria-label="访问审计" className="acc-dialog-section">
              <div className="acc-dialog-section-head">
                <h3>访问审计</h3>
                <span className="acc-head-count bd-num">{audit?.length ? `最近 ${audit.length} 条` : ""}</span>
                <Button size="sm" variant="light" startContent={<Icon name="history" size={14} />} onPress={() => void loadAudit()}>
                  {audit ? "刷新审计" : "查看审计"}
                </Button>
              </div>
              {audit ? (
                audit.length === 0 ? (
                  <p className="acc-dialog-empty">还没有访问记录。</p>
                ) : (
                  <ul className="acc-audit">
                    {audit.map((entry) => (
                      <li key={entry.auditId}>
                        <RelativeTime className="acc-audit-time" value={entry.at} />
                        <span className="acc-audit-actor">{entry.actor ?? "系统"}</span>
                        <span className="acc-audit-text">{describeAuditEntry(entry)}</span>
                      </li>
                    ))}
                  </ul>
                )
              ) : null}
            </section>
          </ModalBody>
          <ModalFooter>
            <Button variant="flat" onPress={close}>
              关闭
            </Button>
            {availability.available && !blocker ? (
              <Button color="primary" isDisabled={!canCreate} isLoading={creating} startContent={creating ? null : <Icon name="share" />} onPress={() => void create()}>
                创建分享
              </Button>
            ) : null}
          </ModalFooter>
        </ModalContent>
      </Modal>
      <ConfirmModal
        isOpen={revoking != null}
        onClose={() => setRevoking(null)}
        onConfirm={() => (revoking ? revoke(revoking) : undefined)}
        title="撤销分享"
        description="撤销后持有链接的访客立即失去访问，正在进行的连接也会被切断；撤销不能恢复，需要时请重新创建。"
        confirmLabel="撤销"
        danger
      />
    </>
  );
}

function ShareCreateForm({
  draft,
  update,
  validation,
  detailCaptureEnabled,
}: {
  draft: ShareDraft;
  update: (patch: Partial<ShareDraft>) => void;
  validation: string;
  detailCaptureEnabled: boolean;
}) {
  return (
    <section aria-label="创建分享" className="bd-card acc-share-form">
      <DesignRadioRow
        legend="有效期（必选）"
        value={draft.expiry}
        options={[...SHARE_EXPIRY_PRESETS.map((preset) => ({ key: preset.key, label: preset.label })), { key: "custom", label: "自定义" }]}
        onChange={(expiry) => update({ expiry })}
      />
      {draft.expiry === "custom" ? (
        <div className="acc-share-custom">
          <Input
            className="acc-share-amount"
            inputMode="numeric"
            label="时长"
            value={draft.customAmount}
            onValueChange={(customAmount) => update({ customAmount })}
          />
          <Select
            className="acc-share-unit"
            label="单位"
            selectedKeys={[draft.customUnit]}
            onChange={(event) => update({ customUnit: (event.target.value || "hours") as ShareExpiryUnit })}
          >
            <SelectItem key="minutes">分钟</SelectItem>
            <SelectItem key="hours">小时</SelectItem>
            <SelectItem key="days">天</SelectItem>
          </Select>
          <p className="bd-help acc-share-custom-help">5 分钟到 7 天之间；不提供永久分享，长期访问请使用路由自己的访问密码。</p>
        </div>
      ) : null}
      <RadioCards
        legend="访问方式"
        value={draft.access === "full" ? "full" : "read"}
        onChange={(access) => update({ access: access === "full" ? "full" : "read", fullAccessConfirmed: false })}
        options={[
          { key: "read", title: "只读（GET / HEAD）", description: "按请求方法过滤，不能保证目标应用的 GET 请求没有副作用。" },
          { key: "full", title: "完整", description: "访客可以提交表单、修改数据和建立 WebSocket 连接。" },
        ]}
      />
      {draft.access === "full" ? (
        <div className="bd-alert bd-alert--warning acc-confirm-box">
          <Icon name="alert" />
          <DesignCheck checked={draft.fullAccessConfirmed} onChange={(fullAccessConfirmed) => update({ fullAccessConfirmed })}>
            我了解完整访问允许访客提交表单、修改数据和建立 WebSocket 连接
          </DesignCheck>
        </div>
      ) : null}
      <div className="acc-field-pair">
        <Input
          description="留空表示整条路由，例如 /docs/"
          label="路径前缀（可选）"
          placeholder="/"
          value={draft.pathPrefix}
          onValueChange={(pathPrefix) => update({ pathPrefix })}
        />
        <Input
          description="仅用于你辨认分享，不写入审计"
          label="备注（可选）"
          maxLength={SHARE_LABEL_MAX}
          value={draft.label}
          onValueChange={(label) => update({ label })}
        />
      </div>
      {detailCaptureEnabled ? (
        <p className="acc-publish-warn"><Icon name="alert" size={14} />该路由开启了明细采集：访客的请求内容会被记录。</p>
      ) : null}
      {validation && draft.expiry ? <p className="bd-help bd-help--error">{validation}</p> : null}
    </section>
  );
}
