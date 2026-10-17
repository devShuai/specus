import { useCallback, useEffect, useState } from "react";
import { Button, Checkbox, Chip, Input, Modal, Radio, RadioGroup, Select, Spinner, Label, TextField, Description, SelectTrigger, SelectValue, SelectIndicator, SelectPopover, ListBox, ListBoxItem } from "@heroui/react";
import { adminApi } from "../../api/client";
import type { HttpRoute } from "../../api/types";
import { copyTextWithFeedback } from "../../lib/clipboard";
import { formatDateTime } from "../../lib/format";
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
      <Modal.Root isOpen={isOpen} onOpenChange={(open) => (open ? undefined : close())}>
        <Modal.Backdrop><Modal.Container scroll={"inside"} size={"lg"}><Modal.Dialog className={"max-w-3xl"}><Modal.CloseTrigger />
          <Modal.Header className="flex flex-col gap-1">
            <Modal.Heading>临时分享</Modal.Heading>
            <span className="text-small font-normal text-default-500">
              路由 <code>{route?.route}</code>（{route?.clientName}）
            </span>
          </Modal.Header>
          <Modal.Body className="gap-4">
            <div className="rounded-medium border border-default-200 bg-default-50/70 p-3 text-tiny text-default-600">
              <p>分享不会改变路由的访问认证：路由自己的访问链接仍需用户名和密码，访客也拿不到这组密码。</p>
              <p className="mt-1">路由被停用、改为公开或删除，客户端被停用，或创建者失去管理权时，分享立即失效且不会恢复。</p>
            </div>
            {!availability.available ? (
              <p className="rounded-medium border border-warning-200 bg-warning-50 p-3 text-small text-warning-700" role="alert">
                {availability.reason}
              </p>
            ) : blocker ? (
              <p className="rounded-medium border border-default-200 p-3 text-small text-default-600" role="status">
                {blocker}
              </p>
            ) : (
              <ShareCreateForm
                draft={draft}
                update={update}
                validation={typeof validation === "string" ? validation : ""}
                detailCaptureEnabled={Boolean(route?.detailCaptureEnabled)}
              />
            )}
            {createdLink ? (
              <div className="flex min-w-0 flex-col gap-2 rounded-medium border border-success-200 bg-success-50 p-3 text-small" role="status">
                <span className="font-semibold text-success">分享链接（只显示这一次，关闭后无法再次查看）</span>
                <code className="break-all font-mono">{createdLink}</code>
                <div className="flex gap-2">
                  <Button size="sm" variant={"secondary"} onPress={() => void copyTextWithFeedback(createdLink, "分享链接已复制")}>
                    复制链接
                  </Button>
                </div>
              </div>
            ) : null}
            <section aria-label="分享列表">
              <div className="mb-2 flex items-center justify-between">
                <h3 className="text-small font-semibold">分享列表</h3>
                <Button size="sm" variant={"ghost"} isPending={loading} onPress={() => void load()}>{(loading) ? <Spinner size="sm" aria-hidden="true" /> : null}
                  刷新
                </Button>
              </div>
              {shares.length === 0 ? (
                <p className="text-small text-default-500">{loading ? "加载中…" : "还没有分享"}</p>
              ) : (
                <ul className="flex flex-col gap-2">
                  {shares.map((share) => (
                    <li key={share.shareId} className="flex flex-wrap items-center gap-x-3 gap-y-1 rounded-medium border border-default-200 p-2 text-small">
                      <span className="font-medium">{share.label || "（无备注）"}</span>
                      <Chip size="sm" variant={"soft"} color={share.access === "full" ? "warning" : "default"}>
                        {share.access === "full" ? "完整访问" : "只读"}
                      </Chip>
                      <code className="break-all">{share.pathPrefix}</code>
                      <span className="text-default-500">创建者 {share.createdBy}</span>
                      <span className="text-default-500" title={share.expiresAt}>
                        到期 {formatDateTime(share.expiresAt)}
                        {share.status === "active" ? ` · ${shareRemaining(share.expiresAt, now)}` : ""}
                      </span>
                      <Chip size="sm" variant={"secondary"} color={share.status === "active" ? "success" : "default"} className={"border border-current/20 bg-transparent"}><span aria-hidden="true" className="size-1.5 rounded-full bg-current" />
                        {shareStatusLabel(share)}
                      </Chip>
                      {share.status === "active" ? (
                        <Button className="ml-auto" size="sm" variant={"danger-soft"} onPress={() => setRevoking(share)}>
                          撤销
                        </Button>
                      ) : null}
                    </li>
                  ))}
                </ul>
              )}
            </section>
            <section aria-label="访问审计">
              <div className="mb-2 flex items-center justify-between">
                <h3 className="text-small font-semibold">访问审计</h3>
                <Button size="sm" variant={"ghost"} onPress={() => void loadAudit()}>
                  {audit ? "刷新审计" : "查看审计"}
                </Button>
              </div>
              {audit ? (
                audit.length === 0 ? (
                  <p className="text-small text-default-500">暂无记录</p>
                ) : (
                  <ul className="flex flex-col gap-1 text-tiny">
                    {audit.map((entry) => (
                      <li key={entry.auditId} className="flex flex-wrap gap-x-2">
                        <span className="text-default-500">{formatDateTime(entry.at)}</span>
                        <span>{entry.actor ?? "系统"}</span>
                        <span>{describeAuditEntry(entry)}</span>
                      </li>
                    ))}
                  </ul>
                )
              ) : null}
            </section>
          </Modal.Body>
          <Modal.Footer>
            <Button variant={"secondary"} onPress={close}>
              关闭
            </Button>
            {availability.available && !blocker ? (
              <Button isDisabled={!canCreate} isPending={creating} onPress={() => void create()} variant={"primary"}>{(creating) ? <Spinner size="sm" aria-hidden="true" /> : null}
                创建分享
              </Button>
            ) : null}
          </Modal.Footer>
        </Modal.Dialog></Modal.Container></Modal.Backdrop>
      </Modal.Root>
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
    <section aria-label="创建分享" className="flex flex-col gap-3">
      <RadioGroup orientation="horizontal" value={draft.expiry} onChange={(expiry) => update({ expiry })}
      ><Label>{"有效期（必选）"}</Label>
        {SHARE_EXPIRY_PRESETS.map((preset) => (
          <Radio key={preset.key} value={preset.key}><Radio.Content><Radio.Control><Radio.Indicator /></Radio.Control><Label>
            {preset.label}
          </Label></Radio.Content></Radio>
        ))}
        <Radio value="custom"><Radio.Content><Radio.Control><Radio.Indicator /></Radio.Control><Label>自定义</Label></Radio.Content></Radio>
      </RadioGroup>
      {draft.expiry === "custom" ? (
        <div className="flex flex-wrap gap-2">
          <TextField value={draft.customAmount} onChange={(customAmount) => update({ customAmount })} className={[("w-36")].filter(Boolean).join(" ")}><Label>{"时长"}</Label><Input inputMode="numeric" /></TextField>
          <Select className="w-32" onChange={(nativeSelectionValue) => update({ customUnit: (String(nativeSelectionValue ?? "") || "hours") as ShareExpiryUnit })} value={(Array.from([draft.customUnit])[0] ?? null)}
          ><Label>{"单位"}</Label><SelectTrigger><SelectValue /><SelectIndicator /></SelectTrigger><SelectPopover><ListBox>
            <ListBoxItem key="minutes" id={"minutes"} textValue={"分钟"}>分钟</ListBoxItem>
            <ListBoxItem key="hours" id={"hours"} textValue={"小时"}>小时</ListBoxItem>
            <ListBoxItem key="days" id={"days"} textValue={"天"}>天</ListBoxItem>
          </ListBox></SelectPopover></Select>
          <p className="w-full text-tiny text-default-500">5 分钟到 7 天之间；不提供永久分享，长期访问请使用路由自己的访问密码。</p>
        </div>
      ) : null}
      <RadioGroup orientation="horizontal" value={draft.access} onChange={(access) => update({ access: access === "full" ? "full" : "read", fullAccessConfirmed: false })}
      ><Label>{"访问方式"}</Label>
        <Radio value="read"><Radio.Content><Radio.Control><Radio.Indicator /></Radio.Control><Label>只读（GET / HEAD）</Label></Radio.Content></Radio>
        <Radio value="full"><Radio.Content><Radio.Control><Radio.Indicator /></Radio.Control><Label>完整</Label></Radio.Content></Radio>
      </RadioGroup>
      {draft.access === "read" ? (
        <p className="text-tiny text-default-500">只读按请求方法过滤，不能保证目标应用的 GET 请求没有副作用。</p>
      ) : (
        <Checkbox isSelected={draft.fullAccessConfirmed} onChange={(fullAccessConfirmed) => update({ fullAccessConfirmed })}><Checkbox.Content><Checkbox.Control><Checkbox.Indicator /></Checkbox.Control><Label>
          我了解完整访问允许访客提交表单、修改数据和建立 WebSocket 连接
        </Label></Checkbox.Content></Checkbox>
      )}
      <div className="grid gap-3 sm:grid-cols-2">
        <TextField value={draft.pathPrefix} onChange={(pathPrefix) => update({ pathPrefix })}><Label>{"路径前缀（可选）"}</Label><Input placeholder="/" /><Description>{"留空表示整条路由，例如 /docs/"}</Description></TextField>
        <TextField value={draft.label} onChange={(label) => update({ label })}><Label>{"备注（可选）"}</Label><Input maxLength={SHARE_LABEL_MAX} /><Description>{"仅用于你辨认分享，不写入审计"}</Description></TextField>
      </div>
      {detailCaptureEnabled ? (
        <p className="text-tiny text-warning">该路由开启了明细采集：访客的请求内容会被记录。</p>
      ) : null}
      {validation && draft.expiry ? <p className="text-tiny text-danger">{validation}</p> : null}
    </section>
  );
}
