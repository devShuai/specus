import { useCallback, useEffect, useState } from "react";
import {
  Button,
  Checkbox,
  Chip,
  Input,
  Modal,
  ModalBody,
  ModalContent,
  ModalFooter,
  ModalHeader,
  Radio,
  RadioGroup,
  Select,
  SelectItem,
} from "@heroui/react";
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
      <Modal isOpen={isOpen} onOpenChange={(open) => (open ? undefined : close())} scrollBehavior="inside" size="3xl">
        <ModalContent>
          <ModalHeader className="flex flex-col gap-1">
            <span>临时分享</span>
            <span className="text-small font-normal text-default-500">
              路由 <code>{route?.route}</code>（{route?.clientName}）
            </span>
          </ModalHeader>
          <ModalBody className="gap-4">
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
                  <Button size="sm" variant="flat" onPress={() => void copyTextWithFeedback(createdLink, "分享链接已复制")}>
                    复制链接
                  </Button>
                </div>
              </div>
            ) : null}
            <section aria-label="分享列表">
              <div className="mb-2 flex items-center justify-between">
                <h3 className="text-small font-semibold">分享列表</h3>
                <Button size="sm" variant="light" isLoading={loading} onPress={() => void load()}>
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
                      <Chip size="sm" variant="flat" color={share.access === "full" ? "warning" : "default"}>
                        {share.access === "full" ? "完整访问" : "只读"}
                      </Chip>
                      <code className="break-all">{share.pathPrefix}</code>
                      <span className="text-default-500">创建者 {share.createdBy}</span>
                      <span className="text-default-500" title={share.expiresAt}>
                        到期 {formatDateTime(share.expiresAt)}
                        {share.status === "active" ? ` · ${shareRemaining(share.expiresAt, now)}` : ""}
                      </span>
                      <Chip size="sm" variant="dot" color={share.status === "active" ? "success" : "default"}>
                        {shareStatusLabel(share)}
                      </Chip>
                      {share.status === "active" ? (
                        <Button className="ml-auto" size="sm" color="danger" variant="flat" onPress={() => setRevoking(share)}>
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
                <Button size="sm" variant="light" onPress={() => void loadAudit()}>
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
          </ModalBody>
          <ModalFooter>
            <Button variant="flat" onPress={close}>
              关闭
            </Button>
            {availability.available && !blocker ? (
              <Button color="primary" isDisabled={!canCreate} isLoading={creating} onPress={() => void create()}>
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
    <section aria-label="创建分享" className="flex flex-col gap-3">
      <RadioGroup
        label="有效期（必选）"
        orientation="horizontal"
        value={draft.expiry}
        onValueChange={(expiry) => update({ expiry })}
      >
        {SHARE_EXPIRY_PRESETS.map((preset) => (
          <Radio key={preset.key} value={preset.key}>
            {preset.label}
          </Radio>
        ))}
        <Radio value="custom">自定义</Radio>
      </RadioGroup>
      {draft.expiry === "custom" ? (
        <div className="flex flex-wrap gap-2">
          <Input
            className="w-36"
            inputMode="numeric"
            label="时长"
            value={draft.customAmount}
            onValueChange={(customAmount) => update({ customAmount })}
          />
          <Select
            className="w-32"
            label="单位"
            selectedKeys={[draft.customUnit]}
            onChange={(event) => update({ customUnit: (event.target.value || "hours") as ShareExpiryUnit })}
          >
            <SelectItem key="minutes">分钟</SelectItem>
            <SelectItem key="hours">小时</SelectItem>
            <SelectItem key="days">天</SelectItem>
          </Select>
          <p className="w-full text-tiny text-default-500">5 分钟到 7 天之间；不提供永久分享，长期访问请使用路由自己的访问密码。</p>
        </div>
      ) : null}
      <RadioGroup
        label="访问方式"
        orientation="horizontal"
        value={draft.access}
        onValueChange={(access) => update({ access: access === "full" ? "full" : "read", fullAccessConfirmed: false })}
      >
        <Radio value="read">只读（GET / HEAD）</Radio>
        <Radio value="full">完整</Radio>
      </RadioGroup>
      {draft.access === "read" ? (
        <p className="text-tiny text-default-500">只读按请求方法过滤，不能保证目标应用的 GET 请求没有副作用。</p>
      ) : (
        <Checkbox isSelected={draft.fullAccessConfirmed} onValueChange={(fullAccessConfirmed) => update({ fullAccessConfirmed })}>
          我了解完整访问允许访客提交表单、修改数据和建立 WebSocket 连接
        </Checkbox>
      )}
      <div className="grid gap-3 sm:grid-cols-2">
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
        <p className="text-tiny text-warning">该路由开启了明细采集：访客的请求内容会被记录。</p>
      ) : null}
      {validation && draft.expiry ? <p className="text-tiny text-danger">{validation}</p> : null}
    </section>
  );
}
