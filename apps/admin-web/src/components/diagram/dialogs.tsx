import { useState } from "react";
import type { FormEvent } from "react";
import { Button, Input, Label, Modal, Spinner, TextField, InputGroup } from "@heroui/react";
import { AutoSizeTextArea } from "../AutoSizeTextArea";
import type { UserDiagramDocument } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import type { DiagramDialogRequest, DiagramDialogResult } from "./types";

/**
 * 流程图编辑器的模态对话框：登录、云端文档管理、通用确认/输入。
 *
 * 这三个对话框只依赖入参与 AuthContext，不触碰画布运行时状态，因此独立于主组件。
 */

export function DiagramAccountDialog({
  isOpen,
  onClose,
  onLoggedIn,
}: {
  isOpen: boolean;
  onClose: () => void;
  onLoggedIn: () => void;
}) {
  const {
    oidcConfig,
    loginHint,
    passwordLogin,
    startOidcLogin,
    startOidcRegistration,
  } = useAuth();
  const [username, setUsername] = useState("");
  const [tenantId, setTenantId] = useState("");
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const passwordEnabled = oidcConfig?.passwordLoginEnabled ?? true;
  const oidcEnabled = oidcConfig?.configured ?? false;

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      await passwordLogin(username, password, tenantId.trim() || undefined);
      setPassword("");
      onLoggedIn();
    } catch (loginError) {
      setError(loginError instanceof Error ? loginError.message : "登录失败");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Modal.Root isOpen={isOpen} onOpenChange={(open) => {
        if (!open && !submitting) onClose();
      }}
    >
      <Modal.Backdrop className={"z-[210]! bg-zinc-950/40 backdrop-blur-[6px] dark:bg-black/65"}><Modal.Container className={"z-[220]! px-4 py-6"}><Modal.Dialog className={"diagram-apple-dialog overflow-hidden rounded-2xl border shadow-2xl"}><Modal.CloseTrigger />
        <Modal.Header className="flex flex-col gap-1 border-b border-[var(--diagram-apple-line)] px-5 pb-4 pt-5">
          <Modal.Heading className="text-base font-semibold">登录账号</Modal.Heading>
          <span className="text-[11px] font-normal text-zinc-500 dark:text-zinc-400">{loginHint}</span>
        </Modal.Header>
        <Modal.Body className="gap-3 px-5 py-4">
          {passwordEnabled ? (
            <form id="diagram-account-form" className="grid gap-3" onSubmit={(event) => void submit(event)}>
              <TextField value={tenantId} isDisabled={submitting} onChange={setTenantId}><Label>{"租户 ID（非默认租户填写）"}</Label><Input autoComplete="organization" /></TextField>
              <TextField value={username} isDisabled={submitting} onChange={setUsername}><Label>{"用户名"}</Label><Input autoComplete="username" /></TextField>
              <TextField value={password} isDisabled={submitting} onChange={setPassword}><Label>{"密码"}</Label><Input type="password" autoComplete="current-password" /></TextField>
            </form>
            ) : null}
            {error ? (
            <div className="rounded-lg border border-[var(--diagram-apple-danger)] bg-[var(--diagram-apple-danger-soft)] px-3 py-2 text-[11px] text-[var(--diagram-apple-danger)]">
              {error}
            </div>
            ) : null}
            {!passwordEnabled && !oidcEnabled ? (
            <div className="rounded-lg border border-amber-500/20 bg-amber-50 px-3 py-2 text-[11px] text-amber-800 dark:border-amber-300/20 dark:bg-amber-300/10 dark:text-amber-100">
              当前服务端未启用登录方式。
            </div>
            ) : null}
            </Modal.Body>
            <Modal.Footer className="gap-2 border-t border-[var(--diagram-apple-line)] bg-[var(--diagram-apple-surface-soft)] px-5 py-3">
              <Button size="sm" variant="ghost" isDisabled={submitting} onPress={onClose}>
                取消
              </Button>
              {oidcEnabled ? (
                <Button size="sm" variant="secondary" isDisabled={submitting} onPress={() => void startOidcLogin()}>
                  OIDC 登录
                </Button>
              ) : null}
              {oidcEnabled && oidcConfig?.registrationEndpoint ? (
                <Button size="sm" variant="secondary" isDisabled={submitting} onPress={() => void startOidcRegistration()}>
                  注册 Certus
                </Button>
              ) : null}
              {passwordEnabled ? (
                <Button variant="primary" form="diagram-account-form" type="submit" size="sm" isDisabled={!username.trim() || !password || submitting}
                >{submitting ? <Spinner size="sm" /> : null}
            登录
            </Button>
            ) : null}
            </Modal.Footer>

          </Modal.Dialog>
        </Modal.Container>
      </Modal.Backdrop>
    </Modal.Root>
  );
}

export function DiagramCloudDocumentsDialog({
  isOpen,
  busy,
  currentId,
  documents,
  onClose,
  onDelete,
  onOpen,
  onRefresh,
  onSaveAs,
}: {
  isOpen: boolean;
  busy: boolean;
  currentId: number | null;
  documents: UserDiagramDocument[];
  onClose: () => void;
  onDelete: (document: UserDiagramDocument) => void;
  onOpen: (document: UserDiagramDocument) => void;
  onRefresh: () => void;
  onSaveAs: () => void;
}) {
  return (
    <Modal.Root isOpen={isOpen} onOpenChange={(open) => {
        if (!open && !busy) onClose();
      }}
    >
      <Modal.Backdrop className={"z-[210]! bg-zinc-950/40 backdrop-blur-[6px] dark:bg-black/65"}><Modal.Container className={"z-[220]! px-4 py-6"}><Modal.Dialog className={"diagram-apple-dialog max-h-[min(78dvh,720px)] overflow-hidden rounded-2xl border shadow-2xl"}><Modal.CloseTrigger />
        <Modal.Header className="flex items-center justify-between gap-3 border-b border-[var(--diagram-apple-line)] px-5 pb-4 pt-5">
          <Modal.Heading className="min-w-0">
            <span className="block text-base font-semibold">我的云端文件</span>
            <span className="mt-0.5 block text-[11px] font-normal text-zinc-500 dark:text-zinc-400">{documents.length} 个文件</span>
          </Modal.Heading>
          <span className="flex shrink-0 gap-2 pr-7">
            <Button size="sm" variant={"ghost"} isDisabled={busy} onPress={onRefresh} className={"rounded-small"}>刷新</Button>
            <Button size="sm" variant={"secondary"} isDisabled={busy} onPress={onSaveAs} className={"rounded-small"}>保存当前</Button>
          </span>
        </Modal.Header>
        <Modal.Body className="px-5 pb-5 pt-1">
          {busy && documents.length === 0 ? (
            <div className="flex min-h-40 items-center justify-center gap-2 text-small text-zinc-500 dark:text-zinc-400">
              <span className="h-4 w-4 animate-spin rounded-full border-2 border-[var(--diagram-apple-blue-soft)] border-t-[var(--diagram-apple-blue)]" aria-hidden="true" />
              正在读取云端文件…
            </div>
          ) : documents.length === 0 ? (
            <div className="grid min-h-40 place-items-center rounded-lg border border-dashed border-black/[0.1] bg-white/70 text-small text-zinc-500 dark:border-white/[0.1] dark:bg-white/[0.025] dark:text-zinc-400">
              还没有云端文件
            </div>
            ) : (
            <div className="grid gap-2">
              {documents.map((document) => {
                const isCurrent = currentId === document.id;
                return (
                  <div
                    key={document.id}
                    className={`flex flex-col gap-3 rounded-lg border px-3.5 py-3 sm:flex-row sm:items-center ${isCurrent
                      ? "border-[var(--diagram-apple-blue)] bg-[var(--diagram-apple-blue-soft)]"
                      : "border-black/[0.07] bg-white dark:border-white/[0.08] dark:bg-white/[0.035]"}`}
                  >
                    <div className="min-w-0 flex-1">
                      <div className="flex min-w-0 items-center gap-2">
                        <span className="truncate text-small font-semibold text-zinc-900 dark:text-zinc-100">{document.name}</span>
                        {isCurrent ? <span className="shrink-0 rounded-sm bg-[var(--diagram-apple-blue-soft)] px-1.5 py-0.5 text-[11px] font-semibold text-[var(--diagram-apple-blue)]">当前</span> : null}
                      </div>
                      <div className="mt-1 flex flex-wrap gap-x-2 text-[11px] text-zinc-500 dark:text-zinc-400">
                        <span>{formatCloudDiagramDate(document.updatedAt)}</span>
                        <span>{formatCloudDiagramBytes(document.sizeBytes)}</span>
                        <span>修订 {document.revision}</span>
                      </div>
                    </div>
                    <div className="flex shrink-0 gap-2">
                      <Button size="sm" variant="secondary" isDisabled={busy || isCurrent} onPress={() => onOpen(document)}>
                        {isCurrent ? "已打开" : "打开"}
                      </Button>
                      <Button size="sm" variant="danger" isDisabled={busy} onPress={() => onDelete(document)}>
                        删除
                      </Button>
                    </div>
                  </div>
            );
            })}
            </div>
            )}
            </Modal.Body>
            <Modal.Footer className="border-t border-[var(--diagram-apple-line)] bg-[var(--diagram-apple-surface-soft)] px-5 py-3">
              <Button size="sm" variant="ghost" isDisabled={busy} onPress={onClose}>关闭</Button>
            </Modal.Footer>

          </Modal.Dialog>
        </Modal.Container>
      </Modal.Backdrop>
    </Modal.Root>
  );
}

export function formatCloudDiagramDate(value: string) {
  return formatDiagramTimestamp(value);
}

export function formatDiagramTimestamp(value: string | number) {
  const timestamp = typeof value === "number" ? value : Date.parse(value);
  if (!Number.isFinite(timestamp)) return String(value);
  return new Intl.DateTimeFormat("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(timestamp);
}

export function formatCloudDiagramBytes(value: number) {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / 1024 / 1024).toFixed(1)} MB`;
}

export function DiagramEditorDialog({
  request,
  onResolve,
}: {
  request: DiagramDialogRequest;
  onResolve: (result: DiagramDialogResult) => void;
}) {
  const [value, setValue] = useState(request.initialValue ?? "");
  const canSubmit = request.kind === "confirm" || value.trim().length > 0;
  const submit = () => {
    if (!canSubmit) return;
    onResolve(request.kind === "text" ? value : true);
  };

  return (
    <Modal.Root isOpen onOpenChange={(open) => { if (!open) (() => onResolve(null))?.(); }}
    >
      <Modal.Backdrop variant={"blur"} className={"z-[210]! bg-zinc-950/40 backdrop-blur-[6px] dark:bg-black/65"}><Modal.Container placement={"center"} scroll={"inside"} className={"z-[220]! px-4 py-6"}><Modal.Dialog className={"diagram-apple-dialog max-h-[min(86dvh,620px)] max-w-[440px] overflow-hidden rounded-2xl border shadow-2xl"}><Modal.CloseTrigger className={"text-zinc-500 dark:text-zinc-300"} />
        <form onSubmit={(event) => { event.preventDefault(); submit(); }}>
          <Modal.Header className="flex flex-col gap-1 border-b border-black/[0.07] px-5 pb-4 pt-5 dark:border-white/[0.08]">
            <span className={`text-[11px] font-semibold uppercase ${request.tone === "danger"
              ? "text-[var(--diagram-apple-danger)]"
              : "text-[var(--diagram-apple-blue)]"}`}>专业编辑器</span>
            <Modal.Heading className="pr-8 text-[17px] font-semibold text-zinc-950 dark:text-white">{request.title}</Modal.Heading>
          </Modal.Header>
          <Modal.Body className="gap-4 px-5 py-5">
            {request.message ? (
              <p className="text-[13px] leading-5 text-zinc-600 dark:text-zinc-300">{request.message}</p>
            ) : null}
            {request.kind === "text" ? (
              <div>
                {request.multiline ? (
                  <TextField value={value} onChange={setValue}>
                    <Label className="pb-1 text-[11px] font-semibold text-zinc-700 dark:text-zinc-200">{request.inputLabel}</Label>
                  <AutoSizeTextArea
                    autoFocus
                    placeholder={request.placeholder}
                    value={value}
                    minRows={4}
                    maxRows={9}
                    maxLength={request.maxLength}
                    className="rounded-small border-[var(--diagram-apple-line-strong)] bg-[var(--diagram-apple-surface-soft)] text-[13px] leading-5 text-zinc-950 shadow-none focus:border-[var(--diagram-apple-blue)] dark:text-zinc-50"
                    onFocus={(event) => event.currentTarget.select()}
                    onKeyDown={(event) => {
                      if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
                        event.preventDefault();
                        submit();
                      }
                    }}
                  />
                  </TextField>
                ) : (
                  <TextField value={value} onChange={setValue}><Label className={"pb-1 text-[11px] font-semibold text-zinc-700 dark:text-zinc-200"}>{request.inputLabel}</Label><InputGroup className={"border-[var(--diagram-apple-line-strong)] bg-[var(--diagram-apple-surface-soft)] shadow-none data-[focus=true]:border-[var(--diagram-apple-blue)]"}><Input variant="primary" autoFocus placeholder={request.placeholder} maxLength={request.maxLength} onFocus={(event) => event.currentTarget.select()} className={[("text-[13px] text-zinc-950 dark:text-zinc-50"), ("rounded-small")].filter(Boolean).join(" ")} /></InputGroup></TextField>
                )}
                {request.maxLength ? (
                  <p className="mt-1.5 text-right font-mono text-[11px] text-zinc-400" aria-live="polite">
                    {value.length}/{request.maxLength}
                  </p>
                ) : null}
              </div>
            ) : null}
          </Modal.Body>
          <Modal.Footer className="gap-2 border-t border-[var(--diagram-apple-line)] bg-[var(--diagram-apple-surface-soft)] px-5 py-3">
            <Button type="submit" size="sm" isDisabled={!canSubmit} className={request.tone === "danger"
            ? "font-semibold shadow-none"
            : "bg-[var(--diagram-apple-blue)] font-semibold text-white shadow-none"} variant={"secondary"}
            >
            {request.confirmLabel ?? (request.kind === "text" ? "确定" : "继续")}
            </Button>
            </Modal.Footer>
            </form>

          </Modal.Dialog>
        </Modal.Container>
      </Modal.Backdrop>
    </Modal.Root>
  );
}

