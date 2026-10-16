import { ApiError } from "../api/client";
import type { ManagementUser, OwnedResourceCounts, OwnerTransferPreview, OwnerTransferRequest, OwnerTransferResult } from "../api/types";

export const OWNER_TRANSFER_WARNING = "仅转移管理归属。原接入密钥与有效客户端会话保留，持有密钥的人仍可接入；这不是安全交接。";
export type TransferResource = { kind: "client" | "credential"; id: number };
export interface OwnerTransferPort {
  preview: (resource: TransferResource) => Promise<unknown>;
  users: () => Promise<ManagementUser[]>;
  submit: (resource: TransferResource, request: OwnerTransferRequest) => Promise<unknown>;
}
export interface TransferState {
  resource: TransferResource | null;
  phase: "loading" | "review" | "submitting" | "unknown" | "success" | "error";
  preview: OwnerTransferPreview | null;
  users: ManagementUser[];
  target: string;
  confirmed: boolean;
  message: string;
  result: OwnerTransferResult | null;
}
const object = (value: unknown): value is Record<string, unknown> => !!value && typeof value === "object" && !Array.isArray(value);
const id = (value: unknown): value is number => Number.isSafeInteger(value) && Number(value) > 0;
const nullableText = (value: unknown) => value === null || typeof value === "string";
const invalidPreview = () => new Error("服务端未返回完整、可确认的影响清单。请刷新预览；不要直接提交转移。");

/** Fail closed on incomplete/unsafe previews. Only copy public contract fields, never credentials. */
export function readTransferPreview(value: unknown, resource: TransferResource): OwnerTransferPreview {
  if (!object(value) || value.scope !== (resource.kind === "client" ? "single" : "credential-group")
    || value.accessRetained !== true || typeof value.canTransfer !== "boolean"
    || (resource.kind === "client" ? value.clientId !== resource.id : value.clientId !== null || value.credentialId !== resource.id)
    || !(value.credentialId === null || id(value.credentialId)) || !nullableText(value.credentialOwnerUsername)
    || !(value.credentialEnabled === null || typeof value.credentialEnabled === "boolean")
    || !Array.isArray(value.affectedClients) || value.affectedClientCount !== value.affectedClients.length) throw invalidPreview();
  if (value.credentialId === null && (value.credentialOwnerUsername !== null || value.credentialEnabled !== null)) throw invalidPreview();
  if (value.credentialId !== null && typeof value.credentialEnabled !== "boolean") throw invalidPreview();
  if (value.canTransfer ? typeof value.revision !== "string" || !value.revision.trim() || value.conflictCode !== null
    : value.conflictCode !== "CREDENTIAL_SHARED" || value.revision !== null || !id(value.credentialId) || resource.kind !== "client") throw invalidPreview();
  const seen = new Set<number>();
  const clients = value.affectedClients.map((row: unknown) => {
    if (!object(row) || !id(row.id) || seen.has(row.id) || typeof row.clientName !== "string"
      || !nullableText(row.ownerUsername) || typeof row.enabled !== "boolean") throw invalidPreview();
    seen.add(row.id);
    return { id: row.id, clientName: row.clientName, ownerUsername: row.ownerUsername as string | null, enabled: row.enabled };
  }).sort((a, b) => a.id - b.id);
  if (resource.kind === "client" && (!seen.has(resource.id) || (value.canTransfer && clients.length !== 1))) throw invalidPreview();
  if (!value.canTransfer && clients.length < 2) throw invalidPreview();
  return { scope: resource.kind === "client" ? "single" : "credential-group", clientId: value.clientId as number | null, credentialId: value.credentialId as number | null,
    credentialOwnerUsername: value.credentialOwnerUsername as string | null, credentialEnabled: value.credentialEnabled as boolean | null,
    affectedClients: clients, affectedClientCount: clients.length, canTransfer: value.canTransfer,
    conflictCode: value.conflictCode as "CREDENTIAL_SHARED" | null, revision: value.revision as string | null, accessRetained: true };
}
function readResult(value: unknown, preview: OwnerTransferPreview, target: string): OwnerTransferResult {
  if (!object(value) || value.scope !== preview.scope || value.targetUsername !== target
    || value.credentialId !== preview.credentialId || value.accessRetained !== true || typeof value.changed !== "boolean"
    || !Array.isArray(value.affectedClientIds) || value.affectedClientIds.length !== preview.affectedClientCount) throw new Error("转移响应不完整");
  const ids = value.affectedClientIds;
  if (ids.some((entry, i) => !id(entry) || entry !== preview.affectedClients[i]?.id)) throw new Error("转移响应范围不一致");
  return { scope: preview.scope, targetUsername: target, credentialId: preview.credentialId,
    affectedClientIds: [...ids] as number[], changed: value.changed, accessRetained: true };
}
export const transferCanSubmit = (state: TransferState) => state.phase === "review" && !!state.preview?.canTransfer
  && !!state.preview.revision && state.confirmed && state.users.some(user => user.enabled && user.username === state.target);

/** One controller per dialog. Generation fencing prevents stale reads/results crossing resources. */
export class OwnerTransferController {
  private state: TransferState = { resource: null, phase: "loading", preview: null, users: [], target: "", confirmed: false, message: "", result: null };
  private listeners = new Set<() => void>();
  private generation = 0;
  constructor(private readonly port: OwnerTransferPort) {}
  snapshot = () => this.state;
  subscribe = (listener: () => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  private update(patch: Partial<TransferState>) { this.state = { ...this.state, ...patch }; this.listeners.forEach(listener => listener()); }
  dispose() { ++this.generation; this.listeners.clear(); }
  async load(resource: TransferResource, message = "", preserveTarget = false) {
    if (this.state.phase === "submitting") return;
    const generation = ++this.generation;
    this.update({ resource, phase: "loading", preview: null, confirmed: false, message, result: null, target: preserveTarget ? this.state.target : "" });
    try {
      if (!id(resource.id)) throw invalidPreview();
      const [raw, users] = await Promise.all([this.port.preview(resource), this.port.users()]);
      const preview = readTransferPreview(raw, resource);
      if (generation !== this.generation) return;
      const available = users.filter(user => user.enabled && typeof user.username === "string");
      this.update({ phase: "review", preview, users: available });
    } catch (error) {
      if (generation !== this.generation) return;
      this.update({ phase: "error", message: describeTransferError(error), users: [] });
    }
  }
  setTarget(target: string) { if (this.state.phase === "review") this.update({ target, confirmed: false }); }
  confirm(confirmed: boolean) { if (this.state.phase === "review") this.update({ confirmed }); }
  refresh() { if (this.state.resource) return this.load(this.state.resource, this.state.phase === "unknown"
    ? "已重新读取当前归属。上次提交结果无法确认，请核对清单；如仍需转移，须再次确认。" : "已刷新影响清单，请再次确认。", true); }
  group() {
    const credentialId = this.state.preview?.credentialId;
    if (this.state.phase === "review" && this.state.preview?.conflictCode === "CREDENTIAL_SHARED" && credentialId)
      return this.load({ kind: "credential", id: credentialId }, "已切换至整组预览，请核对全部设备并重新确认。", true);
  }
  async submit(): Promise<OwnerTransferResult | null> {
    if (!transferCanSubmit(this.state)) return null;
    const { resource, preview, target } = this.state;
    const generation = this.generation;
    this.update({ phase: "submitting", confirmed: false, message: "" });
    try {
      const raw = await this.port.submit(resource!, { scope: preview!.scope, targetUsername: target, expectedRevision: preview!.revision! });
      const result = readResult(raw, preview!, target);
      if (generation !== this.generation) return null;
      this.update({ phase: "success", result });
      return result;
    } catch (error) {
      if (generation !== this.generation) return null;
      if (error instanceof ApiError && error.status >= 400 && error.status < 500 && error.status !== 408) {
        this.update({ phase: "review", message: describeTransferError(error) });
        if (error.status === 409 || error.code === "INVALID_TARGET_OWNER") await this.load(resource!, describeTransferError(error), true);
        else if (error.status === 403 || error.status === 404) this.update({ phase: "error" });
      } else this.update({ phase: "unknown", message: "无法确认是否已提交，暂不重复转移。请先重新读取当前归属，再决定是否需要再次确认。" });
      return null;
    }
  }
}
export function describeTransferError(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 403) return "当前账号不再具有转移权限，请刷新登录状态。";
    if (error.status === 404) return error.code === "RESOURCE_NOT_FOUND" ? "该资源已不存在或不再属于当前租户。请返回列表刷新。" : "当前服务端未提供此转移入口，请确认已部署支持该功能的版本。";
    switch (error.code) {
      case "TRANSFER_PREVIEW_CHANGED": return "影响范围或归属已变化，已重新预览。目标选择保留，请核对新清单并再次确认。";
      case "CREDENTIAL_SHARED": return "此凭证还关联其他设备，不能只转移这一台。请进入整组预览后显式确认。";
      case "INCONSISTENT_CREDENTIAL_GROUP": return "凭证关联关系不完整，不能安全转移。请先修复关联关系再刷新预览。";
      case "INVALID_TARGET_OWNER": return "目标账号不存在、已停用或不属于当前租户。请选择当前已启用的账号。";
    }
  }
  return error instanceof Error ? error.message : "读取失败，请刷新预览后重试。";
}
export const ownerResourcesHash = (username: string, section: "clients" | "credentials") =>
  `#/clients?owner=${encodeURIComponent(username)}&section=${section}`;
export const sameOwner = (a: string | null | undefined, b: string) => (a ?? "").trim().toLowerCase() === b.trim().toLowerCase();
export function countOwnedResources(username: string, clients: { ownerUsername?: string | null }[], credentials: { ownerUsername?: string | null }[]): OwnedResourceCounts {
  return { clients: clients.filter(row => sameOwner(row.ownerUsername, username)).length,
    credentials: credentials.filter(row => sameOwner(row.ownerUsername, username)).length };
}
