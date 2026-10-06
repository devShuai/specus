import { useCallback, useEffect, useMemo, useRef, useState, type MouseEvent, type ReactNode } from "react";
import { Button, Modal, ModalBody, ModalContent, ModalFooter, ModalHeader, Spinner } from "@heroui/react";
import { adminApi, recordWorkbenchOpenAsCaller } from "../../api/client";
import type {
  Client,
  HttpRoute,
  PeerMeshServiceSharing,
  PeerMeshSharedService,
  Specus,
  WorkbenchDocument,
  WorkbenchRef,
} from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { ConfirmModal } from "../../components/ConfirmModal";
import { StatusChip } from "../../components/StatusChip";
import { notify } from "../../components/toast";
import { useNowTick } from "../../hooks/useNowTick";
import { copyTextWithFeedback } from "../../lib/clipboard";
import { formatDateTime } from "../../lib/format";
import {
  KIND_LABELS,
  clientsById,
  collectServices,
  formatClock,
  httpRouteAccessUrl,
  isFavorite,
  isWorkbenchUnsupported,
  peerOpenUrl,
  refKey,
  serviceClientName,
  serviceName,
  serviceTarget,
  type WorkbenchService,
} from "../../lib/workbenchModel";
import {
  ATTENTION_NOTE,
  MULTI_INSTANCE_OFFLINE_CAVEAT,
  NO_KNOWN_PROBLEM,
  NO_KNOWN_PROBLEM_CAVEAT,
  PROBLEMS_REFRESH_MS,
  PROBLEMS_STALE_AFTER_MS,
  SOURCE_LABELS,
  derivePendingProblems,
  problemInputFromReads,
  problemNextStep,
  problemTitle,
  sourceStateOfError,
  type PendingProblem,
  type PendingProblems,
  type ProblemCode,
  type SourceRead,
  type WorkbenchReads,
} from "../../lib/workbenchProblems";
import { copyThenRecord, isLinkOpeningClick, type WorkbenchOpenAction } from "../../lib/workbenchRecording";
import { peerServiceAvailability } from "./peerMeshServicesModel";

// The service workbench: favourites and recent opens kept per identity on the server (held here in
// memory only), pending problems derived from the lists this page reads, the merged service list
// and one entry to the three existing publish forms. Loading the page only reads; it never writes.

type DocumentState =
  | { status: "loading" }
  | { status: "ready"; document: WorkbenchDocument }
  | { status: "failed" }
  | { status: "unsupported" };

const MARKERS: Record<ProblemCode, string> = {
  DEVICE_DISABLED: "设备已停用",
  DEVICE_OFFLINE: "设备离线",
  PEER_SHARING_OFF: "服务共享已关闭",
  PEER_NOT_REPORTED: "未上报 · 原因未定",
  PEER_DIRECTORY_EXPIRED: "目录已过期 · 原因未定",
  PEER_NOT_ADVERTISED: "未发布 · 原因未定",
};

async function readSource<T>(load: () => Promise<T>, valid: (data: unknown) => boolean): Promise<SourceRead<T>> {
  try {
    const data = await load();
    return valid(data) ? { state: "ok", data } : { state: "failed" };
  } catch (error) {
    return { state: sourceStateOfError(error) };
  }
}

const isList = (data: unknown) => Array.isArray(data);
const okData = <T,>(read: SourceRead<T> | undefined): T | null => (read?.state === "ok" ? read.data : null);
const isObject = (data: unknown) => data != null && typeof data === "object";

export function WorkbenchPanel() {
  const { profile } = useAuth();
  const identity = profile ? `${profile.tenantId}\n${profile.username}` : null;
  const identityRef = useRef(identity);
  const isAdmin = Boolean(profile?.admin);

  const [documentState, setDocumentState] = useState<DocumentState>({ status: "loading" });
  const [reads, setReads] = useState<WorkbenchReads | null>(null);
  const [readAt, setReadAt] = useState<number | null>(null);
  const [lastCompleteReadAt, setLastCompleteReadAt] = useState<number | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [publishOpen, setPublishOpen] = useState(false);
  const [confirmClearFavorites, setConfirmClearFavorites] = useState(false);
  const [pending, setPending] = useState<Set<string>>(new Set());
  const now = useNowTick(5_000);

  // A response that arrives after the identity changed belongs to someone else: drop it.
  const stillSame = useCallback((at: string | null) => identityRef.current === at, []);

  const loadDocument = useCallback(async () => {
    const at = identityRef.current;
    try {
      const next = await adminApi.workbench();
      if (!stillSame(at)) return;
      if (!next || !Array.isArray(next.favorites) || !Array.isArray(next.recents)) {
        setDocumentState({ status: "failed" });
        return;
      }
      setDocumentState({ status: "ready", document: next });
    } catch (error) {
      if (!stillSame(at)) return;
      // A failed read is never shown as empty lists; an older server says it keeps none.
      setDocumentState({ status: isWorkbenchUnsupported(error) ? "unsupported" : "failed" });
    }
  }, [stillSame]);

  const loadLists = useCallback(async () => {
    const at = identityRef.current;
    const [clients, httpRoutes, tcpMappings, peerSharing, peerServices] = await Promise.all([
      readSource<Client[]>(() => adminApi.listClients(), isList),
      readSource<HttpRoute[]>(() => adminApi.listHttpRoutes(), isList),
      readSource<Specus[]>(() => adminApi.listSpecusMappings(), isList),
      readSource<PeerMeshServiceSharing>(() => adminApi.peerMeshServiceSharing(), isObject),
      readSource<PeerMeshSharedService[]>(() => adminApi.listPeerMeshServices(), isList),
    ]);
    if (!stillSame(at)) return;
    const next: WorkbenchReads = { clients, httpRoutes, tcpMappings, peerSharing, peerServices };
    const readTime = Date.now();
    setReads(next);
    setReadAt(readTime);
    if (Object.values(next).every((read) => read.state !== "failed")) setLastCompleteReadAt(readTime);
  }, [stillSame]);

  const refresh = useCallback(async () => {
    setRefreshing(true);
    try {
      await Promise.all([loadDocument(), loadLists()]);
    } finally {
      setRefreshing(false);
    }
  }, [loadDocument, loadLists]);

  // Entering the page, and a change of identity, start from nothing.
  useEffect(() => {
    identityRef.current = identity;
    setDocumentState({ status: "loading" });
    setReads(null);
    setReadAt(null);
    setLastCompleteReadAt(null);
    if (identity) void refresh();
  }, [identity, refresh]);

  // While the page is visible the lists are read again at most every 30 seconds; never while hidden.
  useEffect(() => {
    const timer = window.setInterval(() => {
      if (document.visibilityState === "visible") void loadLists();
    }, PROBLEMS_REFRESH_MS);
    return () => window.clearInterval(timer);
  }, [loadLists]);

  const clients = okData(reads?.clients);
  const services = useMemo(() => collectServices({
    httpRoutes: okData(reads?.httpRoutes),
    tcpMappings: okData(reads?.tcpMappings),
    peerServices: okData(reads?.peerServices),
  }), [reads]);
  const serviceIndex = useMemo(() => new Map(services.map((service) => [refKey(service), service])), [services]);
  const clientIndex = useMemo(() => clientsById(clients), [clients]);
  const problems: PendingProblems | null = useMemo(
    () => (reads ? derivePendingProblems(problemInputFromReads(reads, readAt ?? Date.now())) : null),
    [reads, readAt],
  );
  const markers = useMemo(() => {
    const out = new Map<string, ProblemCode>();
    for (const problem of problems?.problems ?? []) {
      for (const ref of problem.services) out.set(refKey(ref), problem.code);
    }
    return out;
  }, [problems]);
  const sharing = okData(reads?.peerSharing);
  const sharingEnabled = Boolean(sharing?.deploymentEnabled && sharing?.configuredEnabled);
  const workbenchDocument = documentState.status === "ready" ? documentState.document : null;

  const applyDocument = useCallback((at: string | null, next: WorkbenchDocument | null) => {
    if (next && stillSame(at)) setDocumentState({ status: "ready", document: next });
  }, [stillSame]);

  const recordOpen = useCallback((action: WorkbenchOpenAction, ref: WorkbenchRef) => {
    const at = identityRef.current;
    void recordWorkbenchOpenAsCaller(action, ref).then((next) => applyDocument(at, next));
  }, [applyDocument]);

  const runWrite = useCallback(async (key: string, write: () => Promise<WorkbenchDocument>, failure: string) => {
    const at = identityRef.current;
    setPending((current) => new Set(current).add(key));
    try {
      applyDocument(at, await write());
    } catch (error) {
      if (!stillSame(at)) return;
      const status = (error as { status?: number }).status;
      notify(
        status === 409 ? "常用服务已满（最多 50 项），请先移除一些"
          : status === 404 ? "这个服务已不在你的可见列表中"
            : status === 429 ? "操作过于频繁，请稍后再试"
              : status === 503 ? "工作台暂时无法保存，请稍后重试"
                : failure,
        "error",
      );
    } finally {
      setPending((current) => {
        const next = new Set(current);
        next.delete(key);
        return next;
      });
    }
  }, [applyDocument, stillSame]);

  const toggleFavorite = (ref: WorkbenchRef) => {
    const favorite = isFavorite(workbenchDocument, ref);
    void runWrite(`favorite:${refKey(ref)}`, () => favorite
      ? adminApi.removeWorkbenchFavorite(ref.kind, ref.id)
      : adminApi.addWorkbenchFavorite(ref.kind, ref.id), favorite ? "取消收藏失败" : "收藏失败");
  };

  const stale = lastCompleteReadAt == null || now - lastCompleteReadAt > PROBLEMS_STALE_AFTER_MS;

  return (
    <div className="mt-4 flex flex-col gap-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h2 className="text-lg font-semibold">服务工作台</h2>
          <p className="max-w-3xl text-small text-default-500">
            常用服务、最近打开、已知问题和发布入口。设备在线（不代表目标服务可访问）；本页只读取已有状态，不探测、不扫描任何服务。
          </p>
        </div>
        <div className="flex shrink-0 gap-2">
          <Button size="sm" variant="flat" isLoading={refreshing} onPress={() => void refresh()}>刷新</Button>
          <Button size="sm" color="primary" onPress={() => setPublishOpen(true)}>发布服务</Button>
        </div>
      </div>

      <ProblemsSection problems={problems} readAt={readAt} stale={stale} isAdmin={isAdmin}
        clientIndex={clientIndex} serviceIndex={serviceIndex} />

      {documentState.status === "unsupported" ? (
        <Notice tone="default">当前服务端不支持保存常用服务与最近打开。</Notice>
      ) : (
        <div className="grid gap-4 xl:grid-cols-2">
          <Section
            title="常用服务"
            subtitle={workbenchDocument ? `${workbenchDocument.favorites.length} / ${workbenchDocument.limits.maxFavorites} · 按加入顺序` : "你收藏的服务，只有你自己能看到"}
            action={workbenchDocument && workbenchDocument.favorites.length > 0
              ? <Button size="sm" variant="light" color="danger" onPress={() => setConfirmClearFavorites(true)}>清空收藏</Button>
              : null}
          >
            <RefList
              state={documentState}
              entries={workbenchDocument?.favorites.map((entry) => ({ ref: entry, at: entry.addedAt })) ?? []}
              emptyText="还没有常用服务。在下方的服务列表里点「收藏」即可加入。"
              serviceIndex={serviceIndex}
              clientIndex={clientIndex}
              markers={markers}
              sharingEnabled={sharingEnabled}
              timeLabel="加入于"
              pending={pending}
              onRemove={(ref) => void runWrite(`favorite:${refKey(ref)}`,
                () => adminApi.removeWorkbenchFavorite(ref.kind, ref.id), "取消收藏失败")}
              removeLabel="取消收藏"
              onOpen={recordOpen}
            />
          </Section>
          <Section
            title="最近打开"
            subtitle={workbenchDocument ? `从控制台打开或复制过的服务，保留 ${workbenchDocument.limits.recentRetentionDays} 天、最多 ${workbenchDocument.limits.maxRecents} 条；不说明访问是否成功` : "从控制台打开或复制过的服务"}
            action={workbenchDocument && workbenchDocument.recents.length > 0
              ? <Button size="sm" variant="light" onPress={() => void runWrite("recents:clear", () => adminApi.clearWorkbenchRecents(), "清空失败")}>清空最近打开</Button>
              : null}
          >
            <RefList
              state={documentState}
              entries={workbenchDocument?.recents.map((entry) => ({ ref: entry, at: entry.visitedAt })) ?? []}
              emptyText="还没有最近打开的服务。"
              serviceIndex={serviceIndex}
              clientIndex={clientIndex}
              markers={markers}
              sharingEnabled={sharingEnabled}
              timeLabel="打开于"
              pending={pending}
              onRemove={(ref) => void runWrite(`recent:${refKey(ref)}`,
                () => adminApi.removeWorkbenchRecent(ref.kind, ref.id), "删除失败")}
              removeLabel="删除"
              onOpen={recordOpen}
            />
          </Section>
        </div>
      )}

      <Section title="全部服务" subtitle="HTTP 路由、端口映射与 Peer 服务合在一页；每行只展示原面板里本来就有的信息">
        <ServiceList
          reads={reads}
          services={services}
          clientIndex={clientIndex}
          markers={markers}
          sharingEnabled={sharingEnabled}
          favorites={workbenchDocument}
          pending={pending}
          onToggleFavorite={toggleFavorite}
          onOpen={recordOpen}
        />
      </Section>

      <PublishChooser open={publishOpen} onClose={() => setPublishOpen(false)} reads={reads} isAdmin={isAdmin} />
      <ConfirmModal
        isOpen={confirmClearFavorites}
        onClose={() => setConfirmClearFavorites(false)}
        onConfirm={() => runWrite("favorites:clear", () => adminApi.clearWorkbenchFavorites(), "清空收藏失败")}
        title="清空常用服务"
        description="将移除你收藏的全部服务，其他人的收藏不受影响。服务本身不会被删除。"
        confirmLabel="清空收藏"
        danger
      />
    </div>
  );
}

function Section({ title, subtitle, action, children }: { title: string; subtitle?: string; action?: ReactNode; children: ReactNode }) {
  return (
    <section className="min-w-0 rounded-md border border-default-200 bg-content1 p-4" aria-label={title}>
      <div className="mb-3 flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <h3 className="font-semibold">{title}</h3>
          {subtitle ? <p className="text-tiny text-default-500">{subtitle}</p> : null}
        </div>
        {action}
      </div>
      {children}
    </section>
  );
}

function Notice({ tone, children }: { tone: "default" | "warning"; children: ReactNode }) {
  const color = tone === "warning" ? "border-warning-200 bg-warning-50 text-warning-700" : "border-default-200 bg-default-50 text-default-600";
  return <div className={`rounded-md border p-3 text-small ${color}`} role="status">{children}</div>;
}

// ---- pending problems -------------------------------------------------------------------------

function ProblemsSection({ problems, readAt, stale, isAdmin, clientIndex, serviceIndex }: {
  problems: PendingProblems | null;
  readAt: number | null;
  stale: boolean;
  isAdmin: boolean;
  clientIndex: Map<number, Client>;
  serviceIndex: Map<string, WorkbenchService>;
}) {
  const subtitle = readAt == null ? "正在读取状态…" : `状态读取于 ${formatClock(readAt)}${stale ? " · 已过时" : ""}`;
  return (
    <Section title="待处理问题" subtitle={subtitle}>
      {problems == null ? <Spinner size="sm" label="读取中…" /> : (
        <div className="flex flex-col gap-3">
          {!problems.complete ? (
            <Notice tone="warning">
              问题列表不完整：未能读取{problems.unreadSources.map((source) => SOURCE_LABELS[source]).join("、")}，这些来源的问题没有列出。
            </Notice>
          ) : null}
          {problems.problems.length === 0 && problems.complete ? (
            <div className="text-small">
              <p className="font-medium">{NO_KNOWN_PROBLEM}</p>
              <p className="text-default-500">{NO_KNOWN_PROBLEM_CAVEAT}</p>
            </div>
          ) : null}
          {problems.problems.map((problem) => (
            <ProblemItem key={`${problem.code}:${problem.clientId ?? "tenant"}`} problem={problem} isAdmin={isAdmin}
              clientIndex={clientIndex} serviceIndex={serviceIndex} />
          ))}
        </div>
      )}
    </Section>
  );
}

function ProblemItem({ problem, isAdmin, clientIndex, serviceIndex }: {
  problem: PendingProblem;
  isAdmin: boolean;
  clientIndex: Map<number, Client>;
  serviceIndex: Map<string, WorkbenchService>;
}) {
  const blocking = problem.severity === "blocking";
  const device = problem.clientId != null ? clientIndex.get(problem.clientId)?.clientName ?? `设备 #${problem.clientId}` : null;
  return (
    <div className={`rounded-md border p-3 ${blocking ? "border-warning-300 bg-warning-50/50" : "border-default-200"}`}>
      <div className="flex flex-wrap items-center gap-2">
        <StatusChip tone={blocking ? "warning" : "default"}>{blocking ? "无法经 specus 使用" : "需要留意"}</StatusChip>
        {device ? <span className="text-small font-medium">{device}</span> : null}
      </div>
      <p className="mt-1 text-small font-medium">{problemTitle(problem)}</p>
      <p className="text-small text-default-600">下一步：{problemNextStep(problem, isAdmin)}</p>
      {problem.code === "DEVICE_OFFLINE" ? <p className="text-tiny text-default-500">{MULTI_INSTANCE_OFFLINE_CAVEAT}</p> : null}
      {!blocking ? <p className="text-tiny text-default-500">{ATTENTION_NOTE}</p> : null}
      <p className="mt-1 text-tiny text-default-500 [overflow-wrap:anywhere]">
        {problem.services.map((ref) => {
          const service = serviceIndex.get(refKey(ref));
          return service ? `${KIND_LABELS[ref.kind]} ${serviceName(service)}` : `${KIND_LABELS[ref.kind]} #${ref.id}`;
        }).join("、")}
      </p>
    </div>
  );
}

// ---- favourites and recent opens ---------------------------------------------------------------

function RefList({ state, entries, emptyText, serviceIndex, clientIndex, markers, sharingEnabled, timeLabel, pending, onRemove, removeLabel, onOpen }: {
  state: DocumentState;
  entries: Array<{ ref: WorkbenchRef; at: string }>;
  emptyText: string;
  serviceIndex: Map<string, WorkbenchService>;
  clientIndex: Map<number, Client>;
  markers: Map<string, ProblemCode>;
  sharingEnabled: boolean;
  timeLabel: string;
  pending: Set<string>;
  onRemove: (ref: WorkbenchRef) => void;
  removeLabel: string;
  onOpen: (action: WorkbenchOpenAction, ref: WorkbenchRef) => void;
}) {
  if (state.status === "loading") return <Spinner size="sm" label="读取中…" />;
  if (state.status === "failed") return <Notice tone="warning">读取失败，请稍后刷新。</Notice>;
  if (entries.length === 0) return <p className="text-small text-default-500">{emptyText}</p>;
  return (
    <ul className="flex flex-col divide-y divide-default-100">
      {entries.map(({ ref, at }) => {
        const service = serviceIndex.get(refKey(ref));
        const busy = pending.has(`favorite:${refKey(ref)}`) || pending.has(`recent:${refKey(ref)}`);
        return (
          <li key={refKey(ref)} className="flex flex-wrap items-center justify-between gap-2 py-2">
            {service ? (
              <ServiceSummary service={service} client={clientIndex.get(service.clientId)} marker={markers.get(refKey(ref))} />
            ) : (
              <div className="min-w-0">
                <p className="text-small font-medium">{KIND_LABELS[ref.kind]} #{ref.id} · 不在当前可见列表中</p>
                <p className="text-tiny text-default-500">可能已被删除、权限已变化、列表被截断，或该列表读取失败。</p>
              </div>
            )}
            <div className="flex flex-wrap items-center gap-1">
              <span className="text-tiny text-default-400">{timeLabel} {formatDateTime(at)}</span>
              {service ? <ServiceActions service={service} sharingEnabled={sharingEnabled} onOpen={onOpen} /> : null}
              <Button size="sm" variant="light" isDisabled={busy} onPress={() => onRemove(ref)}>{removeLabel}</Button>
            </div>
          </li>
        );
      })}
    </ul>
  );
}

function ServiceSummary({ service, client, marker }: { service: WorkbenchService; client?: Client; marker?: ProblemCode }) {
  const target = serviceTarget(service);
  return (
    <div className="min-w-0">
      <div className="flex flex-wrap items-center gap-1.5">
        <span className="text-tiny text-default-500">{KIND_LABELS[service.kind]}</span>
        <span className="text-small font-medium [overflow-wrap:anywhere]">{serviceName(service)}</span>
        {!service.enabled ? <StatusChip>已停用</StatusChip> : null}
        {marker ? <StatusChip tone="warning">{MARKERS[marker]}</StatusChip> : null}
      </div>
      <p className="text-tiny text-default-500 [overflow-wrap:anywhere]">
        {serviceClientName(service)}
        {client ? ` · ${!client.enabled ? "设备已停用" : client.online ? "设备在线" : "设备离线"}` : ""}
        {target ? ` · ${service.kind === "peer-service" ? "发布地址" : "目标"} ${target}` : ""}
        {service.kind === "peer-service" ? " · 目标连通性未检测" : ""}
      </p>
    </div>
  );
}

// The only places that record an open: the access link, and the copy buttons.
function ServiceActions({ service, sharingEnabled, onOpen }: {
  service: WorkbenchService;
  sharingEnabled: boolean;
  onOpen: (action: WorkbenchOpenAction, ref: WorkbenchRef) => void;
}) {
  const ref: WorkbenchRef = { kind: service.kind, id: service.id };
  const linkHandlers = (action: WorkbenchOpenAction) => ({
    onClick: (event: MouseEvent<HTMLAnchorElement>) => { if (isLinkOpeningClick(event)) onOpen(action, ref); },
    onAuxClick: (event: MouseEvent<HTMLAnchorElement>) => { if (event.button === 1) onOpen(action, ref); },
  });
  const linkClass = "inline-flex h-8 items-center rounded-small px-3 text-small text-primary hover:bg-default-100";
  if (service.kind === "http-route") {
    const url = httpRouteAccessUrl(service.route, window.location.origin);
    return (<>
      <a className={linkClass} href={url} rel="noreferrer" target="_blank" {...linkHandlers("http-route.open-link")}>打开</a>
      <Button size="sm" variant="light" onPress={() => void copyThenRecord(
        () => copyTextWithFeedback(url, "访问链接已复制"), async () => onOpen("http-route.copy-link", ref))}>
        复制访问链接
      </Button>
    </>);
  }
  if (service.kind === "tcp-mapping") {
    return (
      <Button size="sm" variant="light" onPress={() => void copyThenRecord(
        () => copyTextWithFeedback(String(service.mapping.listenPort), "公网端口已复制"),
        async () => onOpen("tcp-mapping.copy-port", ref))}>
        复制公网端口
      </Button>
    );
  }
  const peer = service.service;
  const available = (peer.instances?.length ? peer.instances : [null])
    .some((instance) => peerServiceAvailability(peer, instance, sharingEnabled).available);
  if (!available || !peer.publishedAddress) {
    return <span className="px-2 text-tiny text-default-400">目录中暂无此服务，不能复制地址</span>;
  }
  const address = peer.publishedAddress;
  const openUrl = peerOpenUrl(peer);
  return (<>
    {openUrl ? <a className={linkClass} href={openUrl} rel="noreferrer" target="_blank" {...linkHandlers("peer-service.open-link")}>打开</a> : null}
    <Button size="sm" variant="light" onPress={() => void copyThenRecord(
      () => copyTextWithFeedback(address, "已复制虚拟地址"), async () => onOpen("peer-service.copy-address", ref))}>
      复制地址
    </Button>
  </>);
}

// ---- merged list --------------------------------------------------------------------------------

function ServiceList({ reads, services, clientIndex, markers, sharingEnabled, favorites, pending, onToggleFavorite, onOpen }: {
  reads: WorkbenchReads | null;
  services: WorkbenchService[];
  clientIndex: Map<number, Client>;
  markers: Map<string, ProblemCode>;
  sharingEnabled: boolean;
  favorites: WorkbenchDocument | null;
  pending: Set<string>;
  onToggleFavorite: (ref: WorkbenchRef) => void;
  onOpen: (action: WorkbenchOpenAction, ref: WorkbenchRef) => void;
}) {
  if (!reads) return <Spinner size="sm" label="读取中…" />;
  const failed = ([
    ["httpRoutes", "HTTP 路由"],
    ["tcpMappings", "端口映射"],
    ["peerServices", "Peer 服务"],
  ] as const).filter(([source]) => reads[source].state === "failed").map(([, label]) => label);
  return (
    <div className="flex flex-col gap-2">
      {failed.length ? <Notice tone="warning">{failed.join("、")}读取失败，列表不完整。</Notice> : null}
      {services.length === 0 && failed.length === 0 ? (
        <p className="text-small text-default-500">还没有发布任何服务。点右上角「发布服务」开始。</p>
      ) : null}
      <ul className="flex flex-col divide-y divide-default-100">
        {services.map((service) => {
          const ref: WorkbenchRef = { kind: service.kind, id: service.id };
          const favorite = isFavorite(favorites, ref);
          return (
            <li key={refKey(ref)} className="flex flex-wrap items-center justify-between gap-2 py-2">
              <ServiceSummary service={service} client={clientIndex.get(service.clientId)} marker={markers.get(refKey(ref))} />
              <div className="flex flex-wrap items-center gap-1">
                <ServiceActions service={service} sharingEnabled={sharingEnabled} onOpen={onOpen} />
                {favorites ? (
                  <Button size="sm" variant={favorite ? "flat" : "light"} color={favorite ? "primary" : "default"}
                    aria-pressed={favorite} isDisabled={pending.has(`favorite:${refKey(ref)}`)}
                    onPress={() => onToggleFavorite(ref)}>
                    {favorite ? "已收藏" : "收藏"}
                  </Button>
                ) : null}
              </div>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

// ---- unified publish entry ------------------------------------------------------------------------

function PublishChooser({ open, onClose, reads, isAdmin }: {
  open: boolean;
  onClose: () => void;
  reads: WorkbenchReads | null;
  isAdmin: boolean;
}) {
  const clientsRead = reads?.clients;
  const noDevices = clientsRead?.state === "ok" && clientsRead.data.length === 0;
  const peerUnsupported = reads?.peerServices.state === "unsupported" || reads?.peerSharing.state === "unsupported"
    || (reads?.peerSharing.state === "ok" && !reads.peerSharing.data.deploymentEnabled);
  const peerDisabledReason = !isAdmin ? "需要租户管理员" : peerUnsupported ? "部署未启用 Peer Mesh" : null;
  const go = (hash: string) => {
    onClose();
    window.location.hash = hash;
  };
  const options: Array<{ key: string; title: string; detail: string; hash: string; disabledReason: string | null }> = [
    { key: "http", title: "HTTP 网页服务", detail: "网页、管理后台或 HTTP API，经 /http/ 访问链接打开。默认受保护，公开发布需要再次确认。",
      hash: "/http-routes", disabledReason: null },
    { key: "tcp", title: "TCP 端口", detail: "SSH、数据库、远程桌面等 TCP 服务，经服务端的一个公网端口转发。",
      hash: "/specusMappings", disabledReason: null },
    { key: "peer", title: "Peer 内网服务", detail: "只发布给已加入私有组网并获授权的设备，不占用公网端口；创建后默认关闭。",
      hash: "/peer-mesh/services", disabledReason: peerDisabledReason },
  ];
  return (
    <Modal isOpen={open} onClose={onClose} size="lg">
      <ModalContent>
        <ModalHeader>发布服务</ModalHeader>
        <ModalBody className="gap-3">
          <p className="text-small text-default-500">选择服务类型后进入对应的发布表单，沿用它的全部确认；这里不会扫描或推荐任何服务。</p>
          {clientsRead?.state === "failed" ? <Notice tone="warning">设备状态读取失败，无法确认是否已有设备。</Notice> : null}
          {noDevices ? (
            <Notice tone="default">
              还没有设备。请先接入设备，再发布服务。
              <Button className="ml-2" size="sm" variant="flat" onPress={() => go("/clients")}>去接入设备</Button>
            </Notice>
          ) : null}
          {options.map((option) => {
            const disabled = noDevices || option.disabledReason != null;
            return (
              <button
                key={option.key}
                type="button"
                className="rounded-md border border-default-200 p-3 text-left enabled:hover:border-primary-300 enabled:hover:bg-primary-50/40 disabled:cursor-not-allowed disabled:opacity-60"
                disabled={disabled}
                onClick={() => go(option.hash)}
              >
                <span className="block font-medium">{option.title}</span>
                <span className="block text-small text-default-500">{option.detail}</span>
                {option.disabledReason ? <span className="mt-1 block text-tiny text-warning-600">不可用：{option.disabledReason}</span> : null}
              </button>
            );
          })}
        </ModalBody>
        <ModalFooter>
          <Button variant="light" onPress={onClose}>取消</Button>
        </ModalFooter>
      </ModalContent>
    </Modal>
  );
}
