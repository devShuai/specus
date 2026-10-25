import { useCallback, useEffect, useMemo, useRef, useState, type CSSProperties, type MouseEvent } from "react";
import { Button, Modal, ModalBody, ModalContent, ModalFooter, ModalHeader } from "@heroui/react";
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
import { notify } from "../../components/toast";
import { useNowTick } from "../../hooks/useNowTick";
import { copyTextWithFeedback } from "../../lib/clipboard";
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
import { PageHeader } from "../../components/PageHeader";
import {
  Alert, Card, CardBody, CardHeader, Empty, Icon, RelativeTime, Section, TableWrap, Tag, type IconName,
} from "../../components/ui";
import { TableLoadingRow, TypeTag, chartVar, type ChartColor } from "./opsUi";

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
        status === 409 ? "常用服务已满（最多 50 项）：先取消几项收藏再加入"
          : status === 404 ? "这个服务已不在你的可见列表中"
            : status === 429 ? "操作太频繁：稍等几秒再试"
              : status === 503 ? "工作台暂时无法保存：服务端存储不可用，稍后再试"
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
    <div className="ops-page">
      <PageHeader
        title="服务工作台"
        description="常用服务、最近打开、已知问题和发布入口。设备在线（不代表目标服务可访问）；本页只读取已有状态，不探测、不扫描任何服务。"
        actions={<>
          <Button variant="flat" isLoading={refreshing} startContent={refreshing ? null : <Icon name="refresh" />}
            onPress={() => void refresh()}>刷新</Button>
          <Button color="primary" startContent={<Icon name="plus" />} onPress={() => setPublishOpen(true)}>发布服务</Button>
        </>}
      />

      <ProblemsSection problems={problems} readAt={readAt} stale={stale} isAdmin={isAdmin}
        clientIndex={clientIndex} serviceIndex={serviceIndex} />

      {documentState.status === "unsupported" ? (
        <Section>
          <Alert tone="info" role="status" title="当前服务端不支持保存常用服务与最近打开。">
            升级服务端后，这里会显示你收藏的服务和最近打开的服务。
          </Alert>
        </Section>
      ) : (
        <section className="jd-section ops-shelves" aria-label="常用服务与最近打开">
          <Card aria-label="常用服务">
            <CardHeader
              title="常用服务"
              description={workbenchDocument ? `${workbenchDocument.favorites.length} / ${workbenchDocument.limits.maxFavorites} · 按加入顺序` : "你收藏的服务，只有你自己能看到"}
              actions={workbenchDocument && workbenchDocument.favorites.length > 0
                ? <Button size="sm" variant="light" color="danger" onPress={() => setConfirmClearFavorites(true)}>清空收藏</Button>
                : null}
            />
            <CardBody>
              <RefList
                state={documentState}
                entries={workbenchDocument?.favorites.map((entry) => ({ ref: entry, at: entry.addedAt })) ?? []}
                emptyIcon="star"
                emptyTitle="还没有常用服务"
                emptyText="在下方「全部服务」里点一行的「收藏」，它就会出现在这里。"
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
            </CardBody>
          </Card>
          <Card aria-label="最近打开">
            <CardHeader
              title="最近打开"
              description={workbenchDocument ? `从控制台打开或复制过的服务，保留 ${workbenchDocument.limits.recentRetentionDays} 天、最多 ${workbenchDocument.limits.maxRecents} 条；不说明访问是否成功` : "从控制台打开或复制过的服务"}
              actions={workbenchDocument && workbenchDocument.recents.length > 0
                ? <Button size="sm" variant="light" onPress={() => void runWrite("recents:clear", () => adminApi.clearWorkbenchRecents(), "清空失败")}>清空最近打开</Button>
                : null}
            />
            <CardBody>
              <RefList
                state={documentState}
                entries={workbenchDocument?.recents.map((entry) => ({ ref: entry, at: entry.visitedAt })) ?? []}
                emptyIcon="clock"
                emptyTitle="还没有最近打开的服务"
                emptyText="从这里打开访问链接或复制地址后，会按时间列在这里。"
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
            </CardBody>
          </Card>
        </section>
      )}

      <Section title="全部服务" description="HTTP 路由、端口映射与 Peer 服务合在一页；每行只展示原面板里本来就有的信息">
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

// Each kind keeps one icon and one chart color wherever it appears on the page.
const KIND_STYLE: Record<WorkbenchRef["kind"], { icon: IconName; color: ChartColor }> = {
  "http-route": { icon: "globe", color: 1 },
  "tcp-mapping": { icon: "shuffle", color: 2 },
  "peer-service": { icon: "wifi", color: 6 },
};

function KindIcon({ kind, missing = false }: { kind: WorkbenchRef["kind"]; missing?: boolean }) {
  const style = KIND_STYLE[kind];
  return (
    <span className={`ops-kind-icon${missing ? " ops-kind-icon--missing" : ""}`}
      style={missing ? undefined : ({ "--k": chartVar(style.color) } as CSSProperties)} aria-hidden="true">
      <Icon name={missing ? "circle-alert" : style.icon} />
    </span>
  );
}

function Loading({ label = "读取中…" }: { label?: string }) {
  return <span className="ops-loading" role="status"><Icon name="loader" />{label}</span>;
}

function deviceState(client: Client | undefined): { label: string; tone: "neutral" | "warning" } | null {
  if (!client) return null;
  if (!client.enabled) return { label: "设备已停用", tone: "neutral" };
  return client.online ? { label: "设备在线", tone: "neutral" } : { label: "设备离线", tone: "warning" };
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
  const count = problems?.problems.length ?? 0;
  return (
    <Section
      title="待处理问题"
      description={subtitle}
      actions={problems && count > 0 ? <Tag tone="warning">{count} 项</Tag> : null}
    >
      {problems == null ? <Loading /> : (
        <div className="ops-problems">
          {!problems.complete ? (
            <Alert tone="warning" role="status" title="问题列表不完整">
              未能读取{problems.unreadSources.map((source) => SOURCE_LABELS[source]).join("、")}，这些来源的问题没有列出。稍后点「刷新」重新读取。
            </Alert>
          ) : null}
          {problems.problems.length === 0 && problems.complete ? (
            <Alert tone="info" role="status" title={NO_KNOWN_PROBLEM}>{NO_KNOWN_PROBLEM_CAVEAT}</Alert>
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
    <Alert
      tone={blocking ? "warning" : "info"}
      className="ops-problem"
      title={<>
        <span className="ops-problem-head">
          <Tag tone={blocking ? "warning" : "neutral"}>{blocking ? "无法经 specus 使用" : "需要留意"}</Tag>
          {device ? <span>{device}</span> : null}
        </span>
        {problemTitle(problem)}
      </>}
    >
      <span className="ops-problem-next">下一步：{problemNextStep(problem, isAdmin)}</span>
      {problem.code === "DEVICE_OFFLINE" ? <span className="ops-problem-note">{MULTI_INSTANCE_OFFLINE_CAVEAT}</span> : null}
      {!blocking ? <span className="ops-problem-note">{ATTENTION_NOTE}</span> : null}
      <span className="ops-problem-services">
        {problem.services.map((ref) => {
          const service = serviceIndex.get(refKey(ref));
          return (
            <Tag key={refKey(ref)} plain>
              {service ? `${KIND_LABELS[ref.kind]} ${serviceName(service)}` : `${KIND_LABELS[ref.kind]} #${ref.id}`}
            </Tag>
          );
        })}
      </span>
    </Alert>
  );
}

// ---- favourites and recent opens ---------------------------------------------------------------

function RefList({ state, entries, emptyIcon, emptyTitle, emptyText, serviceIndex, clientIndex, markers, sharingEnabled, timeLabel, pending, onRemove, removeLabel, onOpen }: {
  state: DocumentState;
  entries: Array<{ ref: WorkbenchRef; at: string }>;
  emptyIcon: IconName;
  emptyTitle: string;
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
  if (state.status === "loading") return <div className="px-2 py-3"><Loading /></div>;
  if (state.status === "failed") {
    return <Alert tone="warning" role="status" title="读取失败">服务端没有返回你的收藏和最近打开；稍后点「刷新」重新读取。</Alert>;
  }
  if (entries.length === 0) return <Empty icon={emptyIcon} title={emptyTitle} description={emptyText} />;
  return (
    <ul className="ops-refs">
      {entries.map(({ ref, at }) => {
        const service = serviceIndex.get(refKey(ref));
        const busy = pending.has(`favorite:${refKey(ref)}`) || pending.has(`recent:${refKey(ref)}`);
        const client = service ? clientIndex.get(service.clientId) : undefined;
        return (
          <li key={refKey(ref)} className="ops-ref">
            <KindIcon kind={ref.kind} missing={!service} />
            {service ? (
              <div className="ops-ref-main">
                <ServiceTitle service={service} marker={markers.get(refKey(ref))} />
                <span className="ops-ref-sub">{serviceFacts(service, client)}</span>
                <span className="ops-ref-sub">{timeLabel} <RelativeTime value={at} /></span>
              </div>
            ) : (
              <div className="ops-ref-main">
                <span className="ops-ref-name"><b>{KIND_LABELS[ref.kind]} #{ref.id} · 不在当前可见列表中</b></span>
                <span className="ops-ref-sub">可能已被删除、权限已变化、列表被截断，或该列表读取失败。</span>
                <span className="ops-ref-sub">{timeLabel} <RelativeTime value={at} /></span>
              </div>
            )}
            <div className="jd-row-actions">
              {service ? <ServiceActions service={service} sharingEnabled={sharingEnabled} onOpen={onOpen} /> : null}
              <Button size="sm" variant="light" isDisabled={busy} onPress={() => onRemove(ref)}>{removeLabel}</Button>
            </div>
          </li>
        );
      })}
    </ul>
  );
}

function ServiceTitle({ service, marker }: { service: WorkbenchService; marker?: ProblemCode }) {
  return (
    <span className="ops-ref-name">
      <b>{serviceName(service)}</b>
      {!service.enabled ? <Tag>已停用</Tag> : null}
      {marker ? <Tag tone="warning">{MARKERS[marker]}</Tag> : null}
    </span>
  );
}

/** The device and target as the kind's own panel shows them. */
function serviceFacts(service: WorkbenchService, client?: Client): string {
  const target = serviceTarget(service);
  const device = deviceState(client);
  return [
    KIND_LABELS[service.kind],
    serviceClientName(service),
    device?.label,
    target ? `${service.kind === "peer-service" ? "发布地址" : "目标"} ${target}` : null,
    service.kind === "peer-service" ? "目标连通性未检测" : null,
  ].filter(Boolean).join(" · ");
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
  if (service.kind === "http-route") {
    const url = httpRouteAccessUrl(service.route, window.location.origin);
    return (<>
      <a className="ops-link" href={url} rel="noreferrer" target="_blank" {...linkHandlers("http-route.open-link")}>
        打开<Icon name="external" />
      </a>
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
    return <span className="ops-unavailable">目录中暂无此服务，不能复制地址</span>;
  }
  const address = peer.publishedAddress;
  const openUrl = peerOpenUrl(peer);
  return (<>
    {openUrl ? (
      <a className="ops-link" href={openUrl} rel="noreferrer" target="_blank" {...linkHandlers("peer-service.open-link")}>
        打开<Icon name="external" />
      </a>
    ) : null}
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
  const failed = reads ? ([
    ["httpRoutes", "HTTP 路由"],
    ["tcpMappings", "端口映射"],
    ["peerServices", "Peer 服务"],
  ] as const).filter(([source]) => reads[source].state === "failed").map(([, label]) => label) : [];
  if (reads && services.length === 0 && failed.length === 0) {
    return (
      <div className="bd-card">
        <Empty icon="layers" title="还没有发布任何服务" description="用右上角的「发布服务」选一种服务类型，进入它的发布表单。" />
      </div>
    );
  }
  return (
    <div className="ops-stack">
      {failed.length ? (
        <Alert tone="warning" role="status" title={`${failed.join("、")}读取失败，列表不完整。`}>
          稍后点「刷新」重新读取；没列出的服务仍在原面板里。
        </Alert>
      ) : null}
      <TableWrap className="ops-table-wrap">
        <table className="bd-table jd-stack" aria-label="全部服务">
          <thead>
            <tr>
              <th>服务</th>
              <th>类型</th>
              <th>设备</th>
              <th>状态</th>
              <th className="jd-col-actions"><span className="jd-sr-only">操作</span></th>
            </tr>
          </thead>
          <tbody>
            {!reads ? <TableLoadingRow colSpan={5} label="读取中…" /> : services.map((service) => {
              const ref: WorkbenchRef = { kind: service.kind, id: service.id };
              const favorite = isFavorite(favorites, ref);
              const client = clientIndex.get(service.clientId);
              const device = deviceState(client);
              const marker = markers.get(refKey(ref));
              const target = serviceTarget(service);
              const targetText = [
                target ? `${service.kind === "peer-service" ? "发布地址" : "目标"} ${target}` : null,
                service.kind === "peer-service" ? "目标连通性未检测" : null,
              ].filter(Boolean).join(" · ");
              return (
                <tr key={refKey(ref)}>
                  <td>
                    <div className="ops-service-name">
                      <KindIcon kind={service.kind} />
                      <div className="jd-table-title">
                        <span className="jd-strong">{serviceName(service)}</span>
                        {targetText ? <span className="ops-service-target" title={targetText}>{targetText}</span> : null}
                      </div>
                    </div>
                  </td>
                  <td data-label="类型"><TypeTag color={KIND_STYLE[service.kind].color}>{KIND_LABELS[service.kind]}</TypeTag></td>
                  <td data-label="设备">
                    <span className="ops-device">
                      <span>{serviceClientName(service)}</span>
                      {device ? <Tag tone={device.tone}>{device.label}</Tag> : null}
                    </span>
                  </td>
                  <td data-label="状态">
                    <span className="jd-badges">
                      {!service.enabled ? <Tag>已停用</Tag> : null}
                      {marker ? <Tag tone="warning">{MARKERS[marker]}</Tag> : null}
                      {service.enabled && !marker ? <span className="ops-subtle">已启用</span> : null}
                    </span>
                  </td>
                  <td className="jd-cell-actions">
                    <div className="jd-row-actions">
                      <ServiceActions service={service} sharingEnabled={sharingEnabled} onOpen={onOpen} />
                      {favorites ? (
                        <Button size="sm" variant={favorite ? "flat" : "light"} color={favorite ? "primary" : "default"}
                          aria-pressed={favorite} isDisabled={pending.has(`favorite:${refKey(ref)}`)}
                          startContent={<Icon name="star" size={14} fill={favorite ? "currentColor" : "none"} />}
                          onPress={() => onToggleFavorite(ref)}>
                          {favorite ? "已收藏" : "收藏"}
                        </Button>
                      ) : null}
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </TableWrap>
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
  const options: Array<{ key: WorkbenchRef["kind"]; title: string; detail: string; hash: string; disabledReason: string | null }> = [
    { key: "http-route", title: "HTTP 网页服务", detail: "网页、管理后台或 HTTP API，经 /http/ 访问链接打开。默认受保护，公开发布需要再次确认。",
      hash: "/http-routes", disabledReason: null },
    { key: "tcp-mapping", title: "TCP 端口", detail: "SSH、数据库、远程桌面等 TCP 服务，经服务端的一个公网端口转发。",
      hash: "/specusMappings", disabledReason: null },
    { key: "peer-service", title: "Peer 内网服务", detail: "只发布给已加入私有组网并获授权的设备，不占用公网端口；创建后默认关闭。",
      hash: "/peer-mesh/services", disabledReason: peerDisabledReason },
  ];
  return (
    <Modal isOpen={open} onClose={onClose} size="lg">
      <ModalContent className="ops-dialog">
        <ModalHeader>发布服务</ModalHeader>
        <ModalBody className="gap-3">
          <p className="ops-muted">选择服务类型后进入对应的发布表单，沿用它的全部确认；这里不会扫描或推荐任何服务。</p>
          {clientsRead?.state === "failed" ? (
            <Alert tone="warning" role="status" title="设备状态读取失败">无法确认是否已有设备；关闭后点「刷新」重新读取。</Alert>
          ) : null}
          {noDevices ? (
            <Alert tone="info" role="status" title="还没有设备"
              actions={<Button size="sm" variant="flat" onPress={() => go("/clients")}>去接入设备</Button>}>
              先接入设备，再发布服务。
            </Alert>
          ) : null}
          <div className="ops-publish-options">
            {options.map((option) => {
              const disabled = noDevices || option.disabledReason != null;
              return (
                <button
                  key={option.key}
                  type="button"
                  className="ops-publish-option"
                  disabled={disabled}
                  onClick={() => go(option.hash)}
                >
                  <KindIcon kind={option.key} />
                  <span className="min-w-0">
                    <b>{option.title}</b>
                    <span className="ops-publish-detail">{option.detail}</span>
                    {option.disabledReason ? <span className="ops-publish-off">不可用：{option.disabledReason}</span> : null}
                  </span>
                </button>
              );
            })}
          </div>
        </ModalBody>
        <ModalFooter>
          <Button variant="light" onPress={onClose}>取消</Button>
        </ModalFooter>
      </ModalContent>
    </Modal>
  );
}
