import {
  Component,
  lazy,
  Suspense,
  type CSSProperties,
  type ReactNode,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import {
  Button,
  Modal,
  ModalBody,
  ModalContent,
  ModalFooter,
  ModalHeader,
  Switch,
  Tab,
  Tabs as HeroTabs,
} from "@heroui/react";
import { adminApi } from "../../api/client";
import type {
  HttpTrafficExchange,
  HttpResponseBodyType,
  HttpTrafficSearchField,
  ResourceTrafficType,
  ResourceTrafficUsage,
  TcpTrafficFrame,
  TcpTrafficStream,
  TrafficInspectionStatus,
  TrafficUsage,
} from "../../api/types";
import { formatAbsoluteTime, formatBytes } from "../../lib/format";
import { notifyError } from "../../components/toast";
import { PageHeader } from "../../components/PageHeader";
import {
  Alert,
  Empty,
  FilterBar,
  Icon,
  RelativeTime,
  Section,
  Stat,
  StatGrid,
  TableWrap,
  Tabs,
  Tag,
  type IconName,
  type Tone,
} from "../../components/ui";
import { KpiLabel, Pagination, TableEmptyRow, TableLoadingRow, TypeTag, rangeText } from "./opsUi";
import {
  aggregateResources,
  formatElapsedMs,
  HTTP_EXCHANGE_PAGE_SIZE,
  HTTP_RESPONSE_BODY_TYPES,
  HTTP_SEARCH_FIELDS,
  httpResponseTypeColor,
  httpResponseTypeLabel,
  httpResponseTypeOption,
  httpSearchFieldOption,
  latestUpdatedAt,
  normalizeHttpResponseType,
  normalizeHttpSearchField,
  TCP_FRAME_PAGE_SIZE,
  TCP_STREAM_PAGE_SIZE,
  TRAFFIC_MODAL_CLASS_NAMES,
  TRAFFIC_VIEW_TABS,
  type BodyPreviewTarget,
  type HttpBodyDecodeStatus,
  type ResourceTotal,
  type TrafficSummary,
  type TrafficViewKey,
} from "./traffic/trafficModel";
import {
  analyzeTcpPayload,
  bytesToHexDump,
  concatTcpPayloads,
  decodeBase64Bytes,
  decodeHexPreview,
  decodeUtf8,
  detectImageMime,
  looksLikeTextPayload,
  parseTcpJson,
  parseTcpHttpMessage,
  tcpFlowLabel,
  tcpHeaderValue,
  tcpPayloadKindLabel,
  tcpStreamRange,
  type TcpHeaderPair,
  type TcpPayloadAnalysis,
} from "./traffic/tcpPayload";
import { isHttpImageBody, resolveHttpImageDataUrl } from "./traffic/httpBodyPreview";

const LazyMediaCapturePanel = lazy(() =>
  import("./traffic/MediaCapturePanel").then((module) => ({ default: module.MediaCapturePanel })),
);

const VIEW_ICONS: Record<TrafficViewKey, IconName> = {
  client: "monitor",
  tcp: "shuffle",
  http: "globe",
  media: "film",
};

export function TrafficPanel() {
  const [clientRows, setClientRows] = useState<TrafficUsage[]>([]);
  const [tcpRows, setTcpRows] = useState<ResourceTrafficUsage[]>([]);
  const [httpRows, setHttpRows] = useState<ResourceTrafficUsage[]>([]);
  const [tcpFrameRows, setTcpFrameRows] = useState<TcpTrafficFrame[]>([]);
  const [tcpFramePage, setTcpFramePage] = useState(0);
  const [tcpFrameTotal, setTcpFrameTotal] = useState(0);
  const [tcpFrameTotalPages, setTcpFrameTotalPages] = useState(1);
  const [tcpFrameLoading, setTcpFrameLoading] = useState(true);
  const [httpExchangeRows, setHttpExchangeRows] = useState<HttpTrafficExchange[]>([]);
  const [httpExchangePage, setHttpExchangePage] = useState(0);
  const [httpExchangeTotal, setHttpExchangeTotal] = useState(0);
  const [httpExchangeTotalPages, setHttpExchangeTotalPages] = useState(1);
  const [httpExchangeLoading, setHttpExchangeLoading] = useState(true);
  const [httpSearchDraft, setHttpSearchDraft] = useState("");
  const [httpSearch, setHttpSearch] = useState("");
  const [httpSearchFieldDraft, setHttpSearchFieldDraft] = useState<HttpTrafficSearchField>("summary");
  const [httpSearchField, setHttpSearchField] = useState<HttpTrafficSearchField>("summary");
  const [httpResponseTypeDraft, setHttpResponseTypeDraft] = useState<"" | HttpResponseBodyType>("");
  const [httpResponseType, setHttpResponseType] = useState<"" | HttpResponseBodyType>("");
  const [httpSearchVersion, setHttpSearchVersion] = useState(0);
  const [selectedHttpExchange, setSelectedHttpExchange] = useState<HttpTrafficExchange | null>(null);
  const [httpExchangeDetailLoadingId, setHttpExchangeDetailLoadingId] =
    useState<HttpTrafficExchange["id"] | null>(null);
  const [selectedTcpFrame, setSelectedTcpFrame] = useState<TcpTrafficFrame | null>(null);
  const [selectedTcpStream, setSelectedTcpStream] = useState<TcpTrafficStream | null>(null);
  const [tcpFrameDetailLoadingId, setTcpFrameDetailLoadingId] = useState<string | null>(null);
  const [tcpStreamLoadingChannel, setTcpStreamLoadingChannel] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [trafficView, setTrafficView] = useState<TrafficViewKey>("client");
  const [inspectionStatus, setInspectionStatus] = useState<TrafficInspectionStatus | null>(null);
  const httpExchangeRequestId = useRef(0);
  const tcpFrameRequestId = useRef(0);

  const loadTraffic = useCallback(async (background = false) => {
    // 后台刷新保留旧数据，不再整表变 Spinner。
    if (!background) {
      setLoading(true);
    }
    try {
      const [clients, tcp, http] = await Promise.all([
        adminApi.listTraffic(150),
        adminApi.listResourceTraffic("TCP_SPECUS", 200),
        adminApi.listResourceTraffic("HTTP_ROUTE", 200),
      ]);
      setClientRows(clients);
      setTcpRows(tcp);
      setHttpRows(http);
    } catch (error) {
      notifyError(error, "加载流量失败");
    } finally {
      if (!background) {
        setLoading(false);
      }
    }
  }, []);

  const loadInspectionStatus = useCallback(async () => {
    try {
      setInspectionStatus(await adminApi.getTrafficInspectionStatus());
    } catch {
      setInspectionStatus(null);
    }
  }, []);

  const loadTcpFrames = useCallback(async (background = false) => {
    const requestId = tcpFrameRequestId.current + 1;
    tcpFrameRequestId.current = requestId;
    if (!background) {
      setTcpFrameLoading(true);
    }
    try {
      const data = await adminApi.listTcpTrafficFrames({
        page: tcpFramePage,
        size: TCP_FRAME_PAGE_SIZE,
      });
      if (requestId !== tcpFrameRequestId.current) {
        return;
      }
      setTcpFrameRows(data.items ?? []);
      setTcpFrameTotal(data.total);
      setTcpFrameTotalPages(Math.max(1, data.totalPages));
    } catch (error) {
      if (requestId === tcpFrameRequestId.current) {
        notifyError(error, "加载 TCP 数据帧失败");
      }
    } finally {
      if (requestId === tcpFrameRequestId.current) {
        setTcpFrameLoading(false);
      }
    }
  }, [tcpFramePage]);

  const loadHttpExchanges = useCallback(async (background = false) => {
    const requestId = httpExchangeRequestId.current + 1;
    httpExchangeRequestId.current = requestId;
    if (!background) {
      setHttpExchangeLoading(true);
    }
    try {
      const data = await adminApi.listHttpTrafficExchanges({
        page: httpExchangePage,
        size: HTTP_EXCHANGE_PAGE_SIZE,
        responseBodyType: httpResponseType || undefined,
        field: httpSearchField,
        q: httpSearch || undefined,
      });
      if (requestId !== httpExchangeRequestId.current) {
        return;
      }
      setHttpExchangeRows(data.items ?? []);
      setHttpExchangeTotal(data.total);
      setHttpExchangeTotalPages(Math.max(1, data.totalPages));
    } catch (error) {
      if (requestId === httpExchangeRequestId.current) {
        notifyError(error, "加载 HTTP 记录失败");
      }
    } finally {
      if (requestId === httpExchangeRequestId.current) {
        setHttpExchangeLoading(false);
      }
    }
  }, [httpExchangePage, httpResponseType, httpSearch, httpSearchField, httpSearchVersion]);

  const refresh = useCallback(async () => {
    setRefreshing(true);
    try {
      await Promise.all([
        loadTraffic(true),
        loadTcpFrames(true),
        loadHttpExchanges(true),
        loadInspectionStatus(),
      ]);
    } finally {
      setRefreshing(false);
    }
  }, [loadTraffic, loadTcpFrames, loadHttpExchanges, loadInspectionStatus]);

  // 可选自动轮询：状态条 + 汇总表每 20s 后台刷新一次。
  useEffect(() => {
    if (!autoRefresh) {
      return;
    }
    const timer = window.setInterval(() => {
      void loadTraffic(true);
      void loadInspectionStatus();
    }, 20_000);
    return () => window.clearInterval(timer);
  }, [autoRefresh, loadTraffic, loadInspectionStatus]);

  useEffect(() => {
    void loadTraffic();
    void loadInspectionStatus();
  }, [loadTraffic, loadInspectionStatus]);

  useEffect(() => {
    void loadTcpFrames();
  }, [loadTcpFrames]);

  useEffect(() => {
    void loadHttpExchanges();
  }, [loadHttpExchanges]);

  const applyHttpSearch = useCallback(() => {
    httpExchangeRequestId.current += 1;
    setHttpExchangeRows([]);
    setHttpExchangeTotal(0);
    setHttpExchangeTotalPages(1);
    setHttpExchangeLoading(true);
    setHttpSearch(httpSearchDraft.trim());
    setHttpSearchField(httpSearchFieldDraft);
    setHttpResponseType(httpResponseTypeDraft);
    setHttpExchangePage(0);
    setHttpSearchVersion((version) => version + 1);
  }, [httpResponseTypeDraft, httpSearchDraft, httpSearchFieldDraft]);

  const resetHttpSearch = useCallback(() => {
    httpExchangeRequestId.current += 1;
    setHttpExchangeRows([]);
    setHttpExchangeTotal(0);
    setHttpExchangeTotalPages(1);
    setHttpExchangeLoading(true);
    setHttpSearchDraft("");
    setHttpSearch("");
    setHttpSearchFieldDraft("summary");
    setHttpSearchField("summary");
    setHttpResponseTypeDraft("");
    setHttpResponseType("");
    setHttpExchangePage(0);
    setHttpSearchVersion((version) => version + 1);
  }, []);

  const changeHttpExchangePage = useCallback(
    (nextPage: number) => {
      if (nextPage === httpExchangePage) {
        return;
      }
      httpExchangeRequestId.current += 1;
      setHttpExchangeRows([]);
      setHttpExchangeLoading(true);
      setHttpExchangePage(nextPage);
    },
    [httpExchangePage],
  );

  const changeTcpFramePage = useCallback(
    (nextPage: number) => {
      if (nextPage === tcpFramePage) {
        return;
      }
      tcpFrameRequestId.current += 1;
      // 保留旧页数据直到新页返回，避免翻页闪烁。
      setTcpFrameLoading(true);
      setTcpFramePage(nextPage);
    },
    [tcpFramePage],
  );

  const changeHttpSearchField = useCallback((field: HttpTrafficSearchField) => {
    setHttpSearchFieldDraft(field);
  }, []);

  const changeHttpResponseType = useCallback((type: "" | HttpResponseBodyType) => {
    setHttpResponseTypeDraft(type);
  }, []);

  const openHttpExchangeDetails = useCallback(async (row: HttpTrafficExchange) => {
    setHttpExchangeDetailLoadingId(row.id);
    try {
      const detail = await adminApi.getHttpTrafficExchange(row.id);
      setSelectedHttpExchange(detail);
    } catch (error) {
      notifyError(error, "加载 HTTP 协议详情失败");
    } finally {
      setHttpExchangeDetailLoadingId(null);
    }
  }, []);

  const openTcpFrameDetails = useCallback(async (row: TcpTrafficFrame) => {
    setTcpFrameDetailLoadingId(row.id);
    try {
      const detail = await adminApi.getTcpTrafficFrame(row.id);
      setSelectedTcpFrame(detail);
    } catch (error) {
      notifyError(error, "加载 TCP 数据帧详情失败");
    } finally {
      setTcpFrameDetailLoadingId(null);
    }
  }, []);

  const openTcpStream = useCallback(async (row: TcpTrafficFrame) => {
    setTcpStreamLoadingChannel(row.channelId);
    try {
      const stream = await adminApi.getTcpTrafficStream(row.channelId, 0, TCP_STREAM_PAGE_SIZE);
      setSelectedTcpStream(stream);
    } catch (error) {
      notifyError(error, "加载 TCP 数据流失败");
    } finally {
      setTcpStreamLoadingChannel(null);
    }
  }, []);

  const changeTcpStreamPage = useCallback(async (page: number) => {
    if (!selectedTcpStream) {
      return;
    }
    setTcpStreamLoadingChannel(selectedTcpStream.channelId);
    try {
      const stream = await adminApi.getTcpTrafficStream(selectedTcpStream.channelId, page, selectedTcpStream.size || TCP_STREAM_PAGE_SIZE);
      setSelectedTcpStream(stream);
    } catch (error) {
      notifyError(error, "切换 TCP 数据流分页失败");
    } finally {
      setTcpStreamLoadingChannel(null);
    }
  }, [selectedTcpStream]);

  return (
    <div className="ops-page">
      <PageHeader
        title="流量使用"
        description="按资源和协议查看流量排行、HTTP 记录与 TCP 帧。"
        actions={<>
          <Switch aria-label="自动刷新" isSelected={autoRefresh} size="sm" onValueChange={setAutoRefresh}>
            自动刷新
          </Switch>
          <Button variant="flat" isLoading={refreshing} startContent={refreshing ? null : <Icon name="refresh" />} onPress={() => void refresh()}>
            刷新
          </Button>
        </>}
      />
      <Tabs
        variant="section"
        label="流量观测维度"
        value={trafficView}
        onChange={setTrafficView}
        items={TRAFFIC_VIEW_TABS.map((item) => ({ key: item.key, label: item.label, icon: VIEW_ICONS[item.key] }))}
      />

      <TrafficInspectionStatusBar status={inspectionStatus} />

      {trafficView === "client" && <ClientTrafficTable rows={clientRows} loading={loading} />}

      {trafficView === "tcp" && (
        <>
          <ResourceTrafficSection
            rows={tcpRows}
            loading={loading}
            emptyContent="暂无 TCP 映射流量"
            type="TCP_SPECUS"
          />
          <TcpFrameTable
            rows={tcpFrameRows}
            loading={tcpFrameLoading}
            page={tcpFramePage}
            pageSize={TCP_FRAME_PAGE_SIZE}
            total={tcpFrameTotal}
            totalPages={tcpFrameTotalPages}
            detailLoadingId={tcpFrameDetailLoadingId}
            streamLoadingChannel={tcpStreamLoadingChannel}
            onPageChange={changeTcpFramePage}
            onOpenDetails={openTcpFrameDetails}
            onOpenStream={openTcpStream}
          />
        </>
      )}

      {trafficView === "http" && (
        <>
          <ResourceTrafficSection
            rows={httpRows}
            loading={loading}
            emptyContent="暂无 HTTP 路由流量"
            type="HTTP_ROUTE"
          />
          <HttpExchangeTable
            rows={httpExchangeRows}
            loading={httpExchangeLoading}
            page={httpExchangePage}
            pageSize={HTTP_EXCHANGE_PAGE_SIZE}
            total={httpExchangeTotal}
            totalPages={httpExchangeTotalPages}
            searchDraft={httpSearchDraft}
            searchField={httpSearchFieldDraft}
            responseType={httpResponseTypeDraft}
            activeSearchField={httpSearchField}
            activeSearch={httpSearch}
            activeResponseType={httpResponseType}
            detailLoadingId={httpExchangeDetailLoadingId}
            onPageChange={changeHttpExchangePage}
            onSearchDraftChange={setHttpSearchDraft}
            onSearchFieldChange={changeHttpSearchField}
            onResponseTypeChange={changeHttpResponseType}
            onSearch={applyHttpSearch}
            onResetSearch={resetHttpSearch}
            onOpenDetails={openHttpExchangeDetails}
          />
        </>
      )}
      {trafficView === "media" && (
        <MediaCaptureLoadBoundary>
          <Suspense fallback={<MediaCaptureLoading />}>
            <LazyMediaCapturePanel />
          </Suspense>
        </MediaCaptureLoadBoundary>
      )}
      <HttpExchangeModal row={selectedHttpExchange} onClose={() => setSelectedHttpExchange(null)} />
      <TcpFrameModal row={selectedTcpFrame} onClose={() => setSelectedTcpFrame(null)} />
      <TcpStreamModal
        stream={selectedTcpStream}
        loading={selectedTcpStream != null && tcpStreamLoadingChannel === selectedTcpStream.channelId}
        onClose={() => setSelectedTcpStream(null)}
        onPageChange={changeTcpStreamPage}
      />
    </div>
  );
}

class MediaCaptureLoadBoundary extends Component<
  { children: ReactNode },
  { failed: boolean }
> {
  state = { failed: false };

  static getDerivedStateFromError() {
    return { failed: true };
  }

  render() {
    if (!this.state.failed) {
      return this.props.children;
    }
    return (
      <Section>
        <Alert
          tone="danger"
          role="alert"
          title="媒体采集模块加载失败"
          actions={<Button color="danger" size="sm" onPress={() => window.location.reload()}>重新加载页面</Button>}
        >
          网络可能中断，或站点刚刚完成版本更新；重新加载页面后再试。
        </Alert>
      </Section>
    );
  }
}

function MediaCaptureLoading() {
  return (
    <Section>
      <div className="bd-card px-4 py-8 text-center" aria-live="polite">
        <span className="ops-loading" role="status"><Icon name="loader" />正在加载媒体采集模块…</span>
      </div>
    </Section>
  );
}

function ClientTrafficTable({ rows, loading }: { rows: TrafficUsage[]; loading: boolean }) {
  const summary = useMemo(
    () => ({
      resources: new Set(rows.map((row) => row.clientId)).size,
      uploadBytes: rows.reduce((sum, row) => sum + row.uploadBytes, 0),
      downloadBytes: rows.reduce((sum, row) => sum + row.downloadBytes, 0),
      updatedAt: latestUpdatedAt(rows),
    }),
    [rows],
  );

  return (
    <>
      <MetricCards summary={summary} resourceLabel="客户端" />
      <Section title="客户端流量明细" description="每个客户端每天一行，日期按 UTC">
        <TableWrap className="ops-table-wrap">
          <table className="bd-table jd-stack" aria-label="客户端流量使用">
            <thead>
              <tr>
                <th>客户端</th>
                <th>日期（UTC）</th>
                <th className="bd-col-num">上传</th>
                <th className="bd-col-num">下载</th>
                <th>更新时间</th>
              </tr>
            </thead>
            <tbody>
              {loading && rows.length === 0 ? <TableLoadingRow colSpan={5} /> : null}
              {!loading && rows.length === 0 ? (
                <TableEmptyRow colSpan={5}>
                  <Empty icon="bar-chart" title="暂无数据" description="客户端转发流量后，按天汇总到这里。" />
                </TableEmptyRow>
              ) : null}
              {rows.map((row) => (
                <tr key={row.id}>
                  <td>
                    <span className="inline-flex min-w-0 items-baseline gap-2">
                      <span className="jd-strong [overflow-wrap:anywhere]">{row.clientName}</span>
                      <span className="bd-num text-[12px] text-[var(--text-subtle)]">#{row.id}</span>
                    </span>
                  </td>
                  <td className="bd-num" data-label="日期">{row.usageDate}</td>
                  <td className="bd-col-num" data-label="上传">{formatBytes(row.uploadBytes)}</td>
                  <td className="bd-col-num" data-label="下载">{formatBytes(row.downloadBytes)}</td>
                  <td data-label="更新于"><RelativeTime value={row.updatedAt} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      </Section>
    </>
  );
}

function TrafficInspectionStatusBar({ status }: { status: TrafficInspectionStatus | null }) {
  const pendingTotal = (status?.pendingHttp ?? 0) + (status?.pendingTcp ?? 0);
  const droppedTotal = (status?.droppedHttp ?? 0) + (status?.droppedTcp ?? 0);

  return (
    <section className="jd-section" aria-label="明细采集状态">
      <dl className="bd-card ops-inspection">
        <TrafficStatusItem
          label="明细采集"
          value={status?.enabled ? "全局开启" : "已关闭"}
          tone={status?.enabled ? "success" : "neutral"}
          hint="仍需通道级开关开启"
        />
        <TrafficStatusItem
          label="待写入"
          value={`${pendingTotal}`}
          tone={pendingTotal > 0 ? "warning" : "neutral"}
          hint={`HTTP ${status?.pendingHttp ?? 0} / TCP ${status?.pendingTcp ?? 0}`}
        />
        <TrafficStatusItem
          label="已丢弃"
          value={`${droppedTotal}`}
          tone={droppedTotal > 0 ? "danger" : "neutral"}
          hint={`HTTP ${status?.droppedHttp ?? 0} / TCP ${status?.droppedTcp ?? 0}`}
        />
        <div>
          <dt>最近 flush</dt>
          <dd>{status?.lastFlushedAt ? <RelativeTime value={status.lastFlushedAt} /> : <span className="ops-subtle">—</span>}</dd>
          <p>查询不再强制 flush</p>
        </div>
      </dl>
    </section>
  );
}

function trafficToneLabel(tone: Tone) {
  switch (tone) {
    case "warning":
      return "注意";
    case "danger":
      return "告警";
    default:
      return "正常";
  }
}

function TrafficStatusItem({
  hint,
  label,
  tone,
  value,
}: {
  hint: string;
  label: string;
  tone: Tone;
  value: string;
}) {
  const numeric = /^\d+$/.test(value);
  return (
    <div>
      <dt>{label}</dt>
      <dd>
        {numeric ? <><span className="bd-num">{value}</span><Tag tone={tone}>{trafficToneLabel(tone)}</Tag></> : <Tag tone={tone}>{value}</Tag>}
      </dd>
      <p>{hint}</p>
    </div>
  );
}

function ResourceTrafficSection({
  emptyContent,
  loading,
  rows,
  type,
}: {
  emptyContent: string;
  loading: boolean;
  rows: ResourceTrafficUsage[];
  type: ResourceTrafficType;
}) {
  const totals = useMemo(() => aggregateResources(rows), [rows]);
  const summary = useMemo(
    () => ({
      resources: totals.length,
      uploadBytes: rows.reduce((sum, row) => sum + row.uploadBytes, 0),
      downloadBytes: rows.reduce((sum, row) => sum + row.downloadBytes, 0),
      updatedAt: latestUpdatedAt(rows),
    }),
    [rows, totals.length],
  );

  return (
    <>
      <MetricCards summary={summary} resourceLabel={type === "TCP_SPECUS" ? "映射" : "路由"} />

      <Section
        title="资源流量排行"
        description={`${type === "TCP_SPECUS" ? "按公网监听端口聚合" : "按 HTTP 路由名聚合"}${totals.length > 8 ? `，仅展示前 8 个（共 ${totals.length} 个）` : ""}`}
      >
        <div className="bd-chart-card">
          <div className="bd-chart-card-body">
            <ResourceBars items={totals.slice(0, 8)} />
          </div>
        </div>
      </Section>

      <Section title="流量明细" description="每个资源每天一行，日期按 UTC">
        <TableWrap className="ops-table-wrap">
          <table className="bd-table jd-stack" aria-label={`${type} 流量明细`}>
            <thead>
              <tr>
                <th>资源</th>
                <th>客户端</th>
                <th>日期（UTC）</th>
                <th className="bd-col-num">上传</th>
                <th className="bd-col-num">下载</th>
                <th>更新时间</th>
              </tr>
            </thead>
            <tbody>
              {loading && rows.length === 0 ? <TableLoadingRow colSpan={6} /> : null}
              {!loading && rows.length === 0 ? (
                <TableEmptyRow colSpan={6}>
                  <Empty icon="bar-chart" title={emptyContent} description="资源转发流量后，按天汇总到这里。" />
                </TableEmptyRow>
              ) : null}
              {rows.map((row) => (
                <tr key={row.id}>
                  <td>
                    <div className="jd-table-title">
                      <span className="jd-strong" title={row.resourceName}>{row.resourceName}</span>
                      <span className="jd-table-sub" title={row.resourceKey}>#{row.id} · {row.resourceKey}</span>
                    </div>
                  </td>
                  <td data-label="客户端">{row.clientName}</td>
                  <td className="bd-num" data-label="日期">{row.usageDate}</td>
                  <td className="bd-col-num" data-label="上传">{formatBytes(row.uploadBytes)}</td>
                  <td className="bd-col-num" data-label="下载">{formatBytes(row.downloadBytes)}</td>
                  <td data-label="更新于"><RelativeTime value={row.updatedAt} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      </Section>
    </>
  );
}

function HttpExchangeTable({
  activeSearchField,
  activeSearch,
  activeResponseType,
  detailLoadingId,
  loading,
  onPageChange,
  onOpenDetails,
  onResetSearch,
  onSearch,
  onSearchDraftChange,
  onSearchFieldChange,
  onResponseTypeChange,
  page,
  pageSize,
  responseType,
  rows,
  searchDraft,
  searchField,
  total,
  totalPages,
}: {
  activeSearchField: HttpTrafficSearchField;
  activeSearch: string;
  activeResponseType: "" | HttpResponseBodyType;
  detailLoadingId: HttpTrafficExchange["id"] | null;
  loading: boolean;
  onPageChange: (page: number) => void;
  onOpenDetails: (row: HttpTrafficExchange) => void;
  onResetSearch: () => void;
  onSearch: () => void;
  onSearchDraftChange: (value: string) => void;
  onSearchFieldChange: (field: HttpTrafficSearchField) => void;
  onResponseTypeChange: (type: "" | HttpResponseBodyType) => void;
  page: number;
  pageSize: number;
  responseType: "" | HttpResponseBodyType;
  rows: HttpTrafficExchange[];
  searchDraft: string;
  searchField: HttpTrafficSearchField;
  total: number;
  totalPages: number;
}) {
  const searchFieldOption = httpSearchFieldOption(searchField);
  const activeSearchFieldOption = httpSearchFieldOption(activeSearchField);
  const hasActiveFilters = Boolean(activeSearch || activeSearchField !== "summary" || activeResponseType);
  const tableScopeKey = useMemo(
    () => `${page}:${pageSize}:${activeSearchField}:${activeSearch}:${activeResponseType}`,
    [activeResponseType, activeSearch, activeSearchField, page, pageSize],
  );
  const tableRows = useMemo(
    () =>
      rows.map((row, index) => ({
        ...row,
        tableKey: `${tableScopeKey}:${index}:${row.id}:${row.capturedAt}:${row.method}:${row.relativePath}`,
      })),
    [rows, tableScopeKey],
  );

  return (
    <Section title="HTTP 协议记录" description="请求行、响应状态、headers 与 body 预览">
      <FilterBar
        className="ops-filterbar"
        end={<span className="ops-count">共 {total} 条</span>}
      >
        <label className="ops-filter-field">
          <span className="ops-filter-label">搜索字段</span>
          <select
            className="bd-select"
            value={searchField}
            onChange={(event) => onSearchFieldChange(normalizeHttpSearchField(event.target.value))}
          >
            {HTTP_SEARCH_FIELDS.map((field) => (
              <option key={field.value} value={field.value}>
                {field.label}
              </option>
            ))}
          </select>
        </label>
        <label className="ops-filter-field">
          <span className="ops-filter-label">返回类型</span>
          <select
            className="bd-select"
            value={responseType}
            onChange={(event) => onResponseTypeChange(normalizeHttpResponseType(event.target.value))}
          >
            {HTTP_RESPONSE_BODY_TYPES.map((type) => (
              <option key={type.value || "all"} value={type.value}>
                {type.label}
              </option>
            ))}
          </select>
        </label>
        <label className="ops-filter-field ops-filter-field--wide">
          <span className="jd-sr-only">搜索内容</span>
          <input
            className="bd-input jd-filter-search"
            type="search"
            placeholder={searchFieldOption.placeholder}
            value={searchDraft}
            onChange={(event) => onSearchDraftChange(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter") {
                onSearch();
              }
            }}
          />
        </label>
        <div className="ops-filter-actions">
          <Button size="sm" color="primary" variant="flat" startContent={<Icon name="search" size={14} />} onPress={onSearch}>
            搜索
          </Button>
          <Button size="sm" variant="light" onPress={onResetSearch}>
            重置
          </Button>
        </div>
      </FilterBar>
      {hasActiveFilters && (
        <div className="ops-active-filters" aria-label="当前搜索">
          <span className="ops-filter-label">当前搜索</span>
          <span className="jd-filter-chip ops-filter-chip"><span>{activeSearchFieldOption.label}</span></span>
          {activeSearch && <span className="jd-filter-chip ops-filter-chip"><span>{activeSearch}</span></span>}
          {activeResponseType && (
            <span className="jd-filter-chip ops-filter-chip"><span>{httpResponseTypeOption(activeResponseType).label}</span></span>
          )}
        </div>
      )}

      <TableWrap className="ops-table-wrap">
        <table className="bd-table jd-stack" aria-label="HTTP 协议记录">
          <thead>
            <tr>
              <th>请求</th>
              <th>状态</th>
              <th>返回类型</th>
              <th>资源</th>
              <th className="bd-col-num">请求 / 响应</th>
              <th className="bd-col-num">耗时</th>
              <th>时间</th>
              <th className="jd-col-actions"><span className="jd-sr-only">协议详情</span></th>
            </tr>
          </thead>
          <tbody>
            {loading && tableRows.length === 0 ? <TableLoadingRow colSpan={8} /> : null}
            {!loading && tableRows.length === 0 ? (
              <TableEmptyRow colSpan={8}>
                <Empty
                  icon="globe"
                  title={hasActiveFilters ? "当前筛选没有匹配的 HTTP 协议记录" : "暂无 HTTP 协议记录"}
                  description={hasActiveFilters ? "换一个搜索字段或关键词，或重置筛选。" : "HTTP 路由开启明细采集后，请求会记在这里。"}
                  actions={hasActiveFilters ? <Button size="sm" variant="flat" onPress={onResetSearch}>重置筛选</Button> : null}
                />
              </TableEmptyRow>
            ) : null}
            {tableRows.map((row) => (
              <tr key={row.tableKey}>
                <td>
                  <div className="jd-table-title ops-request">
                    <span className="ops-request-line">
                      <b className="ops-mono">{row.method}</b>
                      <span className="ops-mono ops-request-path" title={httpPath(row)}>{httpPath(row)}</span>
                    </span>
                    {row.remoteAddress && <span className="jd-table-sub bd-num" title={row.remoteAddress}>{row.remoteAddress}</span>}
                  </div>
                </td>
                <td data-label="状态">
                  <Tag tone={httpStatusTone(row)}>{row.statusCode}</Tag>
                </td>
                <td data-label="返回类型">
                  <HttpResponseTypeChip value={row.responseBodyType} contentType={row.responseContentType} bytes={row.responseBytes} />
                </td>
                <td data-label="资源">
                  <div className="jd-table-title">
                    <span title={row.resourceName}>{row.resourceName}</span>
                    <span className="jd-table-sub" title={row.clientName}>{row.clientName}</span>
                  </div>
                </td>
                <td className="bd-col-num" data-label="流量">
                  <span className="ops-cell-stack">
                    <span>请求 {formatBytes(row.requestBytes)}</span>
                    <span>响应 {formatBytes(row.responseBytes)}</span>
                  </span>
                </td>
                <td className="bd-col-num" data-label="耗时">{formatElapsedMs(row.elapsedMs)}</td>
                <td data-label="时间"><RelativeTime value={row.capturedAt} /></td>
                <td className="jd-cell-actions">
                  <div className="jd-row-actions">
                    <Button
                      isLoading={detailLoadingId === row.id}
                      size="sm"
                      variant="flat"
                      onPress={() => onOpenDetails(row)}
                    >
                      查看详情
                    </Button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </TableWrap>
      <Pagination
        page={page}
        totalPages={Math.max(1, totalPages)}
        total={rangeText(page, pageSize, total)}
        onChange={onPageChange}
        label="HTTP 协议记录分页"
      />
    </Section>
  );
}

function HttpResponseTypeChip({
  bytes,
  contentType,
  value,
}: {
  bytes: number;
  contentType: string | null | undefined;
  value: string | null | undefined;
}) {
  return (
    <TypeTag color={httpResponseTypeColor(value, contentType, bytes)}>
      {httpResponseTypeLabel(value, contentType, bytes)}
    </TypeTag>
  );
}

function HttpExchangeModal({ row, onClose }: { row: HttpTrafficExchange | null; onClose: () => void }) {
  const [bodyPreview, setBodyPreview] = useState<BodyPreviewTarget | null>(null);

  useEffect(() => {
    if (!row) {
      setBodyPreview(null);
    }
  }, [row]);

  return (
    <>
      <Modal classNames={TRAFFIC_MODAL_CLASS_NAMES} isOpen={Boolean(row)} onClose={onClose} size="5xl" scrollBehavior="inside">
        <ModalContent className="ops-dialog max-w-[min(96vw,1180px)] overflow-hidden">
          {row && (
            <>
              <ModalHeader className="pr-12">
                <div className="ops-detail-head">
                  <div className="ops-detail-title">
                    <Tag tone="info" plain>{row.method}</Tag>
                    <Tag tone={httpStatusTone(row)}>{row.statusCode}</Tag>
                    <span className="ops-mono min-w-0" title={httpPath(row)}>{httpPath(row)}</span>
                  </div>
                  <div className="ops-detail-meta">
                    <RelativeTime value={row.capturedAt} />
                    <span>{row.clientName}</span>
                    <span>{row.route}</span>
                    {row.remoteAddress && <span className="bd-num">{row.remoteAddress}</span>}
                  </div>
                </div>
              </ModalHeader>
              <ModalBody className="gap-3 overflow-y-auto">
                <SummaryList
                  cols={5}
                  items={[
                    { label: "请求大小", value: formatBytes(row.requestBytes) },
                    { label: "响应大小", value: formatBytes(row.responseBytes) },
                    { label: "返回类型", value: httpResponseTypeLabel(row.responseBodyType, row.responseContentType, row.responseBytes) },
                    { label: "耗时", value: formatElapsedMs(row.elapsedMs) },
                    { label: "资源", value: row.resourceName, wrap: true },
                  ]}
                />

                {row.error && (
                  <Alert tone="danger" role="alert" title="请求出错">{row.error}</Alert>
                )}

                <div className="grid items-stretch gap-3 xl:grid-cols-2">
                  <HttpMessagePanel
                    title="Request"
                    meta={[row.requestContentType, `${row.method} ${httpPath(row)}`]}
                    bytes={row.requestBytes}
                    headers={row.requestHeaders}
                    previewHex={row.requestPreviewHex}
                    previewText={row.requestPreviewText}
                    truncated={row.requestTruncated}
                    contentType={row.requestContentType}
                    bodyMaxHeightClass="h-full"
                    onPreview={setBodyPreview}
                  />
                  <HttpMessagePanel
                    title="Response"
                    meta={[
                      row.responseContentType,
                      httpResponseTypeLabel(row.responseBodyType, row.responseContentType, row.responseBytes),
                      `HTTP ${row.statusCode}`,
                    ]}
                    bytes={row.responseBytes}
                    headers={row.responseHeaders}
                    previewHex={row.responsePreviewHex}
                    previewText={row.responsePreviewText}
                    truncated={row.responseTruncated}
                    contentType={row.responseContentType}
                    bodyMaxHeightClass="h-full"
                    onPreview={setBodyPreview}
                  />
                </div>
              </ModalBody>
              <ModalFooter>
                <Button variant="flat" onPress={onClose}>
                  关闭
                </Button>
              </ModalFooter>
            </>
          )}
        </ModalContent>
      </Modal>
      <BodyPreviewModal target={bodyPreview} onClose={() => setBodyPreview(null)} />
    </>
  );
}

/** A row of labelled values in hairline cells (the record's summary in the detail dialogs). */
function SummaryList({ items, cols }: {
  items: Array<{ label: string; value: string; wrap?: boolean }>;
  cols: number;
}) {
  return (
    <dl className="ops-desc" style={{ "--cols": cols } as CSSProperties}>
      {items.map((item) => (
        <div key={item.label}>
          <dt>{item.label}</dt>
          <dd className={item.wrap ? "ops-wrap" : undefined} title={item.value}>{item.value}</dd>
        </div>
      ))}
    </dl>
  );
}

function decodeTone(status: HttpBodyDecodeStatus): "warning" | "info" {
  return status === "failed" || status === "unsupported" ? "warning" : "info";
}

function HttpMessagePanel({
  bodyMaxHeightClass,
  bytes,
  contentType,
  headers,
  meta,
  onPreview,
  previewHex,
  previewText,
  title,
  truncated,
}: {
  bodyMaxHeightClass: string;
  bytes: number;
  contentType: string | null;
  headers: string | null;
  meta: Array<string | null>;
  onPreview: (target: BodyPreviewTarget) => void;
  previewHex: string | null;
  previewText: string | null;
  title: string;
  truncated: boolean;
}) {
  const contentEncoding = normalizedContentEncoding(headerValue(headers, "content-encoding"));
  const bodyDisplay = useHttpBodyDisplay({
    content: previewText,
    contentEncoding,
    contentType,
    previewHex,
  });
  const hasBody = bodyDisplay.content != null && bodyDisplay.content.length > 0;
  const previewKind = detectBodyPreviewKind(contentType, bodyDisplay.content);

  return (
    <div className="ops-message">
      <div className="flex min-h-0 items-start justify-between gap-3 overflow-hidden">
        <div className="min-w-0">
          <h4>{title}</h4>
          <div className="ops-message-meta">
            {meta.filter(Boolean).map((item) => (
              <span key={item ?? ""} title={item ?? ""}>
                {item}
              </span>
            ))}
          </div>
        </div>
        <Tag plain className="bd-num shrink-0">{formatBytes(bytes)}</Tag>
      </div>
      <HeaderBlock content={headers} />
      <div className="grid min-h-0 grid-rows-[auto_minmax(0,1fr)] gap-2">
        {bodyDisplay.message ? (
          <Alert tone={decodeTone(bodyDisplay.status)} className="max-h-24 overflow-y-auto text-[12px] leading-[18px]">
            {bodyDisplay.message}
          </Alert>
        ) : <span />}
        <ProtocolBlock
          title={truncated ? "Body Preview / truncated" : "Body"}
          content={bodyDisplay.content}
          className="min-h-0 grid-rows-[auto_minmax(0,1fr)]"
          maxHeightClass={bodyMaxHeightClass}
          contentClassName="min-h-[12rem]"
          action={
            <div className="flex flex-wrap items-center justify-end gap-2">
              {contentEncoding && (
                <Tag plain>Content-Encoding {contentEncoding}</Tag>
              )}
              <Button
                isDisabled={!hasBody || bodyDisplay.status === "pending"}
                isLoading={bodyDisplay.status === "pending"}
                size="sm"
                variant="flat"
                onPress={() =>
                  onPreview({
                    title: `${title} Body`,
                    contentType,
                    contentEncoding,
                    content: bodyDisplay.content,
                    bytes,
                    truncated,
                    decodeMessage: bodyDisplay.message,
                    decodeStatus: bodyDisplay.status,
                  })
                }
              >
                {previewButtonText(previewKind)}
              </Button>
            </div>
          }
        />
      </div>
    </div>
  );
}

function BodyPreviewModal({ target, onClose }: { target: BodyPreviewTarget | null; onClose: () => void }) {
  const content = target?.content ?? "";
  const kind = detectBodyPreviewKind(target?.contentType ?? null, content);
  const label = previewKindLabel(kind);

  return (
    <Modal classNames={TRAFFIC_MODAL_CLASS_NAMES} isOpen={Boolean(target)} onClose={onClose} size="5xl" scrollBehavior="inside">
      <ModalContent className="ops-dialog max-w-[min(96vw,1180px)]">
        {target && (
          <>
            <ModalHeader className="pr-12">
              <div className="ops-detail-head">
                <div className="flex flex-wrap items-center gap-2">
                  <span>{target.title}</span>
                  <Tag tone="info" plain>{label}</Tag>
                  <Tag plain className="bd-num">{formatBytes(target.bytes)}</Tag>
                  {target.contentEncoding && (
                    <Tag plain>Content-Encoding {target.contentEncoding}</Tag>
                  )}
                  {target.truncated && (
                    <Tag tone="warning">已截断</Tag>
                  )}
                </div>
                {target.contentType && (
                  <span className="ops-mono ops-detail-meta">{target.contentType}</span>
                )}
                {target.decodeMessage && (
                  <Alert tone={decodeTone(target.decodeStatus)} className="text-[12px] font-normal leading-[18px]">
                    {target.decodeMessage}
                  </Alert>
                )}
              </div>
            </ModalHeader>
            <ModalBody className="overflow-y-auto">
              <BodyPreviewContent kind={kind} content={content} contentType={target.contentType} />
            </ModalBody>
            <ModalFooter>
              <Button variant="flat" onPress={onClose}>
                关闭
              </Button>
            </ModalFooter>
          </>
        )}
      </ModalContent>
    </Modal>
  );
}

function BodyPreviewContent({
  content,
  contentType,
  kind,
}: {
  content: string;
  contentType: string | null;
  kind: BodyPreviewKind;
}) {
  if (kind === "json") {
    return <JsonBodyPreview content={content} />;
  }
  if (kind === "form") {
    return <FormBodyPreview content={content} />;
  }
  if (kind === "multipart") {
    return <MultipartBodyPreview content={content} contentType={contentType} />;
  }
  if (kind === "html") {
    return <HtmlBodyPreview content={content} />;
  }
  if (kind === "xml") {
    return <XmlBodyPreview content={content} />;
  }
  if (kind === "image") {
    return <ImageBodyPreview content={content} contentType={contentType} />;
  }
  return <TextPreview content={content} maxHeightClass="max-h-[52dvh]" />;
}

interface HttpBodyDisplay {
  content: string | null;
  message: string | null;
  status: HttpBodyDecodeStatus;
}

function useHttpBodyDisplay({
  content,
  contentEncoding,
  contentType,
  previewHex,
}: {
  content: string | null;
  contentEncoding: string | null;
  contentType: string | null;
  previewHex: string | null;
}): HttpBodyDisplay {
  const [display, setDisplay] = useState<HttpBodyDisplay>(() => plainHttpBodyDisplay(content));

  useEffect(() => {
    let canceled = false;
    if (!content || !isCompressedContentEncoding(contentEncoding)) {
      setDisplay(plainHttpBodyDisplay(content));
      return () => {
        canceled = true;
      };
    }

    const bodyBytes = extractStoredBodyBytes(content, previewHex);
    if (!bodyBytes) {
      setDisplay({
        content,
        status: looksUnreadableCompressedText(content) ? "failed" : "stored-decoded",
        message: looksUnreadableCompressedText(content)
          ? `这条旧记录的 Body 声明了 Content-Encoding: ${contentEncoding}，但没有保留可解压的原始压缩字节，无法可靠还原，已展示当前保存内容。`
          : `Content-Encoding: ${contentEncoding}。新记录会在服务端入库前解压；当前内容看起来已经是可读正文，按可读内容展示。`,
      });
      return () => {
        canceled = true;
      };
    }

    if (isProbablyStoredDecodedBody(content, bodyBytes, contentType, contentEncoding)) {
      setDisplay({
        content,
        status: "stored-decoded",
        message: `Content-Encoding: ${contentEncoding}。服务端已按压缩编码解码后返回预览内容。`,
      });
      return () => {
        canceled = true;
      };
    }

    const unsupported = unsupportedContentEncodings(contentEncoding);
    if (unsupported.length > 0) {
      setDisplay({
        content,
        status: "unsupported",
        message: `该 Body 声明了 Content-Encoding: ${contentEncoding}，当前浏览器预览暂不支持 ${unsupported.join(
          "、",
        )} 解压，先展示保存的原始内容。`,
      });
      return () => {
        canceled = true;
      };
    }

    setDisplay({
      content,
      status: "pending",
      message: `正在按 Content-Encoding: ${contentEncoding} 解压预览...`,
    });

    decodeHttpBodyBytes(bodyBytes, contentEncoding)
      .then((decodedBytes) => {
        if (canceled) {
          return;
        }
        setDisplay({
          content: bodyContentFromBytes(decodedBytes, contentType),
          status: "decoded",
          message: `已按 Content-Encoding: ${contentEncoding} 解压后展示。`,
        });
      })
      .catch(() => {
        if (canceled) {
          return;
        }
        setDisplay({
          content,
          status: looksUnreadableCompressedText(content) ? "failed" : "stored-decoded",
          message: looksUnreadableCompressedText(content)
            ? `这条旧记录的 Body 声明了 Content-Encoding: ${contentEncoding}，但浏览器无法从已保存内容中完成解压，已展示当前保存内容。`
            : `Content-Encoding: ${contentEncoding}。解压尝试未成功，当前内容看起来已经可读，按已保存内容展示。`,
        });
      });

    return () => {
      canceled = true;
    };
  }, [content, contentEncoding, contentType, previewHex]);

  return display;
}

function plainHttpBodyDisplay(content: string | null): HttpBodyDisplay {
  return { content, message: null, status: "plain" };
}

function headerValue(headers: string | null, name: string): string | null {
  if (!headers) {
    return null;
  }
  return parseHeaderLines(headers)[name.toLowerCase()] ?? null;
}

function normalizedContentEncoding(value: string | null): string | null {
  const tokens = contentEncodingTokens(value);
  return tokens.length > 0 ? tokens.join(", ") : null;
}

function contentEncodingTokens(value: string | null): string[] {
  return (value ?? "")
    .split(",")
    .map((token) => token.trim().toLowerCase())
    .filter(Boolean);
}

function isCompressedContentEncoding(value: string | null): boolean {
  return contentEncodingTokens(value).some((token) => token !== "identity");
}

function unsupportedContentEncodings(value: string | null): string[] {
  const supported = new Set(["gzip", "x-gzip", "deflate", "x-deflate", "identity"]);
  return contentEncodingTokens(value).filter((token) => !supported.has(token));
}

function encodingIncludesGzip(value: string | null): boolean {
  return contentEncodingTokens(value).some((token) => token === "gzip" || token === "x-gzip");
}

function isProbablyStoredDecodedBody(
  content: string,
  bodyBytes: Uint8Array,
  contentType: string | null,
  contentEncoding: string | null,
): boolean {
  if (encodingIncludesGzip(contentEncoding) && !hasGzipMagic(bodyBytes)) {
    return true;
  }
  const storedMediaType = dataUrlMediaType(content);
  const responseMediaType = mediaTypeFromContentType(contentType);
  if (storedMediaType && storedMediaType !== "application/octet-stream" && storedMediaType === responseMediaType) {
    return true;
  }
  return isTextContentType(responseMediaType) && looksLikeTextPayload(bodyBytes);
}

function hasGzipMagic(bytes: Uint8Array): boolean {
  return bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b;
}

function extractStoredBodyBytes(content: string, previewHex: string | null): Uint8Array | null {
  const dataUrlBytes = decodeDataUrlBytes(content);
  if (dataUrlBytes) {
    return dataUrlBytes;
  }
  const hexBytes = decodeHexPreview(previewHex);
  return hexBytes.length > 0 ? hexBytes : null;
}

function decodeDataUrlBytes(content: string): Uint8Array | null {
  const match = content.match(/^data:([^;,]+)?(?:;[^,]*)?;base64,(.*)$/is);
  if (!match) {
    return null;
  }
  return decodeBase64Bytes(match[2].replace(/\s/g, ""));
}

function dataUrlMediaType(content: string): string | null {
  const match = content.match(/^data:([^;,]+)?(?:;[^,]*)?;base64,/is);
  return match?.[1]?.trim().toLowerCase() || null;
}

async function decodeHttpBodyBytes(bytes: Uint8Array, contentEncoding: string | null): Promise<Uint8Array> {
  let current = bytes;
  const tokens = contentEncodingTokens(contentEncoding).reverse();
  for (const token of tokens) {
    if (token === "identity") {
      continue;
    }
    if (token === "gzip" || token === "x-gzip") {
      current = await decompressBytes(current, "gzip");
      continue;
    }
    if (token === "deflate" || token === "x-deflate") {
      try {
        current = await decompressBytes(current, "deflate");
      } catch {
        current = await decompressBytes(current, "deflate-raw");
      }
      continue;
    }
    throw new Error(`Unsupported content encoding: ${token}`);
  }
  return current;
}

async function decompressBytes(bytes: Uint8Array, format: "gzip" | "deflate" | "deflate-raw"): Promise<Uint8Array> {
  const DecompressionStreamCtor = (
    globalThis as unknown as {
      DecompressionStream?: new (format: "gzip" | "deflate" | "deflate-raw") => TransformStream<Uint8Array, Uint8Array>;
    }
  ).DecompressionStream;
  if (!DecompressionStreamCtor) {
    throw new Error("DecompressionStream is not available");
  }
  const blobBytes = new Uint8Array(bytes.length);
  blobBytes.set(bytes);
  const stream = new Blob([blobBytes.buffer]).stream().pipeThrough(new DecompressionStreamCtor(format));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

function bodyContentFromBytes(bytes: Uint8Array, contentType: string | null): string {
  const detectedImageMime = detectImageMime(bytes);
  const mediaType = mediaTypeFromContentType(contentType);
  if (detectedImageMime || mediaType.startsWith("image/")) {
    return `data:${detectedImageMime ?? mediaType};base64,${bytesToBase64(bytes)}`;
  }
  if (isTextContentType(mediaType) || looksLikeTextPayload(bytes)) {
    return decodeUtf8(bytes);
  }
  return `data:${mediaType};base64,${bytesToBase64(bytes)}`;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary);
}

function mediaTypeFromContentType(contentType: string | null): string {
  const mediaType = contentType?.split(";", 1)[0]?.trim().toLowerCase() ?? "";
  return /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/.test(mediaType) ? mediaType : "application/octet-stream";
}

function isTextContentType(mediaType: string): boolean {
  return (
    mediaType.startsWith("text/") ||
    mediaType === "application/json" ||
    mediaType.endsWith("+json") ||
    mediaType === "application/xml" ||
    mediaType.endsWith("+xml") ||
    mediaType === "application/x-www-form-urlencoded" ||
    mediaType === "application/graphql" ||
    mediaType === "application/javascript" ||
    mediaType === "application/ecmascript" ||
    mediaType === "application/x-yaml" ||
    mediaType === "application/yaml"
  );
}

function looksUnreadableCompressedText(content: string): boolean {
  const sample = content.slice(0, 2048);
  if (!sample) {
    return false;
  }
  const replacementChars = sample.match(/\uFFFD/g)?.length ?? 0;
  const controls = Array.from(sample).filter((char) => {
    const code = char.charCodeAt(0);
    return code < 0x20 && char !== "\r" && char !== "\n" && char !== "\t";
  }).length;
  return replacementChars >= 2 || (replacementChars + controls) / sample.length > 0.02;
}

function JsonBodyPreview({ content }: { content: string }) {
  const parsed = parseJsonPreview(content);
  if (!parsed.ok) {
    return (
      <div className="grid gap-3">
        <div><Tag tone="warning">JSON 解析失败</Tag></div>
        <TextPreview content={content} maxHeightClass="max-h-[52dvh]" />
      </div>
    );
  }

  return (
    <div className="grid gap-3">
      <SummaryList
        cols={4}
        items={[
          { label: "类型", value: jsonRootType(parsed.value) },
          { label: "节点", value: String(countJsonNodes(parsed.value)) },
          { label: "字符", value: String(content.length) },
          { label: "格式", value: "JSON" },
        ]}
      />
      <JsonHighlightedPreview content={JSON.stringify(parsed.value, null, 2)} maxHeightClass="max-h-[52dvh]" />
    </div>
  );
}

function FormBodyPreview({ content }: { content: string }) {
  const rows = parseUrlEncodedForm(content);
  if (rows.length === 0) {
    return <TextPreview content={content} maxHeightClass="max-h-[52dvh]" />;
  }

  return (
    <KeyValuePreviewTable
      rows={rows.map((row, index) => ({
        id: String(index),
        name: row.name,
        meta: "",
        value: row.value,
      }))}
    />
  );
}

function MultipartBodyPreview({ content, contentType }: { content: string; contentType: string | null }) {
  const parts = parseMultipartBody(content, contentType);
  if (parts.length === 0) {
    return <TextPreview content={content} maxHeightClass="max-h-[52dvh]" />;
  }

  return (
    <div className="grid gap-3">
      {parts.map((part) => (
        <div key={part.id} className="ops-header-item">
          <div className="flex flex-wrap items-center gap-2">
            <Tag tone="info" plain>{part.name || `part ${part.id}`}</Tag>
            {part.filename && <Tag plain>{part.filename}</Tag>}
            {part.contentType && <span className="ops-mono ops-subtle [overflow-wrap:anywhere]">{part.contentType}</span>}
          </div>
          <TextPreview content={part.value} maxHeightClass="max-h-64" />
        </div>
      ))}
    </div>
  );
}

function HtmlBodyPreview({ content }: { content: string }) {
  return (
    <HeroTabs aria-label="HTML body preview" destroyInactiveTabPanel={false} size="sm">
      <Tab key="rendered" title="渲染">
        {/* The captured page renders on a white canvas, as a browser would show it. */}
        <div className="ops-html-frame">
          <iframe className="h-[52dvh] w-full" sandbox="" srcDoc={content} title="HTML body preview" />
        </div>
      </Tab>
      <Tab key="source" title="源码">
        <TextPreview content={content} maxHeightClass="max-h-[52dvh]" />
      </Tab>
    </HeroTabs>
  );
}

function XmlBodyPreview({ content }: { content: string }) {
  return <TextPreview content={formatXml(content)} maxHeightClass="max-h-[52dvh]" />;
}

function ImageBodyPreview({ content, contentType }: { content: string; contentType: string | null }) {
  const trimmed = content.trim();
  const imageDataUrl = resolveHttpImageDataUrl(trimmed, contentType);
  if (imageDataUrl) {
    return (
      <div className="ops-image-stage">
        <img alt="HTTP body preview" className="max-h-[52dvh] max-w-full object-contain" src={imageDataUrl} />
      </div>
    );
  }
  if (contentType?.toLowerCase().includes("svg") || trimmed.startsWith("<svg")) {
    return <HtmlBodyPreview content={content} />;
  }
  return (
    <div className="grid gap-3">
      <div><Tag tone="warning">图片二进制无法直接渲染</Tag></div>
      <TextPreview content={content} maxHeightClass="max-h-[52dvh]" />
    </div>
  );
}

function KeyValuePreviewTable({
  rows,
}: {
  rows: Array<{ id: string; name: string; meta: string; value: string }>;
}) {
  return (
    <TableWrap className="max-h-[52dvh]">
      <table className="ops-kv">
        <thead>
          <tr>
            <th className="w-56">Name</th>
            <th className="w-52">Meta</th>
            <th>Value</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.id}>
              <td>{row.name || "—"}</td>
              <td className="ops-subtle">{row.meta || "—"}</td>
              <td className="whitespace-pre-wrap">{row.value || "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </TableWrap>
  );
}

function TextPreview({ content, maxHeightClass }: { content: string; maxHeightClass: string }) {
  return (
    <pre className={`ops-pre ${maxHeightClass}`}>
      {content.length === 0 ? "-" : content}
    </pre>
  );
}

function JsonHighlightedPreview({ content, maxHeightClass }: { content: string; maxHeightClass: string }) {
  return (
    <pre className={`ops-pre ops-pre--code ${maxHeightClass}`}>
      <code className="block min-w-max">{highlightJson(content)}</code>
    </pre>
  );
}

const JSON_TOKEN_PATTERN =
  /("(?:\\u[\da-fA-F]{4}|\\[^u]|[^\\"])*"\s*:)|("(?:\\u[\da-fA-F]{4}|\\[^u]|[^\\"])*")|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)|\b(true|false)\b|\bnull\b|[{}\[\],:]/g;

function highlightJson(content: string): ReactNode[] {
  if (content.length === 0) {
    return ["-"];
  }
  JSON_TOKEN_PATTERN.lastIndex = 0;
  const nodes: ReactNode[] = [];
  let cursor = 0;
  let index = 0;
  let match: RegExpExecArray | null;
  while ((match = JSON_TOKEN_PATTERN.exec(content)) !== null) {
    if (match.index > cursor) {
      nodes.push(content.slice(cursor, match.index));
    }
    nodes.push(jsonTokenNode(match[0], index++));
    cursor = match.index + match[0].length;
  }
  if (cursor < content.length) {
    nodes.push(content.slice(cursor));
  }
  return nodes;
}

// JSON tokens wear the text-safe status tokens of the design, so they hold contrast in both themes.
function jsonTokenNode(token: string, index: number): ReactNode {
  if (token.startsWith("\"") && token.trimEnd().endsWith(":")) {
    return <span key={index} className="ops-json-key">{token}</span>;
  }
  if (token.startsWith("\"")) {
    return <span key={index} className="ops-json-string">{token}</span>;
  }
  if (/^-?\d/.test(token)) {
    return <span key={index} className="ops-json-number">{token}</span>;
  }
  if (token === "true" || token === "false") {
    return <span key={index} className="ops-json-bool">{token}</span>;
  }
  if (token === "null") {
    return <span key={index} className="ops-json-null">{token}</span>;
  }
  return <span key={index} className="ops-json-punct">{token}</span>;
}

function DirectionTag({ direction }: { direction: string }) {
  return (
    <TypeTag color={direction === "PUBLIC_TO_CLIENT" ? 1 : 3}>
      {directionLabel(direction)}
    </TypeTag>
  );
}

function TcpFrameTable({
  rows,
  loading,
  page,
  pageSize,
  total,
  totalPages,
  detailLoadingId,
  streamLoadingChannel,
  onPageChange,
  onOpenDetails,
  onOpenStream,
}: {
  rows: TcpTrafficFrame[];
  loading: boolean;
  page: number;
  pageSize: number;
  total: number;
  totalPages: number;
  detailLoadingId: string | null;
  streamLoadingChannel: string | null;
  onPageChange: (page: number) => void;
  onOpenDetails: (row: TcpTrafficFrame) => void;
  onOpenStream: (row: TcpTrafficFrame) => void;
}) {
  const tableScopeKey = useMemo(() => `${page}:${pageSize}`, [page, pageSize]);
  const tableRows = useMemo(
    () =>
      rows.map((row, index) => ({
        ...row,
        tableKey: `${tableScopeKey}:${index}:${row.id}:${row.frameTime}:${row.direction}:${row.channelId}`,
      })),
    [rows, tableScopeKey],
  );

  return (
    <Section title="TCP 数据帧" description="按公网连接 channelId 展示双向 payload 预览" actions={<span className="ops-count ops-subtle">共 {total} 条</span>}>
      <TableWrap className={`ops-table-wrap${loading && tableRows.length > 0 ? " bd-refetching" : ""}`}>
        <table className="bd-table jd-stack ops-frames" aria-label="TCP 数据帧">
          <thead>
            <tr>
              <th>连接</th>
              <th>时间</th>
              <th>方向</th>
              <th>端口</th>
              <th>流位置</th>
              <th className="bd-col-num">长度</th>
              <th>ASCII / 文本 · HEX</th>
              <th className="jd-col-actions"><span className="jd-sr-only">解析</span></th>
            </tr>
          </thead>
          <tbody>
            {loading && tableRows.length === 0 ? <TableLoadingRow colSpan={8} /> : null}
            {!loading && tableRows.length === 0 ? (
              <TableEmptyRow colSpan={8}>
                <Empty icon="shuffle" title="暂无 TCP 数据帧" description="端口映射开启明细采集后，双向数据帧会记在这里。" />
              </TableEmptyRow>
            ) : null}
            {tableRows.map((row) => (
              <tr key={row.tableKey}>
                <td>
                  <div className="jd-table-title">
                    <span className="ops-mono jd-strong" title={row.channelId}>{shortChannel(row.channelId)}</span>
                    <span className="jd-table-sub bd-num" title={tcpFlowLabel(row)}>{tcpFlowLabel(row)}</span>
                    <span className="jd-table-sub">
                      {[row.remoteAddress ? `peer ${row.remoteAddress}` : null, row.clientName].filter(Boolean).join(" · ")}
                    </span>
                  </div>
                </td>
                <td data-label="时间"><RelativeTime value={row.frameTime} /></td>
                <td data-label="方向"><DirectionTag direction={row.direction} /></td>
                <td data-label="端口">
                  <span className="bd-num jd-strong" title={row.resourceName}>{row.listenPort}</span>
                </td>
                <td data-label="流位置">
                  <span className="ops-mono">#{row.frameIndex ?? 0} · {tcpStreamRange(row)}</span>
                </td>
                <td className="bd-col-num" data-label="长度">
                  <span className="ops-cell-stack">
                    <span>{formatBytes(row.payloadBytes)}</span>
                    {row.truncated && !row.payloadBase64 && <span><Tag tone="warning">仅预览</Tag></span>}
                  </span>
                </td>
                <td className="jd-cell-full ops-payload-cell">
                  <pre className="ops-payload" title="ASCII / 文本">{row.payloadPreviewText || "-"}</pre>
                  <pre className="ops-payload ops-payload--hex" title="HEX">{row.payloadPreviewHex || "-"}</pre>
                </td>
                <td className="jd-cell-actions">
                  <div className="jd-row-actions ops-row-actions--column">
                    <Button
                      isLoading={detailLoadingId === row.id}
                      size="sm"
                      variant="flat"
                      onPress={() => onOpenDetails(row)}
                    >
                      查看详情
                    </Button>
                    <Button
                      isLoading={streamLoadingChannel === row.channelId}
                      size="sm"
                      variant="light"
                      onPress={() => onOpenStream(row)}
                    >
                      查看串流
                    </Button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </TableWrap>
      <Pagination
        page={page}
        totalPages={Math.max(1, totalPages)}
        total={rangeText(page, pageSize, total)}
        onChange={onPageChange}
        label="TCP 数据帧分页"
      />
    </Section>
  );
}

function TcpFrameModal({ row, onClose }: { row: TcpTrafficFrame | null; onClose: () => void }) {
  const analysis = useMemo(() => (row ? analyzeTcpPayload(row) : null), [row]);

  return (
    <Modal classNames={TRAFFIC_MODAL_CLASS_NAMES} isOpen={row != null} size="5xl" scrollBehavior="inside" onOpenChange={(open) => !open && onClose()}>
      <ModalContent className="ops-dialog max-w-[min(96vw,1180px)]">
        {(close) =>
          row && analysis ? (
            <>
              <ModalHeader className="pr-12">
                <div className="ops-detail-head">
                  <div className="flex flex-wrap items-center gap-2">
                    <DirectionTag direction={row.direction} />
                    <span>TCP 数据帧 #{row.id}</span>
                  </div>
                  <div className="ops-detail-meta">
                    <span>{formatAbsoluteTime(row.frameTime)}</span>
                    <span className="bd-num">{row.listenPort}</span>
                    <span>{row.clientName}</span>
                    <span className="bd-num">{tcpFlowLabel(row)}</span>
                  </div>
                </div>
              </ModalHeader>
              <ModalBody className="gap-3 overflow-y-auto">
                <SummaryList
                  cols={6}
                  items={[
                    { label: "长度", value: formatBytes(row.payloadBytes) },
                    { label: "解析类型", value: tcpPayloadKindLabel(analysis.kind) },
                    { label: "资源", value: row.resourceName || "—" },
                    { label: "Channel", value: shortChannel(row.channelId) },
                    { label: "Frame", value: `#${row.frameIndex ?? 0}` },
                    { label: "Offset", value: tcpStreamRange(row) },
                  ]}
                />
                {!analysis.fullAvailable && (
                  <Alert tone="warning" role="status">
                    这条历史记录没有完整二进制字段，只能展示旧版保存的 payload 预览。
                  </Alert>
                )}
                <HeroTabs aria-label="TCP payload 预览" destroyInactiveTabPanel={false} size="sm">
                  <Tab key="parsed" title="解析">
                    <TcpParsedPayload analysis={analysis} />
                  </Tab>
                  <Tab key="text" title="文本">
                    <TextPreview content={analysis.text || row.payloadPreviewText || ""} maxHeightClass="max-h-[52dvh]" />
                  </Tab>
                  <Tab key="hex" title="Hexdump">
                    <TextPreview content={analysis.hexDump || row.payloadPreviewHex || ""} maxHeightClass="max-h-[52dvh]" />
                  </Tab>
                </HeroTabs>
              </ModalBody>
              <ModalFooter>
                <Button variant="flat" onPress={close}>
                  关闭
                </Button>
              </ModalFooter>
            </>
          ) : null
        }
      </ModalContent>
    </Modal>
  );
}

function TcpStreamModal({
  loading,
  onClose,
  onPageChange,
  stream,
}: {
  loading: boolean;
  onClose: () => void;
  onPageChange: (page: number) => void;
  stream: TcpTrafficStream | null;
}) {
  const frames = useMemo(
    () => [...(stream?.items ?? [])].sort((left, right) => Number(left.id) - Number(right.id)),
    [stream],
  );
  const publicFrames = useMemo(
    () =>
      frames
        .filter((frame) => frame.direction === "PUBLIC_TO_CLIENT")
        .sort((left, right) => (left.streamOffset ?? 0) - (right.streamOffset ?? 0)),
    [frames],
  );
  const clientFrames = useMemo(
    () =>
      frames
        .filter((frame) => frame.direction === "CLIENT_TO_PUBLIC")
        .sort((left, right) => (left.streamOffset ?? 0) - (right.streamOffset ?? 0)),
    [frames],
  );
  const totalBytes = frames.reduce((sum, frame) => sum + frame.payloadBytes, 0);

  return (
    <Modal classNames={TRAFFIC_MODAL_CLASS_NAMES} isOpen={stream != null} size="5xl" scrollBehavior="inside" onOpenChange={(open) => !open && onClose()}>
      <ModalContent className="ops-dialog max-w-[min(96vw,1180px)]">
        {(close) =>
          stream ? (
            <>
              <ModalHeader className="pr-12">
                <div className="ops-detail-head">
                  <div className="flex flex-wrap items-center gap-2">
                    <span>TCP 数据流</span>
                    <Tag tone="info" plain className="ops-mono">{shortChannel(stream.channelId)}</Tag>
                    {stream.truncated && (
                      <Tag tone="warning">后续分页可用</Tag>
                    )}
                  </div>
                  <div className="ops-detail-meta">
                    <span className="bd-num">
                      第 {stream.page + 1} / {Math.max(1, stream.totalPages)} 页
                    </span>
                    <span className="bd-num">
                      {stream.total} 帧中的 {frames.length} 帧
                    </span>
                    <span className="bd-num">{formatBytes(totalBytes)}</span>
                    {frames[0] && <span>{frames[0].resourceName}</span>}
                  </div>
                </div>
              </ModalHeader>
              <ModalBody className={`gap-3 overflow-y-auto${loading ? " bd-refetching" : ""}`}>
                <SummaryList
                  cols={4}
                  items={[
                    { label: "总帧数", value: `${frames.length}` },
                    { label: "总流量", value: formatBytes(totalBytes) },
                    { label: "公网 -> 内网", value: `${publicFrames.length} 帧` },
                    { label: "内网 -> 公网", value: `${clientFrames.length} 帧` },
                  ]}
                />
                <HeroTabs aria-label="TCP 数据流视图" destroyInactiveTabPanel={false} size="sm">
                  <Tab key="timeline" title="时间线">
                    <TcpStreamTimeline frames={frames} />
                  </Tab>
                  <Tab key="public" title="公网 -> 内网">
                    <TcpStreamPayload frames={publicFrames} />
                  </Tab>
                  <Tab key="client" title="内网 -> 公网">
                    <TcpStreamPayload frames={clientFrames} />
                  </Tab>
                </HeroTabs>
              </ModalBody>
              <ModalFooter className="flex-wrap items-center">
                {stream.totalPages > 1 && (
                  <Pagination
                    page={stream.page}
                    totalPages={Math.max(1, stream.totalPages)}
                    total={`${stream.total} 帧`}
                    disabled={loading}
                    onChange={(page) => onPageChange(Math.max(0, page))}
                    label="TCP 数据流分页"
                  />
                )}
                <Button variant="flat" onPress={close}>
                  关闭
                </Button>
              </ModalFooter>
            </>
          ) : null
        }
      </ModalContent>
    </Modal>
  );
}

function TcpStreamTimeline({ frames }: { frames: TcpTrafficFrame[] }) {
  if (frames.length === 0) {
    return <TextPreview content="" maxHeightClass="max-h-40" />;
  }
  return (
    <TableWrap className="max-h-[52dvh]">
      <table className="bd-table bd-table--compact">
        <thead>
          <tr>
            <th>时间</th>
            <th>方向</th>
            <th>端点</th>
            <th>Frame / Offset</th>
            <th className="bd-col-num">长度</th>
            <th>文本预览</th>
          </tr>
        </thead>
        <tbody>
          {frames.map((frame) => (
            <tr key={frame.id}>
              <td className="bd-num">{formatAbsoluteTime(frame.frameTime)}</td>
              <td><DirectionTag direction={frame.direction} /></td>
              <td className="jd-wrap ops-mono max-w-96 [overflow-wrap:anywhere]">{tcpFlowLabel(frame)}</td>
              <td className="ops-mono">
                #{frame.frameIndex ?? 0} / {tcpStreamRange(frame)}
              </td>
              <td className="bd-col-num">{formatBytes(frame.payloadBytes)}</td>
              <td className="jd-wrap ops-mono max-w-96 [overflow-wrap:anywhere]">{frame.payloadPreviewText || "-"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </TableWrap>
  );
}

function TcpStreamPayload({ frames }: { frames: TcpTrafficFrame[] }) {
  const bytes = useMemo(() => concatTcpPayloads(frames), [frames]);
  const text = useMemo(() => decodeUtf8(bytes), [bytes]);
  const hexDump = useMemo(() => bytesToHexDump(bytes), [bytes]);
  const http = useMemo(() => parseTcpHttpMessage(text), [text]);
  const jsonPretty = useMemo(() => parseTcpJson(text), [text]);
  const fullAvailable = frames.every((frame) => Boolean(frame.payloadBase64));

  if (frames.length === 0) {
    return <TextPreview content="" maxHeightClass="max-h-40" />;
  }

  return (
    <div className="grid gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <Tag tone="info" plain className="bd-num">{frames.length} 帧</Tag>
        <Tag plain className="bd-num">{formatBytes(bytes.length)}</Tag>
        {!fullAvailable && (
          <Tag tone="warning">含旧版预览数据</Tag>
        )}
      </div>
      <HeroTabs aria-label="TCP 拼接 payload 预览" destroyInactiveTabPanel={false} size="sm">
        <Tab key="parsed" title="解析">
          {http ? (
            <TcpParsedPayload
              analysis={{
                binaryLabel: "HTTP",
                bytes,
                fullAvailable,
                hexDump,
                http,
                imageDataUrl: null,
                imageMime: null,
                jsonPretty: null,
                kind: "http",
                text,
              }}
            />
          ) : jsonPretty ? (
            <JsonHighlightedPreview content={jsonPretty} maxHeightClass="max-h-[52dvh]" />
          ) : looksLikeTextPayload(bytes) ? (
            <TextPreview content={text} maxHeightClass="max-h-[52dvh]" />
          ) : (
            <TextPreview content={hexDump} maxHeightClass="max-h-[52dvh]" />
          )}
        </Tab>
        <Tab key="text" title="文本">
          <TextPreview content={text} maxHeightClass="max-h-[52dvh]" />
        </Tab>
        <Tab key="hex" title="Hexdump">
          <TextPreview content={hexDump} maxHeightClass="max-h-[52dvh]" />
        </Tab>
      </HeroTabs>
    </div>
  );
}

function TcpParsedPayload({ analysis }: { analysis: TcpPayloadAnalysis }) {
  if (analysis.http) {
    const contentType = tcpHeaderValue(analysis.http.headers, "content-type");
    const bodyKind = detectBodyPreviewKind(contentType, analysis.http.body);
    return (
      <div className="grid gap-4">
        <div className="ops-header-item">
          <div className="ops-block-title">Start line</div>
          <div className="ops-mono [overflow-wrap:anywhere]">{analysis.http.startLine}</div>
        </div>
        <TcpHeaderPreview headers={analysis.http.headers} />
        <div className="grid gap-2">
          <div className="ops-block-title">Body</div>
          {analysis.http.body ? (
            <BodyPreviewContent kind={bodyKind} content={analysis.http.body} contentType={contentType} />
          ) : (
            <TextPreview content="" maxHeightClass="max-h-[52dvh]" />
          )}
        </div>
      </div>
    );
  }

  if (analysis.kind === "json" && analysis.jsonPretty) {
    return <JsonHighlightedPreview content={analysis.jsonPretty} maxHeightClass="max-h-[52dvh]" />;
  }

  if (analysis.kind === "image" && analysis.imageDataUrl) {
    return (
      <div className="grid gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <Tag tone="info" plain>{analysis.imageMime}</Tag>
          <span className="ops-muted">已按图片魔数识别并渲染</span>
        </div>
        <div className="ops-image-stage max-h-[52dvh] overflow-auto">
          <img alt="TCP payload preview" className="max-h-[48dvh] max-w-full object-contain" src={analysis.imageDataUrl} />
        </div>
      </div>
    );
  }

  if (analysis.kind === "text") {
    return <TextPreview content={analysis.text} maxHeightClass="max-h-[52dvh]" />;
  }

  return (
    <div className="grid gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <Tag plain>{analysis.binaryLabel}</Tag>
        <span className="ops-muted">无法可靠解析为文本协议，展示二进制 hexdump。</span>
      </div>
      <TextPreview content={analysis.hexDump} maxHeightClass="max-h-[52dvh]" />
    </div>
  );
}

function TcpHeaderPreview({ headers }: { headers: TcpHeaderPair[] }) {
  if (headers.length === 0) {
    return <TextPreview content="" maxHeightClass="max-h-40" />;
  }
  return (
    <TableWrap className="max-h-52">
      <table className="ops-kv">
        <thead>
          <tr>
            <th className="w-56">Header</th>
            <th>Value</th>
          </tr>
        </thead>
        <tbody>
          {headers.map((header, index) => (
            <tr key={`${header.name}-${index}`}>
              <td>{header.name}</td>
              <td className="whitespace-pre-wrap">{header.value}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </TableWrap>
  );
}

interface HeaderRow {
  id: string;
  info: HeaderInfo;
  name: string;
  value: string;
}

interface HeaderInfo {
  details: string;
  links: HeaderLink[];
  summary: string;
}

interface HeaderLink {
  label: string;
  url: string;
}

function HeaderBlock({ content }: { content: string | null }) {
  const value = content == null || content.length === 0 ? "" : content;
  const rows = useMemo(() => parseHeaderRows(value), [value]);

  return (
    <div className="grid min-h-0 min-w-0 grid-rows-[auto_minmax(0,1fr)] gap-1">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="ops-block-title">Headers</span>
        <Tag plain className="bd-num">{rows.length} 项</Tag>
      </div>
      <HeroTabs
        aria-label="Header 展示方式"
        classNames={{ base: "min-h-0", panel: "min-h-0 py-0" }}
        destroyInactiveTabPanel={false}
        size="sm"
      >
        <Tab key="form" title="表单">
          <div className="ops-header-list mt-2">
            {rows.length === 0 ? (
              <div className="ops-header-item ops-subtle">暂无 Header</div>
            ) : (
              rows.map((row) => (
                <div key={row.id} className="ops-header-item">
                  <div className="flex min-w-0 flex-wrap items-start justify-between gap-2">
                    <div className="min-w-0">
                      <div className="ops-header-name">{row.name}</div>
                      <div className="ops-problem-note mt-1">{row.info.summary}</div>
                    </div>
                    {row.info.links.length > 0 && (
                      <div className="flex shrink-0 flex-wrap gap-1">
                        {row.info.links.map((link) => (
                          <a
                            key={link.url}
                            className="ops-spec-link"
                            href={link.url}
                            rel="noreferrer"
                            target="_blank"
                          >
                            {link.label}
                          </a>
                        ))}
                      </div>
                    )}
                  </div>
                  <pre className="ops-pre">
                    {row.value || "-"}
                  </pre>
                  <p className="ops-problem-note">{row.info.details}</p>
                </div>
              ))
            )}
          </div>
        </Tab>
        <Tab key="raw" title="Raw">
          <div className="mt-2 h-[12.75rem]">
            <ProtocolBlock
              className="h-full grid-rows-[auto_minmax(0,1fr)]"
              content={value}
              maxHeightClass="h-full"
              title="Raw Headers"
            />
          </div>
        </Tab>
      </HeroTabs>
    </div>
  );
}

function ProtocolBlock({
  className = "",
  contentClassName = "",
  content,
  maxHeightClass = "max-h-32",
  action,
  title,
}: {
  action?: ReactNode;
  className?: string;
  contentClassName?: string;
  content: string | null;
  maxHeightClass?: string;
  title: string;
}) {
  const value = content == null || content.length === 0 ? "-" : content;

  return (
    <div className={`grid min-w-0 gap-1 ${className}`}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="ops-block-title">{title}</span>
        {action}
      </div>
      <pre className={`ops-pre ${maxHeightClass} ${contentClassName}`}>
        {value}
      </pre>
    </div>
  );
}

function parseHeaderRows(content: string): HeaderRow[] {
  return content
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line, index) => {
      const separator = line.indexOf(":");
      const name = separator >= 0 ? line.slice(0, separator).trim() : line;
      const value = separator >= 0 ? line.slice(separator + 1).trim() : "";
      return {
        id: `${index}:${name}:${value}`,
        info: headerInfo(name),
        name,
        value,
      };
    });
}

const RFC_9110 = "https://www.rfc-editor.org/rfc/rfc9110.html";
const RFC_9111 = "https://www.rfc-editor.org/rfc/rfc9111.html";
const RFC_9112 = "https://www.rfc-editor.org/rfc/rfc9112.html";
const RFC_6265 = "https://www.rfc-editor.org/rfc/rfc6265.html";
const RFC_6266 = "https://www.rfc-editor.org/rfc/rfc6266.html";
const RFC_6454 = "https://www.rfc-editor.org/rfc/rfc6454.html";
const RFC_6648 = "https://www.rfc-editor.org/rfc/rfc6648.html";
const RFC_7239 = "https://www.rfc-editor.org/rfc/rfc7239.html";
const RFC_8942 = "https://www.rfc-editor.org/rfc/rfc8942.html";
const FETCH_STANDARD = "https://fetch.spec.whatwg.org/";
const FETCH_METADATA = "https://www.w3.org/TR/fetch-metadata/";
const TRACE_CONTEXT = "https://www.w3.org/TR/trace-context/";
const UA_CLIENT_HINTS = "https://wicg.github.io/ua-client-hints/";

const HEADER_INFO: Record<string, HeaderInfo> = {
  accept: headerSpec(
    "内容协商：客户端可接受的响应媒体类型。",
    "服务端会根据这个字段选择响应的 Content-Type。常见值包括 application/json、text/html、image/*，权重 q 值越高优先级越高。",
    specLink("RFC 9110 Accept", `${RFC_9110}#field.accept`),
  ),
  "accept-encoding": headerSpec(
    "内容协商：客户端可接受的内容编码。",
    "用于声明 gzip、br、deflate 等压缩能力。服务端如果使用了其中一种编码，应在响应里写入 Content-Encoding。",
    specLink("RFC 9110 Accept-Encoding", `${RFC_9110}#field.accept-encoding`),
  ),
  "accept-language": headerSpec(
    "内容协商：客户端偏好的自然语言。",
    "服务端可据此返回 zh-CN、en-US 等语言版本。它可能暴露用户语言偏好，转发或记录时要注意隐私。",
    specLink("RFC 9110 Accept-Language", `${RFC_9110}#field.accept-language`),
  ),
  authorization: headerSpec(
    "认证凭据：客户端提交访问受保护资源所需的凭证。",
    "常见方案是 Basic、Bearer、Digest。该字段高度敏感，流量观测只应在可信环境保留，展示和导出时建议脱敏。",
    specLink("RFC 9110 Authorization", `${RFC_9110}#field.authorization`),
  ),
  "cache-control": headerSpec(
    "缓存策略：请求或响应对缓存行为的约束。",
    "常见指令包括 no-cache、no-store、max-age、s-maxage、private、public。排查缓存命中、强制回源、CDN 行为时优先看它。",
    specLink("RFC 9111 Cache-Control", `${RFC_9111}#field.cache-control`),
  ),
  connection: headerSpec(
    "连接控制：只作用于当前一跳连接。",
    "这是 hop-by-hop 字段，代理或隧道转发到下一跳时通常不应原样透传。HTTP/2 和 HTTP/3 中不允许使用 Connection 语义。",
    specLink("RFC 9110 Connection", `${RFC_9110}#field.connection`),
  ),
  "content-disposition": headerSpec(
    "内容处置：提示浏览器内联展示或作为附件下载。",
    "常见值为 inline、attachment，并可带 filename。文件下载名称乱码、附件变内联时通常检查这个字段。",
    specLink("RFC 6266", `${RFC_6266}#section-4`),
  ),
  "content-encoding": headerSpec(
    "内容编码：Body 实际使用的压缩或编码方式。",
    "如果值是 gzip、br 等，Body 需要先解码再按 Content-Type 解析。响应体乱码或图片无法预览时可先看这个字段。",
    specLink("RFC 9110 Content-Encoding", `${RFC_9110}#field.content-encoding`),
  ),
  "content-language": headerSpec(
    "内容语言：响应表示数据面向的自然语言。",
    "它描述 Body 语言而不是用户偏好，常与 Accept-Language、Vary 配合影响缓存和多语言资源选择。",
    specLink("RFC 9110 Content-Language", `${RFC_9110}#field.content-language`),
  ),
  "content-length": headerSpec(
    "内容长度：Body 的字节数。",
    "用于确定消息体边界。代理转发、压缩、分块传输或修改 Body 后，如果长度不一致可能导致客户端等待、截断或解析失败。",
    specLink("RFC 9110 Content-Length", `${RFC_9110}#field.content-length`),
  ),
  "content-location": headerSpec(
    "内容位置：当前表示数据对应的更具体 URI。",
    "它不等同于重定向 Location，更多用于说明响应 Body 代表哪个资源版本或变体。",
    specLink("RFC 9110 Content-Location", `${RFC_9110}#field.content-location`),
  ),
  "content-type": headerSpec(
    "内容类型：Body 的媒体类型和可选参数。",
    "决定 Body 应按 JSON、HTML、表单、图片还是二进制解析。charset 参数会影响文本解码。",
    specLink("RFC 9110 Content-Type", `${RFC_9110}#field.content-type`),
  ),
  cookie: headerSpec(
    "Cookie：浏览器随请求发送的站点状态。",
    "它通常包含会话标识、偏好或追踪信息，属于敏感数据。跨域、SameSite、登录态问题常需要结合 Set-Cookie 一起看。",
    specLink("RFC 6265 Cookie", `${RFC_6265}#section-4.2`),
  ),
  date: headerSpec(
    "消息时间：发送方生成此 HTTP 消息的日期时间。",
    "缓存新鲜度、Expires 比较、服务端时间漂移排查都会参考它。格式是 IMF-fixdate。",
    specLink("RFC 9110 Date", `${RFC_9110}#field.date`),
  ),
  etag: headerSpec(
    "实体标签：资源表示版本标识。",
    "客户端可用 If-None-Match 做缓存校验，命中时服务端返回 304。强 ETag 和弱 ETag 对字节级一致性的语义不同。",
    specLink("RFC 9110 ETag", `${RFC_9110}#field.etag`),
  ),
  expires: headerSpec(
    "缓存过期时间：响应在指定时间前可视为新鲜。",
    "现代缓存通常优先使用 Cache-Control；Expires 仍常见于静态资源和兼容旧缓存场景。",
    specLink("RFC 9111 Expires", `${RFC_9111}#field.expires`),
  ),
  host: headerSpec(
    "目标主机：请求要访问的主机名和端口。",
    "HTTP/1.1 请求必须携带 Host。虚拟主机、反向代理路由、内网穿透 HTTP 路由匹配通常依赖它。",
    specLink("RFC 9110 Host", `${RFC_9110}#field.host`),
  ),
  "if-modified-since": headerSpec(
    "条件请求：资源在该时间之后修改才返回完整响应。",
    "若资源未更新，服务端可返回 304。常用于基于 Last-Modified 的缓存协商。",
    specLink("RFC 9110 If-Modified-Since", `${RFC_9110}#field.if-modified-since`),
  ),
  "if-none-match": headerSpec(
    "条件请求：资源 ETag 不匹配才返回完整响应。",
    "缓存校验时它通常优先于 If-Modified-Since。命中 ETag 时常见结果是 304 Not Modified。",
    specLink("RFC 9110 If-None-Match", `${RFC_9110}#field.if-none-match`),
  ),
  "last-modified": headerSpec(
    "最后修改时间：源站认为资源最后变化的时间。",
    "客户端可在后续请求用 If-Modified-Since 做缓存协商。精度通常到秒，不适合表达所有版本差异。",
    specLink("RFC 9110 Last-Modified", `${RFC_9110}#field.last-modified`),
  ),
  location: headerSpec(
    "目标位置：重定向地址或新创建资源地址。",
    "3xx 响应中用于告诉客户端下一跳位置，201 响应中可指向新资源。排查重定向循环时优先看它。",
    specLink("RFC 9110 Location", `${RFC_9110}#field.location`),
  ),
  origin: headerSpec(
    "请求来源：发起跨源请求的 scheme、host、port。",
    "CORS 判断会使用 Origin。它不同于 Referer，不包含路径，常见于 fetch、XHR、WebSocket 和表单跨站请求。",
    [specLink("RFC 6454 Origin", `${RFC_6454}#section-7`), specLink("Fetch Origin", `${FETCH_STANDARD}#origin-header`)],
  ),
  pragma: headerSpec(
    "旧式缓存控制：兼容 HTTP/1.0 的缓存指令。",
    "Pragma: no-cache 常与 Cache-Control: no-cache 同时出现。新实现应主要参考 Cache-Control。",
    specLink("RFC 9111 Pragma", `${RFC_9111}#field.pragma`),
  ),
  range: headerSpec(
    "范围请求：只请求资源的一段字节范围。",
    "常用于断点续传、视频拖动和大文件下载。服务端支持时通常返回 206 Partial Content。",
    specLink("RFC 9110 Range", `${RFC_9110}#field.range`),
  ),
  referer: headerSpec(
    "引用来源：当前请求由哪个页面或资源触发。",
    "字段名历史拼写为 Referer。它可能包含路径和查询参数，记录时需关注隐私和敏感参数。",
    specLink("RFC 9110 Referer", `${RFC_9110}#field.referer`),
  ),
  server: headerSpec(
    "服务端信息：生成响应的软件或产品标识。",
    "可用于排查链路中到底是哪一层返回响应，但也可能暴露服务端版本信息，生产环境常会收敛展示。",
    specLink("RFC 9110 Server", `${RFC_9110}#field.server`),
  ),
  "set-cookie": headerSpec(
    "设置 Cookie：服务端要求客户端保存站点状态。",
    "登录态、SameSite、Secure、HttpOnly、Domain、Path、Max-Age/Expires 都在这里体现。该字段高度敏感。",
    specLink("RFC 6265 Set-Cookie", `${RFC_6265}#section-4.1`),
  ),
  "transfer-encoding": headerSpec(
    "传输编码：消息在当前连接上的编码方式。",
    "常见值是 chunked，表示分块传输。它是传输层 framing 语义，不等同于 Content-Encoding。",
    specLink("RFC 9112 Transfer-Encoding", `${RFC_9112}#field.transfer-encoding`),
  ),
  "user-agent": headerSpec(
    "客户端标识：发起请求的软件、系统和运行环境信息。",
    "常用于兼容性判断、日志分析和风控，但也会增加指纹识别风险。现代浏览器逐步以 Client Hints 替代部分 UA 信息。",
    specLink("RFC 9110 User-Agent", `${RFC_9110}#field.user-agent`),
  ),
  vary: headerSpec(
    "缓存变体：响应会随哪些请求字段变化。",
    "缓存使用它判断同一 URL 是否能复用响应。比如 Vary: Origin 或 Vary: Accept-Encoding 会显著影响缓存命中。",
    specLink("RFC 9110 Vary", `${RFC_9110}#field.vary`),
  ),
  via: headerSpec(
    "代理链路：请求或响应经过的中间节点。",
    "代理应追加 Via 以标识协议版本和节点。它有助于判断响应是否经过网关、缓存或反向代理。",
    specLink("RFC 9110 Via", `${RFC_9110}#field.via`),
  ),
  "www-authenticate": headerSpec(
    "认证挑战：服务端要求客户端使用的认证方案。",
    "401 响应常携带它，客户端随后用 Authorization 提交凭据。排查登录弹窗或 Bearer 认证失败时很关键。",
    specLink("RFC 9110 WWW-Authenticate", `${RFC_9110}#field.www-authenticate`),
  ),
  "access-control-allow-origin": corsHeader(
    "CORS 响应：允许访问该响应的 Origin。",
    "值可以是具体 Origin 或 *。带凭据请求不能使用 *，否则浏览器会拒绝把响应暴露给页面脚本。",
  ),
  "access-control-allow-credentials": corsHeader(
    "CORS 响应：是否允许浏览器暴露带凭据请求的响应。",
    "当请求包含 Cookie、Authorization 或 TLS 客户端证书时，通常需要它为 true，并且 Allow-Origin 必须是具体 Origin。",
  ),
  "access-control-allow-headers": corsHeader(
    "CORS 预检响应：允许实际请求携带哪些非简单请求头。",
    "浏览器会把前端要发送的自定义 Header 放在 Access-Control-Request-Headers，服务端需在这里允许。",
  ),
  "access-control-allow-methods": corsHeader(
    "CORS 预检响应：允许实际请求使用哪些 HTTP 方法。",
    "如果实际请求是 PUT、DELETE、PATCH 等非简单方法，预检响应需要在这里列出允许的方法。",
  ),
  "access-control-expose-headers": corsHeader(
    "CORS 响应：允许前端 JavaScript 读取的响应 Header。",
    "默认只有少量 CORS-safelisted response header 可读；想让页面读取自定义响应头，需要在这里显式暴露。",
  ),
  "access-control-max-age": corsHeader(
    "CORS 预检缓存：浏览器可缓存预检结果的秒数。",
    "值越大，重复跨域请求越少触发 OPTIONS 预检，但策略变更生效也会更慢。",
  ),
  "access-control-request-headers": corsHeader(
    "CORS 预检请求：实际请求准备发送的非简单 Header。",
    "这是浏览器在 OPTIONS 预检里自动发送的字段，服务端应据此返回 Access-Control-Allow-Headers。",
  ),
  "access-control-request-method": corsHeader(
    "CORS 预检请求：实际请求准备使用的方法。",
    "这是浏览器在 OPTIONS 预检里自动发送的字段，服务端应据此返回 Access-Control-Allow-Methods。",
  ),
  "sec-fetch-dest": fetchMetadataHeader(
    "Fetch Metadata：请求目标类型。",
    "描述浏览器请求的是 document、image、script、style、empty 等目标，可用于服务端区分导航、静态资源和 API 请求。",
  ),
  "sec-fetch-mode": fetchMetadataHeader(
    "Fetch Metadata：请求模式。",
    "常见值包括 navigate、cors、no-cors、same-origin。服务端可结合它限制跨站资源读取或 CSRF 风险。",
  ),
  "sec-fetch-site": fetchMetadataHeader(
    "Fetch Metadata：请求发起站点关系。",
    "常见值包括 same-origin、same-site、cross-site、none。服务端可据此拒绝不期望的跨站请求。",
  ),
  "sec-fetch-user": fetchMetadataHeader(
    "Fetch Metadata：是否由用户激活触发导航。",
    "通常只在用户主动点击或提交导致的导航请求里出现 ?1，可帮助区分自动加载和用户交互。",
  ),
  "sec-ch-ua": clientHintHeader(
    "User-Agent Client Hints：浏览器品牌和主要版本。",
    "用于替代部分 User-Agent 解析。它可能包含多个品牌项，服务端不应假设顺序固定。",
  ),
  "sec-ch-ua-mobile": clientHintHeader(
    "User-Agent Client Hints：是否移动设备。",
    "通常为 ?0 或 ?1，用于响应式资源选择或统计，不应作为安全判断依据。",
  ),
  "sec-ch-ua-platform": clientHintHeader(
    "User-Agent Client Hints：客户端平台。",
    "例如 Windows、macOS、Android。它比传统 User-Agent 更结构化，但仍可能受隐私策略限制。",
  ),
  "x-forwarded-for": proxyHeader(
    "代理转发：原始客户端 IP 链。",
    "多个代理会追加地址，最左侧通常是最早的客户端地址，但该字段可被客户端伪造，只有可信代理写入的部分才可用于审计。",
  ),
  "x-forwarded-host": proxyHeader(
    "代理转发：进入代理前的 Host。",
    "反向代理或内网穿透转发后，后端可用它还原公网访问域名。路由生成绝对链接时常会依赖它。",
  ),
  "x-forwarded-port": proxyHeader(
    "代理转发：进入代理前的端口。",
    "后端需要还原外部访问地址时会使用它，例如公网 443 转到内网 8080。",
  ),
  "x-forwarded-proto": proxyHeader(
    "代理转发：进入代理前的协议。",
    "常见值为 http 或 https。后端判断是否生成 HTTPS 链接、是否设置 Secure Cookie 时会用到它。",
  ),
  "x-real-ip": proxyHeader(
    "代理转发：代理记录的客户端 IP。",
    "这是非标准但常见字段，通常由 Nginx 等代理写入。可信度取决于是否只接受可信代理的覆盖。",
  ),
  "x-api-key": sensitiveHeader(
    "敏感凭据：接口密钥。",
    "通常用于服务到服务或开放 API 调用鉴权。记录和展示时建议脱敏，避免泄漏后被复用。",
  ),
  "x-auth-token": sensitiveHeader(
    "敏感凭据：认证令牌。",
    "非标准字段，常见于自定义登录体系。它和 Authorization 一样需要按敏感数据处理。",
  ),
  "x-correlation-id": tracingHeader(
    "链路追踪：跨服务关联 ID。",
    "用于把网关、应用、数据库或异步任务日志串起来。若系统使用 W3C Trace Context，优先关注 traceparent。",
  ),
  "x-csrf-token": sensitiveHeader(
    "安全令牌：CSRF 防护令牌。",
    "服务端用它验证请求是否来自合法页面上下文。它属于敏感值，展示和导出时建议脱敏。",
  ),
  "x-request-id": tracingHeader(
    "请求追踪：单次请求 ID。",
    "常由网关生成并在整条链路透传，用于定位一条 HTTP 请求经过的所有日志。",
  ),
};

function headerInfo(name: string): HeaderInfo {
  const normalized = name.trim().toLowerCase();
  if (HEADER_INFO[normalized]) {
    return HEADER_INFO[normalized];
  }
  if (normalized.startsWith("access-control-")) {
    return corsHeader(
      "CORS 相关字段。",
      "该字段属于浏览器跨源资源共享流程，具体语义取决于请求阶段和响应方向。排查跨域失败时，需要同时看 Origin、预检 OPTIONS、Access-Control-Allow-* 与浏览器控制台错误。",
    );
  }
  if (normalized.startsWith("sec-fetch-")) {
    return fetchMetadataHeader(
      "Fetch Metadata 相关字段。",
      "这些由浏览器自动发送，描述请求的来源站点关系、目标类型和请求模式，可用于服务端做跨站请求保护。",
    );
  }
  if (normalized.startsWith("sec-ch-ua")) {
    return clientHintHeader(
      "User-Agent Client Hints 相关字段。",
      "这些字段是结构化的客户端提示信息，用于减少直接解析 User-Agent 的依赖。具体是否发送受浏览器和权限策略影响。",
    );
  }
  if (normalized.startsWith("cf-")) {
    return headerSpec(
      "Cloudflare 代理相关字段。",
      "通常由 Cloudflare 边缘节点添加，用于描述访客 IP、国家/地区、TLS、缓存或连接信息。生产排查时需要结合 Cloudflare 官方说明和你的代理信任边界判断。",
      specLink("Cloudflare Headers", "https://developers.cloudflare.com/fundamentals/reference/http-headers/"),
    );
  }
  if (normalized.startsWith("x-")) {
    return headerSpec(
      "自定义扩展字段。",
      "X- 前缀常见于历史或私有约定，但 RFC 6648 已不建议新字段继续使用 X- 前缀。它的真实含义需要结合系统约定、网关或上游服务文档判断。",
      specLink("RFC 6648", `${RFC_6648}#section-3`),
    );
  }
  return headerSpec(
    "未内置说明的 HTTP 字段。",
    "HTTP 字段名大小写不敏感，具体语义可能来自标准、IANA HTTP Field Name Registry、框架约定或业务私有协议。排查时可先确认它是在客户端、代理还是源站产生。",
    specLink("RFC 9110 Fields", `${RFC_9110}#name-fields`),
  );
}

function headerSpec(summary: string, details: string, links: HeaderLink | HeaderLink[]): HeaderInfo {
  return {
    details,
    links: Array.isArray(links) ? links : [links],
    summary,
  };
}

function corsHeader(summary: string, details: string): HeaderInfo {
  return headerSpec(summary, details, specLink("Fetch CORS", `${FETCH_STANDARD}#http-cors-protocol`));
}

function fetchMetadataHeader(summary: string, details: string): HeaderInfo {
  return headerSpec(summary, details, specLink("W3C Fetch Metadata", FETCH_METADATA));
}

function clientHintHeader(summary: string, details: string): HeaderInfo {
  return headerSpec(summary, details, [specLink("RFC 8942", RFC_8942), specLink("UA-CH", UA_CLIENT_HINTS)]);
}

function proxyHeader(summary: string, details: string): HeaderInfo {
  return headerSpec(summary, details, [
    specLink("RFC 7239 Forwarded", RFC_7239),
    specLink("MDN X-Forwarded", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Forwarded-For"),
  ]);
}

function sensitiveHeader(summary: string, details: string): HeaderInfo {
  return headerSpec(summary, details, specLink("RFC 9110 Auth", `${RFC_9110}#authentication`));
}

function tracingHeader(summary: string, details: string): HeaderInfo {
  return headerSpec(summary, details, specLink("W3C Trace Context", TRACE_CONTEXT));
}

function specLink(label: string, url: string): HeaderLink {
  return { label, url };
}

type BodyPreviewKind = "json" | "form" | "multipart" | "html" | "xml" | "image" | "text";

function detectBodyPreviewKind(contentType: string | null, content: string | null | undefined): BodyPreviewKind {
  const normalized = contentType?.toLowerCase() ?? "";
  const trimmed = content?.trim() ?? "";
  if (normalized.includes("json")) {
    return "json";
  }
  if (normalized.includes("application/x-www-form-urlencoded")) {
    return "form";
  }
  if (normalized.includes("multipart/form-data")) {
    return "multipart";
  }
  if (normalized.includes("text/html") || normalized.includes("application/xhtml+xml")) {
    return "html";
  }
  if (isHttpImageBody(trimmed, contentType)) {
    return "image";
  }
  if (normalized.includes("xml")) {
    return "xml";
  }
  if (/^[\[{]/.test(trimmed)) {
    return "json";
  }
  if (/^<!doctype\s+html/i.test(trimmed) || /^<html[\s>]/i.test(trimmed)) {
    return "html";
  }
  if (trimmed.startsWith("<?xml")) {
    return "xml";
  }
  return "text";
}

function previewButtonText(kind: BodyPreviewKind): string {
  return `${previewKindLabel(kind)}预览`;
}

function previewKindLabel(kind: BodyPreviewKind): string {
  if (kind === "json") {
    return "JSON";
  }
  if (kind === "form") {
    return "表单";
  }
  if (kind === "multipart") {
    return "Multipart";
  }
  if (kind === "html") {
    return "HTML";
  }
  if (kind === "xml") {
    return "XML";
  }
  if (kind === "image") {
    return "图片";
  }
  return "文本";
}

function parseJsonPreview(content: string): { ok: true; value: unknown } | { ok: false } {
  try {
    return { ok: true, value: JSON.parse(content) };
  } catch {
    return { ok: false };
  }
}

function jsonRootType(value: unknown): string {
  if (Array.isArray(value)) {
    return `Array(${value.length})`;
  }
  if (value === null) {
    return "null";
  }
  return typeof value;
}

function countJsonNodes(value: unknown): number {
  if (value == null || typeof value !== "object") {
    return 1;
  }
  if (Array.isArray(value)) {
    return 1 + value.reduce<number>((sum, item) => sum + countJsonNodes(item), 0);
  }
  return 1 + Object.values(value as Record<string, unknown>).reduce<number>(
    (sum, item) => sum + countJsonNodes(item),
    0,
  );
}

function parseUrlEncodedForm(content: string): Array<{ name: string; value: string }> {
  try {
    return Array.from(new URLSearchParams(content).entries()).map(([name, value]) => ({ name, value }));
  } catch {
    return [];
  }
}

interface MultipartPreviewPart {
  id: string;
  name: string;
  filename: string;
  contentType: string;
  value: string;
}

function parseMultipartBody(content: string, contentType: string | null): MultipartPreviewPart[] {
  const boundary = multipartBoundary(contentType);
  if (!boundary) {
    return [];
  }
  const delimiter = `--${boundary}`;
  return content
    .split(delimiter)
    .map((part) => part.replace(/^\r?\n/, "").replace(/\r?\n$/, ""))
    .filter((part) => part.trim() && part.trim() !== "--")
    .map((part, index) => {
      const splitAt = part.search(/\r?\n\r?\n/);
      const rawHeaders = splitAt >= 0 ? part.slice(0, splitAt) : "";
      const value = splitAt >= 0 ? part.slice(part.match(/\r?\n\r?\n/)?.index ?? splitAt).replace(/^\r?\n\r?\n/, "") : part;
      const headers = parseHeaderLines(rawHeaders);
      const disposition = headers["content-disposition"] ?? "";
      return {
        id: String(index),
        name: dispositionParam(disposition, "name"),
        filename: dispositionParam(disposition, "filename"),
        contentType: headers["content-type"] ?? "",
        value: value.replace(/\r?\n--$/, ""),
      };
    });
}

function multipartBoundary(contentType: string | null): string {
  const match = contentType?.match(/boundary=(?:"([^"]+)"|([^;]+))/i);
  return (match?.[1] ?? match?.[2] ?? "").trim();
}

function parseHeaderLines(headers: string): Record<string, string> {
  return headers.split(/\r?\n/).reduce<Record<string, string>>((acc, line) => {
    const index = line.indexOf(":");
    if (index > 0) {
      acc[line.slice(0, index).trim().toLowerCase()] = line.slice(index + 1).trim();
    }
    return acc;
  }, {});
}

function dispositionParam(disposition: string, name: string): string {
  const match = disposition.match(new RegExp(`${name}=(?:"([^"]*)"|([^;]+))`, "i"));
  return (match?.[1] ?? match?.[2] ?? "").trim();
}

function formatXml(content: string): string {
  const compact = content.trim();
  if (!compact) {
    return content;
  }
  try {
    const parser = new DOMParser();
    const doc = parser.parseFromString(compact, "application/xml");
    if (doc.querySelector("parsererror")) {
      return content;
    }
    return compact
      .replace(/>\s+</g, "><")
      .replace(/></g, ">\n<")
      .split("\n")
      .reduce<{ indent: number; lines: string[] }>(
        (state, rawLine) => {
          const line = rawLine.trim();
          const isClosing = /^<\//.test(line);
          const isOpening = /^<[^!?/][^>]*[^/]?>$/.test(line);
          const indent = Math.max(0, state.indent - (isClosing ? 1 : 0));
          state.lines.push(`${"  ".repeat(indent)}${line}`);
          state.indent = indent + (isOpening ? 1 : 0);
          return state;
        },
        { indent: 0, lines: [] },
      )
      .lines.join("\n");
  } catch {
    return content;
  }
}

function MetricCards({ resourceLabel, summary }: { resourceLabel: string; summary: TrafficSummary }) {
  return (
    <section className="jd-section" aria-label="流量汇总">
      <StatGrid>
        <Stat label={<KpiLabel icon="layers" color={1}>{`活跃${resourceLabel}`}</KpiLabel>} value={summary.resources} meta="当前查询窗口内" />
        <Stat label={<KpiLabel icon="upload" color={3}>上传</KpiLabel>} value={formatBytes(summary.uploadBytes)} meta="查询窗口累计" />
        <Stat label={<KpiLabel icon="download" color={2}>下载</KpiLabel>} value={formatBytes(summary.downloadBytes)} meta="查询窗口累计" />
        <Stat
          label={<KpiLabel icon="clock" color={6}>最新更新</KpiLabel>}
          value={summary.updatedAt ? <RelativeTime value={summary.updatedAt} /> : "—"}
          meta="flush 后写入"
        />
      </StatGrid>
    </section>
  );
}

function ResourceBars({ items }: { items: ResourceTotal[] }) {
  const max = Math.max(...items.map((item) => item.totalBytes), 0);
  if (items.length === 0) {
    return <Empty icon="bar-chart" title="暂无资源流量" description="资源转发流量后，按总量排在这里。" />;
  }

  return (
    <ol className="ops-rank" aria-label="资源流量排行">
      {items.map((item) => {
        const width = `${Math.max(2, Math.round((item.totalBytes / Math.max(max, 1)) * 100))}%`;
        return (
          <li key={item.key} className="ops-rank-row">
            <span className="ops-rank-label">
              <span className="jd-strong" title={item.name}>{item.name}</span>
              <span className="ops-rank-sub">
                {item.clientName}
                {item.updatedAt ? <> · <RelativeTime value={item.updatedAt} /></> : null}
              </span>
            </span>
            <span className="jd-hbar-track" aria-hidden="true"><i style={{ "--v": width } as CSSProperties} /></span>
            <span className="ops-rank-value">
              <b className="bd-num">{formatBytes(item.totalBytes)}</b>
              <span className="bd-num">上传 {formatBytes(item.uploadBytes)} · 下载 {formatBytes(item.downloadBytes)}</span>
            </span>
          </li>
        );
      })}
    </ol>
  );
}

function httpPath(row: HttpTrafficExchange): string {
  return `${row.relativePath || "/"}${row.rawQuery ? `?${row.rawQuery}` : ""}`;
}

/** The status of one exchange as a Tag tone: errors and 5xx failed, 4xx needs attention. */
function httpStatusTone(row: HttpTrafficExchange): "danger" | "warning" | "success" {
  if (row.error || row.statusCode >= 500) {
    return "danger";
  }
  if (row.statusCode >= 400) {
    return "warning";
  }
  return "success";
}

function directionLabel(direction: string): string {
  if (direction === "PUBLIC_TO_CLIENT") {
    return "公网 -> 内网";
  }
  if (direction === "CLIENT_TO_PUBLIC") {
    return "内网 -> 公网";
  }
  return direction;
}

function shortChannel(channelId: string): string {
  if (channelId.length <= 18) {
    return channelId;
  }
  return `${channelId.slice(0, 8)}...${channelId.slice(-8)}`;
}

