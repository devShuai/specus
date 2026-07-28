import { type ReactNode, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Button,
  Card,
  CardBody,
  Chip,
  Input,
  Modal,
  ModalBody,
  ModalContent,
  ModalFooter,
  ModalHeader,
  Pagination,
  Popover,
  PopoverContent,
  PopoverTrigger,
  Switch,
  Tab,
  Table,
  TableBody,
  TableCell,
  TableColumn,
  TableHeader,
  TableRow,
  Tabs,
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
import { formatBytes, formatDateTime } from "../../lib/format";
import { notifyError } from "../../components/toast";
import { MobileListCard, MobileListCardList } from "../../components/MobileListCard";
import {
  aggregateResources,
  formatElapsedMs,
  HTTP_EXCHANGE_PAGE_SIZE,
  HTTP_RESPONSE_BODY_TYPES,
  HTTP_SEARCH_FIELDS,
  httpResponseTypeChipClass,
  httpResponseTypeLabel,
  httpResponseTypeOption,
  httpSearchFieldOption,
  latestUpdatedAt,
  normalizeHttpResponseType,
  normalizeHttpSearchField,
  TCP_FRAME_PAGE_SIZE,
  TCP_STREAM_PAGE_SIZE,
  trafficFilterControlClass,
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
import { MediaCapturePanel } from "./traffic/MediaCapturePanel";

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
    <div className="mt-4 flex min-w-0 flex-col gap-2">
      <div className="flex min-h-10 flex-wrap items-center justify-between gap-3">
        <Tabs
          aria-label="流量观测维度"
          classNames={{ base: "min-w-0 max-w-full overflow-x-auto", tabList: "gap-4 sm:gap-6" }}
          selectedKey={trafficView}
          variant="underlined"
          onSelectionChange={(key) => setTrafficView(String(key) as TrafficViewKey)}
        >
          {TRAFFIC_VIEW_TABS.map((item) => (
            <Tab key={item.key} title={item.label} />
          ))}
        </Tabs>
        <div className="flex shrink-0 items-center gap-3">
          <Switch aria-label="自动刷新" isSelected={autoRefresh} size="sm" onValueChange={setAutoRefresh}>
            自动刷新
          </Switch>
          <Button className="shrink-0" size="sm" variant="flat" isLoading={refreshing} onPress={() => void refresh()}>
            刷新
          </Button>
        </div>
      </div>

      <TrafficInspectionStatusBar status={inspectionStatus} />

      {trafficView === "client" && <ClientTrafficTable rows={clientRows} loading={loading} />}

      {trafficView === "tcp" && (
        <div className="flex flex-col gap-2">
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
        </div>
      )}

      {trafficView === "http" && (
        <div className="flex flex-col gap-2">
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
        </div>
      )}
      {trafficView === "media" && <MediaCapturePanel />}
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
    <div className="mt-3 flex min-w-0 flex-col gap-3">
      <MetricCards summary={summary} resourceLabel="客户端" />

      {/* mobile: 卡片 */}
      <div className="lg:hidden">
        <MobileListCardList
          items={rows}
          isLoading={loading}
          emptyContent="暂无数据"
          renderCard={(raw) => {
            const row = raw as TrafficUsage;
            return (
              <MobileListCard
                key={row.id}
                title={<span className="break-all">{row.clientName}</span>}
                subtitle={`${row.usageDate} · #${row.id}`}
                fields={[
                  { label: "上传", value: formatBytes(row.uploadBytes) },
                  { label: "下载", value: formatBytes(row.downloadBytes) },
                  { label: "更新时间", value: formatDateTime(row.updatedAt) },
                ]}
              />
            );
          }}
        />
      </div>

      {/* desktop: 表格 */}
      <div className="hidden min-w-0 overflow-x-auto lg:block">
      <Table aria-label="客户端流量使用" isHeaderSticky removeWrapper>
        <TableHeader>
          <TableColumn>ID</TableColumn>
          <TableColumn>客户端</TableColumn>
          <TableColumn>日期（UTC）</TableColumn>
          <TableColumn>上传</TableColumn>
          <TableColumn>下载</TableColumn>
          <TableColumn>更新时间</TableColumn>
        </TableHeader>
        <TableBody items={rows} isLoading={loading} emptyContent="暂无数据">
          {(row) => (
            <TableRow key={row.id}>
              <TableCell>{row.id}</TableCell>
              <TableCell>{row.clientName}</TableCell>
              <TableCell>{row.usageDate}</TableCell>
              <TableCell>{formatBytes(row.uploadBytes)}</TableCell>
              <TableCell>{formatBytes(row.downloadBytes)}</TableCell>
              <TableCell>{formatDateTime(row.updatedAt)}</TableCell>
            </TableRow>
          )}
        </TableBody>
      </Table>
      </div>
    </div>
  );
}

function TrafficInspectionStatusBar({ status }: { status: TrafficInspectionStatus | null }) {
  const pendingTotal = (status?.pendingHttp ?? 0) + (status?.pendingTcp ?? 0);
  const droppedTotal = (status?.droppedHttp ?? 0) + (status?.droppedTcp ?? 0);

  return (
    <Card shadow="none" className="rounded-md border border-default-200">
      <CardBody className="grid gap-2 p-3 md:grid-cols-4">
        <TrafficStatusItem
          label="明细采集"
          value={status?.enabled ? "全局开启" : "已关闭"}
          tone={status?.enabled ? "success" : "default"}
          hint="仍需通道级开关开启"
        />
        <TrafficStatusItem
          label="待写入"
          value={`${pendingTotal}`}
          tone={pendingTotal > 0 ? "warning" : "default"}
          hint={`HTTP ${status?.pendingHttp ?? 0} / TCP ${status?.pendingTcp ?? 0}`}
        />
        <TrafficStatusItem
          label="已丢弃"
          value={`${droppedTotal}`}
          tone={droppedTotal > 0 ? "danger" : "default"}
          hint={`HTTP ${status?.droppedHttp ?? 0} / TCP ${status?.droppedTcp ?? 0}`}
        />
        <TrafficStatusItem
          label="最近 flush"
          value={formatDateTime(status?.lastFlushedAt)}
          tone="default"
          hint="查询不再强制 flush"
        />
      </CardBody>
    </Card>
  );
}

function trafficToneLabel(tone: "default" | "success" | "warning" | "danger") {
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
  tone: "default" | "success" | "warning" | "danger";
  value: string;
}) {
  return (
    <div className="flex min-w-0 items-center justify-between gap-2 rounded-small bg-default-50 px-3 py-2">
      <div className="min-w-0">
        <div className="text-tiny text-default-500">{label}</div>
        <div className="truncate text-small font-semibold text-foreground">{value}</div>
        <div className="truncate text-tiny text-default-400">{hint}</div>
      </div>
      <Chip color={tone} size="sm" variant="flat">
        {trafficToneLabel(tone)}
      </Chip>
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
    <div className="flex flex-col gap-2">
      <MetricCards summary={summary} resourceLabel={type === "TCP_SPECUS" ? "映射" : "路由"} />

      <Card shadow="none" className="rounded-md border border-default-200">
        <CardBody className="gap-2 p-2.5">
          <div>
            <h3 className="text-small font-semibold">资源流量排行</h3>
            <p className="text-tiny text-default-500">
              {type === "TCP_SPECUS" ? "按公网监听端口聚合" : "按 HTTP 路由名聚合"}
              {totals.length > 8 ? `，仅展示前 8 个（共 ${totals.length} 个）` : ""}
            </p>
          </div>
          <ResourceBars items={totals.slice(0, 8)} />
        </CardBody>
      </Card>

      {/* mobile: 卡片 */}
      <div className="lg:hidden">
        <MobileListCardList
          items={rows}
          isLoading={loading}
          emptyContent={emptyContent}
          renderCard={(raw) => {
            const row = raw as ResourceTrafficUsage;
            return (
              <MobileListCard
                key={row.id}
                title={<span className="break-all">{row.resourceName}</span>}
                subtitle={
                  <div className="flex flex-col gap-0.5 break-all">
                    <span>{row.clientName} · {row.usageDate}</span>
                    <span className="text-tiny text-default-400">{row.resourceKey}</span>
                  </div>
                }
                fields={[
                  { label: "上传", value: formatBytes(row.uploadBytes) },
                  { label: "下载", value: formatBytes(row.downloadBytes) },
                  { label: "更新时间", value: formatDateTime(row.updatedAt) },
                ]}
              />
            );
          }}
        />
      </div>

      {/* desktop: 表格 */}
      <div className="hidden min-w-0 overflow-x-auto lg:block">
      <Table aria-label={`${type} 流量明细`} isHeaderSticky removeWrapper>
        <TableHeader>
          <TableColumn>ID</TableColumn>
          <TableColumn>资源</TableColumn>
          <TableColumn>客户端</TableColumn>
          <TableColumn>日期（UTC）</TableColumn>
          <TableColumn>上传</TableColumn>
          <TableColumn>下载</TableColumn>
          <TableColumn>更新时间</TableColumn>
        </TableHeader>
        <TableBody items={rows} isLoading={loading} emptyContent={emptyContent}>
          {(row) => (
            <TableRow key={row.id}>
              <TableCell>{row.id}</TableCell>
              <TableCell>
                <div className="flex min-w-0 flex-col">
                  <span className="max-w-96 whitespace-normal break-all font-medium" title={row.resourceName}>
                    {row.resourceName}
                  </span>
                  <span className="break-all text-tiny text-default-400" title={row.resourceKey}>
                    {row.resourceKey}
                  </span>
                </div>
              </TableCell>
              <TableCell>{row.clientName}</TableCell>
              <TableCell>{row.usageDate}</TableCell>
              <TableCell>{formatBytes(row.uploadBytes)}</TableCell>
              <TableCell>{formatBytes(row.downloadBytes)}</TableCell>
              <TableCell>{formatDateTime(row.updatedAt)}</TableCell>
            </TableRow>
          )}
        </TableBody>
      </Table>
      </div>
    </div>
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
  const rangeStart = total === 0 ? 0 : page * pageSize + 1;
  const rangeEnd = Math.min(total, (page + 1) * pageSize);
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
  const tableCollectionKey = useMemo(() => {
    const first = rows[0];
    const last = rows[rows.length - 1];
    return [
      tableScopeKey,
      rows.length,
      first ? `${first.id}:${first.capturedAt}` : "empty",
      last ? `${last.id}:${last.capturedAt}` : "empty",
    ].join("|");
  }, [rows, tableScopeKey]);

  return (
    <Card shadow="none" className="rounded-md border border-default-200">
      <CardBody className="gap-3 p-3">
        <div className="flex flex-col gap-1">
          <div>
            <h3 className="text-small font-semibold">HTTP 协议记录</h3>
            <p className="text-tiny text-default-500">请求行、响应状态、headers 与 body 预览</p>
          </div>
          <div className="flex flex-wrap items-end gap-2 lg:hidden" aria-label="HTTP 协议记录筛选">
            <label className="flex min-w-[6.5rem] flex-1 flex-col gap-1 sm:flex-none sm:w-32">
              <span className="text-tiny text-default-500">搜索字段</span>
              <select
                className={trafficFilterControlClass}
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
            <label className="flex min-w-[6rem] flex-1 flex-col gap-1 sm:flex-none sm:w-28">
              <span className="text-tiny text-default-500">返回类型</span>
              <select
                className={trafficFilterControlClass}
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
            <Input
              classNames={{ inputWrapper: "h-9 min-h-9" }}
              className="w-full sm:w-64 lg:w-72"
              label="搜索"
              placeholder={searchFieldOption.placeholder}
              size="sm"
              value={searchDraft}
              onKeyDown={(event) => {
                if (event.key === "Enter") {
                  onSearch();
                }
              }}
              onValueChange={onSearchDraftChange}
            />
            <div className="flex items-center gap-2">
              <Button className="h-9" size="sm" variant="flat" onPress={onSearch}>
                搜索
              </Button>
              <Button className="h-9" size="sm" variant="flat" onPress={onResetSearch}>
                重置
              </Button>
            </div>
          </div>
        </div>
        {hasActiveFilters && (
          <div className="flex flex-wrap items-center gap-2 text-tiny text-default-500">
            <span>当前搜索</span>
            <Chip size="sm" variant="flat">
              {activeSearchFieldOption.label}
            </Chip>
            {activeSearch && (
              <Chip size="sm" variant="flat">
                {activeSearch}
              </Chip>
            )}
            {activeResponseType && (
              <HttpResponseTypeChip value={activeResponseType} contentType={null} bytes={0} />
            )}
          </div>
        )}

        {/* mobile: HTTP 协议记录卡片 */}
        <div className="lg:hidden">
          <MobileListCardList
            items={tableRows}
            isLoading={loading}
            emptyContent="暂无 HTTP 协议记录"
            renderCard={(raw) => {
              const row = raw as (typeof tableRows)[number];
              return (
                <MobileListCard
                  key={row.tableKey}
                  title={
                    <div className="flex items-baseline gap-2 break-all">
                      <span className="font-mono">{row.method}</span>
                      <span className="font-mono text-tiny text-default-500">{httpPath(row)}</span>
                    </div>
                  }
                  subtitle={
                    <div className="flex flex-col gap-0.5 break-all">
                      <span>{row.clientName} · {formatDateTime(row.capturedAt)}</span>
                      {row.remoteAddress ? (
                        <span className="text-tiny text-default-400">{row.remoteAddress}</span>
                      ) : null}
                    </div>
                  }
                  badges={
                    <>
                      <Chip color={httpStatusColor(row)} size="sm" variant="flat">
                        {row.statusCode}
                      </Chip>
                      <HttpResponseTypeChip
                        value={row.responseBodyType}
                        contentType={row.responseContentType}
                        bytes={row.responseBytes}
                      />
                    </>
                  }
                  fields={[
                    {
                      label: "资源",
                      value: <span className="break-all">{row.resourceName}</span>,
                    },
                    {
                      label: "流量",
                      value: (
                        <div className="flex flex-col">
                          <span>请求 {formatBytes(row.requestBytes)}</span>
                          <span>响应 {formatBytes(row.responseBytes)}</span>
                        </div>
                      ),
                    },
                    { label: "耗时", value: formatElapsedMs(row.elapsedMs) },
                  ]}
                  actions={
                    <Button
                      isLoading={detailLoadingId === row.id}
                      size="sm"
                      variant="flat"
                      onPress={() => onOpenDetails(row)}
                    >
                      协议详情
                    </Button>
                  }
                />
              );
            }}
          />
        </div>

        <div className="hidden min-w-0 lg:block">
        <Table
          aria-label="HTTP 协议记录"
          classNames={{ table: "w-full table-fixed", th: "px-2", td: "px-2 align-middle" }}
          isHeaderSticky
          removeWrapper
        >
          <TableHeader>
            <TableColumn className="w-[14%]">时间</TableColumn>
            <TableColumn className="w-[22%]">
              <HttpSearchFilterHeader
                activeSearch={activeSearch}
                activeSearchField={activeSearchField}
                onResetSearch={onResetSearch}
                onSearch={onSearch}
                onSearchDraftChange={onSearchDraftChange}
                onSearchFieldChange={onSearchFieldChange}
                searchDraft={searchDraft}
                searchField={searchField}
                searchFieldOption={searchFieldOption}
              />
            </TableColumn>
            <TableColumn className="w-[8%]">状态</TableColumn>
            <TableColumn className="w-[11%]">
              <HttpResponseTypeFilterHeader
                activeResponseType={activeResponseType}
                onResetSearch={onResetSearch}
                onSearch={onSearch}
                onResponseTypeChange={onResponseTypeChange}
                responseType={responseType}
              />
            </TableColumn>
            <TableColumn className="w-[21%]">资源</TableColumn>
            <TableColumn className="w-[10%]">流量</TableColumn>
            <TableColumn className="w-[6%]">耗时</TableColumn>
            <TableColumn className="w-[8%]">协议详情</TableColumn>
          </TableHeader>
          <TableBody
            key={tableCollectionKey}
            items={tableRows}
            isLoading={loading}
            emptyContent={
              <div className="flex flex-col items-center gap-2 py-3">
                <span>{hasActiveFilters ? "当前筛选没有匹配的 HTTP 协议记录" : "暂无 HTTP 协议记录"}</span>
                {hasActiveFilters && (
                  <Button size="sm" variant="light" onPress={onResetSearch}>
                    重置筛选
                  </Button>
                )}
              </div>
            }
          >
            {(row) => (
              <TableRow key={row.tableKey}>
                <TableCell>
                  <span className="block truncate" title={formatDateTime(row.capturedAt)}>
                    {formatDateTime(row.capturedAt)}
                  </span>
                </TableCell>
                <TableCell>
                  <div className="flex min-w-0 flex-col">
                    <span className="font-mono text-small font-semibold">{row.method}</span>
                    <span className="block max-w-full truncate font-mono text-tiny text-default-500" title={httpPath(row)}>{httpPath(row)}</span>
                    {row.remoteAddress && <span className="block truncate text-tiny text-default-400" title={row.remoteAddress}>{row.remoteAddress}</span>}
                  </div>
                </TableCell>
                <TableCell>
                  <Chip color={httpStatusColor(row)} size="sm" variant="flat">
                    {row.statusCode}
                  </Chip>
                </TableCell>
                <TableCell>
                  <HttpResponseTypeChip
                    value={row.responseBodyType}
                    contentType={row.responseContentType}
                    bytes={row.responseBytes}
                  />
                </TableCell>
                <TableCell>
                  <div className="flex min-w-0 flex-col">
                    <span className="block max-w-full truncate font-medium" title={row.resourceName}>
                      {row.resourceName}
                    </span>
                    <span className="block truncate text-tiny text-default-400" title={row.clientName}>{row.clientName}</span>
                  </div>
                </TableCell>
                <TableCell>
                  <div className="flex flex-col text-small">
                    <span>请求 {formatBytes(row.requestBytes)}</span>
                    <span>响应 {formatBytes(row.responseBytes)}</span>
                  </div>
                </TableCell>
                <TableCell>{formatElapsedMs(row.elapsedMs)}</TableCell>
                <TableCell>
                  <Button
                    isLoading={detailLoadingId === row.id}
                    size="sm"
                    variant="flat"
                    onPress={() => onOpenDetails(row)}
                  >
                    详情
                  </Button>
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
        </div>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <span className="text-small text-default-500">
            {total === 0 ? "共 0 条" : `第 ${rangeStart}-${rangeEnd} 条，共 ${total} 条`}
          </span>
          <Pagination
            showControls
            page={page + 1}
            total={Math.max(1, totalPages)}
            onChange={(value) => onPageChange(value - 1)}
          />
        </div>
      </CardBody>
    </Card>
  );
}

function HttpSearchFilterHeader({
  activeSearch,
  activeSearchField,
  onResetSearch,
  onSearch,
  onSearchDraftChange,
  onSearchFieldChange,
  searchDraft,
  searchField,
  searchFieldOption,
}: {
  activeSearch: string;
  activeSearchField: HttpTrafficSearchField;
  onResetSearch: () => void;
  onSearch: () => void;
  onSearchDraftChange: (value: string) => void;
  onSearchFieldChange: (field: HttpTrafficSearchField) => void;
  searchDraft: string;
  searchField: HttpTrafficSearchField;
  searchFieldOption: { label: string; placeholder: string; value: HttpTrafficSearchField };
}) {
  const active = Boolean(activeSearch || activeSearchField !== "summary");
  const label = active ? `请求: ${httpSearchFieldOption(activeSearchField).label}` : "请求";
  const [popoverOpen, setPopoverOpen] = useState(false);

  return (
    <TrafficTableFilterHeader label={label} active={active} title="搜索 HTTP 记录">
      <Popover isOpen={popoverOpen} placement="bottom-start" shouldBlockScroll={false} onOpenChange={setPopoverOpen}>
        <PopoverTrigger>
          <Button
            isIconOnly
            aria-label="搜索 HTTP 记录"
            className="h-7 min-w-7 text-default-500"
            color={active ? "primary" : "default"}
            size="sm"
            title="搜索 HTTP 记录"
            variant={active ? "flat" : "light"}
          >
            <TrafficFilterIcon />
          </Button>
        </PopoverTrigger>
        <PopoverContent className="w-80 p-3">
          <div className="flex w-full flex-col gap-3">
            <div className="text-small font-semibold">HTTP 记录搜索</div>
            <label className="flex flex-col gap-1">
              <span className="text-tiny text-default-500">搜索字段</span>
              <select
                className={trafficFilterControlClass}
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
            <Input
              label="搜索内容"
              placeholder={searchFieldOption.placeholder}
              size="sm"
              value={searchDraft}
              onKeyDown={(event) => {
                if (event.key === "Enter") {
                  onSearch();
                }
              }}
              onValueChange={onSearchDraftChange}
            />
            <div className="flex justify-end gap-2">
              <Button className="h-9" size="sm" variant="flat" onPress={() => { onResetSearch(); setPopoverOpen(false); }}>
                重置
              </Button>
              <Button className="h-9" color="primary" size="sm" variant="flat" onPress={() => { onSearch(); setPopoverOpen(false); }}>
                应用
              </Button>
            </div>
          </div>
        </PopoverContent>
      </Popover>
    </TrafficTableFilterHeader>
  );
}

function HttpResponseTypeFilterHeader({
  activeResponseType,
  onResetSearch,
  onResponseTypeChange,
  onSearch,
  responseType,
}: {
  activeResponseType: "" | HttpResponseBodyType;
  onResetSearch: () => void;
  onResponseTypeChange: (type: "" | HttpResponseBodyType) => void;
  onSearch: () => void;
  responseType: "" | HttpResponseBodyType;
}) {
  const active = Boolean(activeResponseType);
  const label = active ? `返回: ${httpResponseTypeOption(activeResponseType).label}` : "返回类型";
  const [popoverOpen, setPopoverOpen] = useState(false);

  return (
    <TrafficTableFilterHeader label={label} active={active} title="筛选返回类型">
      <Popover isOpen={popoverOpen} placement="bottom-start" shouldBlockScroll={false} onOpenChange={setPopoverOpen}>
        <PopoverTrigger>
          <Button
            isIconOnly
            aria-label="筛选返回类型"
            className="h-7 min-w-7 text-default-500"
            color={active ? "primary" : "default"}
            size="sm"
            title="筛选返回类型"
            variant={active ? "flat" : "light"}
          >
            <TrafficFilterIcon />
          </Button>
        </PopoverTrigger>
        <PopoverContent className="w-64 p-3">
          <div className="flex w-full flex-col gap-3">
            <div className="text-small font-semibold">返回类型筛选</div>
            <label className="flex flex-col gap-1">
              <span className="text-tiny text-default-500">返回类型</span>
              <select
                className={trafficFilterControlClass}
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
            <div className="flex justify-end gap-2">
              <Button className="h-9" size="sm" variant="flat" onPress={() => { onResetSearch(); setPopoverOpen(false); }}>
                重置
              </Button>
              <Button className="h-9" color="primary" size="sm" variant="flat" onPress={() => { onSearch(); setPopoverOpen(false); }}>
                应用
              </Button>
            </div>
          </div>
        </PopoverContent>
      </Popover>
    </TrafficTableFilterHeader>
  );
}

function TrafficTableFilterHeader({
  active,
  children,
  label,
  title,
}: {
  active: boolean;
  children: ReactNode;
  label: string;
  title: string;
}) {
  return (
    <div className="flex min-w-0 items-center gap-1">
      <span className="truncate" title={label}>
        {label}
      </span>
      <span className="relative z-10" title={title}>{children}</span>
      {active ? <span className="h-1.5 w-1.5 rounded-full bg-primary" aria-hidden /> : null}
    </div>
  );
}

function TrafficFilterIcon() {
  return (
    <svg className="h-4 w-4" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" viewBox="0 0 24 24">
      <path d="M4 5h16l-6 7v5l-4 2v-7L4 5z" />
    </svg>
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
    <Chip
      className={httpResponseTypeChipClass(value, contentType, bytes)}
      size="sm"
      variant="flat"
    >
      {httpResponseTypeLabel(value, contentType, bytes)}
    </Chip>
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
        <ModalContent className="max-w-[min(96vw,1180px)] overflow-hidden">
          {row && (
            <>
              <ModalHeader className="flex min-w-0 flex-col gap-2 pr-12">
                <div className="grid min-w-0 grid-cols-[auto_auto_minmax(0,1fr)] items-start gap-2">
                  <Chip className="mt-0.5" color="primary" size="sm" variant="flat">
                    {row.method}
                  </Chip>
                  <Chip className="mt-0.5" color={httpStatusColor(row)} size="sm" variant="flat">
                    {row.statusCode}
                  </Chip>
                  <span
                    className="max-h-16 min-w-0 overflow-y-auto break-all pr-1 font-mono text-small leading-relaxed"
                    title={httpPath(row)}
                  >
                    {httpPath(row)}
                  </span>
                </div>
                <div className="flex flex-wrap gap-x-4 gap-y-1 text-tiny font-normal text-default-500">
                  <span>{formatDateTime(row.capturedAt)}</span>
                  <span>{row.clientName}</span>
                  <span>{row.route}</span>
                  {row.remoteAddress && <span>{row.remoteAddress}</span>}
                </div>
              </ModalHeader>
              <ModalBody className="gap-3 overflow-y-auto">
                <div className="grid grid-cols-2 gap-2 lg:grid-cols-5">
                  <HttpSummaryTile label="请求大小" value={formatBytes(row.requestBytes)} />
                  <HttpSummaryTile label="响应大小" value={formatBytes(row.responseBytes)} />
                  <HttpSummaryTile
                    label="返回类型"
                    value={httpResponseTypeLabel(row.responseBodyType, row.responseContentType, row.responseBytes)}
                  />
                  <HttpSummaryTile label="耗时" value={formatElapsedMs(row.elapsedMs)} />
                  <HttpSummaryTile label="资源" value={row.resourceName} wrapValue />
                </div>

                {row.error && (
                  <div className="rounded-small border border-danger-200 bg-danger-50 p-3 text-small text-danger">
                    {row.error}
                  </div>
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

function HttpSummaryTile({ label, value, wrapValue = false }: { label: string; value: string; wrapValue?: boolean }) {
  return (
    <div className="min-w-0 rounded-small border border-default-200 bg-default-50 p-2">
      <div className="text-tiny text-default-500">{label}</div>
      <div className={`mt-1 text-small font-semibold ${wrapValue ? "break-all leading-relaxed" : "truncate"}`} title={value}>
        {value}
      </div>
    </div>
  );
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
    <div className="grid h-full min-h-[min(68dvh,44rem)] min-w-0 grid-rows-[4.75rem_17rem_minmax(14rem,1fr)] gap-3 overflow-hidden rounded-small border border-default-200 p-3">
      <div className="flex min-h-0 items-start justify-between gap-3 overflow-hidden">
        <div className="min-w-0">
          <h4 className="text-small font-semibold">{title}</h4>
          <div className="mt-1 flex min-w-0 flex-col gap-1 text-tiny text-default-500">
            {meta.filter(Boolean).map((item) => (
              <span key={item ?? ""} className="block max-w-full truncate" title={item ?? ""}>
                {item}
              </span>
            ))}
          </div>
        </div>
        <Chip className="shrink-0" size="sm" variant="flat">
          {formatBytes(bytes)}
        </Chip>
      </div>
      <HeaderBlock content={headers} />
      <div className="grid min-h-0 grid-rows-[auto_minmax(0,1fr)] gap-2">
        {bodyDisplay.message && (
          <div
            className={`max-h-20 overflow-y-auto rounded-small border p-2 text-tiny leading-relaxed ${
              bodyDisplay.status === "failed" || bodyDisplay.status === "unsupported"
                ? "border-warning-200 bg-warning-50 text-warning-700"
                : "border-primary-100 bg-primary-50 text-primary-700"
            }`}
          >
            {bodyDisplay.message}
          </div>
        )}
        <ProtocolBlock
          title={truncated ? "Body Preview / truncated" : "Body"}
          content={bodyDisplay.content}
          className="min-h-0 grid-rows-[auto_minmax(0,1fr)]"
          maxHeightClass={bodyMaxHeightClass}
          contentClassName="min-h-0"
          action={
            <div className="flex flex-wrap items-center justify-end gap-2">
              {contentEncoding && (
                <Chip color="secondary" size="sm" variant="flat">
                  Content-Encoding {contentEncoding}
                </Chip>
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
      <ModalContent className="max-w-[min(96vw,1180px)]">
        {target && (
          <>
            <ModalHeader className="flex flex-col gap-2">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-semibold">{target.title}</span>
                <Chip color="primary" size="sm" variant="flat">
                  {label}
                </Chip>
                <Chip size="sm" variant="flat">
                  {formatBytes(target.bytes)}
                </Chip>
                {target.contentEncoding && (
                  <Chip color="secondary" size="sm" variant="flat">
                    Content-Encoding {target.contentEncoding}
                  </Chip>
                )}
                {target.truncated && (
                  <Chip color="warning" size="sm" variant="flat">
                    已截断
                  </Chip>
                )}
              </div>
              {target.contentType && (
                <span className="break-all font-mono text-tiny font-normal text-default-500">
                  {target.contentType}
                </span>
              )}
              {target.decodeMessage && (
                <div
                  className={`rounded-small border p-2 text-tiny font-normal leading-relaxed ${
                    target.decodeStatus === "failed" || target.decodeStatus === "unsupported"
                      ? "border-warning-200 bg-warning-50 text-warning-700"
                      : "border-primary-100 bg-primary-50 text-primary-700"
                  }`}
                >
                  {target.decodeMessage}
                </div>
              )}
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
        <Chip color="warning" size="sm" variant="flat">
          JSON 解析失败
        </Chip>
        <TextPreview content={content} maxHeightClass="max-h-[52dvh]" />
      </div>
    );
  }

  return (
    <div className="grid gap-3">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <HttpSummaryTile label="类型" value={jsonRootType(parsed.value)} />
        <HttpSummaryTile label="节点" value={String(countJsonNodes(parsed.value))} />
        <HttpSummaryTile label="字符" value={String(content.length)} />
        <HttpSummaryTile label="格式" value="JSON" />
      </div>
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
        <div key={part.id} className="grid gap-2 rounded-small border border-default-200 p-3">
          <div className="flex flex-wrap items-center gap-2">
            <Chip color="primary" size="sm" variant="flat">
              {part.name || `part ${part.id}`}
            </Chip>
            {part.filename && (
              <Chip size="sm" variant="flat">
                {part.filename}
              </Chip>
            )}
            {part.contentType && (
              <span className="break-all font-mono text-tiny text-default-500">{part.contentType}</span>
            )}
          </div>
          <TextPreview content={part.value} maxHeightClass="max-h-64" />
        </div>
      ))}
    </div>
  );
}

function HtmlBodyPreview({ content }: { content: string }) {
  return (
    <Tabs aria-label="HTML body preview" destroyInactiveTabPanel={false} variant="underlined">
      <Tab key="rendered" title="渲染">
        <div className="mt-3 overflow-hidden rounded-small border border-default-200 bg-white">
          <iframe className="h-[52dvh] w-full bg-white" sandbox="" srcDoc={content} title="HTML body preview" />
        </div>
      </Tab>
      <Tab key="source" title="源码">
        <div className="mt-3">
          <TextPreview content={content} maxHeightClass="max-h-[52dvh]" />
        </div>
      </Tab>
    </Tabs>
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
      <div className="flex min-h-52 items-center justify-center rounded-small border border-default-200 bg-default-50 p-3">
        <img alt="HTTP body preview" className="max-h-[52dvh] max-w-full object-contain" src={imageDataUrl} />
      </div>
    );
  }
  if (contentType?.toLowerCase().includes("svg") || trimmed.startsWith("<svg")) {
    return <HtmlBodyPreview content={content} />;
  }
  return (
    <div className="grid gap-3">
      <Chip color="warning" size="sm" variant="flat">
        图片二进制无法直接渲染
      </Chip>
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
    <div className="max-h-[52dvh] overflow-auto rounded-small border border-default-200">
      <table className="w-full min-w-[680px] border-collapse text-left text-small">
        <thead className="sticky top-0 bg-default-100 text-tiny uppercase text-default-500">
          <tr>
            <th className="w-56 border-b border-default-200 px-3 py-2 font-semibold">Name</th>
            <th className="w-52 border-b border-default-200 px-3 py-2 font-semibold">Meta</th>
            <th className="border-b border-default-200 px-3 py-2 font-semibold">Value</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.id} className="border-b border-default-100 last:border-b-0">
              <td className="break-all px-3 py-2 font-mono text-tiny">{row.name || "-"}</td>
              <td className="break-all px-3 py-2 font-mono text-tiny text-default-500">{row.meta || "-"}</td>
              <td className="whitespace-pre-wrap break-all px-3 py-2 font-mono text-tiny">{row.value || "-"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function TextPreview({ content, maxHeightClass }: { content: string; maxHeightClass: string }) {
  return (
    <pre className={`${maxHeightClass} overflow-auto whitespace-pre-wrap break-all rounded-small bg-background p-3 font-mono text-tiny`}>
      {content.length === 0 ? "-" : content}
    </pre>
  );
}

function JsonHighlightedPreview({ content, maxHeightClass }: { content: string; maxHeightClass: string }) {
  return (
    <pre
      className={`${maxHeightClass} overflow-auto rounded-small border border-default-200 bg-default-50 p-3 font-mono text-tiny leading-relaxed`}
    >
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

function jsonTokenNode(token: string, index: number): ReactNode {
  if (token.startsWith("\"") && token.trimEnd().endsWith(":")) {
    return (
      <span key={index} className="font-semibold text-primary">
        {token}
      </span>
    );
  }
  if (token.startsWith("\"")) {
    return (
      <span key={index} className="text-success-600">
        {token}
      </span>
    );
  }
  if (/^-?\d/.test(token)) {
    return (
      <span key={index} className="text-warning-600">
        {token}
      </span>
    );
  }
  if (token === "true" || token === "false") {
    return (
      <span key={index} className="text-secondary-600">
        {token}
      </span>
    );
  }
  if (token === "null") {
    return (
      <span key={index} className="italic text-default-400">
        {token}
      </span>
    );
  }
  return (
    <span key={index} className="text-default-500">
      {token}
    </span>
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
  const rangeStart = total === 0 ? 0 : page * pageSize + 1;
  const rangeEnd = Math.min(total, (page + 1) * pageSize);
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
    <Card shadow="none" className="rounded-md border border-default-200">
      <CardBody className="gap-3 p-3">
        <div>
          <h3 className="text-small font-semibold">TCP 数据帧</h3>
          <p className="text-tiny text-default-500">按公网连接 channelId 展示双向 payload 预览</p>
        </div>

        {/* mobile: 卡片 */}
        <div className="lg:hidden">
          <MobileListCardList
            items={tableRows}
            isLoading={loading}
            emptyContent="暂无 TCP 数据帧"
            renderCard={(raw) => {
              const row = raw as (typeof tableRows)[number];
              return (
                <MobileListCard
                  key={row.tableKey}
                  title={
                    <div className="flex items-baseline gap-2">
                      <span>{formatDateTime(row.frameTime)}</span>
                      <span className="text-tiny font-normal text-default-400">#{row.frameIndex ?? 0}</span>
                    </div>
                  }
                  subtitle={
                    <div className="flex flex-col gap-0.5 break-all">
                      <span>{row.clientName} · :{row.listenPort}</span>
                      <span className="text-tiny text-default-400" title={row.resourceName}>{row.resourceName}</span>
                    </div>
                  }
                  badges={
                    <Chip
                      color={row.direction === "PUBLIC_TO_CLIENT" ? "primary" : "secondary"}
                      size="sm"
                      variant="flat"
                    >
                      {directionLabel(row.direction)}
                    </Chip>
                  }
                  fields={[
                    {
                      label: "连接",
                      value: (
                        <div className="flex flex-col gap-0.5 break-all font-mono text-tiny">
                          <span>{shortChannel(row.channelId)}</span>
                          <span className="text-default-500">{tcpFlowLabel(row)}</span>
                          {row.remoteAddress ? <span className="text-default-400">peer {row.remoteAddress}</span> : null}
                        </div>
                      ),
                    },
                    {
                      label: "流位置",
                      value: <span className="font-mono text-tiny">{tcpStreamRange(row)}</span>,
                    },
                    {
                      label: "长度",
                      value: (
                        <span>
                          {formatBytes(row.payloadBytes)}
                          {row.truncated && !row.payloadBase64 ? <span className="ml-1 text-tiny text-warning">仅预览</span> : null}
                        </span>
                      ),
                    },
                  ]}
                  extra={
                    <details className="rounded-small border border-default-200 bg-default-50">
                      <summary className="cursor-pointer px-2 py-1 text-tiny text-default-500">展开 ASCII / HEX</summary>
                      <div className="flex flex-col gap-2 p-2">
                        <div>
                          <div className="text-tiny text-default-500">ASCII / 文本</div>
                          <pre className="max-h-36 overflow-auto whitespace-pre-wrap break-all rounded-small bg-content1 p-2 font-mono text-tiny">
                            {row.payloadPreviewText || "-"}
                          </pre>
                        </div>
                        <div>
                          <div className="text-tiny text-default-500">HEX</div>
                          <pre className="max-h-36 overflow-auto whitespace-pre-wrap break-all rounded-small bg-content1 p-2 font-mono text-tiny">
                            {row.payloadPreviewHex || "-"}
                          </pre>
                        </div>
                      </div>
                    </details>
                  }
                  actions={
                    <>
                      <Button
                        isLoading={detailLoadingId === row.id}
                        size="sm"
                        variant="flat"
                        onPress={() => onOpenDetails(row)}
                      >
                        详情
                      </Button>
                      <Button
                        isLoading={streamLoadingChannel === row.channelId}
                        size="sm"
                        variant="flat"
                        onPress={() => onOpenStream(row)}
                      >
                        串流
                      </Button>
                    </>
                  }
                />
              );
            }}
          />
        </div>

        {/* desktop: 表格 */}
        <div className="hidden min-w-0 overflow-x-auto lg:block">
        <Table aria-label="TCP 数据帧" isHeaderSticky removeWrapper>
          <TableHeader>
            <TableColumn>时间</TableColumn>
            <TableColumn>方向</TableColumn>
            <TableColumn>端口</TableColumn>
            <TableColumn>连接</TableColumn>
            <TableColumn>流位置</TableColumn>
            <TableColumn>长度</TableColumn>
            <TableColumn>ASCII / 文本</TableColumn>
            <TableColumn>HEX</TableColumn>
            <TableColumn>解析</TableColumn>
          </TableHeader>
          <TableBody items={tableRows} isLoading={loading} emptyContent="暂无 TCP 数据帧">
            {(row) => (
              <TableRow key={row.tableKey}>
                <TableCell>{formatDateTime(row.frameTime)}</TableCell>
                <TableCell>
                  <Chip
                    color={row.direction === "PUBLIC_TO_CLIENT" ? "primary" : "secondary"}
                    size="sm"
                    variant="flat"
                  >
                    {directionLabel(row.direction)}
                  </Chip>
                </TableCell>
                <TableCell>
                  <div className="flex min-w-0 flex-col">
                    <span className="font-semibold">{row.listenPort}</span>
                    <span className="max-w-64 whitespace-normal break-all text-tiny text-default-400" title={row.resourceName}>
                      {row.resourceName}
                    </span>
                  </div>
                </TableCell>
                <TableCell>
                  <div className="flex min-w-0 flex-col">
                    <span className="max-w-48 truncate font-mono text-tiny">{shortChannel(row.channelId)}</span>
                    <span className="max-w-72 whitespace-normal break-all text-tiny text-default-500" title={tcpFlowLabel(row)}>
                      {tcpFlowLabel(row)}
                    </span>
                    {row.remoteAddress && <span className="max-w-48 truncate text-tiny text-default-400">peer {row.remoteAddress}</span>}
                    <span className="text-tiny text-default-400">{row.clientName}</span>
                  </div>
                </TableCell>
                <TableCell>
                  <div className="flex min-w-0 flex-col font-mono text-tiny">
                    <span>#{row.frameIndex ?? 0}</span>
                    <span className="text-default-400">{tcpStreamRange(row)}</span>
                  </div>
                </TableCell>
                <TableCell>
                  {formatBytes(row.payloadBytes)}
                  {row.truncated && !row.payloadBase64 && <span className="ml-1 text-tiny text-warning">仅预览</span>}
                </TableCell>
                <TableCell>
                  <pre className="max-h-24 max-w-80 overflow-auto whitespace-pre-wrap break-all rounded-small bg-default-50 p-2 font-mono text-tiny">
                    {row.payloadPreviewText || "-"}
                  </pre>
                </TableCell>
                <TableCell>
                  <pre className="max-h-24 max-w-96 overflow-auto whitespace-pre-wrap break-all rounded-small bg-default-50 p-2 font-mono text-tiny">
                    {row.payloadPreviewHex || "-"}
                  </pre>
                </TableCell>
                <TableCell>
                  <div className="flex flex-wrap gap-2">
                    <Button
                      isLoading={detailLoadingId === row.id}
                      size="sm"
                      variant="flat"
                      onPress={() => onOpenDetails(row)}
                    >
                      详情
                    </Button>
                    <Button
                      isLoading={streamLoadingChannel === row.channelId}
                      size="sm"
                      variant="flat"
                      onPress={() => onOpenStream(row)}
                    >
                      串流
                    </Button>
                  </div>
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
        </div>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <span className="text-small text-default-500">
            {total === 0 ? "共 0 条" : `第 ${rangeStart}-${rangeEnd} 条，共 ${total} 条`}
          </span>
          <Pagination
            showControls
            page={page + 1}
            total={Math.max(1, totalPages)}
            onChange={(value) => onPageChange(value - 1)}
          />
        </div>
      </CardBody>
    </Card>
  );
}

function TcpFrameModal({ row, onClose }: { row: TcpTrafficFrame | null; onClose: () => void }) {
  const analysis = useMemo(() => (row ? analyzeTcpPayload(row) : null), [row]);

  return (
    <Modal classNames={TRAFFIC_MODAL_CLASS_NAMES} isOpen={row != null} size="5xl" scrollBehavior="inside" onOpenChange={(open) => !open && onClose()}>
      <ModalContent className="max-w-[min(96vw,1180px)]">
        {(close) =>
          row && analysis ? (
            <>
              <ModalHeader className="flex flex-col gap-2">
                <div className="flex flex-wrap items-center gap-2">
                  <Chip color={row.direction === "PUBLIC_TO_CLIENT" ? "primary" : "secondary"} size="sm" variant="flat">
                    {directionLabel(row.direction)}
                  </Chip>
                  <span className="font-semibold">TCP 数据帧 #{row.id}</span>
                </div>
                <div className="flex flex-wrap gap-4 text-small font-normal text-default-500">
                  <span>{formatDateTime(row.frameTime)}</span>
                  <span>{row.listenPort}</span>
                  <span>{row.clientName}</span>
                  <span>{tcpFlowLabel(row)}</span>
                </div>
              </ModalHeader>
              <ModalBody className="gap-3 overflow-y-auto">
                <div className="grid gap-2 md:grid-cols-4 xl:grid-cols-6">
                  <HttpSummaryTile label="长度" value={formatBytes(row.payloadBytes)} />
                  <HttpSummaryTile label="解析类型" value={tcpPayloadKindLabel(analysis.kind)} />
                  <HttpSummaryTile label="资源" value={row.resourceName || "-"} />
                  <HttpSummaryTile label="Channel" value={shortChannel(row.channelId)} />
                  <HttpSummaryTile label="Frame" value={`#${row.frameIndex ?? 0}`} />
                  <HttpSummaryTile label="Offset" value={tcpStreamRange(row)} />
                </div>
                {!analysis.fullAvailable && (
                  <div className="rounded-small border border-warning-200 bg-warning-50 px-3 py-2 text-small text-warning-700">
                    这条历史记录没有完整二进制字段，只能展示旧版保存的 payload 预览。
                  </div>
                )}
                <Tabs aria-label="TCP payload 预览" destroyInactiveTabPanel={false} variant="underlined">
                  <Tab key="parsed" title="解析">
                    <TcpParsedPayload analysis={analysis} />
                  </Tab>
                  <Tab key="text" title="文本">
                    <TextPreview content={analysis.text || row.payloadPreviewText || ""} maxHeightClass="max-h-[52dvh]" />
                  </Tab>
                  <Tab key="hex" title="Hexdump">
                    <TextPreview content={analysis.hexDump || row.payloadPreviewHex || ""} maxHeightClass="max-h-[52dvh]" />
                  </Tab>
                </Tabs>
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
      <ModalContent className="max-w-[min(96vw,1180px)]">
        {(close) =>
          stream ? (
            <>
              <ModalHeader className="flex flex-col gap-2">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-semibold">TCP 数据流</span>
                  <Chip color="primary" size="sm" variant="flat">
                    {shortChannel(stream.channelId)}
                  </Chip>
                  {stream.truncated && (
                    <Chip color="warning" size="sm" variant="flat">
                      后续分页可用
                    </Chip>
                  )}
                </div>
                <div className="flex flex-wrap gap-x-4 gap-y-1 text-small font-normal text-default-500">
                  <span>
                    第 {stream.page + 1} / {Math.max(1, stream.totalPages)} 页
                  </span>
                  <span>
                    {stream.total} 帧中的 {frames.length} 帧
                  </span>
                  <span>{formatBytes(totalBytes)}</span>
                  {frames[0] && <span>{frames[0].resourceName}</span>}
                </div>
              </ModalHeader>
              <ModalBody className="gap-3 overflow-y-auto">
                <div className="grid gap-2 md:grid-cols-4">
                  <HttpSummaryTile label="总帧数" value={`${frames.length}`} />
                  <HttpSummaryTile label="总流量" value={formatBytes(totalBytes)} />
                  <HttpSummaryTile label="公网 -> 内网" value={`${publicFrames.length} 帧`} />
                  <HttpSummaryTile label="内网 -> 公网" value={`${clientFrames.length} 帧`} />
                </div>
                <Tabs aria-label="TCP 数据流视图" destroyInactiveTabPanel={false} variant="underlined">
                  <Tab key="timeline" title="时间线">
                    <TcpStreamTimeline frames={frames} />
                  </Tab>
                  <Tab key="public" title="公网 -> 内网">
                    <TcpStreamPayload frames={publicFrames} />
                  </Tab>
                  <Tab key="client" title="内网 -> 公网">
                    <TcpStreamPayload frames={clientFrames} />
                  </Tab>
                </Tabs>
              </ModalBody>
              <ModalFooter>
                {stream.totalPages > 1 && (
                  <Pagination
                    showControls
                    isDisabled={loading}
                    page={stream.page + 1}
                    total={Math.max(1, stream.totalPages)}
                    onChange={(page) => onPageChange(Math.max(0, page - 1))}
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
    <div className="max-h-[52dvh] overflow-auto rounded-small border border-default-200">
      <table className="w-full min-w-[900px] border-collapse text-left text-small">
        <thead className="sticky top-0 bg-default-100 text-tiny uppercase text-default-500">
          <tr>
            <th className="border-b border-default-200 px-3 py-2 font-semibold">时间</th>
            <th className="border-b border-default-200 px-3 py-2 font-semibold">方向</th>
            <th className="border-b border-default-200 px-3 py-2 font-semibold">端点</th>
            <th className="border-b border-default-200 px-3 py-2 font-semibold">Frame / Offset</th>
            <th className="border-b border-default-200 px-3 py-2 font-semibold">长度</th>
            <th className="border-b border-default-200 px-3 py-2 font-semibold">文本预览</th>
          </tr>
        </thead>
        <tbody>
          {frames.map((frame) => (
            <tr key={frame.id} className="border-b border-default-100 last:border-b-0">
              <td className="whitespace-nowrap px-3 py-2 text-tiny">{formatDateTime(frame.frameTime)}</td>
              <td className="px-3 py-2">
                <Chip color={frame.direction === "PUBLIC_TO_CLIENT" ? "primary" : "secondary"} size="sm" variant="flat">
                  {directionLabel(frame.direction)}
                </Chip>
              </td>
              <td className="max-w-96 break-all px-3 py-2 font-mono text-tiny">{tcpFlowLabel(frame)}</td>
              <td className="px-3 py-2 font-mono text-tiny">
                #{frame.frameIndex ?? 0} / {tcpStreamRange(frame)}
              </td>
              <td className="whitespace-nowrap px-3 py-2">{formatBytes(frame.payloadBytes)}</td>
              <td className="max-w-96 break-all px-3 py-2 font-mono text-tiny">{frame.payloadPreviewText || "-"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
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
        <Chip color="primary" size="sm" variant="flat">
          {frames.length} 帧
        </Chip>
        <Chip size="sm" variant="flat">
          {formatBytes(bytes.length)}
        </Chip>
        {!fullAvailable && (
          <Chip color="warning" size="sm" variant="flat">
            含旧版预览数据
          </Chip>
        )}
      </div>
      <Tabs aria-label="TCP 拼接 payload 预览" destroyInactiveTabPanel={false} variant="underlined">
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
      </Tabs>
    </div>
  );
}

function TcpParsedPayload({ analysis }: { analysis: TcpPayloadAnalysis }) {
  if (analysis.http) {
    const contentType = tcpHeaderValue(analysis.http.headers, "content-type");
    const bodyKind = detectBodyPreviewKind(contentType, analysis.http.body);
    return (
      <div className="grid gap-4">
        <div className="rounded-small border border-default-200 bg-default-50 p-3">
          <div className="text-tiny font-semibold uppercase text-default-500">Start line</div>
          <div className="mt-1 break-all font-mono text-small">{analysis.http.startLine}</div>
        </div>
        <TcpHeaderPreview headers={analysis.http.headers} />
        <div className="grid gap-2">
          <div className="text-small font-semibold">Body</div>
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
          <Chip color="primary" size="sm" variant="flat">
            {analysis.imageMime}
          </Chip>
          <span className="text-small text-default-500">已按图片魔数识别并渲染</span>
        </div>
        <div className="flex max-h-[52dvh] items-center justify-center overflow-auto rounded-small border border-default-200 bg-default-50 p-3">
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
        <Chip color="default" size="sm" variant="flat">
          {analysis.binaryLabel}
        </Chip>
        <span className="text-small text-default-500">无法可靠解析为文本协议，展示二进制 hexdump。</span>
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
    <div className="max-h-52 overflow-auto rounded-small border border-default-200">
      <table className="w-full min-w-[560px] border-collapse text-left text-small">
        <thead className="sticky top-0 bg-default-100 text-tiny uppercase text-default-500">
          <tr>
            <th className="w-56 border-b border-default-200 px-3 py-2 font-semibold">Header</th>
            <th className="border-b border-default-200 px-3 py-2 font-semibold">Value</th>
          </tr>
        </thead>
        <tbody>
          {headers.map((header, index) => (
            <tr key={`${header.name}-${index}`} className="border-b border-default-100 last:border-b-0">
              <td className="break-all px-3 py-2 font-mono text-tiny">{header.name}</td>
              <td className="whitespace-pre-wrap break-all px-3 py-2 font-mono text-tiny">{header.value}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
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
        <span className="text-tiny font-semibold text-default-500">Headers</span>
        <Chip size="sm" variant="flat">
          {rows.length} 项
        </Chip>
      </div>
      <Tabs
        aria-label="Header 展示方式"
        classNames={{ base: "min-h-0", panel: "min-h-0 py-0" }}
        destroyInactiveTabPanel={false}
        size="sm"
        variant="underlined"
      >
        <Tab key="form" title="表单">
          <div className="mt-2 grid h-[12.75rem] min-w-0 gap-2 overflow-y-auto rounded-small border border-default-200 bg-default-50 p-2">
            {rows.length === 0 ? (
              <div className="rounded-small bg-background p-3 text-tiny text-default-400">暂无 Header</div>
            ) : (
              rows.map((row) => (
                <div key={row.id} className="grid min-w-0 gap-2 rounded-small border border-default-100 bg-background p-3">
                  <div className="flex min-w-0 flex-wrap items-start justify-between gap-2">
                    <div className="min-w-0">
                      <div className="break-all font-mono text-tiny font-semibold">{row.name}</div>
                      <div className="mt-1 text-tiny leading-relaxed text-default-500">{row.info.summary}</div>
                    </div>
                    {row.info.links.length > 0 && (
                      <div className="flex shrink-0 flex-wrap gap-1">
                        {row.info.links.map((link) => (
                          <a
                            key={link.url}
                            className="rounded-small bg-primary-50 px-2 py-1 text-[11px] font-medium text-primary hover:bg-primary-100"
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
                  <pre className="max-h-28 min-w-0 overflow-auto whitespace-pre-wrap break-all rounded-small bg-default-50 p-2 font-mono text-[11px] leading-relaxed">
                    {row.value || "-"}
                  </pre>
                  <p className="text-tiny leading-relaxed text-default-500">{row.info.details}</p>
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
      </Tabs>
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
        <span className="text-tiny font-semibold text-default-500">{title}</span>
        {action}
      </div>
      <pre className={`${maxHeightClass} ${contentClassName} overflow-auto whitespace-pre-wrap break-all rounded-small bg-background p-2 font-mono text-tiny`}>
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
  const cards = [
    { label: `活跃${resourceLabel}`, value: String(summary.resources), hint: "当前查询窗口内" },
    { label: "上传", value: formatBytes(summary.uploadBytes), hint: "查询窗口累计" },
    { label: "下载", value: formatBytes(summary.downloadBytes), hint: "查询窗口累计" },
    { label: "最新更新", value: formatDateTime(summary.updatedAt), hint: "flush 后写入" },
  ];

  return (
    <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-4">
      {cards.map((card) => (
        <Card key={card.label} shadow="none" className="rounded-md border border-default-200">
          <CardBody className="gap-0.5 p-2.5">
            <span className="text-small text-default-500">{card.label}</span>
            <span className="text-lg font-semibold">{card.value}</span>
            <span className="text-tiny text-default-400">{card.hint}</span>
          </CardBody>
        </Card>
      ))}
    </div>
  );
}

function ResourceBars({ items }: { items: ResourceTotal[] }) {
  const max = Math.max(...items.map((item) => item.totalBytes), 0);
  if (items.length === 0) {
    return (
      <div className="flex min-h-40 items-center justify-center rounded-small bg-default-50 text-small text-default-400">
        暂无资源流量
      </div>
    );
  }

  return (
    <div className="grid gap-1.5">
      {items.map((item) => {
        const width = `${Math.max(3, Math.round((item.totalBytes / Math.max(max, 1)) * 100))}%`;
        return (
          <div key={item.key} className="grid gap-0.5">
            <div className="flex items-center justify-between gap-3 text-small">
              <span className="min-w-0 break-all font-medium" title={item.name}>
                {item.name}
              </span>
              <span className="shrink-0 text-default-500">{formatBytes(item.totalBytes)}</span>
            </div>
            <div className="h-1.5 overflow-hidden rounded-small bg-default-100">
              <div className="h-full rounded-small bg-primary" style={{ width }} />
            </div>
            <div className="flex flex-wrap items-center gap-2 text-tiny text-default-400">
              <Chip size="sm" variant="flat">
                {item.clientName}
              </Chip>
              <span>上传 {formatBytes(item.uploadBytes)}</span>
              <span>下载 {formatBytes(item.downloadBytes)}</span>
              <span>{formatDateTime(item.updatedAt)}</span>
            </div>
          </div>
        );
      })}
    </div>
  );
}

function httpPath(row: HttpTrafficExchange): string {
  return `${row.relativePath || "/"}${row.rawQuery ? `?${row.rawQuery}` : ""}`;
}

function httpStatusColor(row: HttpTrafficExchange): "danger" | "warning" | "success" {
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

