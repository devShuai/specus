import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Button,
  Card,
  CardBody,
  Chip,
  Modal,
  ModalBody,
  ModalContent,
  ModalFooter,
  ModalHeader,
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
  ResourceTrafficType,
  ResourceTrafficUsage,
  TcpTrafficFrame,
  TrafficUsage,
} from "../../api/types";
import { formatBytes, formatDateTime } from "../../lib/format";
import { notifyError } from "../../components/toast";

interface TrafficSummary {
  resources: number;
  uploadBytes: number;
  downloadBytes: number;
  updatedAt: string | null;
}

interface ResourceTotal {
  key: string;
  name: string;
  clientName: string;
  uploadBytes: number;
  downloadBytes: number;
  totalBytes: number;
  updatedAt: string | null;
}

export function TrafficPanel() {
  const [clientRows, setClientRows] = useState<TrafficUsage[]>([]);
  const [tcpRows, setTcpRows] = useState<ResourceTrafficUsage[]>([]);
  const [httpRows, setHttpRows] = useState<ResourceTrafficUsage[]>([]);
  const [tcpFrameRows, setTcpFrameRows] = useState<TcpTrafficFrame[]>([]);
  const [httpExchangeRows, setHttpExchangeRows] = useState<HttpTrafficExchange[]>([]);
  const [selectedHttpExchange, setSelectedHttpExchange] = useState<HttpTrafficExchange | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [clients, tcp, http, tcpFrames, httpExchanges] = await Promise.all([
        adminApi.listTraffic(150),
        adminApi.listResourceTraffic("TCP_TUNNEL", 200),
        adminApi.listResourceTraffic("HTTP_ROUTE", 200),
        adminApi.listTcpTrafficFrames(200),
        adminApi.listHttpTrafficExchanges(100),
      ]);
      setClientRows(clients);
      setTcpRows(tcp);
      setHttpRows(http);
      setTcpFrameRows(tcpFrames);
      setHttpExchangeRows(httpExchanges);
    } catch (error) {
      notifyError(error, "加载流量失败");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <div className="mt-4 flex flex-col gap-4">
      <div className="flex justify-end">
        <Button size="sm" variant="flat" onPress={() => void load()}>
          刷新
        </Button>
      </div>

      <Tabs aria-label="流量观测维度" variant="underlined" destroyInactiveTabPanel={false}>
        <Tab key="client" title="客户端汇总">
          <ClientTrafficTable rows={clientRows} loading={loading} />
        </Tab>
        <Tab key="tcp" title="TCP 映射">
          <div className="flex flex-col gap-4">
            <ResourceTrafficSection
              rows={tcpRows}
              loading={loading}
              emptyContent="暂无 TCP 映射流量"
              type="TCP_TUNNEL"
            />
            <TcpFrameTable rows={tcpFrameRows} loading={loading} />
          </div>
        </Tab>
        <Tab key="http" title="HTTP 路由">
          <div className="flex flex-col gap-4">
            <ResourceTrafficSection
              rows={httpRows}
              loading={loading}
              emptyContent="暂无 HTTP 路由流量"
              type="HTTP_ROUTE"
            />
            <HttpExchangeTable
              rows={httpExchangeRows}
              loading={loading}
              onOpenDetails={setSelectedHttpExchange}
            />
          </div>
        </Tab>
      </Tabs>
      <HttpExchangeModal row={selectedHttpExchange} onClose={() => setSelectedHttpExchange(null)} />
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
    <div className="mt-4 flex flex-col gap-4">
      <MetricCards summary={summary} resourceLabel="客户端" />
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
    <div className="mt-4 flex flex-col gap-4">
      <MetricCards summary={summary} resourceLabel={type === "TCP_TUNNEL" ? "映射" : "路由"} />

      <Card shadow="none" className="rounded-md border border-default-200">
        <CardBody className="gap-4 p-4">
          <div>
            <h3 className="text-small font-semibold">资源流量排行</h3>
            <p className="text-tiny text-default-500">
              {type === "TCP_TUNNEL" ? "按公网监听端口聚合" : "按 HTTP 路由名聚合"}
            </p>
          </div>
          <ResourceBars items={totals.slice(0, 8)} />
        </CardBody>
      </Card>

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
                  <span className="max-w-80 truncate font-medium">{row.resourceName}</span>
                  <span className="text-tiny text-default-400">{row.resourceKey}</span>
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
  );
}

function HttpExchangeTable({
  rows,
  loading,
  onOpenDetails,
}: {
  rows: HttpTrafficExchange[];
  loading: boolean;
  onOpenDetails: (row: HttpTrafficExchange) => void;
}) {
  return (
    <Card shadow="none" className="rounded-md border border-default-200">
      <CardBody className="gap-4 p-4">
        <div>
          <h3 className="text-small font-semibold">HTTP 协议记录</h3>
          <p className="text-tiny text-default-500">请求行、响应状态、headers 与 body 预览</p>
        </div>
        <Table aria-label="HTTP 协议记录" isHeaderSticky removeWrapper>
          <TableHeader>
            <TableColumn>时间</TableColumn>
            <TableColumn>请求</TableColumn>
            <TableColumn>状态</TableColumn>
            <TableColumn>资源</TableColumn>
            <TableColumn>流量</TableColumn>
            <TableColumn>耗时</TableColumn>
            <TableColumn>协议详情</TableColumn>
          </TableHeader>
          <TableBody items={rows} isLoading={loading} emptyContent="暂无 HTTP 协议记录">
            {(row) => (
              <TableRow key={row.id}>
                <TableCell>{formatDateTime(row.capturedAt)}</TableCell>
                <TableCell>
                  <div className="flex min-w-0 flex-col">
                    <span className="font-mono text-small font-semibold">{row.method}</span>
                    <span className="max-w-80 truncate font-mono text-tiny text-default-500">{httpPath(row)}</span>
                    {row.remoteAddress && <span className="text-tiny text-default-400">{row.remoteAddress}</span>}
                  </div>
                </TableCell>
                <TableCell>
                  <Chip color={httpStatusColor(row)} size="sm" variant="flat">
                    {row.statusCode}
                  </Chip>
                </TableCell>
                <TableCell>
                  <div className="flex min-w-0 flex-col">
                    <span className="max-w-80 truncate font-medium">{row.resourceName}</span>
                    <span className="text-tiny text-default-400">{row.clientName}</span>
                  </div>
                </TableCell>
                <TableCell>
                  <div className="flex flex-col text-small">
                    <span>请求 {formatBytes(row.requestBytes)}</span>
                    <span>响应 {formatBytes(row.responseBytes)}</span>
                  </div>
                </TableCell>
                <TableCell>{row.elapsedMs} ms</TableCell>
                <TableCell>
                  <Button size="sm" variant="flat" onPress={() => onOpenDetails(row)}>
                    详情
                  </Button>
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </CardBody>
    </Card>
  );
}

function HttpExchangeModal({ row, onClose }: { row: HttpTrafficExchange | null; onClose: () => void }) {
  return (
    <Modal isOpen={Boolean(row)} onClose={onClose} size="5xl" scrollBehavior="inside">
      <ModalContent>
        {row && (
          <>
            <ModalHeader className="flex flex-col gap-3">
              <div className="flex flex-wrap items-center gap-2">
                <Chip color="primary" size="sm" variant="flat">
                  {row.method}
                </Chip>
                <Chip color={httpStatusColor(row)} size="sm" variant="flat">
                  {row.statusCode}
                </Chip>
                <span className="min-w-0 flex-1 break-all font-mono text-small">{httpPath(row)}</span>
              </div>
              <div className="flex flex-wrap gap-x-4 gap-y-1 text-tiny font-normal text-default-500">
                <span>{formatDateTime(row.capturedAt)}</span>
                <span>{row.clientName}</span>
                <span>{row.route}</span>
                {row.remoteAddress && <span>{row.remoteAddress}</span>}
              </div>
            </ModalHeader>
            <ModalBody className="gap-4">
              <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
                <HttpSummaryTile label="请求大小" value={formatBytes(row.requestBytes)} />
                <HttpSummaryTile label="响应大小" value={formatBytes(row.responseBytes)} />
                <HttpSummaryTile label="耗时" value={`${row.elapsedMs} ms`} />
                <HttpSummaryTile label="资源" value={row.resourceName} />
              </div>

              {row.error && (
                <div className="rounded-small border border-danger-200 bg-danger-50 p-3 text-small text-danger">
                  {row.error}
                </div>
              )}

              <div className="grid gap-4 xl:grid-cols-2">
                <HttpMessagePanel
                  title="Request"
                  meta={[row.requestContentType, `${row.method} ${httpPath(row)}`]}
                  bytes={row.requestBytes}
                  headers={row.requestHeaders}
                  previewText={row.requestPreviewText}
                  truncated={row.requestTruncated}
                />
                <HttpMessagePanel
                  title="Response"
                  meta={[row.responseContentType, `HTTP ${row.statusCode}`]}
                  bytes={row.responseBytes}
                  headers={row.responseHeaders}
                  previewText={row.responsePreviewText}
                  truncated={row.responseTruncated}
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
  );
}

function HttpSummaryTile({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0 rounded-small border border-default-200 bg-default-50 p-3">
      <div className="text-tiny text-default-500">{label}</div>
      <div className="mt-1 truncate text-small font-semibold">{value}</div>
    </div>
  );
}

function HttpMessagePanel({
  bytes,
  headers,
  meta,
  previewText,
  title,
  truncated,
}: {
  bytes: number;
  headers: string | null;
  meta: Array<string | null>;
  previewText: string | null;
  title: string;
  truncated: boolean;
}) {
  return (
    <div className="grid min-w-0 gap-3 rounded-small border border-default-200 p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h4 className="text-small font-semibold">{title}</h4>
          <div className="mt-1 flex flex-wrap gap-2 text-tiny text-default-500">
            {meta.filter(Boolean).map((item) => (
              <span key={item ?? ""} className="max-w-full break-all">
                {item}
              </span>
            ))}
          </div>
        </div>
        <Chip size="sm" variant="flat">
          {formatBytes(bytes)}
        </Chip>
      </div>
      <ProtocolBlock title="Headers" content={headers} maxHeightClass="max-h-48" />
      <ProtocolBlock
        title={truncated ? "Body Preview / truncated" : "Body"}
        content={previewText}
        maxHeightClass="max-h-64"
      />
    </div>
  );
}

function TcpFrameTable({ rows, loading }: { rows: TcpTrafficFrame[]; loading: boolean }) {
  return (
    <Card shadow="none" className="rounded-md border border-default-200">
      <CardBody className="gap-4 p-4">
        <div>
          <h3 className="text-small font-semibold">TCP 数据帧</h3>
          <p className="text-tiny text-default-500">按公网连接 channelId 展示双向 payload 预览</p>
        </div>
        <Table aria-label="TCP 数据帧" isHeaderSticky removeWrapper>
          <TableHeader>
            <TableColumn>时间</TableColumn>
            <TableColumn>方向</TableColumn>
            <TableColumn>端口</TableColumn>
            <TableColumn>连接</TableColumn>
            <TableColumn>长度</TableColumn>
            <TableColumn>ASCII / 文本</TableColumn>
            <TableColumn>HEX</TableColumn>
          </TableHeader>
          <TableBody items={rows} isLoading={loading} emptyContent="暂无 TCP 数据帧">
            {(row) => (
              <TableRow key={row.id}>
                <TableCell>{formatDateTime(row.frameTime)}</TableCell>
                <TableCell>
                  <Chip
                    color={row.direction === "PUBLIC_TO_CLIENT" ? "primary" : "warning"}
                    size="sm"
                    variant="flat"
                  >
                    {directionLabel(row.direction)}
                  </Chip>
                </TableCell>
                <TableCell>
                  <div className="flex min-w-0 flex-col">
                    <span className="font-semibold">{row.listenPort}</span>
                    <span className="max-w-52 truncate text-tiny text-default-400">{row.resourceName}</span>
                  </div>
                </TableCell>
                <TableCell>
                  <div className="flex min-w-0 flex-col">
                    <span className="max-w-48 truncate font-mono text-tiny">{shortChannel(row.channelId)}</span>
                    {row.remoteAddress && <span className="max-w-48 truncate text-tiny text-default-400">{row.remoteAddress}</span>}
                    <span className="text-tiny text-default-400">{row.clientName}</span>
                  </div>
                </TableCell>
                <TableCell>
                  {formatBytes(row.payloadBytes)}
                  {row.truncated && <span className="ml-1 text-tiny text-warning">截断</span>}
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
              </TableRow>
            )}
          </TableBody>
        </Table>
      </CardBody>
    </Card>
  );
}

function ProtocolBlock({
  content,
  maxHeightClass = "max-h-32",
  title,
}: {
  content: string | null;
  maxHeightClass?: string;
  title: string;
}) {
  return (
    <div className="grid gap-1">
      <span className="text-tiny font-semibold text-default-500">{title}</span>
      <pre className={`${maxHeightClass} overflow-auto whitespace-pre-wrap break-all rounded-small bg-background p-2 font-mono text-tiny`}>
        {content?.trim() || "-"}
      </pre>
    </div>
  );
}

function MetricCards({ resourceLabel, summary }: { resourceLabel: string; summary: TrafficSummary }) {
  const cards = [
    { label: `活跃${resourceLabel}`, value: String(summary.resources), hint: "当前查询窗口内" },
    { label: "上传", value: formatBytes(summary.uploadBytes), hint: "查询窗口累计" },
    { label: "下载", value: formatBytes(summary.downloadBytes), hint: "查询窗口累计" },
    { label: "最新更新", value: formatDateTime(summary.updatedAt), hint: "flush 后写入" },
  ];

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      {cards.map((card) => (
        <Card key={card.label} shadow="none" className="rounded-md border border-default-200">
          <CardBody className="gap-1 p-4">
            <span className="text-small text-default-500">{card.label}</span>
            <span className="text-xl font-semibold">{card.value}</span>
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
    <div className="grid gap-3">
      {items.map((item) => {
        const width = `${Math.max(3, Math.round((item.totalBytes / Math.max(max, 1)) * 100))}%`;
        return (
          <div key={item.key} className="grid gap-1">
            <div className="flex items-center justify-between gap-3 text-small">
              <span className="min-w-0 truncate font-medium">{item.name}</span>
              <span className="shrink-0 text-default-500">{formatBytes(item.totalBytes)}</span>
            </div>
            <div className="h-2 overflow-hidden rounded-small bg-default-100">
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

function aggregateResources(rows: ResourceTrafficUsage[]): ResourceTotal[] {
  const byResource = new Map<string, ResourceTotal>();
  for (const row of rows) {
    const key = `${row.resourceType}:${row.resourceKey}:${row.clientId}`;
    const item = byResource.get(key) ?? {
      key,
      name: row.resourceName,
      clientName: row.clientName,
      uploadBytes: 0,
      downloadBytes: 0,
      totalBytes: 0,
      updatedAt: null,
    };
    item.name = row.resourceName || item.name;
    item.clientName = row.clientName || item.clientName;
    item.uploadBytes += row.uploadBytes;
    item.downloadBytes += row.downloadBytes;
    item.totalBytes = item.uploadBytes + item.downloadBytes;
    item.updatedAt = later(item.updatedAt, row.updatedAt);
    byResource.set(key, item);
  }
  return Array.from(byResource.values()).sort((a, b) => b.totalBytes - a.totalBytes);
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

function latestUpdatedAt(rows: Array<{ updatedAt: string }>): string | null {
  return rows.reduce<string | null>((latest, row) => later(latest, row.updatedAt), null);
}

function later(left: string | null, right: string | null | undefined): string | null {
  if (!right) {
    return left;
  }
  if (!left) {
    return right;
  }
  return new Date(right).getTime() > new Date(left).getTime() ? right : left;
}
