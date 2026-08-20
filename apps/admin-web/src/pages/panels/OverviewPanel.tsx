import { useCallback, useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import { Button, Card, Spinner } from "@heroui/react";
import { adminApi } from "../../api/client";
import type { Client, Overview, TrafficUsage } from "../../api/types";
import { formatBytes } from "../../lib/format";
import { notifyError } from "../../components/toast";
import { EmptyState } from "../../components/EmptyState";

/** 全局面指标配色常量：趋势图与占比环保持一致。 */
const TOTAL_COLOR = "hsl(var(--heroui-primary))";
const DOWNLOAD_COLOR = "hsl(var(--heroui-secondary))";
const UPLOAD_COLOR = "hsl(var(--heroui-success))";

interface MetricCard {
  label: string;
  value: string;
  hint: string;
}

interface TrafficDay {
  date: string;
  uploadBytes: number;
  downloadBytes: number;
  totalBytes: number;
}

interface ClientTraffic {
  clientName: string;
  uploadBytes: number;
  downloadBytes: number;
  totalBytes: number;
}

export function OverviewPanel() {
  const [overview, setOverview] = useState<Overview | null>(null);
  const [traffic, setTraffic] = useState<TrafficUsage[]>([]);
  const [clients, setClients] = useState<Client[]>([]);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [overviewData, trafficData, clientData] = await Promise.all([
        adminApi.overview(),
        adminApi.listTraffic(120),
        adminApi.listClients(),
      ]);
      setOverview(overviewData);
      setTraffic(trafficData);
      setClients(clientData);
    } catch (error) {
      notifyError(error, "加载概览失败");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  if (loading && !overview) {
    return <span className="inline-flex items-center gap-2 mt-6"><Spinner /><span className="text-sm text-default-500">加载中…</span></span>;
  }

  const trafficTrend = buildTrafficTrend(traffic).slice(-10);
  const clientTraffic = buildClientTraffic(traffic).slice(0, 6);
  const totalConnections = overview
    ? overview.successfulConnections + overview.failedConnections
    : 0;
  const successRate = totalConnections > 0 && overview
    ? `${Math.round((overview.successfulConnections / totalConnections) * 100)}%`
    : "0%";
  const totalTrafficBytes = overview ? overview.uploadBytes + overview.downloadBytes : 0;
  const downloadRate = totalTrafficBytes > 0 && overview
    ? `${Math.round(Math.min(1, Math.max(0, overview.downloadBytes / totalTrafficBytes)) * 100)}%`
    : "0%";

  const cards: MetricCard[] = overview
    ? [
        {
          label: "客户端",
          value: String(overview.clients),
          hint: `${overview.onlineClients} 个在线`,
        },
        {
          label: "连接成功率",
          value: successRate,
          hint: `${overview.successfulConnections} 成功 / ${overview.failedConnections} 失败`,
        },
        {
          label: "当前代理连接",
          value: String(overview.externalConnections),
          hint: `${overview.rejectedExternalConnections} 个被拒绝`,
        },
        {
          label: "累计流量",
          value: formatBytes(totalTrafficBytes),
          hint: `上传 ${formatBytes(overview.uploadBytes)} / 下载 ${formatBytes(overview.downloadBytes)}`,
        },
      ]
    : [];

  return (
    <div className="mt-4 flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold">运行概览</h2>
          <p className="text-small text-default-500">客户端、连接质量和流量走势</p>
        </div>
        <Button size="sm" variant="secondary" onPress={() => void load()} isDisabled={loading}>{loading ? <Spinner size="sm" /> : null}
          刷新
        </Button>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {cards.map((card) => (
          <Card key={card.label}>
            <Card.Content className="gap-1 p-4">
              <span className="text-small text-default-500">{card.label}</span>
              <span className="text-2xl font-semibold">{card.value}</span>
              <span className="text-tiny text-default-400">{card.hint}</span>
            </Card.Content>
          </Card>
        ))}
      </div>

      {overview && (
        <div className="grid gap-4 lg:grid-cols-[1.35fr_0.65fr]">
          <ChartPanel title="近日日流量" subtitle="按 UTC 日期聚合">
            <TrafficTrendChart days={trafficTrend} />
          </ChartPanel>

          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-1">
            <ChartPanel title="连接结果" subtitle={`${totalConnections} 次控制连接`}>
              <DonutChart
                total={Math.max(totalConnections, 0)}
                primaryValue={overview.successfulConnections}
                primaryLabel="成功"
                secondaryLabel="失败"
                primaryText={successRate}
                primaryDetail={`${overview.successfulConnections} 次`}
                secondaryDetail={`${overview.failedConnections} 次`}
              />
            </ChartPanel>

            <ChartPanel title="上下行占比" subtitle={formatBytes(totalTrafficBytes)}>
              <DonutChart
                total={Math.max(totalTrafficBytes, 0)}
                primaryValue={overview.downloadBytes}
                primaryLabel="下载"
                secondaryLabel="上传"
                primaryText={downloadRate}
                primaryDetail={formatBytes(overview.downloadBytes)}
                secondaryDetail={formatBytes(overview.uploadBytes)}
                primaryColor={DOWNLOAD_COLOR}
                secondaryColor={UPLOAD_COLOR}
              />
            </ChartPanel>
          </div>
        </div>
      )}

      <ChartPanel title="客户端流量排行" subtitle="最近记录按客户端汇总">
        <ClientTrafficBars items={clientTraffic} />
      </ChartPanel>

      <ChartPanel title="客户端版本分布" subtitle={`${clients.length} 个已注册实例 · 版本来自最近一次登录`}>
        <ClientVersionDistribution clients={clients} />
      </ChartPanel>
    </div>
  );
}

function ChartPanel({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle: string;
  children: ReactNode;
}) {
  return (
    <Card>
      <Card.Header className="flex flex-col items-start gap-0 px-4 pb-0 pt-4">
        <h3 className="text-small font-semibold">{title}</h3>
        <p className="text-tiny text-default-400">{subtitle}</p>
      </Card.Header>
      <Card.Content className="p-4">{children}</Card.Content>
    </Card>
  );
}

/** 监听容器宽度，小屏时切换紧凑 viewBox，保证刻度字号可读。 */
function useContainerWidth() {
  const ref = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(0);
  useEffect(() => {
    const element = ref.current;
    if (!element) {
      return;
    }
    const observer = new ResizeObserver((entries) => {
      setWidth(entries[0]?.contentRect.width ?? 0);
    });
    observer.observe(element);
    return () => observer.disconnect();
  }, []);
  return [ref, width] as const;
}

function TrafficTrendChart({ days }: { days: TrafficDay[] }) {
  const [containerRef, containerWidth] = useContainerWidth();
  const compact = containerWidth > 0 && containerWidth < 520;

  if (days.length === 0) {
    return <EmptyChart message="暂无流量数据" />;
  }

  // 小屏收窄 viewBox 并放大字号：360px 手机上刻度不再被等比缩到不可读。
  const width = compact ? 420 : 640;
  const height = 240;
  const padding = { top: 16, right: compact ? 12 : 18, bottom: 36, left: compact ? 50 : 58 };
  const tickFontSize = compact ? 13 : 11;
  const xLabelEvery = compact && days.length > 5 ? 2 : 1;
  const plotWidth = width - padding.left - padding.right;
  const plotHeight = height - padding.top - padding.bottom;
  const maxValue = Math.max(...days.map((day) => day.totalBytes), 1);
  const x = (index: number) =>
    padding.left + (days.length === 1 ? plotWidth / 2 : (index / (days.length - 1)) * plotWidth);
  const y = (value: number) => padding.top + plotHeight - (value / maxValue) * plotHeight;
  const totalPoints = days.map((day, index) => `${x(index)},${y(day.totalBytes)}`).join(" ");
  const uploadPoints = days.map((day, index) => `${x(index)},${y(day.uploadBytes)}`).join(" ");
  const downloadPoints = days.map((day, index) => `${x(index)},${y(day.downloadBytes)}`).join(" ");
  const areaPath = `M ${x(0)} ${y(days[0].totalBytes)} ${days
    .map((day, index) => `L ${x(index)} ${y(day.totalBytes)}`)
    .join(" ")} L ${x(days.length - 1)} ${height - padding.bottom} L ${x(0)} ${height - padding.bottom} Z`;
  const gridValues = [0.25, 0.5, 0.75, 1];

  return (
    <div ref={containerRef} className="flex flex-col gap-3">
      <svg aria-label="近日日流量趋势" className="h-64 w-full" role="img" viewBox={`0 0 ${width} ${height}`}>
        <defs>
          <linearGradient id="traffic-area" x1="0" x2="0" y1="0" y2="1">
            <stop offset="0%" stopColor={TOTAL_COLOR} stopOpacity="0.22" />
            <stop offset="100%" stopColor={TOTAL_COLOR} stopOpacity="0.02" />
          </linearGradient>
        </defs>
        {gridValues.map((ratio) => {
          const lineY = padding.top + plotHeight - ratio * plotHeight;
          return (
            <g key={ratio}>
              <line
                stroke="hsl(var(--heroui-default-200))"
                strokeWidth="1"
                x1={padding.left}
                x2={width - padding.right}
                y1={lineY}
                y2={lineY}
              />
              <text
                fill="hsl(var(--heroui-default-500))"
                fontSize={tickFontSize}
                textAnchor="end"
                x={padding.left - 8}
                y={lineY + 4}
              >
                {formatBytes(maxValue * ratio)}
              </text>
            </g>
          );
        })}
        <path d={areaPath} fill="url(#traffic-area)" />
        <polyline fill="none" points={totalPoints} stroke={TOTAL_COLOR} strokeWidth="3" />
        <polyline fill="none" points={downloadPoints} stroke={DOWNLOAD_COLOR} strokeWidth="2" />
        <polyline fill="none" points={uploadPoints} stroke={UPLOAD_COLOR} strokeWidth="2" />
        {days.map((day, index) => (
          <g key={day.date}>
            <circle cx={x(index)} cy={y(day.totalBytes)} fill={TOTAL_COLOR} r="4" />
            {index % xLabelEvery === 0 ? (
              <text
                fill="hsl(var(--heroui-default-500))"
                fontSize={tickFontSize}
                textAnchor="middle"
                x={x(index)}
                y={height - 12}
              >
                {shortDate(day.date)}
              </text>
            ) : null}
          </g>
        ))}
      </svg>
      <div className="flex flex-wrap gap-3 text-tiny text-default-500">
        <Legend color={TOTAL_COLOR} label="总量" />
        <Legend color={DOWNLOAD_COLOR} label="下载" />
        <Legend color={UPLOAD_COLOR} label="上传" />
      </div>
    </div>
  );
}

function DonutChart({
  total,
  primaryValue,
  primaryLabel,
  secondaryLabel,
  primaryText,
  primaryDetail,
  secondaryDetail,
  primaryColor = "hsl(var(--heroui-success))",
  secondaryColor = "hsl(var(--heroui-danger))",
}: {
  total: number;
  primaryValue: number;
  primaryLabel: string;
  secondaryLabel: string;
  primaryText: string;
  primaryDetail: string;
  secondaryDetail: string;
  primaryColor?: string;
  secondaryColor?: string;
}) {
  const radius = 52;
  const circumference = 2 * Math.PI * radius;
  const clampedTotal = Math.max(total, 0);
  const primaryRatio = clampedTotal > 0 ? Math.min(1, Math.max(0, primaryValue / clampedTotal)) : 0;
  const primaryStroke = circumference * primaryRatio;

  return (
    <div className="flex min-h-40 flex-wrap items-center justify-center gap-3">
      <svg
        aria-label={`${primaryLabel} ${primaryDetail}，${secondaryLabel} ${secondaryDetail}，${primaryLabel}占比 ${primaryText}`}
        className="h-28 w-28 shrink-0"
        role="img"
        viewBox="0 0 140 140"
      >
        <circle
          cx="70"
          cy="70"
          fill="none"
          r={radius}
          stroke={clampedTotal > 0 ? secondaryColor : "hsl(var(--heroui-default-200))"}
          strokeWidth="18"
        />
        {clampedTotal > 0 && (
          <circle
            cx="70"
            cy="70"
            fill="none"
            r={radius}
            stroke={primaryColor}
            strokeDasharray={`${primaryStroke} ${circumference - primaryStroke}`}
            strokeLinecap="round"
            strokeWidth="18"
            transform="rotate(-90 70 70)"
          />
        )}
        <text fill="hsl(var(--heroui-foreground))" fontSize="20" fontWeight="700" textAnchor="middle" x="70" y="66">
          {primaryText}
        </text>
        <text fill="hsl(var(--heroui-default-500))" fontSize="11" textAnchor="middle" x="70" y="84">
          {primaryLabel}
        </text>
      </svg>
      <div className="flex min-w-28 flex-1 flex-col gap-2 text-small">
        <DonutLegendRow color={primaryColor} label={primaryLabel} value={primaryDetail} />
        <DonutLegendRow color={secondaryColor} label={secondaryLabel} value={secondaryDetail} />
      </div>
    </div>
  );
}

function ClientTrafficBars({ items }: { items: ClientTraffic[] }) {
  if (items.length === 0) {
    return <EmptyChart message="暂无客户端流量数据" />;
  }

  const maxValue = Math.max(...items.map((item) => item.totalBytes), 1);

  return (
    <div className="grid gap-3">
      {items.map((item) => {
        const width = `${Math.max(4, (item.totalBytes / maxValue) * 100)}%`;
        return (
          <div key={item.clientName} className="grid gap-1">
            <div className="flex items-center justify-between gap-3 text-small">
              <span className="min-w-0 truncate font-medium">{item.clientName}</span>
              <span className="shrink-0 text-default-500">{formatBytes(item.totalBytes)}</span>
            </div>
            <div className="h-2 overflow-hidden rounded-small bg-default-100">
              <div className="h-full rounded-small bg-primary" style={{ width }} />
            </div>
            <span className="text-tiny text-default-400">
              上传 {formatBytes(item.uploadBytes)} / 下载 {formatBytes(item.downloadBytes)}
            </span>
          </div>
        );
      })}
    </div>
  );
}

function EmptyChart({ message }: { message: string }) {
  return <EmptyState className="min-h-40 py-8" icon="traffic" title={message} />;
}

function ClientVersionDistribution({ clients }: { clients: Client[] }) {
  const counts = new Map<string, { version: string; total: number; online: number }>();
  clients.forEach((client) => {
    const version = client.clientVersion?.trim() || "未上报";
    const item = counts.get(version) ?? { version, total: 0, online: 0 };
    item.total += 1;
    if (client.online) item.online += 1;
    counts.set(version, item);
  });
  const rows = Array.from(counts.values()).sort((left, right) =>
    right.total - left.total || right.version.localeCompare(left.version, undefined, { numeric: true }));
  if (rows.length === 0) return <EmptyChart message="暂无客户端版本数据" />;
  const maximum = Math.max(...rows.map((row) => row.total), 1);
  return (
    <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
      {rows.map((row, index) => (
        <div key={row.version} className="relative overflow-hidden rounded-md border border-default-200 bg-default-50 p-3">
          <div className="absolute inset-y-0 left-0 w-1 bg-primary" style={{ opacity: Math.max(0.25, 1 - index * 0.12) }} />
          <div className="flex items-start justify-between gap-3 pl-1">
            <div className="min-w-0">
              <p className="truncate font-mono text-small font-semibold" title={row.version}>{row.version}</p>
              <p className="mt-1 text-tiny text-default-500">{row.online} 个在线</p>
            </div>
            <span className="text-xl font-semibold tabular-nums">{row.total}</span>
          </div>
          <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-default-200">
            <div className="h-full rounded-full bg-primary" style={{ width: `${Math.max(8, row.total / maximum * 100)}%` }} />
          </div>
        </div>
      ))}
    </div>
  );
}

function Legend({ color, label }: { color: string; label: string }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className="h-2 w-2 rounded-full" style={{ backgroundColor: color }} />
      {label}
    </span>
  );
}

function DonutLegendRow({ color, label, value }: { color: string; label: string; value: string }) {
  return (
    <div className="grid min-w-0 grid-cols-[minmax(0,1fr)_auto] items-center gap-3">
      <Legend color={color} label={label} />
      <span
        title={value}
        className="min-w-0 max-w-32 text-right text-tiny font-medium tabular-nums text-default-600 [overflow-wrap:anywhere]"
      >
        {value}
      </span>
    </div>
  );
}

function buildTrafficTrend(rows: TrafficUsage[]): TrafficDay[] {
  const byDate = new Map<string, TrafficDay>();
  rows.forEach((row) => {
    const item = byDate.get(row.usageDate) ?? {
      date: row.usageDate,
      uploadBytes: 0,
      downloadBytes: 0,
      totalBytes: 0,
    };
    item.uploadBytes += Number(row.uploadBytes || 0);
    item.downloadBytes += Number(row.downloadBytes || 0);
    item.totalBytes = item.uploadBytes + item.downloadBytes;
    byDate.set(row.usageDate, item);
  });
  return Array.from(byDate.values()).sort((left, right) => left.date.localeCompare(right.date));
}

function buildClientTraffic(rows: TrafficUsage[]): ClientTraffic[] {
  const byClient = new Map<string, ClientTraffic>();
  rows.forEach((row) => {
    const item = byClient.get(row.clientName) ?? {
      clientName: row.clientName,
      uploadBytes: 0,
      downloadBytes: 0,
      totalBytes: 0,
    };
    item.uploadBytes += Number(row.uploadBytes || 0);
    item.downloadBytes += Number(row.downloadBytes || 0);
    item.totalBytes = item.uploadBytes + item.downloadBytes;
    byClient.set(row.clientName, item);
  });
  return Array.from(byClient.values()).sort((left, right) => right.totalBytes - left.totalBytes);
}

function shortDate(date: string): string {
  if (date.length >= 10) {
    return date.slice(5, 10);
  }
  return date;
}
