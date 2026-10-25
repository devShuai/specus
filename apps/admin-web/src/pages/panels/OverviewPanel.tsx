import { useCallback, useEffect, useRef, useState, type CSSProperties, type KeyboardEvent, type PointerEvent } from "react";
import { PageHeader } from "../../components/PageHeader";
import { Button } from "@heroui/react";
import { adminApi } from "../../api/client";
import type { Client, Overview, TrafficUsage } from "../../api/types";
import { formatBytes } from "../../lib/format";
import { notifyError } from "../../components/toast";
import { Alert, Empty, Icon, Section, Segmented, Stat, StatGrid, TableWrap } from "../../components/ui";
import { KpiLabel, chartVar, type ChartColor } from "./opsUi";

/**
 * Series colors come from the design's chart tokens and stay with the series everywhere on the
 * page: total is chart-1, download chart-2, upload chart-3 (checked with the dataviz palette
 * validator in light and dark). Success and failure of connections are status, so they take the
 * status colors instead.
 */
const SERIES: Record<"total" | "download" | "upload", { label: string; color: ChartColor }> = {
  total: { label: "总量", color: 1 },
  download: { label: "下载", color: 2 },
  upload: { label: "上传", color: 3 },
};

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
    return <span className="ops-loading mt-6" role="status"><Icon name="loader" />加载中…</span>;
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

  return (
    <div className="ops-page">
      <PageHeader
        title="运行概览"
        description="客户端、连接质量和流量走势"
        actions={
          <Button variant="flat" isLoading={loading} startContent={loading ? null : <Icon name="refresh" />} onPress={() => void load()}>
            刷新
          </Button>
        }
      />

      <section className="jd-section" aria-label="接入与发布入口">
        <Alert
          tone="info"
          title="接入设备，发布第一个服务"
          actions={<Button as="a" href="#/clients" color="primary" variant="flat">开始接入 / 查看设备</Button>}
        >
          下载 → 保存接入配置 → 等待实例上线 → 发布与验证访问
        </Alert>
      </section>

      {overview ? (
        <section className="jd-section" aria-label="关键指标">
          <StatGrid>
            <Stat label={<KpiLabel icon="monitor" color={1}>客户端</KpiLabel>} value={overview.clients}
              meta={`${overview.onlineClients} 个在线`} />
            <Stat label={<KpiLabel icon="check-circle" color={3}>连接成功率</KpiLabel>} value={successRate}
              meta={`${overview.successfulConnections} 次成功 / ${overview.failedConnections} 次失败`} />
            <Stat label={<KpiLabel icon="activity" color={6}>当前代理连接</KpiLabel>} value={overview.externalConnections}
              meta={`${overview.rejectedExternalConnections} 个被拒绝`} />
            <Stat label={<KpiLabel icon="bar-chart" color={2}>累计流量</KpiLabel>} value={formatBytes(totalTrafficBytes)}
              meta={`上传 ${formatBytes(overview.uploadBytes)} / 下载 ${formatBytes(overview.downloadBytes)}`} />
          </StatGrid>
        </section>
      ) : null}

      {overview && (
        <Section title="流量与连接" description="悬停或用方向键查看每天的数值；切到「表格」看全部数字">
          <div className="ops-chart-grid">
            <TrafficTrendCard days={trafficTrend} />
            <div className="ops-chart-side ops-span-4">
              <SplitCard
                title="连接结果"
                description={`${totalConnections} 次控制连接`}
                value={successRate}
                valueLabel="成功"
                parts={[
                  { label: "成功", value: overview.successfulConnections, detail: `${overview.successfulConnections} 次`, color: "var(--success)" },
                  { label: "失败", value: overview.failedConnections, detail: `${overview.failedConnections} 次`, color: "var(--danger)" },
                ]}
              />
              <SplitCard
                title="上下行占比"
                description={formatBytes(totalTrafficBytes)}
                value={downloadRate}
                valueLabel="下载"
                parts={[
                  { label: "下载", value: overview.downloadBytes, detail: formatBytes(overview.downloadBytes), color: chartVar(SERIES.download.color) },
                  { label: "上传", value: overview.uploadBytes, detail: formatBytes(overview.uploadBytes), color: chartVar(SERIES.upload.color) },
                ]}
              />
            </div>
          </div>
        </Section>
      )}

      <Section title="客户端流量排行" description="最近记录按客户端汇总，前 6 名">
        <ClientTrafficTable items={clientTraffic} />
      </Section>

      <Section title="客户端版本分布" description={`${clients.length} 个已注册实例 · 版本来自最近一次登录`}>
        <ClientVersionDistribution clients={clients} />
      </Section>
    </div>
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

/** Clean axis steps: the largest value rounded up to 4 even steps of 1, 2, 2.5 or 5 × 10ⁿ in one unit. */
function byteTicks(maxBytes: number): { max: number; ticks: number[]; format: (bytes: number) => string } {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let unit = 0;
  while (maxBytes >= 1024 ** (unit + 1) && unit < units.length - 1) unit += 1;
  const scale = 1024 ** unit;
  const raw = Math.max(maxBytes / scale, 1) / 4;
  const power = 10 ** Math.floor(Math.log10(raw));
  const step = [1, 2, 2.5, 5, 10].map((factor) => factor * power).find((candidate) => candidate >= raw) ?? raw;
  const ticks = [0, 1, 2, 3, 4].map((index) => index * step * scale);
  const format = (bytes: number) => {
    const value = bytes / scale;
    return `${Number.isInteger(value) ? value : value.toFixed(1)} ${units[unit]}`;
  };
  return { max: ticks[4], ticks, format };
}

function TrafficTrendCard({ days }: { days: TrafficDay[] }) {
  const [view, setView] = useState<"chart" | "table">("chart");
  return (
    <div className="bd-chart-card ops-span-8" data-view={view}>
      <div className="bd-chart-card-head">
        <div>
          <h3>近日日流量</h3>
          <p>按 UTC 日期聚合，最近 {days.length} 天</p>
        </div>
        <Segmented
          label="近日日流量的展示方式"
          size="sm"
          value={view}
          onChange={setView}
          options={[{ key: "chart", label: "图表", icon: "bar-chart" }, { key: "table", label: "表格", icon: "table" }]}
        />
      </div>
      <div className="bd-chart-card-body">
        {days.length === 0 ? <EmptyChart message="暂无流量数据" /> : (
          <>
            <div className="bd-chart-view"><TrafficTrendChart days={days} /></div>
            <div className="bd-table-view">
              <TableWrap>
                <table className="bd-table bd-table--compact">
                  <caption className="jd-sr-only">近日日流量</caption>
                  <thead>
                    <tr><th>日期（UTC）</th><th className="bd-col-num">下载</th><th className="bd-col-num">上传</th><th className="bd-col-num">总量</th></tr>
                  </thead>
                  <tbody>
                    {days.map((day) => (
                      <tr key={day.date}>
                        <td className="bd-num">{day.date}</td>
                        <td className="bd-col-num">{formatBytes(day.downloadBytes)}</td>
                        <td className="bd-col-num">{formatBytes(day.uploadBytes)}</td>
                        <td className="bd-col-num">{formatBytes(day.totalBytes)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </TableWrap>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

function TrafficTrendChart({ days }: { days: TrafficDay[] }) {
  const [containerRef, containerWidth] = useContainerWidth();
  const [active, setActive] = useState<number | null>(null);
  const compact = containerWidth > 0 && containerWidth < 520;

  // 小屏收窄 viewBox 并放大字号：360px 手机上刻度不再被等比缩到不可读。
  const width = compact ? 420 : 640;
  const height = compact ? 240 : 280;
  const padding = { top: 16, right: compact ? 12 : 18, bottom: 36, left: compact ? 56 : 64 };
  const tickFontSize = compact ? 13 : 11;
  const xLabelEvery = compact && days.length > 5 ? 2 : 1;
  const plotWidth = width - padding.left - padding.right;
  const plotHeight = height - padding.top - padding.bottom;
  const scale = byteTicks(Math.max(...days.map((day) => day.totalBytes), 1));
  const x = (index: number) =>
    padding.left + (days.length === 1 ? plotWidth / 2 : (index / (days.length - 1)) * plotWidth);
  const y = (value: number) => padding.top + plotHeight - (value / scale.max) * plotHeight;
  const points = (key: "totalBytes" | "uploadBytes" | "downloadBytes") =>
    days.map((day, index) => `${x(index)},${y(day[key])}`).join(" ");
  const baseline = height - padding.bottom;
  const areaPath = `M ${x(0)} ${baseline} ${days.map((day, index) => `L ${x(index)} ${y(day.totalBytes)}`).join(" ")} L ${x(days.length - 1)} ${baseline} Z`;

  const pick = (event: PointerEvent<SVGSVGElement>) => {
    const box = event.currentTarget.getBoundingClientRect();
    const svgX = ((event.clientX - box.left) / box.width) * width;
    const ratio = days.length === 1 ? 0 : (svgX - padding.left) / plotWidth;
    setActive(Math.max(0, Math.min(days.length - 1, Math.round(ratio * (days.length - 1)))));
  };
  const onKeyDown = (event: KeyboardEvent<SVGSVGElement>) => {
    const delta = event.key === "ArrowRight" ? 1 : event.key === "ArrowLeft" ? -1 : 0;
    if (!delta) return;
    event.preventDefault();
    setActive((current) => Math.max(0, Math.min(days.length - 1, (current ?? days.length - 1) + delta)));
  };
  const activeDay = active != null ? days[active] : null;
  const tipLeft = active != null && containerWidth > 0 ? (x(active) / width) * containerWidth : 0;
  const tipOnLeft = tipLeft > containerWidth / 2;
  const line = (key: keyof typeof SERIES) => ({ stroke: chartVar(SERIES[key].color) });

  return (
    <div ref={containerRef} className="ops-chart">
      <svg
        aria-label="近日日流量趋势；用左右方向键逐日查看"
        role="img"
        tabIndex={0}
        viewBox={`0 0 ${width} ${height}`}
        onPointerMove={pick}
        onPointerLeave={() => setActive(null)}
        onFocus={() => setActive((current) => current ?? days.length - 1)}
        onBlur={() => setActive(null)}
        onKeyDown={onKeyDown}
        className="outline-none focus-visible:rounded-[var(--radius-md)] focus-visible:shadow-[0_0_0_3px_var(--focus-ring)]"
      >
        {scale.ticks.map((tick, index) => {
          const lineY = y(tick);
          return (
            <g key={tick}>
              <line className={index === 0 ? "ops-axis-line" : "ops-grid-line"} x1={padding.left} x2={width - padding.right} y1={lineY} y2={lineY} />
              <text className="ops-tick" fontSize={tickFontSize} textAnchor="end" x={padding.left - 8} y={lineY + 4}>
                {scale.format(tick)}
              </text>
            </g>
          );
        })}
        <path d={areaPath} style={{ fill: chartVar(SERIES.total.color), fillOpacity: 0.1 }} />
        {activeDay ? <line className="ops-crosshair" x1={x(active!)} x2={x(active!)} y1={padding.top} y2={baseline} /> : null}
        <polyline fill="none" points={points("downloadBytes")} style={line("download")} strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" />
        <polyline fill="none" points={points("uploadBytes")} style={line("upload")} strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" />
        <polyline fill="none" points={points("totalBytes")} style={line("total")} strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" />
        {days.map((day, index) => (
          <g key={day.date}>
            {index === days.length - 1 || index === active ? (
              <circle className="ops-dot" cx={x(index)} cy={y(day.totalBytes)} r="4" style={{ fill: chartVar(SERIES.total.color) }} />
            ) : null}
            {index === active ? (<>
              <circle className="ops-dot" cx={x(index)} cy={y(day.downloadBytes)} r="4" style={{ fill: chartVar(SERIES.download.color) }} />
              <circle className="ops-dot" cx={x(index)} cy={y(day.uploadBytes)} r="4" style={{ fill: chartVar(SERIES.upload.color) }} />
            </>) : null}
            {index % xLabelEvery === 0 ? (
              <text className="ops-tick" fontSize={tickFontSize} textAnchor="middle" x={x(index)} y={height - 12}>
                {shortDate(day.date)}
              </text>
            ) : null}
          </g>
        ))}
      </svg>
      {activeDay ? (
        <div
          className="bd-chart-tip"
          style={tipOnLeft ? { right: containerWidth - tipLeft + 12 } : { left: tipLeft + 12 }}
          aria-hidden="true"
        >
          <div className="bd-chart-tip-title">{activeDay.date}</div>
          {(["total", "download", "upload"] as const).map((key) => (
            <div key={key} className="bd-chart-tip-row">
              <i className="ops-tip-key" style={{ "--k": chartVar(SERIES[key].color) } as CSSProperties} />
              <b>{formatBytes(key === "total" ? activeDay.totalBytes : key === "download" ? activeDay.downloadBytes : activeDay.uploadBytes)}</b>
              <span>{SERIES[key].label}</span>
            </div>
          ))}
        </div>
      ) : null}
      <div className="ops-legend">
        {(["total", "download", "upload"] as const).map((key) => (
          <span key={key} className="ops-legend-item">
            <i className="ops-key-line" style={{ "--k": chartVar(SERIES[key].color) } as CSSProperties} />
            {SERIES[key].label}
          </span>
        ))}
      </div>
    </div>
  );
}

/** A part-to-whole card: the headline share, one split bar and the two values written out. */
function SplitCard({ title, description, value, valueLabel, parts }: {
  title: string;
  description: string;
  value: string;
  valueLabel: string;
  parts: Array<{ label: string; value: number; detail: string; color: string }>;
}) {
  const total = parts.reduce((sum, part) => sum + Math.max(0, part.value), 0);
  return (
    <div className="bd-chart-card">
      <div className="bd-chart-card-head">
        <div>
          <h3>{title}</h3>
          <p className="bd-num">{description}</p>
        </div>
      </div>
      <div className="bd-chart-card-body">
        <div className="ops-split-head">
          <span className="ops-split-value">{value}</span>
          <span className="ops-subtle text-[12px]">{valueLabel}占比</span>
        </div>
        <div
          className={total > 0 ? "ops-split" : "ops-split ops-split--empty"}
          role="img"
          aria-label={`${parts.map((part) => `${part.label} ${part.detail}`).join("，")}，${valueLabel}占比 ${value}`}
        >
          {total > 0 ? parts.filter((part) => part.value > 0).map((part) => (
            <i key={part.label} title={`${part.label} ${part.detail}`}
              style={{ "--k": part.color, flexGrow: part.value, flexBasis: 0 } as CSSProperties} />
          )) : null}
        </div>
        <dl className="ops-split-rows">
          {parts.map((part) => (
            <div key={part.label}>
              <dt><i className="ops-key-box" style={{ "--k": part.color } as CSSProperties} />{part.label}</dt>
              <dd>{part.detail}</dd>
            </div>
          ))}
        </dl>
      </div>
    </div>
  );
}

function ClientTrafficTable({ items }: { items: ClientTraffic[] }) {
  if (items.length === 0) {
    return <div className="bd-card"><EmptyChart message="暂无客户端流量数据" /></div>;
  }
  const maxValue = Math.max(...items.map((item) => item.totalBytes), 1);
  const sum = items.reduce((total, item) => total + item.totalBytes, 0) || 1;
  return (
    <TableWrap>
      <table className="bd-table jd-stack" aria-label="客户端流量排行">
        <thead>
          <tr>
            <th>客户端</th>
            <th className="bd-col-num">上传</th>
            <th className="bd-col-num">下载</th>
            <th className="bd-col-num">合计</th>
            <th>占比</th>
          </tr>
        </thead>
        <tbody>
          {items.map((item, index) => (
            <tr key={item.clientName}>
              <td>
                <span className="ops-ranked">
                  <span className="ops-rank-no bd-num" aria-hidden="true">{index + 1}</span>
                  <span className="jd-sr-only">第 {index + 1} 名</span>
                  <span className="jd-strong">{item.clientName}</span>
                </span>
              </td>
              <td className="bd-col-num" data-label="上传">{formatBytes(item.uploadBytes)}</td>
              <td className="bd-col-num" data-label="下载">{formatBytes(item.downloadBytes)}</td>
              <td className="bd-col-num jd-strong" data-label="合计">{formatBytes(item.totalBytes)}</td>
              <td data-label="占比">
                <span className="ops-share">
                  <span className="ops-share-track">
                    <i style={{ "--v": `${Math.max(2, (item.totalBytes / maxValue) * 100)}%` } as CSSProperties} />
                  </span>
                  <span>{Math.round((item.totalBytes / sum) * 100)}%</span>
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </TableWrap>
  );
}

function EmptyChart({ message }: { message: string }) {
  return <Empty icon="bar-chart" title={message} description="客户端转发流量后，按天汇总到这里。" />;
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
  if (rows.length === 0) {
    return <div className="bd-card"><Empty icon="monitor" title="暂无客户端版本数据" description="客户端登录后会上报版本，按版本数到这里。" /></div>;
  }
  const maximum = Math.max(...rows.map((row) => row.total), 1);
  return (
    <div className="bd-chart-card">
      <div className="bd-chart-card-body">
        <ul className="jd-hbars ops-version-bars" aria-label="客户端版本分布">
          {rows.map((row) => (
            <li key={row.version} className="jd-hbar">
              <span className="jd-hbar-label" title={row.version}><span>{row.version}</span></span>
              <span className="jd-hbar-track" aria-hidden="true">
                <i style={{ "--v": `${Math.max(2, (row.total / maximum) * 100)}%` } as CSSProperties} />
              </span>
              <span className="jd-hbar-value">{row.total} 台 · {row.online} 台在线</span>
            </li>
          ))}
        </ul>
      </div>
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
