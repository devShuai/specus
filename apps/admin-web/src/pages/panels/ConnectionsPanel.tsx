import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Button } from "@heroui/react";
import { adminApi } from "../../api/client";
import type { ConnectionRecord, LiveConnectionEvent } from "../../api/types";
import { formatElapsed } from "../../lib/format";
import { notifyError } from "../../components/toast";
import { useConnectionsFeed } from "../../hooks/useConnectionsFeed";
import { useNowTick } from "../../hooks/useNowTick";
import { useAuth } from "../../auth/AuthContext";
import { PageHeader } from "../../components/PageHeader";
import { Empty, FilterBar, Icon, RelativeTime, TableWrap, Tag } from "../../components/ui";
import { Pagination, TableEmptyRow, TableLoadingRow, rangeText } from "./opsUi";

const PAGE_SIZE = 50;

export function ConnectionsPanel() {
  const { expireSession } = useAuth();
  const [clients, setClients] = useState<{ id: number; clientName: string }[]>([]);
  const [items, setItems] = useState<ConnectionRecord[]>([]);
  const [total, setTotal] = useState(0);
  const [totalPages, setTotalPages] = useState(1);
  const [page, setPage] = useState(0);
  const [loading, setLoading] = useState(true);

  const [clientId, setClientId] = useState("");
  const [result, setResult] = useState("");
  const [fromDate, setFromDate] = useState("");
  const [toDate, setToDate] = useState("");
  const connectionRequestId = useRef(0);

  const filterRef = useRef({ clientId, result, fromDate, toDate, page });
  filterRef.current = { clientId, result, fromDate, toDate, page };

  const now = useNowTick(1000); // live durations for active rows

  useEffect(() => {
    adminApi
      .listClients()
      .then((list) => setClients(list.map((c) => ({ id: c.id, clientName: c.clientName }))))
      .catch(() => undefined);
  }, []);

  const load = useCallback(async (silent = false) => {
    const requestId = connectionRequestId.current + 1;
    connectionRequestId.current = requestId;
    if (!silent) {
      setLoading(true);
    }
    try {
      const data = await adminApi.listConnections({
        page,
        size: PAGE_SIZE,
        clientId: clientId ? Number(clientId) : undefined,
        success: result === "" ? undefined : result === "true",
        from: fromDate ? `${fromDate}T00:00:00Z` : undefined,
        to: toDate ? `${toDate}T23:59:59Z` : undefined,
      });
      if (requestId !== connectionRequestId.current) {
        return;
      }
      setItems(data.items ?? []);
      setTotal(data.total);
      setTotalPages(Math.max(1, data.totalPages));
    } catch (error) {
      if (requestId === connectionRequestId.current) {
        notifyError(error, "加载连接记录失败");
      }
      if (silent) {
        throw error;
      }
    } finally {
      if (!silent && requestId === connectionRequestId.current) {
        setLoading(false);
      }
    }
  }, [page, clientId, result, fromDate, toDate]);

  useEffect(() => {
    void load();
  }, [load]);

  const matchesFilter = useCallback((record: ConnectionRecord): boolean => {
    const f = filterRef.current;
    if (f.clientId && String(record.clientId ?? "") !== f.clientId) {
      return false;
    }
    if (f.result !== "" && String(record.success) !== f.result) {
      return false;
    }
    if (f.fromDate && record.connectedAt < `${f.fromDate}T00:00:00Z`) {
      return false;
    }
    if (f.toDate && record.connectedAt > `${f.toDate}T23:59:59Z`) {
      return false;
    }
    return true;
  }, []);

  const onLiveEvent = useCallback(
    (event: LiveConnectionEvent) => {
      // Only mutate when on the first page and the record matches the active filter; other
      // pages are re-fetched on navigation/refresh (mirrors the original SPA).
      if (filterRef.current.page !== 0 || !matchesFilter(event.connection)) {
        return;
      }
      setItems((prev) => {
        const existingIndex = prev.findIndex((row) => row.id === event.connection.id);
        if (existingIndex >= 0) {
          const next = prev.slice();
          next[existingIndex] = event.connection;
          return next;
        }
        if (event.type === "created") {
          const next = [event.connection, ...prev];
          if (next.length > PAGE_SIZE) {
            next.length = PAGE_SIZE;
          }
          setTotal((value) => value + 1);
          return next;
        }
        return prev;
      });
    },
    [matchesFilter],
  );

  useConnectionsFeed({
    enabled: true,
    onEvent: onLiveEvent,
    onResync: () => load(true),
    onAuthError: expireSession,
  });

  const resetConnectionPage = useCallback(() => {
    connectionRequestId.current += 1;
    setItems([]);
    setTotal(0);
    setTotalPages(1);
    setLoading(true);
    setPage(0);
  }, []);

  const changePage = useCallback(
    (nextPage: number) => {
      if (nextPage === page) {
        return;
      }
      connectionRequestId.current += 1;
      setItems([]);
      setLoading(true);
      setPage(nextPage);
    },
    [page],
  );

  const changeClientId = useCallback(
    (value: string) => {
      setClientId(value);
      resetConnectionPage();
    },
    [resetConnectionPage],
  );

  const changeResult = useCallback(
    (value: string) => {
      setResult(value);
      resetConnectionPage();
    },
    [resetConnectionPage],
  );

  const changeFromDate = useCallback(
    (value: string) => {
      setFromDate(value);
      resetConnectionPage();
    },
    [resetConnectionPage],
  );

  const changeToDate = useCallback(
    (value: string) => {
      setToDate(value);
      resetConnectionPage();
    },
    [resetConnectionPage],
  );

  const reset = () => {
    setClientId("");
    setResult("");
    setFromDate("");
    setToDate("");
    resetConnectionPage();
  };

  const tableScopeKey = useMemo(
    () => `${page}:${PAGE_SIZE}:${clientId}:${result}:${fromDate}:${toDate}`,
    [clientId, fromDate, page, result, toDate],
  );
  const tableRows = useMemo(
    () =>
      items.map((item, index) => ({
        ...item,
        tableKey: `${tableScopeKey}:${index}:${item.id}:${item.connectedAt}:${item.clientName}`,
      })),
    [items, tableScopeKey],
  );
  const activeFilterCount = [clientId, result, fromDate, toDate].filter(Boolean).length;
  const hasActiveFilters = activeFilterCount > 0;

  return (
    <div className="ops-page">
      <PageHeader
        title="连接记录"
        description="客户端连接结果、来源地址与在线时长。"
        actions={
          <Button variant="flat" isLoading={loading} startContent={loading ? null : <Icon name="refresh" />} onPress={() => void load()}>
            刷新记录
          </Button>
        }
      />

      <FilterBar
        className="ops-filterbar"
        end={<>
          <Button size="sm" variant="light" isDisabled={!hasActiveFilters} onPress={reset}>重置筛选</Button>
          <span className="ops-count">{hasActiveFilters ? `已启用 ${activeFilterCount} 项筛选 · ` : ""}共 {total} 条</span>
        </>}
      >
        <label className="ops-filter-field">
          <span className="ops-filter-label">客户端</span>
          <select className="bd-select" value={clientId} onChange={(event) => changeClientId(event.target.value)}>
            <option value="">全部客户端</option>
            {clients.map((client) => <option key={client.id} value={String(client.id)}>{client.clientName}</option>)}
          </select>
        </label>
        <label className="ops-filter-field">
          <span className="ops-filter-label">结果</span>
          <select className="bd-select" value={result} onChange={(event) => changeResult(event.target.value)}>
            <option value="">全部结果</option>
            <option value="true">成功</option>
            <option value="false">失败</option>
          </select>
        </label>
        <label className="ops-filter-field">
          <span className="ops-filter-label">开始日期</span>
          <input className="bd-input jd-filter-date" type="date" value={fromDate} max={toDate || undefined}
            onChange={(event) => changeFromDate(event.target.value)} />
        </label>
        <label className="ops-filter-field">
          <span className="ops-filter-label">结束日期</span>
          <input className="bd-input jd-filter-date" type="date" value={toDate} min={fromDate || undefined}
            onChange={(event) => changeToDate(event.target.value)} />
        </label>
      </FilterBar>

      <TableWrap className="ops-table-wrap">
        <table className="bd-table jd-stack" aria-label="连接记录">
          <thead>
            <tr>
              <th>客户端</th>
              <th>结果</th>
              <th>远端地址</th>
              <th>连接时间</th>
              <th>断开时间</th>
              <th className="bd-col-num">持续时长</th>
              <th>原因</th>
            </tr>
          </thead>
          <tbody>
            {loading && tableRows.length === 0 ? <TableLoadingRow colSpan={7} /> : null}
            {!loading && tableRows.length === 0 ? (
              <TableEmptyRow colSpan={7}>
                <Empty
                  icon="history"
                  title="暂无连接记录"
                  description={hasActiveFilters ? "当前筛选没有匹配的记录；放宽条件或重置筛选。" : "客户端接入后，每次连接都会记在这里。"}
                  actions={hasActiveFilters ? <Button size="sm" variant="flat" onPress={reset}>重置筛选</Button> : null}
                />
              </TableEmptyRow>
            ) : null}
            {tableRows.map((record) => {
              const reason = connectionReason(record);
              const active = record.success && !record.disconnectedAt;
              const seconds = elapsedSeconds(record, now);
              return (
                <tr key={record.tableKey}>
                  <td>
                    <span className="inline-flex min-w-0 items-baseline gap-2">
                      <span className="jd-strong [overflow-wrap:anywhere]">{record.clientName}</span>
                      <span className="bd-num text-[12px] text-[var(--text-subtle)]">#{record.id}</span>
                    </span>
                  </td>
                  <td data-label="结果"><Tag tone={record.success ? "success" : "danger"}>{record.success ? "成功" : "失败"}</Tag></td>
                  <td data-label="远端地址" className={record.remoteAddress ? "bd-num" : "bd-num ops-subtle"}>{record.remoteAddress || "—"}</td>
                  <td data-label="连接时间"><RelativeTime value={record.connectedAt} /></td>
                  <td data-label="断开时间">
                    {record.disconnectedAt ? <RelativeTime value={record.disconnectedAt} />
                      : <span className="ops-subtle">{active ? "未断开" : "—"}</span>}
                  </td>
                  <td data-label="持续时长" className="bd-col-num">
                    {seconds == null ? <span className="ops-subtle">—</span> : formatElapsed(seconds)}
                  </td>
                  <td data-label="原因" className="jd-wrap">
                    <span className={`ops-reason${reason ? "" : " ops-subtle"}`} title={reason || undefined}>{reason || "—"}</span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </TableWrap>
      <Pagination
        page={page}
        totalPages={totalPages}
        total={rangeText(page, PAGE_SIZE, total)}
        disabled={loading}
        onChange={changePage}
        label="连接记录分页"
      />
    </div>
  );
}

/** Why a connection ended or failed, as the record says it; nothing for a connection still open. */
function connectionReason(record: ConnectionRecord): string {
  return record.success
    ? record.disconnectReasonText || ""
    : record.failureReason || record.disconnectReasonText || "登录失败";
}

/**
 * How long a connection lasted, or has lasted while still open. A failed login has no duration
 * unless the record carries a disconnect time.
 */
function elapsedSeconds(record: ConnectionRecord, now: number): number | null {
  const start = new Date(record.connectedAt).getTime();
  if (Number.isNaN(start)) return null;
  if (record.disconnectedAt) {
    const end = new Date(record.disconnectedAt).getTime();
    return Number.isNaN(end) ? null : Math.max(0, (end - start) / 1000);
  }
  return record.success ? Math.max(0, (now - start) / 1000) : null;
}
