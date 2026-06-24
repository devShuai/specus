import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Button,
  Chip,
  Input,
  Pagination,
  Select,
  SelectItem,
  Table,
  TableBody,
  TableCell,
  TableColumn,
  TableHeader,
  TableRow,
} from "@heroui/react";
import { adminApi } from "../../api/client";
import type { ConnectionRecord, LiveConnectionEvent } from "../../api/types";
import { formatDateTime, formatDuration } from "../../lib/format";
import { notifyError } from "../../components/toast";
import { useConnectionsFeed } from "../../hooks/useConnectionsFeed";
import { useNowTick } from "../../hooks/useNowTick";
import { useAuth } from "../../auth/AuthContext";
import { MobileListCard, MobileListCardList } from "../../components/MobileListCard";

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
  const durationTick = Math.floor(now / 1000);

  useEffect(() => {
    adminApi
      .listClients()
      .then((list) => setClients(list.map((c) => ({ id: c.id, clientName: c.clientName }))))
      .catch(() => undefined);
  }, []);

  const load = useCallback(async () => {
    const requestId = connectionRequestId.current + 1;
    connectionRequestId.current = requestId;
    setLoading(true);
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
    } finally {
      if (requestId === connectionRequestId.current) {
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

  useConnectionsFeed({ enabled: true, onEvent: onLiveEvent, onAuthError: expireSession });

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

  const rangeStart = total === 0 ? 0 : page * PAGE_SIZE + 1;
  const rangeEnd = Math.min(total, (page + 1) * PAGE_SIZE);
  const tableScopeKey = useMemo(
    () => `${page}:${PAGE_SIZE}:${clientId}:${result}:${fromDate}:${toDate}:${durationTick}`,
    [clientId, durationTick, fromDate, page, result, toDate],
  );
  const tableRows = useMemo(
    () =>
      items.map((item, index) => ({
        ...item,
        tableKey: `${tableScopeKey}:${index}:${item.id}:${item.connectedAt}:${item.clientName}`,
      })),
    [items, tableScopeKey],
  );
  const tableCollectionKey = useMemo(() => {
    const first = items[0];
    const last = items[items.length - 1];
    return [
      tableScopeKey,
      items.length,
      first ? `${first.id}:${first.connectedAt}` : "empty",
      last ? `${last.id}:${last.connectedAt}` : "empty",
    ].join("|");
  }, [items, tableScopeKey]);

  return (
    <div className="mt-4 flex min-w-0 flex-col gap-4">
      <div className="flex flex-wrap items-end gap-3">
        <Select
          className="w-full sm:w-44"
          label="客户端"
          items={[{ id: "", clientName: "全部" }, ...clients.map((c) => ({ id: String(c.id), clientName: c.clientName }))]}
          selectedKeys={clientId ? [clientId] : [""]}
          onChange={(event) => changeClientId(event.target.value)}
        >
          {(item) => <SelectItem key={item.id}>{item.clientName}</SelectItem>}
        </Select>
        <Select
          className="w-full sm:w-32"
          label="结果"
          selectedKeys={result ? [result] : [""]}
          onChange={(event) => changeResult(event.target.value)}
        >
          <SelectItem key="">全部</SelectItem>
          <SelectItem key="true">成功</SelectItem>
          <SelectItem key="false">失败</SelectItem>
        </Select>
        <Input className="w-full sm:w-44" type="date" label="开始日期（UTC）" value={fromDate} onValueChange={changeFromDate} />
        <Input className="w-full sm:w-44" type="date" label="结束日期（UTC）" value={toDate} onValueChange={changeToDate} />
        <Button className="w-full sm:w-auto" variant="flat" onPress={reset}>
          重置
        </Button>
        <Button className="w-full sm:w-auto" variant="flat" onPress={() => void load()}>
          刷新
        </Button>
      </div>

      {/* mobile: 卡片堆叠 */}
      <div className="lg:hidden">
        <MobileListCardList
          items={tableRows}
          isLoading={loading}
          emptyContent="暂无数据"
          renderCard={(raw) => {
            const record = raw as (typeof tableRows)[number];
            const reason = record.success
              ? record.disconnectReasonText || "-"
              : record.failureReason || record.disconnectReasonText || "登录失败";
            return (
              <MobileListCard
                key={record.tableKey}
                title={
                  <div className="flex items-center gap-2">
                    <span className="break-all">{record.clientName}</span>
                    <span className="text-tiny font-normal text-default-400">#{record.id}</span>
                  </div>
                }
                badges={
                  <Chip size="sm" variant="flat" color={record.success ? "success" : "danger"}>
                    {record.success ? "成功" : "失败"}
                  </Chip>
                }
                fields={[
                  { label: "远端地址", value: record.remoteAddress || "-" },
                  { label: "连接时间", value: formatDateTime(record.connectedAt) },
                  { label: "断开时间", value: record.disconnectedAt ? formatDateTime(record.disconnectedAt) : "-" },
                  { label: "持续时长", value: formatDuration(record.connectedAt, record.disconnectedAt, now) },
                  { label: "原因", value: reason },
                ]}
              />
            );
          }}
        />
      </div>

      {/* desktop: 表格 */}
      <div className="hidden min-w-0 overflow-x-auto lg:block">
      <Table key={tableCollectionKey} aria-label="连接记录" isHeaderSticky removeWrapper>
        <TableHeader>
          <TableColumn>ID</TableColumn>
          <TableColumn>客户端</TableColumn>
          <TableColumn>结果</TableColumn>
          <TableColumn>远端地址</TableColumn>
          <TableColumn>连接时间</TableColumn>
          <TableColumn>断开时间</TableColumn>
          <TableColumn>持续时长</TableColumn>
          <TableColumn>原因</TableColumn>
        </TableHeader>
        <TableBody key={tableCollectionKey} items={tableRows} isLoading={loading} emptyContent="暂无数据">
          {(record) => (
            <TableRow key={record.tableKey}>
              <TableCell>{record.id}</TableCell>
              <TableCell>{record.clientName}</TableCell>
              <TableCell>
                <Chip size="sm" variant="flat" color={record.success ? "success" : "danger"}>
                  {record.success ? "成功" : "失败"}
                </Chip>
              </TableCell>
              <TableCell>{record.remoteAddress || "-"}</TableCell>
              <TableCell>{formatDateTime(record.connectedAt)}</TableCell>
              <TableCell>{record.disconnectedAt ? formatDateTime(record.disconnectedAt) : "-"}</TableCell>
              <TableCell>{formatDuration(record.connectedAt, record.disconnectedAt, now)}</TableCell>
              <TableCell>
                {record.success
                  ? record.disconnectReasonText || "-"
                  : record.failureReason || record.disconnectReasonText || "登录失败"}
              </TableCell>
            </TableRow>
          )}
        </TableBody>
      </Table>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="text-small text-default-500">
          {total === 0 ? "共 0 条" : `第 ${rangeStart}-${rangeEnd} 条，共 ${total} 条`}
        </span>
        <Pagination
          showControls
          page={page + 1}
          total={totalPages}
          onChange={(value) => changePage(value - 1)}
        />
      </div>
    </div>
  );
}
