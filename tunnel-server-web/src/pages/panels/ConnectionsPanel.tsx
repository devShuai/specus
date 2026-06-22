import { useCallback, useEffect, useRef, useState } from "react";
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

const PAGE_SIZE = 50;

export function ConnectionsPanel() {
  const { logout } = useAuth();
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

  const filterRef = useRef({ clientId, result, fromDate, toDate, page });
  filterRef.current = { clientId, result, fromDate, toDate, page };

  useNowTick(1000); // live durations for active rows

  useEffect(() => {
    adminApi
      .listClients()
      .then((list) => setClients(list.map((c) => ({ id: c.id, clientName: c.clientName }))))
      .catch(() => undefined);
  }, []);

  const load = useCallback(async () => {
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
      setItems(data.items ?? []);
      setTotal(data.total);
      setTotalPages(Math.max(1, data.totalPages));
    } catch (error) {
      notifyError(error, "加载连接记录失败");
    } finally {
      setLoading(false);
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

  useConnectionsFeed({ enabled: true, onEvent: onLiveEvent, onAuthError: logout });

  const reset = () => {
    setClientId("");
    setResult("");
    setFromDate("");
    setToDate("");
    setPage(0);
  };

  const rangeStart = total === 0 ? 0 : page * PAGE_SIZE + 1;
  const rangeEnd = Math.min(total, (page + 1) * PAGE_SIZE);

  return (
    <div className="mt-4 flex flex-col gap-4">
      <div className="flex flex-wrap items-end gap-3">
        <Select
          className="w-44"
          label="客户端"
          items={[{ id: "", clientName: "全部" }, ...clients.map((c) => ({ id: String(c.id), clientName: c.clientName }))]}
          selectedKeys={clientId ? [clientId] : [""]}
          onChange={(event) => { setClientId(event.target.value); setPage(0); }}
        >
          {(item) => <SelectItem key={item.id}>{item.clientName}</SelectItem>}
        </Select>
        <Select
          className="w-32"
          label="结果"
          selectedKeys={result ? [result] : [""]}
          onChange={(event) => { setResult(event.target.value); setPage(0); }}
        >
          <SelectItem key="">全部</SelectItem>
          <SelectItem key="true">成功</SelectItem>
          <SelectItem key="false">失败</SelectItem>
        </Select>
        <Input className="w-44" type="date" label="开始日期（UTC）" value={fromDate} onValueChange={(v) => { setFromDate(v); setPage(0); }} />
        <Input className="w-44" type="date" label="结束日期（UTC）" value={toDate} onValueChange={(v) => { setToDate(v); setPage(0); }} />
        <Button variant="flat" onPress={reset}>
          重置
        </Button>
        <Button variant="flat" onPress={() => void load()}>
          刷新
        </Button>
      </div>

      <Table aria-label="连接记录" isHeaderSticky removeWrapper>
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
        <TableBody items={items} isLoading={loading} emptyContent="暂无数据">
          {(record) => (
            <TableRow key={record.id}>
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
              <TableCell>{formatDuration(record.connectedAt, record.disconnectedAt)}</TableCell>
              <TableCell>
                {record.success
                  ? record.disconnectReasonText || "-"
                  : record.failureReason || record.disconnectReasonText || "登录失败"}
              </TableCell>
            </TableRow>
          )}
        </TableBody>
      </Table>

      <div className="flex items-center justify-between">
        <span className="text-small text-default-500">
          {total === 0 ? "共 0 条" : `第 ${rangeStart}-${rangeEnd} 条，共 ${total} 条`}
        </span>
        <Pagination
          showControls
          page={page + 1}
          total={totalPages}
          onChange={(value) => setPage(value - 1)}
        />
      </div>
    </div>
  );
}
