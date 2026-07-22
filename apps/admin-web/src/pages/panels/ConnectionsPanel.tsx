import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import {
  Button,
  Card,
  CardBody,
  Chip,
  Dropdown,
  DropdownItem,
  DropdownMenu,
  DropdownTrigger,
  Input,
  Pagination,
  Popover,
  PopoverContent,
  PopoverTrigger,
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
const FILTER_POPOVER_CLASS_NAMES = {
  content: "border border-default-200 bg-content1 text-foreground shadow-large",
} as const;

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

  const rangeStart = total === 0 ? 0 : page * PAGE_SIZE + 1;
  const rangeEnd = Math.min(total, (page + 1) * PAGE_SIZE);
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
  const activeFilterCount = [clientId, result, fromDate, toDate].filter(Boolean).length;
  const hasActiveFilters = activeFilterCount > 0;

  return (
    <div className="mt-2 flex min-w-0 flex-col gap-4">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="text-lg font-semibold text-foreground">连接记录</h2>
            <Chip radius="sm" size="sm" variant="flat">
              {total} 条
            </Chip>
          </div>
          <p className="mt-1 text-small text-default-500">查看客户端连接结果、来源地址与在线时长。</p>
        </div>
        <Button
          className="w-full shrink-0 sm:w-auto"
          color="primary"
          isLoading={loading}
          radius="sm"
          variant="flat"
          onPress={() => void load()}
        >
          刷新记录
        </Button>
      </div>

      {/* mobile: 卡片堆叠 */}
      <div className="xl:hidden">
        <div className="mb-3 rounded-lg border border-default-200 bg-content1 p-3 sm:p-4">
          <div className="mb-3 flex items-center justify-between gap-3">
            <div className="min-w-0">
              <div className="text-small font-semibold text-foreground">筛选条件</div>
              <div className="mt-0.5 truncate text-tiny text-default-500">
                {hasActiveFilters ? `已启用 ${activeFilterCount} 项筛选` : "按客户端、结果和时间范围筛选"}
              </div>
            </div>
            <Button
              className="shrink-0"
              isDisabled={!hasActiveFilters}
              radius="sm"
              size="sm"
              variant="light"
              onPress={reset}
            >
              重置筛选
            </Button>
          </div>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <Select className="w-full" label="客户端" items={[{ id: "", clientName: "全部" }, ...clients.map((c) => ({ id: String(c.id), clientName: c.clientName }))]} selectedKeys={clientId ? [clientId] : [""]} onChange={(event) => changeClientId(event.target.value)}>
              {(item) => <SelectItem key={item.id}>{item.clientName}</SelectItem>}
            </Select>
            <Select className="w-full" label="结果" selectedKeys={result ? [result] : [""]} onChange={(event) => changeResult(event.target.value)}>
              <SelectItem key="">全部</SelectItem>
              <SelectItem key="true">成功</SelectItem>
              <SelectItem key="false">失败</SelectItem>
            </Select>
            <Input className="w-full" type="date" label="开始日期" value={fromDate} onValueChange={changeFromDate} />
            <Input className="w-full" type="date" label="结束日期" value={toDate} onValueChange={changeToDate} />
          </div>
        </div>
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

      {/* desktop: 表格 + 搜索条件在表头 */}
      <div className="hidden min-w-0 xl:block">
      <Card shadow="none" className="overflow-visible rounded-lg border border-default-200 bg-content1">
        <CardBody className="p-3">
        <div className="mb-3 flex min-h-9 items-center justify-between gap-3">
          <div className="flex min-w-0 items-center gap-2 text-tiny text-default-500">
            <span className="truncate">点击列标题旁的筛选图标缩小记录范围</span>
            {hasActiveFilters ? (
              <Chip color="primary" radius="sm" size="sm" variant="flat">
                {activeFilterCount} 项筛选
              </Chip>
            ) : null}
          </div>
          <Button
            className="h-9 shrink-0"
            isDisabled={!hasActiveFilters}
            radius="sm"
            size="sm"
            variant="light"
            onPress={reset}
          >
            重置筛选
          </Button>
        </div>
        <Table
          key={tableCollectionKey}
          aria-label="连接记录"
          classNames={{
            table: "w-full table-fixed",
            th: "h-10 bg-content2 px-2 text-tiny font-semibold text-default-600",
            td: "border-b border-divider/70 px-2 py-2.5 align-middle text-small text-default-700",
          }}
          isHeaderSticky
          removeWrapper
        >
        <TableHeader>
          <TableColumn className="w-[6%]">ID</TableColumn>
          <TableColumn className="w-[16%]">
            <ConnectionClientFilterHeader clients={clients} selectedClientId={clientId} onSelect={changeClientId} />
          </TableColumn>
          <TableColumn className="w-[10%]">
            <ConnectionResultFilterHeader selectedResult={result} onSelect={changeResult} />
          </TableColumn>
          <TableColumn className="w-[15%]">远端地址</TableColumn>
          <TableColumn className="w-[15%]">
            <ConnectionDateFilterHeader fromDate={fromDate} toDate={toDate} onFromChange={changeFromDate} onToChange={changeToDate} />
          </TableColumn>
          <TableColumn className="w-[15%]">断开时间</TableColumn>
          <TableColumn className="w-[11%]">持续时长</TableColumn>
          <TableColumn>原因</TableColumn>
        </TableHeader>
        <TableBody key={tableCollectionKey} items={tableRows} isLoading={loading} emptyContent="暂无数据">
          {(record) => (
            <TableRow key={record.tableKey}>
              <TableCell>{record.id}</TableCell>
              <TableCell>
                <span className="block truncate" title={record.clientName}>
                  {record.clientName}
                </span>
              </TableCell>
              <TableCell>
                <Chip size="sm" variant="flat" color={record.success ? "success" : "danger"}>
                  {record.success ? "成功" : "失败"}
                </Chip>
              </TableCell>
              <TableCell>
                <span className="block truncate" title={record.remoteAddress || "-"}>
                  {record.remoteAddress || "-"}
                </span>
              </TableCell>
              <TableCell>
                <span className="block truncate" title={formatDateTime(record.connectedAt)}>
                  {formatDateTime(record.connectedAt)}
                </span>
              </TableCell>
              <TableCell>
                <span className="block truncate" title={record.disconnectedAt ? formatDateTime(record.disconnectedAt) : "-"}>
                  {record.disconnectedAt ? formatDateTime(record.disconnectedAt) : "-"}
                </span>
              </TableCell>
              <TableCell>{formatDuration(record.connectedAt, record.disconnectedAt, now)}</TableCell>
              <TableCell>
                <span className="block truncate" title={record.success
                  ? record.disconnectReasonText || "-"
                  : record.failureReason || record.disconnectReasonText || "登录失败"}>
                {record.success
                  ? record.disconnectReasonText || "-"
                  : record.failureReason || record.disconnectReasonText || "登录失败"}
                </span>
              </TableCell>
            </TableRow>
          )}
        </TableBody>
      </Table>
        </CardBody>
      </Card>
      </div>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="text-small text-default-600">
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

function ConnectionClientFilterHeader({
  clients,
  onSelect,
  selectedClientId,
}: {
  clients: Array<{ id: number; clientName: string }>;
  onSelect: (clientId: string) => void;
  selectedClientId: string;
}) {
  const activeClient = clients.find((client) => String(client.id) === selectedClientId);
  const label = activeClient ? `客户端: ${activeClient.clientName}` : "客户端";
  const filterItems = [
    { key: "", label: "全部客户端" },
    ...clients.map((client) => ({ key: String(client.id), label: client.clientName })),
  ];

  return (
    <TableFilterHeader label={label} active={Boolean(selectedClientId)} title="筛选客户端">
      <Dropdown classNames={FILTER_POPOVER_CLASS_NAMES} placement="bottom-start" shouldBlockScroll={false}>
        <DropdownTrigger>
          <Button
            isIconOnly
            aria-label="筛选客户端"
            className="h-7 min-w-7 text-default-500"
            color={selectedClientId ? "primary" : "default"}
            size="sm"
            title="筛选客户端"
            variant={selectedClientId ? "flat" : "light"}
          >
            <FilterIcon />
          </Button>
        </DropdownTrigger>
        <DropdownMenu
          aria-label="筛选连接记录客户端"
          items={filterItems}
          selectedKeys={[selectedClientId || ""]}
          selectionMode="single"
          onAction={(key) => onSelect(String(key))}
        >
          {(item) => <DropdownItem key={item.key}>{item.label}</DropdownItem>}
        </DropdownMenu>
      </Dropdown>
    </TableFilterHeader>
  );
}

function ConnectionResultFilterHeader({
  onSelect,
  selectedResult,
}: {
  onSelect: (result: string) => void;
  selectedResult: string;
}) {
  const label = selectedResult === "true" ? "结果: 成功" : selectedResult === "false" ? "结果: 失败" : "结果";
  const filterItems = [
    { key: "", label: "全部结果" },
    { key: "true", label: "成功" },
    { key: "false", label: "失败" },
  ];

  return (
    <TableFilterHeader label={label} active={Boolean(selectedResult)} title="筛选结果">
      <Dropdown classNames={FILTER_POPOVER_CLASS_NAMES} placement="bottom-start" shouldBlockScroll={false}>
        <DropdownTrigger>
          <Button
            isIconOnly
            aria-label="筛选结果"
            className="h-7 min-w-7 text-default-500"
            color={selectedResult ? "primary" : "default"}
            size="sm"
            title="筛选结果"
            variant={selectedResult ? "flat" : "light"}
          >
            <FilterIcon />
          </Button>
        </DropdownTrigger>
        <DropdownMenu
          aria-label="筛选连接记录结果"
          items={filterItems}
          selectedKeys={[selectedResult || ""]}
          selectionMode="single"
          onAction={(key) => onSelect(String(key))}
        >
          {(item) => <DropdownItem key={item.key}>{item.label}</DropdownItem>}
        </DropdownMenu>
      </Dropdown>
    </TableFilterHeader>
  );
}

function ConnectionDateFilterHeader({
  fromDate,
  onFromChange,
  onToChange,
  toDate,
}: {
  fromDate: string;
  onFromChange: (value: string) => void;
  onToChange: (value: string) => void;
  toDate: string;
}) {
  const active = Boolean(fromDate || toDate);
  const label = active ? "连接时间: 已筛选" : "连接时间";

  return (
    <TableFilterHeader label={label} active={active} title="筛选连接时间">
      <Popover classNames={FILTER_POPOVER_CLASS_NAMES} placement="bottom-start" shouldBlockScroll={false}>
        <PopoverTrigger>
          <Button
            isIconOnly
            aria-label="筛选连接时间"
            className="h-7 min-w-7 text-default-500"
            color={active ? "primary" : "default"}
            size="sm"
            title="筛选连接时间"
            variant={active ? "flat" : "light"}
          >
            <FilterIcon />
          </Button>
        </PopoverTrigger>
        <PopoverContent className="w-64 p-3">
          <div className="flex w-full flex-col gap-3">
            <div className="text-small font-semibold text-foreground">连接时间范围</div>
            <Input label="开始日期" size="sm" type="date" value={fromDate} onValueChange={onFromChange} />
            <Input label="结束日期" size="sm" type="date" value={toDate} onValueChange={onToChange} />
            <Button size="sm" variant="flat" onPress={() => { onFromChange(""); onToChange(""); }}>
              清空时间筛选
            </Button>
          </div>
        </PopoverContent>
      </Popover>
    </TableFilterHeader>
  );
}

function TableFilterHeader({
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
      <span className={`truncate ${active ? "text-foreground" : "text-default-600"}`} title={label}>
        {label}
      </span>
      <span title={title}>{children}</span>
      {active ? <span className="h-1.5 w-1.5 rounded-full bg-primary" aria-hidden /> : null}
    </div>
  );
}

function FilterIcon() {
  return (
    <svg className="h-4 w-4" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" viewBox="0 0 24 24">
      <path d="M4 5h16l-6 7v5l-4 2v-7L4 5z" />
    </svg>
  );
}
