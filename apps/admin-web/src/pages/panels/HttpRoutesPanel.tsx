import { useCallback, useEffect, useState, type FormEvent } from "react";
import {
  Button,
  Dropdown,
  DropdownItem,
  DropdownMenu,
  DropdownTrigger,
  Input,
  Modal,
  ModalBody,
  ModalContent,
  ModalFooter,
  ModalHeader,
  Pagination,
  Select,
  SelectItem,
  Switch,
  Table,
  TableBody,
  TableCell,
  TableColumn,
  TableHeader,
  TableRow,
  useDisclosure,
} from "@heroui/react";
import { adminApi } from "../../api/client";
import type { HttpRoute } from "../../api/types";
import { formatDateTime } from "../../lib/format";
import { copyTextWithFeedback } from "../../lib/clipboard";
import { notify, notifyError } from "../../components/toast";
import { useClients } from "../../hooks/useClients";
import { MobileListCard, MobileListCardList } from "../../components/MobileListCard";
import { ConfirmModal } from "../../components/ConfirmModal";
import { EmptyState } from "../../components/EmptyState";

const PAGE_SIZE = 10;

export function HttpRoutesPanel() {
  const { clients } = useClients();
  const [routes, setRoutes] = useState<HttpRoute[]>([]);
  const [loading, setLoading] = useState(true);
  const [filterClientId, setFilterClientId] = useState("");
  const [createClientId, setCreateClientId] = useState("");
  const [route, setRoute] = useState("");
  const [targetBaseUrl, setTargetBaseUrl] = useState("");
  const [lastCreatedAccessUrl, setLastCreatedAccessUrl] = useState("");
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<HttpRoute | null>(null);
  const [pendingIds, setPendingIds] = useState<Set<number>>(new Set());
  const [confirm, setConfirm] = useState<{ title: string; description: string; action: () => Promise<void> } | null>(null);
  const [page, setPage] = useState(1);
  const editModal = useDisclosure();

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setRoutes(await adminApi.listHttpRoutes(filterClientId ? Number(filterClientId) : undefined));
    } catch (error) {
      notifyError(error, "加载 HTTP 路由失败");
    } finally {
      setLoading(false);
    }
  }, [filterClientId]);

  useEffect(() => {
    void load();
  }, [load]);

  const onCreate = async (event: FormEvent) => {
    event.preventDefault();
    if (!createClientId) {
      notify("请先选择客户端", "error");
      return;
    }
    setCreating(true);
    try {
      const created = await adminApi.createHttpRoute(Number(createClientId), {
        route: route.trim(),
        targetBaseUrl: targetBaseUrl.trim(),
        enabled: true,
        detailCaptureEnabled: false,
        pathRewriteEnabled: false,
      });
      setRoute("");
      setTargetBaseUrl("");
      setLastCreatedAccessUrl(httpRouteAccessUrl(created));
      notify("HTTP 路由已创建");
      await load();
    } catch (error) {
      notifyError(error, "创建失败");
    } finally {
      setCreating(false);
    }
  };

  /** 乐观更新 + 失败回滚；切换期间该行开关禁用，避免整表刷新与连点竞态。 */
  const patchRoute = async (
    item: HttpRoute,
    patch: Partial<Pick<HttpRoute, "enabled" | "detailCaptureEnabled" | "pathRewriteEnabled">>,
    errorMessage: string,
  ) => {
    if (pendingIds.has(item.id)) {
      return;
    }
    setPendingIds((prev) => new Set(prev).add(item.id));
    setRoutes((prev) => prev.map((row) => (row.id === item.id ? { ...row, ...patch } : row)));
    try {
      await adminApi.updateHttpRoute(item.id, {
        route: item.route,
        targetBaseUrl: item.targetBaseUrl,
        enabled: patch.enabled ?? item.enabled,
        detailCaptureEnabled: patch.detailCaptureEnabled ?? Boolean(item.detailCaptureEnabled),
        pathRewriteEnabled: patch.pathRewriteEnabled ?? Boolean(item.pathRewriteEnabled),
      });
    } catch (error) {
      setRoutes((prev) => prev.map((row) => (row.id === item.id ? item : row)));
      notifyError(error, errorMessage);
    } finally {
      setPendingIds((prev) => {
        const next = new Set(prev);
        next.delete(item.id);
        return next;
      });
    }
  };

  const toggle = (item: HttpRoute) => patchRoute(item, { enabled: !item.enabled }, "切换状态失败");

  const toggleDetailCapture = (item: HttpRoute) =>
    patchRoute(item, { detailCaptureEnabled: !Boolean(item.detailCaptureEnabled) }, "切换明细采集失败");

  const togglePathRewrite = (item: HttpRoute) =>
    patchRoute(item, { pathRewriteEnabled: !Boolean(item.pathRewriteEnabled) }, "切换路径改写失败");

  const remove = (item: HttpRoute) => {
    setConfirm({
      title: "删除 HTTP 路由",
      description: `确定删除路由「${item.route}」（${item.clientName}）吗？删除后访问链接立即失效。`,
      action: async () => {
        try {
          await adminApi.deleteHttpRoute(item.id);
          notify("HTTP 路由已删除");
          await load();
        } catch (error) {
          notifyError(error, "删除失败");
        }
      },
    });
  };

  const totalPages = Math.max(1, Math.ceil(routes.length / PAGE_SIZE));
  const safePage = Math.min(page, totalPages);
  const pagedRoutes = routes.slice((safePage - 1) * PAGE_SIZE, safePage * PAGE_SIZE);

  return (
    <div className="mt-4 flex min-w-0 flex-col gap-4">
      <form className="flex flex-wrap items-end gap-3" onSubmit={onCreate}>
        <Select
          className="w-full sm:w-48"
          label="客户端"
          selectedKeys={createClientId ? [createClientId] : []}
          onChange={(event) => setCreateClientId(event.target.value)}
          isRequired
        >
          {clients.map((client) => (
            <SelectItem key={String(client.id)}>{client.clientName}</SelectItem>
          ))}
        </Select>
        <Input className="w-full sm:w-40" label="路由名" placeholder="web" value={route} onValueChange={setRoute} maxLength={60} isRequired />
        <Input className="w-full sm:w-64" label="目标地址" placeholder="http://127.0.0.1:8080" value={targetBaseUrl} onValueChange={setTargetBaseUrl} maxLength={512} isRequired />
        <Button className="h-14 w-full sm:w-auto" type="submit" color="primary" isLoading={creating}>
          新建路由
        </Button>
        <Button className="h-14 w-full sm:w-auto" variant="flat" isLoading={loading} onPress={() => void load()}>
          刷新
        </Button>
      </form>

      {lastCreatedAccessUrl && (
        <div className="flex min-w-0 flex-wrap items-center gap-2 rounded-small border border-success-200 bg-success-50 p-3 text-small">
          <span className="shrink-0 font-semibold text-success">访问链接</span>
          <a
            className="min-w-0 flex-1 break-all font-mono text-primary underline-offset-2 hover:underline"
            href={lastCreatedAccessUrl}
            rel="noreferrer"
            target="_blank"
          >
            {lastCreatedAccessUrl}
          </a>
          <Button size="sm" variant="flat" onPress={() => void copyAccessUrl(lastCreatedAccessUrl)}>
            复制
          </Button>
          <Button
            isIconOnly
            aria-label="关闭提示"
            className="h-7 w-7 min-w-7"
            size="sm"
            variant="light"
            onPress={() => setLastCreatedAccessUrl("")}
          >
            <svg className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 6l12 12M6 18L18 6" />
            </svg>
          </Button>
        </div>
      )}

      <div className="flex flex-wrap items-end gap-3 xl:hidden">
        <Select
          className="w-full sm:w-48"
          label="筛选客户端"
          items={[{ id: "", clientName: "全部" }, ...clients.map((c) => ({ id: String(c.id), clientName: c.clientName }))]}
          selectedKeys={filterClientId ? [filterClientId] : [""]}
          onChange={(event) => setFilterClientId(event.target.value)}
        >
          {(item) => <SelectItem key={item.id}>{item.clientName}</SelectItem>}
        </Select>
        <Button className="h-14 w-full sm:w-auto" variant="flat" isLoading={loading} onPress={() => void load()}>
          刷新
        </Button>
      </div>

      {/* mobile: 卡片堆叠 */}
      <div className="xl:hidden">
        <MobileListCardList
          items={pagedRoutes}
          isLoading={loading}
          emptyContent={<EmptyState icon="generic" title="后台尚未维护 HTTP 路由" description="创建路由后即可通过访问链接打开内网应用" />}
          renderCard={(raw) => {
            const item = raw as HttpRoute;
            const accessUrl = httpRouteAccessUrl(item);
            const pending = pendingIds.has(item.id);
            return (
              <MobileListCard
                key={item.id}
                title={
                  <div className="flex items-center gap-2">
                    <code className="break-all">{item.route}</code>
                    <span className="text-tiny font-normal text-default-400">#{item.id}</span>
                  </div>
                }
                subtitle={
                  <div className="flex flex-col gap-0.5">
                    <span>{item.clientName}</span>
                    <code className="break-all">{item.targetBaseUrl || "-"}</code>
                  </div>
                }
                badges={
                  <>
                    <Switch
                      size="sm"
                      isSelected={item.enabled}
                      isDisabled={pending}
                      onValueChange={() => void toggle(item)}
                    >
                      启用
                    </Switch>
                    <Switch
                      size="sm"
                      isSelected={Boolean(item.detailCaptureEnabled)}
                      isDisabled={pending}
                      onValueChange={() => void toggleDetailCapture(item)}
                    >
                      明细采集
                    </Switch>
                    <Switch
                      size="sm"
                      isSelected={Boolean(item.pathRewriteEnabled)}
                      isDisabled={pending}
                      onValueChange={() => void togglePathRewrite(item)}
                    >
                      路径改写
                    </Switch>
                  </>
                }
                fields={[
                  {
                    label: "访问链接",
                    value: (
                      <div className="flex flex-col gap-1">
                        <a
                          className="break-all font-mono text-primary underline-offset-2 hover:underline"
                          href={accessUrl}
                          rel="noreferrer"
                          target="_blank"
                        >
                          {accessUrl}
                        </a>
                        <Button
                          size="sm"
                          className="w-fit"
                          variant="light"
                          onPress={() => void copyAccessUrl(accessUrl)}
                        >
                          复制
                        </Button>
                      </div>
                    ),
                  },
                  { label: "更新时间", value: formatDateTime(item.updatedAt || item.createdAt) },
                ]}
                actions={
                  <>
                    <Button size="sm" variant="flat" onPress={() => { setEditing(item); editModal.onOpen(); }}>
                      编辑
                    </Button>
                    <Button size="sm" color="danger" variant="flat" onPress={() => remove(item)}>
                      删除
                    </Button>
                  </>
                }
              />
            );
          }}
        />
      </div>

      {/* desktop: 表格优先自适应，长文本单行省略 */}
      <div className="hidden min-w-0 xl:block">
        <Table
          aria-label="HTTP 路由列表"
          classNames={{ table: "w-full table-fixed", th: "px-2", td: "px-2 align-middle" }}
          isHeaderSticky
          removeWrapper
        >
        <TableHeader>
          <TableColumn className="w-[6%]">ID</TableColumn>
          <TableColumn className="w-[12%]">
            <ClientFilterHeader
              clients={clients}
              selectedClientId={filterClientId}
              onSelect={setFilterClientId}
            />
          </TableColumn>
          <TableColumn className="w-[8%]">路由名</TableColumn>
          <TableColumn className="w-[14%]">目标地址</TableColumn>
          <TableColumn className="w-[16%]">访问链接</TableColumn>
          <TableColumn className="w-[7%]">启用</TableColumn>
          <TableColumn className="w-[7%]">明细</TableColumn>
          <TableColumn className="w-[7%]">改写</TableColumn>
          <TableColumn className="w-[11%]">更新时间</TableColumn>
          <TableColumn className="w-[12%]">操作</TableColumn>
        </TableHeader>
        <TableBody items={pagedRoutes} isLoading={loading} emptyContent={<EmptyState icon="generic" title="后台尚未维护 HTTP 路由" description="创建路由后即可通过访问链接打开内网应用" />}>
          {(item) => {
            const pending = pendingIds.has(item.id);
            return (
            <TableRow key={item.id}>
              <TableCell>
                <span className="block truncate font-mono text-tiny" title={String(item.id)}>
                  {item.id}
                </span>
              </TableCell>
              <TableCell>
                <span className="block truncate" title={item.clientName}>
                  {item.clientName}
                </span>
              </TableCell>
              <TableCell>
                <code className="block truncate" title={item.route}>
                  {item.route}
                </code>
              </TableCell>
              <TableCell>
                <code className="block truncate" title={item.targetBaseUrl || "-"}>
                  {item.targetBaseUrl || "-"}
                </code>
              </TableCell>
              <TableCell>
                <HttpRouteAccessLink route={item} />
              </TableCell>
              <TableCell>
                <Switch
                  aria-label="启用"
                  size="sm"
                  isSelected={item.enabled}
                  isDisabled={pending}
                  onValueChange={() => void toggle(item)}
                />
              </TableCell>
              <TableCell>
                <Switch
                  aria-label="明细采集"
                  size="sm"
                  isSelected={Boolean(item.detailCaptureEnabled)}
                  isDisabled={pending}
                  onValueChange={() => void toggleDetailCapture(item)}
                />
              </TableCell>
              <TableCell>
                <Switch
                  aria-label="路径改写"
                  size="sm"
                  isSelected={Boolean(item.pathRewriteEnabled)}
                  isDisabled={pending}
                  onValueChange={() => void togglePathRewrite(item)}
                />
              </TableCell>
              <TableCell>
                <span className="block truncate" title={formatDateTime(item.updatedAt || item.createdAt)}>
                  {formatDateTime(item.updatedAt || item.createdAt)}
                </span>
              </TableCell>
              <TableCell>
                <div className="flex gap-1">
                  <Button className="min-w-0 px-2" size="sm" variant="flat" onPress={() => { setEditing(item); editModal.onOpen(); }}>
                    编辑
                  </Button>
                  <Button className="min-w-0 px-2" size="sm" color="danger" variant="flat" onPress={() => remove(item)}>
                    删除
                  </Button>
                </div>
              </TableCell>
            </TableRow>
            );
          }}
        </TableBody>
      </Table>
      </div>

      {totalPages > 1 ? (
        <div className="flex justify-end">
          <Pagination showControls page={safePage} total={totalPages} onChange={setPage} />
        </div>
      ) : null}

      <EditHttpRouteModal disclosure={editModal} route={editing} onSaved={() => void load()} />
      <ConfirmModal
        isOpen={confirm != null}
        onClose={() => setConfirm(null)}
        onConfirm={() => confirm?.action()}
        title={confirm?.title ?? ""}
        description={confirm?.description}
        confirmLabel="删除"
        danger
      />
    </div>
  );
}

function HttpRouteAccessLink({ route }: { route: HttpRoute }) {
  const accessUrl = httpRouteAccessUrl(route);

  return (
    <div className="flex min-w-0 flex-col gap-1">
      <a
        className="block max-w-full truncate font-mono text-tiny text-primary underline-offset-2 hover:underline"
        href={accessUrl}
        rel="noreferrer"
        target="_blank"
        title={accessUrl}
      >
        {accessUrl}
      </a>
      <div>
        <Button size="sm" variant="light" onPress={() => void copyAccessUrl(accessUrl)}>
          复制
        </Button>
      </div>
    </div>
  );
}

function ClientFilterHeader({
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
    <div className="flex min-w-0 items-center gap-1">
      <span className="truncate" title={label}>
        {label}
      </span>
      <Dropdown placement="bottom-start" shouldBlockScroll={false}>
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
          aria-label="筛选 HTTP 路由客户端"
          items={filterItems}
          selectedKeys={[selectedClientId || ""]}
          selectionMode="single"
          onAction={(key) => onSelect(String(key))}
        >
          {(item) => <DropdownItem key={item.key}>{item.label}</DropdownItem>}
        </DropdownMenu>
      </Dropdown>
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

function httpRouteAccessUrl(route: Pick<HttpRoute, "clientName" | "route">): string {
  const origin = typeof window === "undefined" ? "" : window.location.origin;
  return `${origin}/http/${encodeRouteSegment(route.clientName)}/${encodeRouteSegment(route.route)}/`;
}

function encodeRouteSegment(value: string): string {
  return encodeURIComponent(value.trim());
}

async function copyAccessUrl(url: string): Promise<void> {
  await copyTextWithFeedback(url, "访问链接已复制");
}

interface EditHttpRouteModalProps {
  disclosure: ReturnType<typeof useDisclosure>;
  route: HttpRoute | null;
  onSaved: () => void;
}

function EditHttpRouteModal({ disclosure, route, onSaved }: EditHttpRouteModalProps) {
  const [name, setName] = useState("");
  const [targetBaseUrl, setTargetBaseUrl] = useState("");
  const [enabled, setEnabled] = useState(true);
  const [detailCaptureEnabled, setDetailCaptureEnabled] = useState(false);
  const [pathRewriteEnabled, setPathRewriteEnabled] = useState(false);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (route) {
      setName(route.route);
      setTargetBaseUrl(route.targetBaseUrl);
      setEnabled(route.enabled);
      setDetailCaptureEnabled(Boolean(route.detailCaptureEnabled));
      setPathRewriteEnabled(Boolean(route.pathRewriteEnabled));
    }
  }, [route]);

  const save = async () => {
    if (!route) {
      return;
    }
    setSaving(true);
    try {
      await adminApi.updateHttpRoute(route.id, {
        route: name.trim(),
        targetBaseUrl: targetBaseUrl.trim(),
        enabled,
        detailCaptureEnabled,
        pathRewriteEnabled,
      });
      notify("HTTP 路由已更新");
      disclosure.onClose();
      onSaved();
    } catch (error) {
      notifyError(error, "更新失败");
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal isOpen={disclosure.isOpen} onOpenChange={disclosure.onOpenChange}>
      <ModalContent>
        {(onClose) => (
          <>
            <ModalHeader>编辑 HTTP 路由 #{route?.id}</ModalHeader>
            <ModalBody className="gap-3">
              <Input label="路由名" value={name} onValueChange={setName} maxLength={60} isRequired />
              <Input label="目标地址" value={targetBaseUrl} onValueChange={setTargetBaseUrl} maxLength={512} isRequired />
              <Switch isSelected={enabled} onValueChange={setEnabled}>
                启用
              </Switch>
              <Switch isSelected={detailCaptureEnabled} onValueChange={setDetailCaptureEnabled}>
                明细采集
              </Switch>
              <Switch isSelected={pathRewriteEnabled} onValueChange={setPathRewriteEnabled}>
                路径改写
              </Switch>
            </ModalBody>
            <ModalFooter>
              <Button variant="flat" onPress={onClose}>
                取消
              </Button>
              <Button color="primary" isLoading={saving} onPress={() => void save()}>
                保存
              </Button>
            </ModalFooter>
          </>
        )}
      </ModalContent>
    </Modal>
  );
}
