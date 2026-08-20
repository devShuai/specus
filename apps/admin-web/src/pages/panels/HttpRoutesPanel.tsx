import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { Button, Chip, Description, Dropdown, DropdownItem, DropdownMenu, DropdownPopover, DropdownTrigger, FieldError, Input, Label, ListBox, ListBoxItem, Modal, Select, SelectIndicator, SelectPopover, SelectTrigger, SelectValue, Spinner, Switch, Table, TableBody, TableCell, TableColumn, TableContent, TableHeader, TableRow, TextField, buttonVariants, cn, useOverlayState } from "@heroui/react";
import { Pager } from "../../components/Pager";
import { adminApi } from "../../api/client";
import type { HttpRoute } from "../../api/types";
import { formatDateTime } from "../../lib/format";
import { copyTextWithFeedback } from "../../lib/clipboard";
import { notify, notifyError } from "../../components/toast";
import { useClients } from "../../hooks/useClients";
import { MobileListCard, MobileListCardList } from "../../components/MobileListCard";
import { ConfirmModal } from "../../components/ConfirmModal";
import { EmptyState } from "../../components/EmptyState";
import {
  buildHttpRouteAuthMutation,
  HTTP_ROUTE_AUTH_PASSWORD_MAX_LENGTH,
  HTTP_ROUTE_AUTH_USERNAME_MAX_LENGTH,
  validateHttpRouteAuth,
  type HttpRouteAuthDraft,
} from "./httpRouteAuth";

const PAGE_SIZE = 10;
type RouteToggleField = "enabled" | "detailCaptureEnabled" | "mediaCaptureEnabled" | "pathRewriteEnabled";

function pendingKey(id: number, field: RouteToggleField): string {
  return `${id}:${field}`;
}

export function HttpRoutesPanel() {
  const { clients } = useClients();
  const [routes, setRoutes] = useState<HttpRoute[]>([]);
  const [loading, setLoading] = useState(true);
  const [filterClientId, setFilterClientId] = useState("");
  const [createClientId, setCreateClientId] = useState("");
  const [route, setRoute] = useState("");
  const [targetBaseUrl, setTargetBaseUrl] = useState("");
  const [authEnabled, setAuthEnabled] = useState(false);
  const [authUsername, setAuthUsername] = useState("");
  const [authPassword, setAuthPassword] = useState("");
  const [authValidationVisible, setAuthValidationVisible] = useState(false);
  const [lastCreatedAccessUrl, setLastCreatedAccessUrl] = useState("");
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<HttpRoute | null>(null);
  const pendingKeysRef = useRef<Set<string>>(new Set());
  const [pendingKeys, setPendingKeys] = useState<Set<string>>(new Set());
  const [confirm, setConfirm] = useState<{ title: string; description: string; action: () => Promise<void> } | null>(null);
  const [page, setPage] = useState(1);
  const editModal = useOverlayState();

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
    const authDraft: HttpRouteAuthDraft = {
      enabled: authEnabled,
      username: authUsername,
      password: authPassword,
      passwordConfigured: false,
    };
    const authError = validateHttpRouteAuth(authDraft);
    if (authError) {
      setAuthValidationVisible(true);
      notify(authError, "error");
      return;
    }
    setCreating(true);
    try {
      const created = await adminApi.createHttpRoute(Number(createClientId), {
        route: route.trim(),
        targetBaseUrl: targetBaseUrl.trim(),
        enabled: true,
        detailCaptureEnabled: false,
        mediaCaptureEnabled: false,
        pathRewriteEnabled: false,
        ...buildHttpRouteAuthMutation(authDraft),
      });
      setRoute("");
      setTargetBaseUrl("");
      setAuthEnabled(false);
      setAuthUsername("");
      setAuthPassword("");
      setAuthValidationVisible(false);
      setLastCreatedAccessUrl(httpRouteAccessUrl(created));
      notify("HTTP 路由已创建");
      await load();
    } catch (error) {
      notifyError(error, "创建失败");
    } finally {
      setCreating(false);
    }
  };

  /** 乐观更新 + 单字段回滚；同一行的其他开关可继续操作。 */
  const patchRoute = async (
    item: HttpRoute,
    field: RouteToggleField,
    value: boolean,
    errorMessage: string,
  ) => {
    const key = pendingKey(item.id, field);
    if (pendingKeysRef.current.has(key)) {
      return;
    }
    pendingKeysRef.current.add(key);
    setPendingKeys(new Set(pendingKeysRef.current));
    setRoutes((prev) => prev.map((row) => (row.id === item.id ? { ...row, [field]: value } : row)));
    try {
      await adminApi.updateHttpRoute(item.id, {
        route: item.route,
        targetBaseUrl: item.targetBaseUrl,
        [field]: value,
      });
    } catch (error) {
      setRoutes((prev) => prev.map((row) => (
        row.id === item.id ? { ...row, [field]: item[field] } : row
      )));
      notifyError(error, errorMessage);
    } finally {
      pendingKeysRef.current.delete(key);
      setPendingKeys(new Set(pendingKeysRef.current));
    }
  };

  const toggle = (item: HttpRoute) =>
    patchRoute(item, "enabled", !item.enabled, "切换状态失败");

  const toggleDetailCapture = (item: HttpRoute) =>
    patchRoute(item, "detailCaptureEnabled", !Boolean(item.detailCaptureEnabled), "切换明细采集失败");

  const toggleMediaCapture = (item: HttpRoute) =>
    patchRoute(item, "mediaCaptureEnabled", !Boolean(item.mediaCaptureEnabled), "切换媒体采集失败");

  const togglePathRewrite = (item: HttpRoute) =>
    patchRoute(item, "pathRewriteEnabled", !Boolean(item.pathRewriteEnabled), "切换路径改写失败");

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
  const createAuthDraft: HttpRouteAuthDraft = {
    enabled: authEnabled,
    username: authUsername,
    password: authPassword,
    passwordConfigured: false,
  };
  const createAuthError = authValidationVisible ? validateHttpRouteAuth(createAuthDraft) : "";

  return (
    <div className="mt-4 flex min-w-0 flex-col gap-4">
      <form className="flex flex-wrap items-end gap-3" onSubmit={onCreate}>
        <Select
          className="w-full sm:w-48"
          isRequired selectedKey={createClientId || null} onSelectionChange={(event) => setCreateClientId(String(event ?? ""))}>
          <Label>客户端</Label>
          <SelectTrigger>
            <SelectValue />
            <SelectIndicator />
          </SelectTrigger>
          <SelectPopover>
            <ListBox>
              {clients.map((client) => (
            <ListBoxItem key={String(client.id)} id={String(client.id)}>{client.clientName}</ListBoxItem>
          ))}
            </ListBox>
          </SelectPopover>
        </Select>
        <TextField value={route} onChange={setRoute} isRequired className="w-full sm:w-40">
          <Label>路由名</Label>
          <Input placeholder="web" maxLength={60} />
        </TextField>
        <TextField value={targetBaseUrl} onChange={setTargetBaseUrl} isRequired className="w-full sm:w-64">
          <Label>目标地址</Label>
          <Input placeholder="http://127.0.0.1:8080" maxLength={512} />
        </TextField>
        <Button variant="primary" className="h-14 w-full sm:w-auto" type="submit" isDisabled={creating}>{creating ? <Spinner size="sm" /> : null}
          新建路由
        </Button>
        <Button className="h-14 w-full sm:w-auto" variant="secondary" onPress={() => void load()} isDisabled={loading}>{loading ? <Spinner size="sm" /> : null}
          刷新
        </Button>
        <div className="w-full rounded-medium border border-default-200 bg-default-50/70 p-3">
          <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
            <Switch
              isSelected={authEnabled}
              onChange={(enabled) => {
                setAuthEnabled(enabled);
                setAuthValidationVisible(false);
              }}
            >
              访问认证
            </Switch>
            <HttpRouteAuthChip enabled={authEnabled} />
            <span className="text-tiny text-default-500">
              {authEnabled ? "访问链接时由浏览器验证用户名和密码" : "拥有链接的访问者可直接打开"}
            </span>
          </div>
          {authEnabled ? (
            <div className="mt-3 grid gap-3 border-t border-default-200 pt-3 sm:grid-cols-2">
              <TextField value={authUsername} onChange={setAuthUsername} isRequired isInvalid={Boolean(createAuthError && createAuthError.includes("用户名"))} autoComplete="off">
                <Label>访问用户名</Label>
                <Input maxLength={HTTP_ROUTE_AUTH_USERNAME_MAX_LENGTH}  />
                <FieldError>{createAuthError.includes("用户名") ? createAuthError : ""}</FieldError>
              </TextField>
              <TextField value={authPassword} onChange={setAuthPassword} isRequired isInvalid={Boolean(createAuthError && createAuthError.includes("密码"))} type="password" autoComplete="new-password">
                <Label>访问密码</Label>
                <Input maxLength={HTTP_ROUTE_AUTH_PASSWORD_MAX_LENGTH}  />
                <FieldError>{createAuthError.includes("密码") ? createAuthError : ""}</FieldError>
              </TextField>
            </div>
          ) : null}
        </div>
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
          <Button size="sm" variant="secondary" onPress={() => void copyAccessUrl(lastCreatedAccessUrl)}>
            复制
          </Button>
          <Button
            isIconOnly
            aria-label="关闭提示"
            className="h-7 w-7 min-w-7"
            size="sm" variant="ghost"
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
          className="w-full sm:w-48" selectedKey={filterClientId || ""} onSelectionChange={(event) => setFilterClientId(String(event ?? ""))}>
          <Label>筛选客户端</Label>
          <SelectTrigger>
            <SelectValue />
            <SelectIndicator />
          </SelectTrigger>
          <SelectPopover>
            <ListBox items={[{ id: "", clientName: "全部" }, ...clients.map((c) => ({ id: String(c.id), clientName: c.clientName }))]}>
              {(item) => <ListBoxItem key={item.id} id={item.id}>{item.clientName}</ListBoxItem>}
            </ListBox>
          </SelectPopover>
        </Select>
        <Button className="h-14 w-full sm:w-auto" variant="secondary" onPress={() => void load()} isDisabled={loading}>{loading ? <Spinner size="sm" /> : null}
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
                      isSelected={item.enabled}
                      isDisabled={pendingKeys.has(pendingKey(item.id, "enabled"))}
                      onChange={() => void toggle(item)}
                    >
                      启用
                    </Switch>
                    <Switch
                      isSelected={Boolean(item.detailCaptureEnabled)}
                      isDisabled={pendingKeys.has(pendingKey(item.id, "detailCaptureEnabled"))}
                      onChange={() => void toggleDetailCapture(item)}
                    >
                      明细采集
                    </Switch>
                    <Switch
                      isSelected={Boolean(item.pathRewriteEnabled)}
                      isDisabled={pendingKeys.has(pendingKey(item.id, "pathRewriteEnabled"))}
                      onChange={() => void togglePathRewrite(item)}
                    >
                      路径改写
                    </Switch>
                    <Switch
                      isSelected={Boolean(item.mediaCaptureEnabled)}
                      isDisabled={pendingKeys.has(pendingKey(item.id, "mediaCaptureEnabled"))}
                      onChange={() => void toggleMediaCapture(item)}
                    >
                      媒体采集
                    </Switch>
                    <HttpRouteAuthChip enabled={Boolean(item.authEnabled)} />
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
                          className="w-fit" variant="ghost"
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
                    <Button size="sm" variant="secondary" onPress={() => { setEditing(item); editModal.open(); }}>
                      编辑
                    </Button>
                    <Button size="sm" variant="danger-soft" onPress={() => remove(item)}>
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
        >
          <TableContent aria-label="HTTP 路由列表">
          <TableHeader>
            <TableColumn isRowHeader className="w-[5%]">ID</TableColumn>
            <TableColumn className="w-[10%]">
              <ClientFilterHeader
                clients={clients}
                selectedClientId={filterClientId}
                onSelect={setFilterClientId}
              />
            </TableColumn>
            <TableColumn className="w-[7%]">路由名</TableColumn>
            <TableColumn className="w-[12%]">目标地址</TableColumn>
            <TableColumn className="w-[14%]">访问链接</TableColumn>
            <TableColumn className="w-[8%]">认证</TableColumn>
            <TableColumn className="w-[6%]">启用</TableColumn>
            <TableColumn className="w-[6%]">明细</TableColumn>
            <TableColumn className="w-[6%]">媒体</TableColumn>
            <TableColumn className="w-[6%]">改写</TableColumn>
            <TableColumn className="w-[10%]">更新时间</TableColumn>
            <TableColumn className="w-[10%]">操作</TableColumn>
          </TableHeader>
          <TableBody items={pagedRoutes} renderEmptyState={() => (loading ? <Spinner size="sm" /> : <EmptyState icon="generic" title="后台尚未维护 HTTP 路由" description="创建路由后即可通过访问链接打开内网应用" />)}>
            {(item) => {
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
                  <HttpRouteAuthChip enabled={Boolean(item.authEnabled)} />
                </TableCell>
                <TableCell>
                  <Switch
                    aria-label="启用"
                    isSelected={item.enabled}
                    isDisabled={pendingKeys.has(pendingKey(item.id, "enabled"))}
                    onChange={() => void toggle(item)}
                  />
                </TableCell>
                <TableCell>
                  <Switch
                    aria-label="明细采集"
                    isSelected={Boolean(item.detailCaptureEnabled)}
                    isDisabled={pendingKeys.has(pendingKey(item.id, "detailCaptureEnabled"))}
                    onChange={() => void toggleDetailCapture(item)}
                  />
                </TableCell>
                <TableCell>
                  <Switch
                    aria-label="媒体采集"
                    isSelected={Boolean(item.mediaCaptureEnabled)}
                    isDisabled={pendingKeys.has(pendingKey(item.id, "mediaCaptureEnabled"))}
                    onChange={() => void toggleMediaCapture(item)}
                  />
                </TableCell>
                <TableCell>
                  <Switch
                    aria-label="路径改写"
                    isSelected={Boolean(item.pathRewriteEnabled)}
                    isDisabled={pendingKeys.has(pendingKey(item.id, "pathRewriteEnabled"))}
                    onChange={() => void togglePathRewrite(item)}
                  />
                </TableCell>
                <TableCell>
                  <span className="block truncate" title={formatDateTime(item.updatedAt || item.createdAt)}>
                    {formatDateTime(item.updatedAt || item.createdAt)}
                  </span>
                </TableCell>
                <TableCell>
                  <div className="flex gap-1">
                    <Button className="min-w-0 px-2" size="sm" variant="secondary" onPress={() => { setEditing(item); editModal.open(); }}>
                      编辑
                    </Button>
                    <Button className="min-w-0 px-2" size="sm" variant="danger-soft" onPress={() => remove(item)}>
                      删除
                    </Button>
                  </div>
                </TableCell>
              </TableRow>
              );
            }}
          </TableBody>
      
          </TableContent>
        </Table>
      </div>

      {totalPages > 1 ? (
        <div className="flex justify-end">
          <Pager page={safePage} total={totalPages} onChange={setPage}  />
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
        <Button size="sm" variant="ghost" onPress={() => void copyAccessUrl(accessUrl)}>
          复制
        </Button>
      </div>
    </div>
  );
}

function HttpRouteAuthChip({ enabled }: { enabled: boolean }) {
  return (
    <Chip
      size="sm"
      title={enabled ? "访问者需要通过 HTTP Basic 认证" : "无需认证即可访问"}
      variant="soft" color={enabled ? "accent" : "default"}>{<RouteAuthIcon locked={enabled} />}
      {enabled ? "Basic" : "公开"}
    </Chip>
  );
}

function RouteAuthIcon({ locked }: { locked: boolean }) {
  return locked ? (
    <svg aria-hidden="true" className="h-3.5 w-3.5" fill="none" stroke="currentColor" strokeWidth="1.8" viewBox="0 0 24 24">
      <rect height="10" rx="2" width="14" x="5" y="10" />
      <path strokeLinecap="round" d="M8 10V7a4 4 0 018 0v3" />
    </svg>
  ) : (
    <svg aria-hidden="true" className="h-3.5 w-3.5" fill="none" stroke="currentColor" strokeWidth="1.8" viewBox="0 0 24 24">
      <circle cx="12" cy="12" r="8" />
      <path strokeLinecap="round" d="M4 12h16M12 4c2 2.2 3 4.9 3 8s-1 5.8-3 8c-2-2.2-3-4.9-3-8s1-5.8 3-8z" />
    </svg>
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
      <Dropdown>
        <DropdownTrigger
            aria-label="筛选客户端" className={cn(buttonVariants({ variant: selectedClientId ? "secondary" : "ghost", size: "sm", isIconOnly: true }), "h-7 min-w-7 text-default-500")}>
            <FilterIcon />
          </DropdownTrigger>
        <DropdownPopover placement="bottom start">
          <DropdownMenu
            aria-label="筛选 HTTP 路由客户端"
            items={filterItems}
            selectedKeys={[selectedClientId || ""]}
            selectionMode="single"
            onAction={(key) => onSelect(String(key))}
          >
            {(item) => <DropdownItem id={item.key}>{item.label}</DropdownItem>}
          </DropdownMenu>
        </DropdownPopover>
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
  disclosure: ReturnType<typeof useOverlayState>;
  route: HttpRoute | null;
  onSaved: () => void;
}

function EditHttpRouteModal({ disclosure, route, onSaved }: EditHttpRouteModalProps) {
  const [name, setName] = useState("");
  const [targetBaseUrl, setTargetBaseUrl] = useState("");
  const [authEnabled, setAuthEnabled] = useState(false);
  const [authUsername, setAuthUsername] = useState("");
  const [authPassword, setAuthPassword] = useState("");
  const [authPasswordConfigured, setAuthPasswordConfigured] = useState(false);
  const [authValidationVisible, setAuthValidationVisible] = useState(false);
  const [enabled, setEnabled] = useState(true);
  const [detailCaptureEnabled, setDetailCaptureEnabled] = useState(false);
  const [mediaCaptureEnabled, setMediaCaptureEnabled] = useState(false);
  const [pathRewriteEnabled, setPathRewriteEnabled] = useState(false);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (route) {
      setName(route.route);
      setTargetBaseUrl(route.targetBaseUrl);
      setAuthEnabled(Boolean(route.authEnabled));
      setAuthUsername(route.authUsername || "");
      setAuthPassword("");
      setAuthPasswordConfigured(Boolean(route.authPasswordConfigured));
      setAuthValidationVisible(false);
      setEnabled(route.enabled);
      setDetailCaptureEnabled(Boolean(route.detailCaptureEnabled));
      setMediaCaptureEnabled(Boolean(route.mediaCaptureEnabled));
      setPathRewriteEnabled(Boolean(route.pathRewriteEnabled));
    }
  }, [route]);

  const authDraft: HttpRouteAuthDraft = {
    enabled: authEnabled,
    username: authUsername,
    password: authPassword,
    passwordConfigured: authPasswordConfigured,
  };
  const authError = authValidationVisible ? validateHttpRouteAuth(authDraft) : "";

  const save = async () => {
    if (!route) {
      return;
    }
    const nextAuthError = validateHttpRouteAuth(authDraft);
    if (nextAuthError) {
      setAuthValidationVisible(true);
      notify(nextAuthError, "error");
      return;
    }
    setSaving(true);
    try {
      await adminApi.updateHttpRoute(route.id, {
        route: name.trim(),
        targetBaseUrl: targetBaseUrl.trim(),
        enabled,
        detailCaptureEnabled,
        mediaCaptureEnabled,
        pathRewriteEnabled,
        ...buildHttpRouteAuthMutation(authDraft),
      });
      notify("HTTP 路由已更新");
      disclosure.close();
      onSaved();
    } catch (error) {
      notifyError(error, "更新失败");
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal.Root isOpen={disclosure.isOpen} onOpenChange={disclosure.setOpen}>
      <Modal.Backdrop>
        <Modal.Container>
          <Modal.Dialog>
            {({ close: onClose }) => (
            <>
            <Modal.Header>编辑 HTTP 路由 #{route?.id}</Modal.Header>
            <Modal.Body className="gap-3">
              <TextField value={name} onChange={setName} isRequired>
                <Label>路由名</Label>
                <Input maxLength={60} />
              </TextField>
            <TextField value={targetBaseUrl} onChange={setTargetBaseUrl} isRequired>
              <Label>目标地址</Label>
              <Input maxLength={512} />
            </TextField>
            <div className="rounded-medium border border-default-200 bg-default-50/70 p-3">
              <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
                <Switch
                  isSelected={authEnabled}
                  onChange={(nextEnabled) => {
                    setAuthEnabled(nextEnabled);
                    setAuthValidationVisible(false);
                  }}
                >
                  访问认证
                </Switch>
                <HttpRouteAuthChip enabled={authEnabled} />
            </div>
            <p className="mt-2 text-tiny text-default-500">
              {authEnabled
                ? "浏览器访问该路由时需要输入 HTTP Basic 用户名和密码。"
                : authPasswordConfigured
                  ? "当前公开访问；已保存的凭据会保留，重新开启后可继续使用。"
                  : "当前公开访问，拥有链接的访问者可直接打开。"}
            </p>
            {authEnabled ? (
            <div className="mt-3 grid gap-3 border-t border-default-200 pt-3 sm:grid-cols-2">
              <TextField value={authUsername} onChange={setAuthUsername} isRequired isInvalid={Boolean(authError && authError.includes("用户名"))} autoComplete="off">
                <Label>访问用户名</Label>
                <Input maxLength={HTTP_ROUTE_AUTH_USERNAME_MAX_LENGTH}  />
                <FieldError>{authError.includes("用户名") ? authError : ""}</FieldError>
              </TextField>
            <TextField value={authPassword} onChange={setAuthPassword} isRequired={!authPasswordConfigured} isInvalid={Boolean(authError && authError.includes("密码"))} type="password" autoComplete="new-password">
              <Label>{authPasswordConfigured ? "更换访问密码" : "访问密码"}</Label>
              <Input
              maxLength={HTTP_ROUTE_AUTH_PASSWORD_MAX_LENGTH}   />
              <Description>{authPasswordConfigured ? "留空表示保留当前密码" : "首次开启时必须设置密码"}</Description>
              <FieldError>{authError.includes("密码") ? authError : ""}</FieldError>
            </TextField>
            </div>
            ) : null}
            </div>
            <Switch isSelected={enabled} onChange={setEnabled}>
              启用
            </Switch>
            <Switch isSelected={detailCaptureEnabled} onChange={setDetailCaptureEnabled}>
              明细采集
            </Switch>
            <Switch isSelected={mediaCaptureEnabled} onChange={setMediaCaptureEnabled}>
              媒体采集（RustFS）
            </Switch>
            <Switch isSelected={pathRewriteEnabled} onChange={setPathRewriteEnabled}>
              路径改写
            </Switch>
            </Modal.Body>
            <Modal.Footer>
              <Button variant="secondary" onPress={onClose}>
                取消
              </Button>
              <Button variant="primary" isDisabled={Boolean(authError) || saving} onPress={() => void save()}>{saving ? <Spinner size="sm" /> : null}
                保存
              </Button>
            </Modal.Footer>
            </>
            )}

          </Modal.Dialog>
        </Modal.Container>
      </Modal.Backdrop>
    </Modal.Root>
  );
}
