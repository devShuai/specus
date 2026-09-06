import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import {
  Button,
  Checkbox,
  Chip,
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
  Radio,
  RadioGroup,
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
import type { Client, HttpRoute } from "../../api/types";
import { formatDateTime } from "../../lib/format";
import { copyTextWithFeedback } from "../../lib/clipboard";
import { notify, notifyError } from "../../components/toast";
import { useClients } from "../../hooks/useClients";
import { MobileListCard, MobileListCardList } from "../../components/MobileListCard";
import { ConfirmModal } from "../../components/ConfirmModal";
import { EmptyState } from "../../components/EmptyState";
import { StatusChip, onlineTone } from "../../components/StatusChip";
import {
  buildHttpRouteAuthMutation,
  HTTP_ROUTE_AUTH_PASSWORD_MAX_LENGTH,
  HTTP_ROUTE_AUTH_USERNAME_MAX_LENGTH,
  validateHttpRouteAuth,
  requiresPublicAccessConfirmation,
  type HttpRouteAuthDraft,
} from "./httpRouteAuth";
import { findHttpRouteClient } from "./httpRouteClient";

const PAGE_SIZE = 10;
type RouteToggleField = "enabled" | "detailCaptureEnabled" | "mediaCaptureEnabled" | "pathRewriteEnabled";

function pendingKey(id: number, field: RouteToggleField): string {
  return `${id}:${field}`;
}

export function HttpRoutesPanel() {
  const { clients, loading: clientsLoading, error: clientsError, reload: reloadClients } = useClients();
  const [routes, setRoutes] = useState<HttpRoute[]>([]);
  const [routesLoading, setRoutesLoading] = useState(true);
  const [filterClientId, setFilterClientId] = useState("");
  const [createClientId, setCreateClientId] = useState("");
  const [route, setRoute] = useState("");
  const [targetBaseUrl, setTargetBaseUrl] = useState("");
  const [verifyTlsCertificate, setVerifyTlsCertificate] = useState(true);
  const [authEnabled, setAuthEnabled] = useState(true);
  const [authUsername, setAuthUsername] = useState("");
  const [authPassword, setAuthPassword] = useState("");
  const [authValidationVisible, setAuthValidationVisible] = useState(false);
  const [lastCreatedAccessUrl, setLastCreatedAccessUrl] = useState("");
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<HttpRoute | null>(null);
  const pendingKeysRef = useRef<Set<string>>(new Set());
  const [pendingKeys, setPendingKeys] = useState<Set<string>>(new Set());
  const [confirm, setConfirm] = useState<{ title: string; description: string; confirmLabel?: string; action: () => Promise<void> } | null>(null);
  const [page, setPage] = useState(1);
  const editModal = useDisclosure();

  const load = useCallback(async () => {
    setRoutesLoading(true);
    try {
      setRoutes(await adminApi.listHttpRoutes(filterClientId ? Number(filterClientId) : undefined));
    } catch (error) {
      notifyError(error, "加载 HTTP 路由失败");
    } finally {
      setRoutesLoading(false);
    }
  }, [filterClientId]);

  useEffect(() => {
    void load();
  }, [load]);

  const refresh = useCallback(async () => {
    await Promise.all([load(), reloadClients()]);
  }, [load, reloadClients]);

  const onCreate = async (event: FormEvent) => {
    event.preventDefault();
    if (creating || clientsLoading) return;
    if (clientsError || !clients.some((client) => String(client.id) === createClientId)) {
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
    const publish = async () => {
      setCreating(true);
      try {
        const created = await adminApi.createHttpRoute(Number(createClientId), {
          route: route.trim(),
          targetBaseUrl: targetBaseUrl.trim(),
          enabled: true,
          detailCaptureEnabled: false,
          mediaCaptureEnabled: false,
          pathRewriteEnabled: false,
          insecureSkipVerify: !verifyTlsCertificate,
          ...buildHttpRouteAuthMutation(authDraft),
        });
        setRoute("");
        setTargetBaseUrl("");
        setVerifyTlsCertificate(true);
        setAuthEnabled(true);
        setAuthUsername("");
        setAuthPassword("");
        setAuthValidationVisible(false);
        setLastCreatedAccessUrl(httpRouteAccessUrl(created));
        notify("HTTP 路由已创建，请打开访问链接验证目标应用");
        await load();
      } catch (error) {
        notifyError(error, "创建失败");
      } finally {
        setCreating(false);
      }
    };
    if (requiresPublicAccessConfirmation(null, authEnabled)) {
      setConfirm({
        title: "确认公开发布 HTTP 服务？",
        description: `将 ${clients.find((client) => String(client.id) === createClientId)?.clientName} 的 ${targetBaseUrl.trim()} 发布为路由“${route.trim()}”。任何可访问此服务器的人都可能访问该应用，无需登录管理后台；链接不是访问口令。可在路由中开启认证或停用以撤销访问。`,
        confirmLabel: "确认公开发布",
        action: publish,
      });
    } else {
      await publish();
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
  const loading = routesLoading || clientsLoading;
  // Both list renderers keep rendering non-empty items while isLoading=true.
  // Hide route rows until the client lookup is ready so a fast route response
  // cannot briefly turn every association into "状态未知".
  const displayedRoutes = loading ? [] : pagedRoutes;
  const createAuthDraft: HttpRouteAuthDraft = {
    enabled: authEnabled,
    username: authUsername,
    password: authPassword,
    passwordConfigured: false,
  };
  const createAuthError = authValidationVisible ? validateHttpRouteAuth(createAuthDraft) : "";

  return (
    <div className="mt-4 flex min-w-0 flex-col gap-4">
      {!clientsLoading && clientsError ? <div role="alert" className="rounded-md border border-danger-200 p-3 text-small text-danger">客户端状态读取失败，暂时不能发布。<Button className="ml-2" size="sm" variant="flat" onPress={() => void reloadClients()}>重新加载客户端</Button></div>
        : !clientsLoading && clients.length === 0 ? <div className="rounded-md border border-primary-200 bg-primary-50/40 p-3 text-small">尚无客户端实例。请先创建接入凭证并启动客户端，首次登录后才能选择它。<Button as="a" href="#/clients" className="ml-2" size="sm" variant="flat">去接入设备</Button></div> : null}
      <form className="flex flex-wrap items-end gap-3" onSubmit={onCreate}>
        <Select
          className="w-full sm:w-48"
          label="客户端"
          selectedKeys={createClientId ? [createClientId] : []}
          onChange={(event) => setCreateClientId(event.target.value)}
          isRequired
          isDisabled={clientsLoading || Boolean(clientsError) || clients.length === 0}
        >
          {clients.map((client) => (
            <SelectItem key={String(client.id)}>{client.clientName}</SelectItem>
          ))}
        </Select>
        <Input className="w-full sm:w-40" label="路由名" placeholder="web" value={route} onValueChange={setRoute} maxLength={60} isRequired />
        <Input className="w-full sm:w-64" label="目标地址" placeholder="http://127.0.0.1:8080" value={targetBaseUrl} onValueChange={setTargetBaseUrl} maxLength={512} isRequired />
        <Switch
          className="h-14"
          isSelected={verifyTlsCertificate}
          onValueChange={setVerifyTlsCertificate}
        >
          验证 HTTPS 证书
        </Switch>
        <Button className="h-14 w-full sm:w-auto" variant="flat" isLoading={loading} onPress={() => void refresh()}>
          刷新
        </Button>
        <div className="w-full rounded-medium border border-default-200 bg-default-50/70 p-3">
          <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
            <HttpRouteAccessChoice
              enabled={authEnabled}
              onChange={(enabled) => {
                setAuthEnabled(enabled);
                setAuthValidationVisible(false);
              }}
            />
            <span className="text-tiny text-default-500">
              {authEnabled ? "访问链接时验证独立的用户名和密码，不使用后台登录账号。请通过 HTTPS 分享。" : "无需登录后台或输入访问密码，知道或猜到地址的人都可能访问。"}
            </span>
          </div>
          {authEnabled ? (
            <div className="mt-3 grid gap-3 border-t border-default-200 pt-3 sm:grid-cols-2">
              <Input
                autoComplete="off"
                label="访问用户名"
                maxLength={HTTP_ROUTE_AUTH_USERNAME_MAX_LENGTH}
                value={authUsername}
                onValueChange={setAuthUsername}
                isInvalid={Boolean(createAuthError && createAuthError.includes("用户名"))}
                errorMessage={createAuthError.includes("用户名") ? createAuthError : ""}
                isRequired
              />
              <Input
                autoComplete="new-password"
                label="访问密码"
                maxLength={HTTP_ROUTE_AUTH_PASSWORD_MAX_LENGTH}
                type="password"
                value={authPassword}
                onValueChange={setAuthPassword}
                isInvalid={Boolean(createAuthError && createAuthError.includes("密码"))}
                errorMessage={createAuthError.includes("密码") ? createAuthError : ""}
                isRequired
              />
            </div>
          ) : null}
        </div>
        <div className="w-full rounded-md border border-default-200 p-3 text-small [overflow-wrap:anywhere]" role="status" aria-label="发布范围摘要">
          <strong>{authEnabled ? "受保护访问" : "公开访问"}</strong> · {clients.find((client) => String(client.id) === createClientId)?.clientName || "尚未选择设备"} · {route.trim() || "尚未填写路由名"}
          <p className="mt-1 break-all text-default-500">目标：{targetBaseUrl.trim() || "尚未填写目标地址"}</p>
          {createClientId && !clients.find((client) => String(client.id) === createClientId)?.online ? <p className="mt-1 text-warning">所选设备当前离线；配置创建后需等待设备上线，再验证访问。</p> : null}
          {!verifyTlsCertificate ? <p className="mt-1 text-warning">已关闭目标 HTTPS 证书校验，仅用于可信内网自签名服务。</p> : null}
        </div>
        <Button className="min-h-11 w-full sm:w-auto" type="submit" color="primary" isLoading={creating} isDisabled={clientsLoading || Boolean(clientsError) || !createClientId}>
          {authEnabled ? "发布受保护的服务" : "检查并公开发布"}
        </Button>
      </form>

      {lastCreatedAccessUrl && (
        <div className="flex min-w-0 flex-wrap items-center gap-2 rounded-small border border-success-200 bg-success-50 p-3 text-small">
          <span className="w-full shrink-0 font-semibold text-success sm:w-auto">已创建 · 待验证访问</span>
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
        <Button className="h-14 w-full sm:w-auto" variant="flat" isLoading={loading} onPress={() => void refresh()}>
          刷新
        </Button>
      </div>

      {/* mobile: 卡片堆叠 */}
      <div className="xl:hidden">
        <MobileListCardList
          items={displayedRoutes}
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
                    <div className="flex flex-wrap items-center gap-2">
                      <span>{item.clientName}</span>
                      <ClientOnlineStatus client={findHttpRouteClient(item, clients)} />
                    </div>
                    <code className="break-all">{item.targetBaseUrl || "-"}</code>
                  </div>
                }
                badges={
                  <>
                    <Switch
                      size="sm"
                      isSelected={item.enabled}
                      isDisabled={pendingKeys.has(pendingKey(item.id, "enabled"))}
                      onValueChange={() => void toggle(item)}
                    >
                      启用
                    </Switch>
                    <Switch
                      size="sm"
                      isSelected={Boolean(item.detailCaptureEnabled)}
                      isDisabled={pendingKeys.has(pendingKey(item.id, "detailCaptureEnabled"))}
                      onValueChange={() => void toggleDetailCapture(item)}
                    >
                      明细采集
                    </Switch>
                    <Switch
                      size="sm"
                      isSelected={Boolean(item.pathRewriteEnabled)}
                      isDisabled={pendingKeys.has(pendingKey(item.id, "pathRewriteEnabled"))}
                      onValueChange={() => void togglePathRewrite(item)}
                    >
                      路径改写
                    </Switch>
                    <Switch
                      size="sm"
                      isSelected={Boolean(item.mediaCaptureEnabled)}
                      isDisabled={pendingKeys.has(pendingKey(item.id, "mediaCaptureEnabled"))}
                      onValueChange={() => void toggleMediaCapture(item)}
                    >
                      媒体采集
                    </Switch>
                    <HttpRouteAuthChip enabled={Boolean(item.authEnabled)} />
                    {item.targetBaseUrl?.toLowerCase().startsWith("https://") ? (
                      <Chip color={item.insecureSkipVerify ? "warning" : "success"} size="sm" variant="flat">
                        {item.insecureSkipVerify ? "跳过证书校验" : "证书校验"}
                      </Chip>
                    ) : null}
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
          <TableColumn className="w-[5%]">ID</TableColumn>
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
        <TableBody items={displayedRoutes} isLoading={loading} emptyContent={<EmptyState icon="generic" title="后台尚未维护 HTTP 路由" description="创建路由后即可通过访问链接打开内网应用" />}>
          {(item) => {
            return (
            <TableRow key={item.id}>
              <TableCell>
                <span className="block truncate font-mono text-tiny" title={String(item.id)}>
                  {item.id}
                </span>
              </TableCell>
              <TableCell>
                <div className="flex min-w-0 flex-col items-start gap-1">
                  <span className="block max-w-full truncate" title={item.clientName}>
                    {item.clientName}
                  </span>
                  <ClientOnlineStatus client={findHttpRouteClient(item, clients)} />
                </div>
              </TableCell>
              <TableCell>
                <code className="block truncate" title={item.route}>
                  {item.route}
                </code>
              </TableCell>
              <TableCell>
                <div className="flex min-w-0 flex-col gap-1">
                  <code className="block truncate" title={item.targetBaseUrl || "-"}>
                    {item.targetBaseUrl || "-"}
                  </code>
                  {item.targetBaseUrl?.toLowerCase().startsWith("https://") ? (
                    <Chip
                      className="w-fit"
                      color={item.insecureSkipVerify ? "warning" : "success"}
                      size="sm"
                      variant="flat"
                    >
                      {item.insecureSkipVerify ? "跳过证书校验" : "证书校验"}
                    </Chip>
                  ) : null}
                </div>
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
                  size="sm"
                  isSelected={item.enabled}
                  isDisabled={pendingKeys.has(pendingKey(item.id, "enabled"))}
                  onValueChange={() => void toggle(item)}
                />
              </TableCell>
              <TableCell>
                <Switch
                  aria-label="明细采集"
                  size="sm"
                  isSelected={Boolean(item.detailCaptureEnabled)}
                  isDisabled={pendingKeys.has(pendingKey(item.id, "detailCaptureEnabled"))}
                  onValueChange={() => void toggleDetailCapture(item)}
                />
              </TableCell>
              <TableCell>
                <Switch
                  aria-label="媒体采集"
                  size="sm"
                  isSelected={Boolean(item.mediaCaptureEnabled)}
                  isDisabled={pendingKeys.has(pendingKey(item.id, "mediaCaptureEnabled"))}
                  onValueChange={() => void toggleMediaCapture(item)}
                />
              </TableCell>
              <TableCell>
                <Switch
                  aria-label="路径改写"
                  size="sm"
                  isSelected={Boolean(item.pathRewriteEnabled)}
                  isDisabled={pendingKeys.has(pendingKey(item.id, "pathRewriteEnabled"))}
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
        description={<span className="[overflow-wrap:anywhere]">{confirm?.description}</span>}
        confirmLabel={confirm?.confirmLabel ?? "删除"}
        danger
      />
    </div>
  );
}

function ClientOnlineStatus({ client }: { client?: Client }) {
  if (!client) {
    return <StatusChip>状态未知</StatusChip>;
  }

  return (
    <StatusChip tone={onlineTone(client.online, !client.enabled)}>
      {client.online ? "在线" : "离线"}
    </StatusChip>
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

function HttpRouteAuthChip({ enabled }: { enabled: boolean }) {
  return (
    <Chip
      color={enabled ? "primary" : "default"}
      size="sm"
      startContent={<RouteAuthIcon locked={enabled} />}
      title={enabled ? "访问者需要通过 HTTP Basic 认证" : "无需认证即可访问"}
      variant="flat"
    >
      {enabled ? "Basic" : "公开"}
    </Chip>
  );
}

function HttpRouteAccessChoice({ enabled, onChange }: { enabled: boolean; onChange: (enabled: boolean) => void }) {
  return <RadioGroup label="访问范围" orientation="horizontal" value={enabled ? "protected" : "public"} onValueChange={(value) => onChange(value === "protected")}>
    <Radio value="protected">受保护访问（用户名与密码）</Radio>
    <Radio value="public">公开访问（无需认证）</Radio>
  </RadioGroup>;
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
  const [authEnabled, setAuthEnabled] = useState(false);
  const [authUsername, setAuthUsername] = useState("");
  const [authPassword, setAuthPassword] = useState("");
  const [authPasswordConfigured, setAuthPasswordConfigured] = useState(false);
  const [authValidationVisible, setAuthValidationVisible] = useState(false);
  const [enabled, setEnabled] = useState(true);
  const [detailCaptureEnabled, setDetailCaptureEnabled] = useState(false);
  const [mediaCaptureEnabled, setMediaCaptureEnabled] = useState(false);
  const [pathRewriteEnabled, setPathRewriteEnabled] = useState(false);
  const [verifyTlsCertificate, setVerifyTlsCertificate] = useState(true);
  const [saving, setSaving] = useState(false);
  const [publicAccessConfirmed, setPublicAccessConfirmed] = useState(false);

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
      setVerifyTlsCertificate(!Boolean(route.insecureSkipVerify));
      setPublicAccessConfirmed(false);
    }
  }, [route, disclosure.isOpen]);

  const authDraft: HttpRouteAuthDraft = {
    enabled: authEnabled,
    username: authUsername,
    password: authPassword,
    passwordConfigured: authPasswordConfigured,
  };
  const authError = authValidationVisible ? validateHttpRouteAuth(authDraft) : "";
  const publicConfirmationRequired = requiresPublicAccessConfirmation(Boolean(route?.authEnabled), authEnabled);

  const save = async () => {
    if (!route) {
      return;
    }
    if (publicConfirmationRequired && !publicAccessConfirmed) {
      notify("请先确认公开访问范围，或保持受保护访问", "error");
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
        insecureSkipVerify: !verifyTlsCertificate,
        ...buildHttpRouteAuthMutation(authDraft),
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
              <div className="rounded-medium border border-default-200 bg-default-50/70 p-3">
                <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
                  <HttpRouteAccessChoice
                    enabled={authEnabled}
                    onChange={(nextEnabled) => {
                      setAuthEnabled(nextEnabled);
                      setAuthValidationVisible(false);
                      setPublicAccessConfirmed(false);
                    }}
                  />
                  <HttpRouteAuthChip enabled={authEnabled} />
                </div>
                <p className="mt-2 text-tiny text-default-500">
                  {authEnabled
                    ? "浏览器访问该路由时需要输入 HTTP Basic 用户名和密码。"
                    : authPasswordConfigured
                      ? "当前公开访问；已保存的凭据会保留，重新开启后可继续使用。"
                      : "当前公开访问，无需登录后台或输入访问密码；链接不是访问口令。"}
                </p>
                {publicConfirmationRequired ? <Checkbox className="mt-3" isSelected={publicAccessConfirmed} onValueChange={setPublicAccessConfirmed}>我确认关闭访问认证，允许公开访问此内网应用</Checkbox> : null}
                {authEnabled ? (
                  <div className="mt-3 grid gap-3 border-t border-default-200 pt-3 sm:grid-cols-2">
                    <Input
                      autoComplete="off"
                      label="访问用户名"
                      maxLength={HTTP_ROUTE_AUTH_USERNAME_MAX_LENGTH}
                      value={authUsername}
                      onValueChange={setAuthUsername}
                      isInvalid={Boolean(authError && authError.includes("用户名"))}
                      errorMessage={authError.includes("用户名") ? authError : ""}
                      isRequired
                    />
                    <Input
                      autoComplete="new-password"
                      description={authPasswordConfigured ? "留空表示保留当前密码" : "首次开启时必须设置密码"}
                      label={authPasswordConfigured ? "更换访问密码" : "访问密码"}
                      maxLength={HTTP_ROUTE_AUTH_PASSWORD_MAX_LENGTH}
                      type="password"
                      value={authPassword}
                      onValueChange={setAuthPassword}
                      isInvalid={Boolean(authError && authError.includes("密码"))}
                      errorMessage={authError.includes("密码") ? authError : ""}
                      isRequired={!authPasswordConfigured}
                    />
                  </div>
                ) : null}
              </div>
              <Switch isSelected={enabled} onValueChange={setEnabled}>
                启用
              </Switch>
              <Switch isSelected={detailCaptureEnabled} onValueChange={setDetailCaptureEnabled}>
                明细采集
              </Switch>
              <Switch isSelected={mediaCaptureEnabled} onValueChange={setMediaCaptureEnabled}>
                媒体采集（RustFS）
              </Switch>
              <Switch isSelected={pathRewriteEnabled} onValueChange={setPathRewriteEnabled}>
                路径改写
              </Switch>
              <Switch isSelected={verifyTlsCertificate} onValueChange={setVerifyTlsCertificate}>
                验证 HTTPS/WSS 证书
              </Switch>
              {!verifyTlsCertificate ? (
                <p className="text-tiny text-warning">
                  已关闭证书和主机名校验，仅应对可信内网中的自签名服务使用。
                </p>
              ) : null}
            </ModalBody>
            <ModalFooter>
              <Button variant="flat" onPress={onClose}>
                取消
              </Button>
              <Button color="primary" isDisabled={Boolean(authError) || (publicConfirmationRequired && !publicAccessConfirmed)} isLoading={saving} onPress={() => void save()}>
                保存
              </Button>
            </ModalFooter>
          </>
        )}
      </ModalContent>
    </Modal>
  );
}
