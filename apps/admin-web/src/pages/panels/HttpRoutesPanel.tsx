import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { PageHeader } from "../../components/PageHeader";
import {
  Button,
  Input,
  Modal,
  ModalBody,
  ModalContent,
  ModalFooter,
  ModalHeader,
  Pagination,
  Select,
  SelectItem,
  useDisclosure,
} from "@heroui/react";
import { adminApi, recordWorkbenchOpenAsCaller } from "../../api/client";
import type { Client, HttpRoute } from "../../api/types";
import { copyTextWithFeedback } from "../../lib/clipboard";
import { copyThenRecord, isLinkOpeningClick } from "../../lib/workbenchRecording";
import { notify, notifyError } from "../../components/toast";
import { useClients } from "../../hooks/useClients";
import { MobileListCard, MobileListCardList } from "../../components/MobileListCard";
import { ConfirmModal } from "../../components/ConfirmModal";
import { Alert, Empty, FilterBar, Icon, Section, TableWrap, Tag } from "../../components/ui";
import {
  buildHttpRouteAuthMutation,
  HTTP_ROUTE_AUTH_PASSWORD_MAX_LENGTH,
  HTTP_ROUTE_AUTH_USERNAME_MAX_LENGTH,
  validateHttpRouteAuth,
  requiresPublicAccessConfirmation,
  type HttpRouteAuthDraft,
} from "./httpRouteAuth";
import { findHttpRouteClient } from "./httpRouteClient";
import { HttpRouteSharesModal } from "./HttpRouteSharesModal";
import { ConnectivityCheckModal, RouteCheckButtons, useRouteConnectivityChecks } from "./HttpRouteConnectivityCheck";
import { NOT_A_CHECK_NOTE } from "../../lib/connectivityCheck";
import { DesignCheck, DesignSwitch, ListLoading, RadioCards, TimeText } from "./accessUi";

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
  const [sharing, setSharing] = useState<HttpRoute | null>(null);
  const pendingKeysRef = useRef<Set<string>>(new Set());
  const [pendingKeys, setPendingKeys] = useState<Set<string>>(new Set());
  const [confirm, setConfirm] = useState<{ title: string; description: string; confirmLabel?: string; action: () => Promise<void> } | null>(null);
  const [page, setPage] = useState(1);
  const editModal = useDisclosure();
  const connectivityChecks = useRouteConnectivityChecks();

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
  const routesEmpty = filterClientId ? (
    <Empty icon="filter" title="这台客户端还没有路由" description="换一台客户端，或在筛选里选“全部客户端”。" />
  ) : (
    <Empty icon="globe" title="还没有 HTTP 路由" description="在上面发布一个服务后，就能通过访问链接打开内网应用。" />
  );
  const createAuthDraft: HttpRouteAuthDraft = {
    enabled: authEnabled,
    username: authUsername,
    password: authPassword,
    passwordConfigured: false,
  };
  const createAuthError = authValidationVisible ? validateHttpRouteAuth(createAuthDraft) : "";
  const createClient = clients.find((client) => String(client.id) === createClientId);
  const enabledCount = routes.filter((item) => item.enabled).length;

  return (
    <div className="acc-page">
      <PageHeader
        title="HTTP 路由"
        description="通过服务端的 HTTP 入口发布客户端网络里的 Web 服务，可加访问认证与分享链接。"
        actions={<Button variant="flat" isLoading={loading} startContent={loading ? null : <Icon name="refresh" />} onPress={() => void refresh()}>刷新</Button>}
      />
      {!clientsLoading && clientsError ? (
        <Alert
          tone="danger"
          role="alert"
          title="客户端状态读取失败，暂时不能发布。"
          actions={<Button size="sm" variant="flat" onPress={() => void reloadClients()}>重新加载客户端</Button>}
        >
          已发布的路由仍可管理；重新加载客户端后再发布新服务。
        </Alert>
      ) : !clientsLoading && clients.length === 0 ? (
        <Alert
          tone="info"
          title="尚无客户端实例"
          actions={<Button as="a" href="#/clients" size="sm" color="primary" startContent={<Icon name="arrow-right" size={14} />}>去接入设备</Button>}
        >
          先创建接入凭证并启动客户端，首次登录后才能选择它。
        </Alert>
      ) : null}

      <Section title="发布服务" description="选择设备和它所在网络里的地址，确定谁能访问后发布；发布后打开访问链接验证。">
        <form className="bd-card acc-publish" onSubmit={onCreate} aria-label="发布 HTTP 服务">
          <div className="acc-publish-body">
            <div className="acc-publish-grid">
              <Select
                label="客户端"
                selectedKeys={createClientId ? [createClientId] : []}
                onChange={(event) => setCreateClientId(event.target.value)}
                description="已注册的客户端实例"
                isRequired
                isDisabled={clientsLoading || Boolean(clientsError) || clients.length === 0}
              >
                {clients.map((client) => (
                  <SelectItem key={String(client.id)}>{client.clientName}</SelectItem>
                ))}
              </Select>
              <Input label="路由名" placeholder="web" value={route} onValueChange={setRoute} maxLength={60} description="访问链接里的一段" isRequired />
              <Input label="目标地址" placeholder="http://127.0.0.1:8080" value={targetBaseUrl} onValueChange={setTargetBaseUrl} maxLength={512} description="从客户端能访问到的地址" isRequired />
            </div>
            <div className="acc-publish-tls">
              <DesignSwitch checked={verifyTlsCertificate} onChange={setVerifyTlsCertificate} label="验证 HTTPS 证书" />
              <span className="bd-help">目标是 HTTPS 时校验证书和主机名；只有可信内网里的自签名服务才关掉。</span>
            </div>
            <HttpRouteAccessChoice
              enabled={authEnabled}
              onChange={(enabled) => {
                setAuthEnabled(enabled);
                setAuthValidationVisible(false);
              }}
            />
            {authEnabled ? (
              <div className="acc-publish-auth">
                <Input
                  autoComplete="off"
                  label="访问用户名"
                  maxLength={HTTP_ROUTE_AUTH_USERNAME_MAX_LENGTH}
                  value={authUsername}
                  onValueChange={setAuthUsername}
                  isInvalid={Boolean(createAuthError && createAuthError.includes("用户名"))}
                  errorMessage={createAuthError.includes("用户名") ? createAuthError : ""}
                  description="访客打开链接时输入，和后台账号无关"
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
          <div className="acc-publish-foot">
            <div className="acc-publish-summary" role="status" aria-label="发布范围摘要">
              <div className="acc-publish-summary-line">
                <Tag tone={authEnabled ? "info" : "warning"}>{authEnabled ? "受保护访问" : "公开访问"}</Tag>
                <span className={createClient ? undefined : "jd-subtle"}>{createClient?.clientName || "尚未选择设备"}</span>
                <span className="jd-subtle" aria-hidden="true">·</span>
                <span className={route.trim() ? "font-mono" : "jd-subtle"}>{route.trim() || "尚未填写路由名"}</span>
              </div>
              <p className="acc-publish-target">目标：<span className={targetBaseUrl.trim() ? "font-mono" : undefined}>{targetBaseUrl.trim() || "尚未填写目标地址"}</span></p>
              {createClientId && !createClient?.online ? <p className="acc-publish-warn"><Icon name="alert" size={14} />所选设备当前离线；配置创建后需等待设备上线，再验证访问。</p> : null}
              {!verifyTlsCertificate ? <p className="acc-publish-warn"><Icon name="alert" size={14} />已关闭目标 HTTPS 证书校验，仅用于可信内网自签名服务。</p> : null}
            </div>
            <Button className="acc-publish-submit" type="submit" color="primary" isLoading={creating} isDisabled={clientsLoading || Boolean(clientsError) || !createClientId}
              startContent={creating ? null : <Icon name={authEnabled ? "lock" : "globe"} />}>
              {authEnabled ? "发布受保护的服务" : "检查并公开发布"}
            </Button>
          </div>
        </form>
      </Section>

      {lastCreatedAccessUrl && (
        <Alert
          tone="success"
          className="acc-created"
          title="已创建 · 待验证访问"
          actions={<>
            <Button size="sm" variant="flat" startContent={<Icon name="copy" size={14} />} onPress={() => void copyAccessUrl(lastCreatedAccessUrl)}>
              复制
            </Button>
            <button type="button" className="bd-icon-btn acc-icon-btn-sm" aria-label="关闭提示" onClick={() => setLastCreatedAccessUrl("")}>
              <Icon name="x" size={16} />
            </button>
          </>}
        >
          <a className="jd-link font-mono acc-break" href={lastCreatedAccessUrl} rel="noreferrer" target="_blank">
            {lastCreatedAccessUrl}
          </a>
          <span className="acc-created-hint">打开链接，亲自确认目标应用可用。</span>
        </Alert>
      )}

      <Section
        title="已发布的路由"
        description={NOT_A_CHECK_NOTE}
        actions={!loading ? (
          <>
            {enabledCount > 0 ? <Tag tone="success">{enabledCount} 条启用</Tag> : null}
            <span className="acc-head-count bd-num">共 {routes.length} 条</span>
          </>
        ) : null}
      >
        <FilterBar end={<span className="bd-num">{loading ? "正在读取…" : `${routes.length} 条路由`}</span>}>
          <Select
            className="acc-filter-select"
            classNames={{ trigger: "acc-filter-trigger" }}
            aria-label="筛选客户端"
            size="sm"
            items={[{ id: "", clientName: "全部客户端" }, ...clients.map((c) => ({ id: String(c.id), clientName: c.clientName }))]}
            selectedKeys={filterClientId ? [filterClientId] : [""]}
            onChange={(event) => setFilterClientId(event.target.value)}
          >
            {(item) => <SelectItem key={item.id}>{item.clientName}</SelectItem>}
          </Select>
        </FilterBar>

        {/* 窄屏：卡片堆叠 */}
        <div className="acc-routes-cards">
          <MobileListCardList
            items={displayedRoutes}
            isLoading={loading}
            emptyContent={routesEmpty}
            renderCard={(raw) => {
              const item = raw as HttpRoute;
              const accessUrl = httpRouteAccessUrl(item);
              return (
                <MobileListCard
                  key={item.id}
                  title={
                    <div className="acc-card-title-row">
                      <code className="font-mono acc-break">{item.route}</code>
                      <span className="jd-table-sub bd-num">#{item.id}</span>
                    </div>
                  }
                  subtitle={
                    <div className="acc-card-sub">
                      <div className="acc-client-cell">
                        <span>{item.clientName}</span>
                        <ClientOnlineStatus client={findHttpRouteClient(item, clients)} />
                      </div>
                      <code className="font-mono acc-break">{item.targetBaseUrl || "—"}</code>
                    </div>
                  }
                  badges={
                    <>
                      <HttpRouteAuthChip enabled={Boolean(item.authEnabled)} />
                      <TlsTag route={item} />
                    </>
                  }
                  fields={[
                    {
                      label: "访问链接",
                      value: (
                        <div className="acc-link-cell is-stacked">
                          <a className="jd-link font-mono acc-break" href={accessUrl} rel="noreferrer" target="_blank" {...routeLinkRecording(item)}>
                            {accessUrl}
                          </a>
                          <Button size="sm" variant="flat" startContent={<Icon name="copy" size={14} />} onPress={() => void copyRouteLink(item, accessUrl)}>
                            复制
                          </Button>
                        </div>
                      ),
                    },
                    { label: "更新时间", value: <TimeText value={item.updatedAt || item.createdAt} /> },
                  ]}
                  extra={
                    <div className="acc-card-switches">
                      <DesignSwitch label="启用" checked={item.enabled} disabled={pendingKeys.has(pendingKey(item.id, "enabled"))} onChange={() => void toggle(item)} />
                      <DesignSwitch label="明细采集" checked={Boolean(item.detailCaptureEnabled)} disabled={pendingKeys.has(pendingKey(item.id, "detailCaptureEnabled"))} onChange={() => void toggleDetailCapture(item)} />
                      <DesignSwitch label="路径改写" checked={Boolean(item.pathRewriteEnabled)} disabled={pendingKeys.has(pendingKey(item.id, "pathRewriteEnabled"))} onChange={() => void togglePathRewrite(item)} />
                      <DesignSwitch label="媒体采集" checked={Boolean(item.mediaCaptureEnabled)} disabled={pendingKeys.has(pendingKey(item.id, "mediaCaptureEnabled"))} onChange={() => void toggleMediaCapture(item)} />
                    </div>
                  }
                  actions={
                    <>
                      <RouteCheckButtons route={item} checks={connectivityChecks} />
                      <Button size="sm" variant="flat" onPress={() => { setEditing(item); editModal.onOpen(); }}>
                        编辑
                      </Button>
                      <Button size="sm" variant="flat" onPress={() => setSharing(item)}>
                        分享
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

        {/* 宽屏：表格，长文本单行省略 */}
        <div className="acc-routes-table">
          {loading && routes.length === 0 ? <ListLoading label="正在读取 HTTP 路由…" /> : displayedRoutes.length === 0 && !loading ? (
            <div className="bd-card">{routesEmpty}</div>
          ) : (
            <TableWrap className={loading ? "bd-refetching" : undefined}>
              <table className="bd-table acc-routes" aria-label="HTTP 路由列表">
                <colgroup>
                  <col />
                  <col className="acc-col-client" />
                  <col className="acc-col-auth" />
                  <col className="acc-col-switch" />
                  <col className="acc-col-switch" />
                  <col className="acc-col-switch" />
                  <col className="acc-col-switch" />
                  <col className="acc-col-time" />
                  <col className="acc-col-actions" />
                </colgroup>
                <thead>
                  <tr>
                    <th>路由 · 访问链接</th>
                    <th>客户端</th>
                    <th>认证</th>
                    <th className="acc-col-center">启用</th>
                    <th className="acc-col-center">明细</th>
                    <th className="acc-col-center">媒体</th>
                    <th className="acc-col-center">改写</th>
                    <th>更新时间</th>
                    <th><span className="jd-sr-only">操作</span></th>
                  </tr>
                </thead>
                <tbody>
                  {displayedRoutes.map((item) => (
                    <tr key={item.id}>
                      <td>
                        <div className="acc-route-cell">
                          <span className="acc-route-name">
                            <code className="font-mono" title={item.route}>{item.route}</code>
                            <span className="jd-table-sub bd-num">#{item.id}</span>
                          </span>
                          <HttpRouteAccessLink route={item} />
                          <span className="acc-route-target">
                            <Icon name="arrow-right" size={12} label="转发到" />
                            <code className="font-mono" title={item.targetBaseUrl || ""}>{item.targetBaseUrl || "—"}</code>
                            <TlsTag route={item} />
                          </span>
                        </div>
                      </td>
                      <td>
                        <div className="acc-client-cell is-column">
                          <span className="jd-ellipsis" title={item.clientName}>{item.clientName}</span>
                          <ClientOnlineStatus client={findHttpRouteClient(item, clients)} />
                        </div>
                      </td>
                      <td><HttpRouteAuthChip enabled={Boolean(item.authEnabled)} /></td>
                      <td className="acc-col-center">
                        <DesignSwitch ariaLabel="启用" checked={item.enabled} disabled={pendingKeys.has(pendingKey(item.id, "enabled"))} onChange={() => void toggle(item)} />
                      </td>
                      <td className="acc-col-center">
                        <DesignSwitch ariaLabel="明细采集" checked={Boolean(item.detailCaptureEnabled)} disabled={pendingKeys.has(pendingKey(item.id, "detailCaptureEnabled"))} onChange={() => void toggleDetailCapture(item)} />
                      </td>
                      <td className="acc-col-center">
                        <DesignSwitch ariaLabel="媒体采集" checked={Boolean(item.mediaCaptureEnabled)} disabled={pendingKeys.has(pendingKey(item.id, "mediaCaptureEnabled"))} onChange={() => void toggleMediaCapture(item)} />
                      </td>
                      <td className="acc-col-center">
                        <DesignSwitch ariaLabel="路径改写" checked={Boolean(item.pathRewriteEnabled)} disabled={pendingKeys.has(pendingKey(item.id, "pathRewriteEnabled"))} onChange={() => void togglePathRewrite(item)} />
                      </td>
                      <td><TimeText value={item.updatedAt || item.createdAt} /></td>
                      <td className="jd-cell-actions">
                        <div className="jd-row-actions acc-route-actions">
                          <RouteCheckButtons route={item} checks={connectivityChecks} compact />
                          <Button size="sm" variant="flat" onPress={() => { setEditing(item); editModal.onOpen(); }}>
                            编辑
                          </Button>
                          <Button size="sm" variant="flat" onPress={() => setSharing(item)}>
                            分享
                          </Button>
                          <Button size="sm" color="danger" variant="flat" onPress={() => remove(item)}>
                            删除
                          </Button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableWrap>
          )}
        </div>

        {totalPages > 1 ? (
          <div className="acc-pager">
            <span className="bd-num">共 {routes.length} 条</span>
            <Pagination showControls size="sm" page={safePage} total={totalPages} onChange={setPage} />
          </div>
        ) : null}
      </Section>

      <EditHttpRouteModal disclosure={editModal} route={editing} onSaved={() => void load()} />
      <HttpRouteSharesModal
        route={sharing}
        clientEnabled={sharing ? findHttpRouteClient(sharing, clients)?.enabled : undefined}
        isOpen={sharing != null}
        onClose={() => setSharing(null)}
      />
      <ConnectivityCheckModal checks={connectivityChecks} />
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
    return <Tag plain>状态未知</Tag>;
  }

  return (
    <Tag tone={client.enabled && client.online ? "success" : "neutral"}>
      {client.online ? "在线" : "离线"}
    </Tag>
  );
}

function TlsTag({ route }: { route: HttpRoute }) {
  if (!route.targetBaseUrl?.toLowerCase().startsWith("https://")) return null;
  return (
    <Tag tone={route.insecureSkipVerify ? "warning" : "success"} className="acc-tls-tag">
      {route.insecureSkipVerify ? "跳过证书校验" : "证书校验"}
    </Tag>
  );
}

function HttpRouteAccessLink({ route }: { route: HttpRoute }) {
  const accessUrl = httpRouteAccessUrl(route);

  return (
    <div className="acc-link-cell">
      <a
        className="jd-link font-mono jd-ellipsis"
        href={accessUrl}
        rel="noreferrer"
        target="_blank"
        title={accessUrl}
        {...routeLinkRecording(route)}
      >
        {accessUrl}
      </a>
      <button type="button" className="bd-icon-btn acc-icon-btn-sm" aria-label="复制" title="复制访问链接" onClick={() => void copyRouteLink(route, accessUrl)}>
        <Icon name="copy" size={14} />
      </button>
    </div>
  );
}

function HttpRouteAuthChip({ enabled }: { enabled: boolean }) {
  return (
    <span
      className={`bd-tag bd-tag--plain acc-auth-tag ${enabled ? "bd-tag--info" : "is-public"}`}
      title={enabled ? "访问者需要通过 HTTP Basic 认证" : "无需认证即可访问"}
    >
      <Icon name={enabled ? "lock" : "globe"} size={12} />
      {enabled ? "Basic" : "公开"}
    </span>
  );
}

function HttpRouteAccessChoice({ enabled, onChange }: { enabled: boolean; onChange: (enabled: boolean) => void }) {
  return (
    <RadioCards
      legend="访问范围"
      value={enabled ? "protected" : "public"}
      onChange={(value) => onChange(value === "protected")}
      options={[
        { key: "protected", title: "受保护访问（用户名与密码）", description: "访问链接时验证独立的用户名和密码，不用后台登录账号；分享时用 HTTPS 链接。" },
        { key: "public", title: "公开访问（无需认证）", description: "无需登录后台或输入访问密码，知道或猜到地址的人都可能访问。" },
      ]}
    />
  );
}

function httpRouteAccessUrl(route: Pick<HttpRoute, "clientName" | "route">): string {
  const origin = typeof window === "undefined" ? "" : window.location.origin;
  return `${origin}/http/${encodeRouteSegment(route.clientName)}/${encodeRouteSegment(route.route)}/`;
}

function encodeRouteSegment(value: string): string {
  return encodeURIComponent(value.trim());
}

async function copyAccessUrl(url: string): Promise<boolean> {
  return copyTextWithFeedback(url, "访问链接已复制");
}

// Opening a route's access link (left or middle click) and copying it are the explicit actions the
// service workbench lists under 「最近打开」; the link stays native and nothing waits for the record.
function routeLinkRecording(route: HttpRoute) {
  const record = () => void recordWorkbenchOpenAsCaller("http-route.open-link", { kind: "http-route", id: route.id });
  return {
    onClick: (event: React.MouseEvent<HTMLAnchorElement>) => { if (isLinkOpeningClick(event)) record(); },
    onAuxClick: (event: React.MouseEvent<HTMLAnchorElement>) => { if (event.button === 1) record(); },
  };
}

async function copyRouteLink(route: HttpRoute, url: string): Promise<void> {
  await copyThenRecord(() => copyAccessUrl(url),
    () => recordWorkbenchOpenAsCaller("http-route.copy-link", { kind: "http-route", id: route.id }));
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
    <Modal isOpen={disclosure.isOpen} onOpenChange={disclosure.onOpenChange} size="lg" scrollBehavior="inside">
      <ModalContent>
        {(onClose) => (
          <>
            <ModalHeader>编辑 HTTP 路由 #{route?.id}</ModalHeader>
            <ModalBody className="acc-dialog-body">
              <div className="acc-field-pair">
                <Input label="路由名" value={name} onValueChange={setName} maxLength={60} isRequired />
                <Input label="目标地址" value={targetBaseUrl} onValueChange={setTargetBaseUrl} maxLength={512} isRequired />
              </div>
              <HttpRouteAccessChoice
                enabled={authEnabled}
                onChange={(nextEnabled) => {
                  setAuthEnabled(nextEnabled);
                  setAuthValidationVisible(false);
                  setPublicAccessConfirmed(false);
                }}
              />
              <p className="bd-help acc-tight">
                {authEnabled
                  ? "浏览器访问该路由时需要输入 HTTP Basic 用户名和密码。"
                  : authPasswordConfigured
                    ? "当前公开访问；已保存的凭据会保留，重新开启后可继续使用。"
                    : "当前公开访问，无需登录后台或输入访问密码；链接不是访问口令。"}
              </p>
              {publicConfirmationRequired ? (
                <div className="bd-alert bd-alert--warning acc-confirm-box">
                  <Icon name="alert" />
                  <DesignCheck checked={publicAccessConfirmed} onChange={setPublicAccessConfirmed}>
                    我确认关闭访问认证，允许公开访问此内网应用
                  </DesignCheck>
                </div>
              ) : null}
              {authEnabled ? (
                <div className="acc-field-pair">
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
              <fieldset className="jd-fieldset acc-switch-list">
                <legend className="bd-label">转发设置</legend>
                <DesignSwitch checked={enabled} onChange={setEnabled} label="启用" />
                <DesignSwitch checked={detailCaptureEnabled} onChange={setDetailCaptureEnabled} label="明细采集" />
                <DesignSwitch checked={mediaCaptureEnabled} onChange={setMediaCaptureEnabled} label="媒体采集（RustFS）" />
                <DesignSwitch checked={pathRewriteEnabled} onChange={setPathRewriteEnabled} label="路径改写" />
                <DesignSwitch checked={verifyTlsCertificate} onChange={setVerifyTlsCertificate} label="验证 HTTPS/WSS 证书" />
              </fieldset>
              {!verifyTlsCertificate ? (
                <Alert tone="warning">已关闭证书和主机名校验，仅应对可信内网中的自签名服务使用。</Alert>
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
