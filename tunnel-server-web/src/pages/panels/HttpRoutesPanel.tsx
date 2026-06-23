import { useCallback, useEffect, useState, type FormEvent } from "react";
import {
  Button,
  Chip,
  Input,
  Modal,
  ModalBody,
  ModalContent,
  ModalFooter,
  ModalHeader,
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
import { notify, notifyError } from "../../components/toast";
import { useClients } from "../../hooks/useClients";

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

  const toggle = async (item: HttpRoute) => {
    try {
      await adminApi.updateHttpRoute(item.id, {
        route: item.route,
        targetBaseUrl: item.targetBaseUrl,
        enabled: !item.enabled,
        detailCaptureEnabled: Boolean(item.detailCaptureEnabled),
        pathRewriteEnabled: Boolean(item.pathRewriteEnabled),
      });
      await load();
    } catch (error) {
      notifyError(error, "切换状态失败");
    }
  };

  const toggleDetailCapture = async (item: HttpRoute) => {
    try {
      await adminApi.updateHttpRoute(item.id, {
        route: item.route,
        targetBaseUrl: item.targetBaseUrl,
        enabled: item.enabled,
        detailCaptureEnabled: !Boolean(item.detailCaptureEnabled),
        pathRewriteEnabled: Boolean(item.pathRewriteEnabled),
      });
      await load();
    } catch (error) {
      notifyError(error, "切换明细采集失败");
    }
  };

  const togglePathRewrite = async (item: HttpRoute) => {
    try {
      await adminApi.updateHttpRoute(item.id, {
        route: item.route,
        targetBaseUrl: item.targetBaseUrl,
        enabled: item.enabled,
        detailCaptureEnabled: Boolean(item.detailCaptureEnabled),
        pathRewriteEnabled: !Boolean(item.pathRewriteEnabled),
      });
      await load();
    } catch (error) {
      notifyError(error, "切换路径改写失败");
    }
  };

  const remove = async (item: HttpRoute) => {
    if (!window.confirm("确定删除该 HTTP 路由？")) {
      return;
    }
    try {
      await adminApi.deleteHttpRoute(item.id);
      notify("HTTP 路由已删除");
      await load();
    } catch (error) {
      notifyError(error, "删除失败");
    }
  };

  return (
    <div className="mt-4 flex flex-col gap-4">
      <form className="flex flex-wrap items-end gap-3" onSubmit={onCreate}>
        <Select
          className="w-48"
          label="客户端"
          selectedKeys={createClientId ? [createClientId] : []}
          onChange={(event) => setCreateClientId(event.target.value)}
          isRequired
        >
          {clients.map((client) => (
            <SelectItem key={String(client.id)}>{client.clientName}</SelectItem>
          ))}
        </Select>
        <Input className="w-40" label="路由名" placeholder="web" value={route} onValueChange={setRoute} maxLength={60} isRequired />
        <Input className="w-64" label="目标地址" placeholder="http://127.0.0.1:8080" value={targetBaseUrl} onValueChange={setTargetBaseUrl} maxLength={512} isRequired />
        <Button type="submit" color="primary" isLoading={creating}>
          新建路由
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
        </div>
      )}

      <div className="flex flex-wrap items-end gap-3">
        <Select
          className="w-48"
          label="筛选客户端"
          items={[{ id: "", clientName: "全部" }, ...clients.map((c) => ({ id: String(c.id), clientName: c.clientName }))]}
          selectedKeys={filterClientId ? [filterClientId] : [""]}
          onChange={(event) => setFilterClientId(event.target.value)}
        >
          {(item) => <SelectItem key={item.id}>{item.clientName}</SelectItem>}
        </Select>
        <Button variant="flat" onPress={() => void load()}>
          刷新
        </Button>
      </div>

      <Table aria-label="HTTP 路由列表" isHeaderSticky removeWrapper>
        <TableHeader>
          <TableColumn>ID</TableColumn>
          <TableColumn>客户端</TableColumn>
          <TableColumn>路由名</TableColumn>
          <TableColumn>目标地址</TableColumn>
          <TableColumn>访问链接</TableColumn>
          <TableColumn>状态</TableColumn>
          <TableColumn>明细采集</TableColumn>
          <TableColumn>路径改写</TableColumn>
          <TableColumn>更新时间</TableColumn>
          <TableColumn>操作</TableColumn>
        </TableHeader>
        <TableBody items={routes} isLoading={loading} emptyContent="后台尚未维护 HTTP 路由">
          {(item) => (
            <TableRow key={item.id}>
              <TableCell>{item.id}</TableCell>
              <TableCell>{item.clientName}</TableCell>
              <TableCell>
                <code>{item.route}</code>
              </TableCell>
              <TableCell>
                <code>{item.targetBaseUrl || "-"}</code>
              </TableCell>
              <TableCell>
                <HttpRouteAccessLink route={item} />
              </TableCell>
              <TableCell>
                <Chip
                  size="sm"
                  variant="flat"
                  color={item.enabled ? "success" : "warning"}
                  className="cursor-pointer"
                  onClick={() => void toggle(item)}
                >
                  {item.enabled ? "启用" : "停用"}
                </Chip>
              </TableCell>
              <TableCell>
                <Chip
                  size="sm"
                  variant="flat"
                  color={item.detailCaptureEnabled ? "primary" : "default"}
                  className="cursor-pointer"
                  onClick={() => void toggleDetailCapture(item)}
                >
                  {item.detailCaptureEnabled ? "采集" : "关闭"}
                </Chip>
              </TableCell>
              <TableCell>
                <Chip
                  size="sm"
                  variant="flat"
                  color={item.pathRewriteEnabled ? "secondary" : "default"}
                  className="cursor-pointer"
                  onClick={() => void togglePathRewrite(item)}
                  title="开启后改写 HTML/CSS/JS 中的绝对路径，使内网应用的资源也能经过隧道"
                >
                  {item.pathRewriteEnabled ? "开启" : "关闭"}
                </Chip>
              </TableCell>
              <TableCell>{formatDateTime(item.updatedAt || item.createdAt)}</TableCell>
              <TableCell>
                <div className="flex gap-2">
                  <Button size="sm" variant="flat" onPress={() => { setEditing(item); editModal.onOpen(); }}>
                    编辑
                  </Button>
                  <Button size="sm" color="danger" variant="flat" onPress={() => void remove(item)}>
                    删除
                  </Button>
                </div>
              </TableCell>
            </TableRow>
          )}
        </TableBody>
      </Table>

      <EditHttpRouteModal disclosure={editModal} route={editing} onSaved={() => void load()} />
    </div>
  );
}

function HttpRouteAccessLink({ route }: { route: HttpRoute }) {
  const accessUrl = httpRouteAccessUrl(route);

  return (
    <div className="flex min-w-0 flex-col gap-1">
      <a
        className="max-w-80 truncate font-mono text-tiny text-primary underline-offset-2 hover:underline"
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

function httpRouteAccessUrl(route: Pick<HttpRoute, "clientName" | "route">): string {
  const origin = typeof window === "undefined" ? "" : window.location.origin;
  return `${origin}/http/${encodeRouteSegment(route.clientName)}/${encodeRouteSegment(route.route)}/`;
}

function encodeRouteSegment(value: string): string {
  return encodeURIComponent(value.trim());
}

async function copyAccessUrl(url: string): Promise<void> {
  try {
    await navigator.clipboard?.writeText(url);
    notify("访问链接已复制");
  } catch {
    notify("复制失败", "error");
  }
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
