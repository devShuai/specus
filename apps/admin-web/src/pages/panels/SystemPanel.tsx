import { useEffect, useState, type DragEvent } from "react";
import { Button, Card, Chip, FieldError, Input, Label, ListBox, ListBoxItem, Modal, Select, SelectIndicator, SelectPopover, SelectTrigger, SelectValue, Spinner, Switch, Table, TableBody, TableCell, TableColumn, TableContent, TableHeader, TableRow, TextArea, TextField, useOverlayState } from "@heroui/react";
import { adminApi } from "../../api/client";
import type {
  ClientArch,
  ClientDownloadLink,
  ClientDownloadLinkMutation,
  ClientPackageUpload,
  ClientImplementation,
  ClientPlatform,
  ManagementRole,
  ManagementUser,
  ManagementUserMutation,
} from "../../api/types";
import { formatBytes, formatDateTime } from "../../lib/format";
import { notify, notifyError } from "../../components/toast";
import { MobileListCard, MobileListCardList } from "../../components/MobileListCard";
import { ConfirmModal } from "../../components/ConfirmModal";
import { EmptyState } from "../../components/EmptyState";
import { StatusChip, enabledTone } from "../../components/StatusChip";
import { archLabel, platformLabel } from "./ClientDownloadsPanel";

interface ConfirmState {
  title: string;
  description: string;
  confirmLabel?: string;
  danger?: boolean;
  action: () => Promise<void>;
}

type SystemPanelProps = {
  initializing: boolean;
  onInitializeDatabase: () => Promise<void>;
};

export function SystemPanel({ initializing, onInitializeDatabase }: SystemPanelProps) {
  const [users, setUsers] = useState<ManagementUser[]>([]);
  const [loadingUsers, setLoadingUsers] = useState(false);
  const [savingUser, setSavingUser] = useState(false);
  const [userForm, setUserForm] = useState<ManagementUserMutation>({
    username: "",
    password: "",
    role: "USER",
    enabled: true,
  });

  const loadUsers = async () => {
    setLoadingUsers(true);
    try {
      setUsers(await adminApi.listUsers());
    } catch (error) {
      notifyError(error, "用户列表加载失败");
    } finally {
      setLoadingUsers(false);
    }
  };

  useEffect(() => {
    void loadUsers();
  }, []);

  const createUser = async () => {
    setSavingUser(true);
    try {
      await adminApi.createUser(userForm);
      notify("用户已创建");
      setUserForm({ username: "", password: "", role: "USER", enabled: true });
      await loadUsers();
    } catch (error) {
      notifyError(error, "创建用户失败");
    } finally {
      setSavingUser(false);
    }
  };

  const [confirm, setConfirm] = useState<ConfirmState | null>(null);
  const [resetTarget, setResetTarget] = useState<ManagementUser | null>(null);

  const updateUser = async (user: ManagementUser, patch: ManagementUserMutation) => {
    try {
      await adminApi.updateUser(user.username, patch);
      notify("用户已更新");
      await loadUsers();
    } catch (error) {
      notifyError(error, "更新用户失败");
    }
  };

  const confirmToggleRole = (user: ManagementUser) => {
    const toAdmin = user.role !== "ADMIN";
    setConfirm({
      title: toAdmin ? "设为管理员" : "设为普通用户",
      description: toAdmin
        ? `确定将 ${user.username} 设为管理员吗？管理员可管理全部用户、客户端与系统配置。`
        : `确定将 ${user.username} 降为普通用户吗？其管理权限将立即失效。`,
      confirmLabel: toAdmin ? "设为管理员" : "设为普通",
      danger: toAdmin,
      action: () => updateUser(user, { role: toAdmin ? "ADMIN" : "USER" }),
    });
  };

  const confirmToggleEnabled = (user: ManagementUser) => {
    setConfirm({
      title: user.enabled ? "停用用户" : "启用用户",
      description: user.enabled
        ? `确定停用 ${user.username} 吗？停用后该用户将无法登录管理后台。`
        : `确定恢复启用 ${user.username} 吗？`,
      confirmLabel: user.enabled ? "停用" : "启用",
      danger: Boolean(user.enabled),
      action: () => updateUser(user, { enabled: !user.enabled }),
    });
  };

  const deleteUser = (user: ManagementUser) => {
    setConfirm({
      title: "删除用户",
      description: `确定删除用户 ${user.username} 吗？该操作不可恢复。`,
      confirmLabel: "删除",
      danger: true,
      action: async () => {
        try {
          await adminApi.deleteUser(user.username);
          notify("用户已删除");
          await loadUsers();
        } catch (error) {
          notifyError(error, "删除用户失败");
        }
      },
    });
  };

  // ---- 客户端版本编目与可选的服务端托管发布包 ----
  const [downloadLinks, setDownloadLinks] = useState<ClientDownloadLink[]>([]);
  const [loadingDownloads, setLoadingDownloads] = useState(false);
  const [editingLink, setEditingLink] = useState<ClientDownloadLink | null>(null);
  const linkModal = useOverlayState();
  const packageModal = useOverlayState();

  const loadDownloadLinks = async () => {
    setLoadingDownloads(true);
    try {
      setDownloadLinks(await adminApi.listClientDownloads());
    } catch (error) {
      notifyError(error, "下载链接加载失败");
    } finally {
      setLoadingDownloads(false);
    }
  };

  useEffect(() => {
    void loadDownloadLinks();
  }, []);

  const openCreateLink = () => {
    setEditingLink(null);
    linkModal.open();
  };

  const openEditLink = (link: ClientDownloadLink) => {
    setEditingLink(link);
    linkModal.open();
  };

  const [pendingLinkIds, setPendingLinkIds] = useState<Set<number>>(new Set());

  /** 乐观更新 + 失败回滚；切换期间该行开关禁用。 */
  const toggleLinkEnabled = async (link: ClientDownloadLink) => {
    if (pendingLinkIds.has(link.id)) {
      return;
    }
    setPendingLinkIds((prev) => new Set(prev).add(link.id));
    const nextLatest = link.enabled ? false : link.isLatest;
    setDownloadLinks((prev) => prev.map((item) => (item.id === link.id
      ? { ...item, enabled: !link.enabled, isLatest: nextLatest }
      : item)));
    try {
      await adminApi.updateClientDownload(link.id, {
        implementation: link.implementation,
        platform: link.platform,
        arch: link.arch,
        displayName: link.displayName,
        downloadUrl: link.downloadUrl,
        description: link.description ?? null,
        displayOrder: link.displayOrder,
        enabled: !link.enabled,
        version: link.version,
        isLatest: nextLatest,
        changelogUrl: link.changelogUrl,
        minSupportedVersion: link.minSupportedVersion,
      });
    } catch (error) {
      setDownloadLinks((prev) => prev.map((item) => (item.id === link.id ? link : item)));
      notifyError(error, "切换状态失败");
    } finally {
      setPendingLinkIds((prev) => {
        const next = new Set(prev);
        next.delete(link.id);
        return next;
      });
    }
  };

  const markLinkLatest = async (link: ClientDownloadLink) => {
    if (link.isLatest) return;
    try {
      await adminApi.setClientDownloadLatest(link.id);
      notify(`v${link.version || "-"} 已设为最新版本`);
      await loadDownloadLinks();
    } catch (error) {
      notifyError(error, "设置最新版本失败");
    }
  };

  const deleteLink = (link: ClientDownloadLink) => {
    setConfirm({
      title: "删除下载链接",
      description: `确定删除「${link.displayName}」吗？删除后公开下载和版本检查将不再返回该条目。`,
      confirmLabel: "删除",
      danger: true,
      action: async () => {
        try {
          await adminApi.deleteClientDownload(link.id);
          notify("已删除");
          await loadDownloadLinks();
        } catch (error) {
          notifyError(error, "删除失败");
        }
      },
    });
  };

  return (
    <div className="flex flex-col gap-4">
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1.5fr)_minmax(360px,0.8fr)]">
      <Card className="rounded-md border border-default-200 bg-content1">
        <Card.Header className="flex items-center justify-between gap-4 px-5 pb-2 pt-5">
          <div>
            <h2 className="text-lg font-semibold text-foreground">用户管理</h2>
            <p className="mt-1 text-small text-default-500">数据库用户、角色和启用状态</p>
          </div>
          <Button variant="secondary" onPress={() => void loadUsers()} isDisabled={loadingUsers}>{loadingUsers ? <Spinner size="sm" /> : null}
            刷新
          </Button>
        </Card.Header>
        <Card.Content className="gap-4 px-5 pb-5 pt-2">
          <div className="grid gap-3 rounded-md border border-default-200 bg-default-50 p-3 lg:grid-cols-[1fr_1fr_150px_auto_auto]">
            <TextField value={userForm.username || ""} onChange={(username) => setUserForm((prev) => ({ ...prev, username }))}>
              <Label>用户名</Label>
              <Input />
            </TextField>
            <TextField value={userForm.password || ""} onChange={(password) => setUserForm((prev) => ({ ...prev, password }))} type="password">
              <Label>密码</Label>
              <Input />
            </TextField>
            <Select
              onSelectionChange={(keys) => {
                const role = (keys == null ? undefined : String(keys)) as ManagementRole | undefined;
                setUserForm((prev) => ({ ...prev, role: role || "USER" }));
              }} selectedKey={userForm.role || "USER"}>
              <Label>角色</Label>
              <SelectTrigger>
                <SelectValue />
                <SelectIndicator />
              </SelectTrigger>
              <SelectPopover>
                <ListBox>
                  <ListBoxItem id="USER">普通用户</ListBoxItem>
              <ListBoxItem id="ADMIN">管理员</ListBoxItem>
                </ListBox>
              </SelectPopover>
            </Select>
            <Switch
              className="self-center"
              isSelected={userForm.enabled !== false}
              onChange={(enabled) => setUserForm((prev) => ({ ...prev, enabled }))}
            >
              启用
            </Switch>
            <Button variant="primary"
              className="self-center"
              onPress={() => void createUser()} isDisabled={savingUser}>{savingUser ? <Spinner size="sm" /> : null}
              创建用户
            </Button>
          </div>

          {/* mobile: 用户卡片 */}
          <div className="lg:hidden">
            <MobileListCardList
              items={users}
              isLoading={loadingUsers}
              emptyContent={<EmptyState icon="clients" title="暂无用户" />}
              renderCard={(raw) => {
                const user = raw as ManagementUser;
                return (
                  <MobileListCard
                    key={user.username}
                    title={user.username}
                    subtitle={user.builtIn ? "配置文件内置账号" : undefined}
                    badges={
                      <>
                        <StatusChip tone={user.admin ? "primary" : "default"}>{roleText(user.role)}</StatusChip>
                        <StatusChip tone={enabledTone(user.enabled)}>{user.enabled ? "启用" : "停用"}</StatusChip>
                      </>
                    }
                    fields={[
                      { label: "租户", value: user.tenantId },
                      { label: "更新时间", value: formatDateTime(user.updatedAt) },
                    ]}
                    actions={
                      <>
                        <Button isDisabled={user.builtIn} size="sm" variant="secondary" onPress={() => confirmToggleRole(user)}>
                          {user.role === "ADMIN" ? "设为普通" : "设为管理员"}
                        </Button>
                        <Button isDisabled={user.builtIn} size="sm" variant="secondary" onPress={() => confirmToggleEnabled(user)}>
                          {user.enabled ? "停用" : "启用"}
                        </Button>
                        <Button isDisabled={user.builtIn} size="sm" variant="secondary" onPress={() => setResetTarget(user)}>
                          重置密码
                        </Button>
                        <Button isDisabled={user.builtIn} size="sm" variant="danger-soft" onPress={() => deleteUser(user)}>
                          删除
                        </Button>
                      </>
                    }
                  />
                );
              }}
            />
          </div>

          {/* desktop: 表格 */}
          <div className="hidden overflow-x-auto lg:block">
            <Table
            >
              <TableContent aria-label="管理用户">
                <TableHeader>
                  <TableColumn isRowHeader>用户名</TableColumn>
                  <TableColumn>租户</TableColumn>
                  <TableColumn>角色</TableColumn>
                  <TableColumn>状态</TableColumn>
                  <TableColumn>更新时间</TableColumn>
                  <TableColumn className="text-right">操作</TableColumn>
                </TableHeader>
                <TableBody items={users} renderEmptyState={() => (loadingUsers ? <Spinner size="sm" /> : <EmptyState icon="clients" title="暂无用户" />)}>
                  {(user) => (
                    <TableRow key={user.username}>
                      <TableCell>
                        <div className="font-medium text-foreground">{user.username}</div>
                        {user.builtIn ? <div className="text-tiny text-default-500">配置文件内置账号</div> : null}
                      </TableCell>
                      <TableCell>{user.tenantId}</TableCell>
                      <TableCell>
                        <StatusChip tone={user.admin ? "primary" : "default"}>{roleText(user.role)}</StatusChip>
                      </TableCell>
                      <TableCell>
                        <StatusChip tone={enabledTone(user.enabled)}>{user.enabled ? "启用" : "停用"}</StatusChip>
                      </TableCell>
                      <TableCell className="whitespace-nowrap text-default-500">{formatDateTime(user.updatedAt)}</TableCell>
                      <TableCell>
                        <div className="flex justify-end gap-2">
                          <Button
                            isDisabled={user.builtIn}
                            size="sm" variant="secondary"
                            onPress={() => confirmToggleRole(user)}
                          >
                            {user.role === "ADMIN" ? "设为普通" : "设为管理员"}
                          </Button>
                          <Button
                            isDisabled={user.builtIn}
                            size="sm" variant="secondary"
                            onPress={() => confirmToggleEnabled(user)}
                          >
                            {user.enabled ? "停用" : "启用"}
                          </Button>
                          <Button
                            isDisabled={user.builtIn}
                            size="sm" variant="secondary"
                            onPress={() => setResetTarget(user)}
                          >
                            重置密码
                          </Button>
                          <Button
                            isDisabled={user.builtIn}
                            size="sm" variant="danger-soft"
                            onPress={() => deleteUser(user)}
                          >
                            删除
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
            
              </TableContent>
            </Table>
          </div>
        </Card.Content>
      </Card>

      <Card className="rounded-md border border-default-200 bg-content1">
        <Card.Header className="flex items-center justify-between gap-4 px-5 pb-2 pt-5">
          <div>
            <h2 className="text-lg font-semibold text-foreground">数据库</h2>
            <p className="mt-1 text-small text-default-500">基础数据维护</p>
          </div>
          <Button variant="secondary"
            onPress={() => void onInitializeDatabase()} isDisabled={initializing}>{initializing ? <Spinner size="sm" /> : null}
            初始化数据库
          </Button>
        </Card.Header>
        <Card.Content className="px-5 pb-5 pt-2">
          <div className="rounded-md border border-default-200 bg-default-50 p-4 text-small text-default-600">
            初始化会补齐管理端所需的基础数据，操作前会再次确认。
          </div>
        </Card.Content>
      </Card>
    </div>

    <Card className="rounded-md border border-default-200 bg-content1">
      <Card.Header className="flex flex-col items-stretch gap-4 px-5 pb-2 pt-5 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 className="text-lg font-semibold text-foreground">客户端发布</h2>
          <p className="mt-1 text-small text-default-500">
            上传受校验的发布包，按实现、平台与架构维护版本轨道。
          </p>
        </div>
        <div className="grid grid-cols-2 gap-2 sm:flex sm:flex-wrap sm:justify-end">
          <Button variant="secondary" onPress={() => void loadDownloadLinks()} isDisabled={loadingDownloads}>{loadingDownloads ? <Spinner size="sm" /> : null}
            刷新
          </Button>
          <Button variant="outline" onPress={openCreateLink}>
            新增外链
          </Button>
          <Button variant="primary" className="col-span-2 sm:col-span-1" onPress={packageModal.open}>
            上传发布包
          </Button>
        </div>
      </Card.Header>
      <Card.Content className="gap-4 px-5 pb-5 pt-2">
        {/* mobile: 下载链接卡片 */}
        <div className="lg:hidden">
          <MobileListCardList
            items={downloadLinks}
            isLoading={loadingDownloads}
            emptyContent={<EmptyState icon="generic" title="暂无客户端版本" description="上传第一个发布包后会出现在公开下载页" />}
            renderCard={(raw) => {
              const link = raw as ClientDownloadLink;
              const pending = pendingLinkIds.has(link.id);
              return (
                <MobileListCard
                  key={link.id}
                  title={<span className="break-all">{link.displayName}</span>}
                  subtitle={link.description || undefined}
                  badges={
                    <>
                      <Chip size="sm" variant="soft" color="accent">
                        {implementationLabel(link.implementation)}
                      </Chip>
                      <Chip size="sm" variant="soft">{platformLabel(link.platform)}</Chip>
                      <Chip size="sm" variant="soft">{archLabel(link.arch)}</Chip>
                      {link.version ? <Chip size="sm" color={link.isLatest ? "success" : "default"} variant="soft">v{link.version}</Chip> : null}
                      {link.hosted ? <Chip size="sm" color="default" variant="soft">托管</Chip> : null}
                      <Switch
                        isSelected={link.enabled}
                        isDisabled={pending}
                        onChange={() => void toggleLinkEnabled(link)}
                      >
                        启用
                      </Switch>
                    </>
                  }
                  fields={[
                    {
                      label: "URL",
                      value: (
                        <a
                          className="break-all font-mono text-tiny text-primary hover:underline"
                          href={link.downloadUrl}
                          rel="noopener noreferrer"
                          target="_blank"
                        >
                          {link.downloadUrl}
                        </a>
                      ),
                    },
                    { label: "排序", value: link.displayOrder },
                    { label: "文件", value: link.fileSize ? formatBytes(link.fileSize) : "外部链接" },
                    { label: "SHA-256", value: link.sha256 ? <span className="break-all font-mono text-tiny">{link.sha256}</span> : "-" },
                  ]}
                  actions={
                    <>
                      <Button size="sm" variant="secondary" onPress={() => openEditLink(link)}>
                        编辑
                      </Button>
                      {!link.isLatest && link.version ? (
                        <Button size="sm" variant="secondary" onPress={() => void markLinkLatest(link)}>
                          设为最新
                        </Button>
                      ) : null}
                      <Button
                        size="sm" variant="danger-soft"
                        onPress={() => deleteLink(link)}
                      >
                        删除
                      </Button>
                    </>
                  }
                />
              );
            }}
          />
        </div>

        {/* desktop: 表格 */}
        <div className="hidden overflow-x-auto lg:block">
          <Table
          >
            <TableContent aria-label="客户端发布版本">
              <TableHeader>
                <TableColumn isRowHeader>实现</TableColumn>
                <TableColumn>平台 / 架构</TableColumn>
                <TableColumn>名称</TableColumn>
                <TableColumn>版本</TableColumn>
                <TableColumn>URL</TableColumn>
                <TableColumn>校验</TableColumn>
                <TableColumn>启用</TableColumn>
                <TableColumn className="text-right">操作</TableColumn>
              </TableHeader>
              <TableBody items={downloadLinks} renderEmptyState={() => (loadingDownloads ? <Spinner size="sm" /> : <EmptyState icon="generic" title="暂无客户端版本" description="上传第一个发布包后会出现在公开下载页" />)}>
                {(link) => {
                  const pending = pendingLinkIds.has(link.id);
                  return (
                  <TableRow key={link.id}>
                    <TableCell>
                      <Chip size="sm" variant="soft" color="accent">
                        {implementationLabel(link.implementation)}
                      </Chip>
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        <Chip size="sm" variant="soft">{platformLabel(link.platform)}</Chip>
                        <Chip size="sm" variant="soft">{archLabel(link.arch)}</Chip>
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="font-medium">{link.displayName}</div>
                      {link.description ? (
                        <div className="text-tiny text-default-500">{link.description}</div>
                      ) : null}
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        <Chip size="sm" color={link.isLatest ? "success" : "default"} variant="soft">
                          {link.version ? `v${link.version}` : "未标版本"}
                        </Chip>
                        {link.hosted ? <Chip size="sm" color="default" variant="soft">托管</Chip> : null}
                      </div>
                    </TableCell>
                    <TableCell>
                      <a
                        className="block max-w-64 truncate font-mono text-tiny text-primary hover:underline"
                        href={link.downloadUrl}
                        rel="noopener noreferrer"
                        target="_blank"
                        title={link.downloadUrl}
                      >
                        {link.downloadUrl}
                      </a>
                    </TableCell>
                    <TableCell>
                      <div className="text-tiny text-default-500">{link.fileSize ? formatBytes(link.fileSize) : "外部文件"}</div>
                      {link.sha256 ? <div className="max-w-32 truncate font-mono text-tiny" title={link.sha256}>{link.sha256}</div> : null}
                    </TableCell>
                    <TableCell>
                      <Switch
                        aria-label="启用"
                        isSelected={link.enabled}
                        isDisabled={pending}
                        onChange={() => void toggleLinkEnabled(link)}
                      />
                    </TableCell>
                    <TableCell>
                      <div className="flex justify-end gap-2">
                        <Button size="sm" variant="secondary" onPress={() => openEditLink(link)}>
                          编辑
                        </Button>
                        {!link.isLatest && link.version ? (
                          <Button size="sm" variant="secondary" onPress={() => void markLinkLatest(link)}>
                            设为最新
                          </Button>
                        ) : null}
                        <Button
                          size="sm" variant="danger-soft"
                          onPress={() => deleteLink(link)}
                        >
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
      </Card.Content>
    </Card>

    <EditClientDownloadModal
      disclosure={linkModal}
      link={editingLink}
      onSaved={() => void loadDownloadLinks()}
    />
    <UploadClientPackageModal
      disclosure={packageModal}
      onSaved={() => void loadDownloadLinks()}
    />
    <ResetPasswordModal
      user={resetTarget}
      onClose={() => setResetTarget(null)}
      onSubmit={async (password) => {
        if (resetTarget) {
          await updateUser(resetTarget, { password });
        }
      }}
    />
    <ConfirmModal
      isOpen={confirm != null}
      onClose={() => setConfirm(null)}
      onConfirm={() => confirm?.action()}
      title={confirm?.title ?? ""}
      description={confirm?.description}
      confirmLabel={confirm?.confirmLabel}
      danger={confirm?.danger}
    />
    </div>
  );
}

interface ResetPasswordModalProps {
  user: ManagementUser | null;
  onClose: () => void;
  onSubmit: (password: string) => Promise<void>;
}

/** 重置密码弹窗：替代原生 prompt，密码不明文展示且需二次确认。 */
function ResetPasswordModal({ user, onClose, onSubmit }: ResetPasswordModalProps) {
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (user) {
      setPassword("");
      setConfirmPassword("");
    }
  }, [user]);

  const passwordError = !password
    ? "请输入新密码"
    : password.length < 6
      ? "密码至少 6 位"
      : "";
  const confirmError = confirmPassword && confirmPassword !== password ? "两次输入的密码不一致" : "";
  const invalid = Boolean(passwordError) || Boolean(confirmError);

  const submit = async () => {
    if (invalid || saving) {
      return;
    }
    setSaving(true);
    try {
      await onSubmit(password);
      onClose();
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal.Root isOpen={user != null} onOpenChange={(open) => { if (!open) (onClose)(); }}>
      <Modal.Backdrop>
        <Modal.Container size="sm" placement="center">
          <Modal.Dialog>
            <Modal.Header className="text-base">重置密码「{user?.username}」</Modal.Header>
            <Modal.Body className="gap-3">
              <TextField value={password} onChange={setPassword} isInvalid={Boolean(password && passwordError)} type="password" autoComplete="new-password">
                <Label>新密码</Label>
                <Input  />
                <FieldError>{password ? passwordError : ""}</FieldError>
              </TextField>
            <TextField value={confirmPassword} onChange={setConfirmPassword} isInvalid={Boolean(confirmError)} type="password" autoComplete="new-password">
              <Label>确认新密码</Label>
              <Input  />
            <FieldError>{confirmError}</FieldError>
            </TextField>
            </Modal.Body>
            <Modal.Footer>
              <Button variant="secondary" onPress={onClose} isDisabled={saving}>
                取消
              </Button>
              <Button variant="primary" isDisabled={invalid || saving} onPress={() => void submit()}>{saving ? <Spinner size="sm" /> : null}
                重置密码
              </Button>
            </Modal.Footer>

          </Modal.Dialog>
        </Modal.Container>
      </Modal.Backdrop>
    </Modal.Root>
  );
}

function implementationLabel(impl: string): string {
  switch (impl) {
    case "java":
      return "Java";
    case "go":
      return "Go";
    case "csharp":
      return ".NET";
    case "android":
      return "Android";
    default:
      return impl;
  }
}

interface UploadClientPackageModalProps {
  disclosure: ReturnType<typeof useOverlayState>;
  onSaved: () => void;
}

function UploadClientPackageModal({ disclosure, onSaved }: UploadClientPackageModalProps) {
  const [file, setFile] = useState<File | null>(null);
  const [implementation, setImplementation] = useState<ClientImplementation>("go");
  const [platform, setPlatform] = useState<ClientPlatform>("linux");
  const [arch, setArch] = useState<ClientArch>("x64");
  const [version, setVersion] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [description, setDescription] = useState("");
  const [changelogUrl, setChangelogUrl] = useState("");
  const [minSupportedVersion, setMinSupportedVersion] = useState("");
  const [isLatest, setIsLatest] = useState(false);
  const [enabled, setEnabled] = useState(true);
  const [dragging, setDragging] = useState(false);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!disclosure.isOpen) return;
    setFile(null);
    setVersion("");
    setDisplayName("");
    setDescription("");
    setChangelogUrl("");
    setMinSupportedVersion("");
    setIsLatest(false);
    setEnabled(true);
  }, [disclosure.isOpen]);

  const chooseImplementation = (value: ClientImplementation) => {
    setImplementation(value);
    if (value === "android") {
      setPlatform("android");
      setArch("any");
    } else if (platform === "android") {
      setPlatform("any");
    }
  };

  const selectPackageFile = (nextFile: File) => {
    setDisplayName((current) => !current.trim() || current === file?.name ? nextFile.name : current);
    setFile(nextFile);
  };

  const acceptDroppedFile = (event: DragEvent<HTMLLabelElement>) => {
    event.preventDefault();
    setDragging(false);
    const dropped = event.dataTransfer.files.item(0);
    if (dropped) selectPackageFile(dropped);
  };

  const upload = async () => {
    if (!file || !version.trim() || !displayName.trim()) {
      notify("请选择文件并填写版本号与显示名称", "error");
      return;
    }
    const body: ClientPackageUpload = {
      file,
      implementation,
      platform,
      arch,
      version: version.trim().replace(/^v/, ""),
      displayName: displayName.trim(),
      description: description.trim() || null,
      changelogUrl: changelogUrl.trim() || null,
      minSupportedVersion: minSupportedVersion.trim().replace(/^v/, "") || null,
      enabled,
      isLatest,
    };
    setSaving(true);
    try {
      await adminApi.uploadClientPackage(body);
      notify(`v${body.version} 发布包已上传`);
      disclosure.close();
      onSaved();
    } catch (error) {
      notifyError(error, "发布包上传失败");
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal.Root isOpen={disclosure.isOpen} onOpenChange={disclosure.setOpen}>
      <Modal.Backdrop>
        <Modal.Container size="cover" scroll="inside">
          <Modal.Dialog className="bg-content1">
            {({ close: onClose }) => (
            <>
            <Modal.Header className="flex flex-col items-start gap-1">
              <span>上传客户端发布包</span>
              <span className="text-tiny font-normal text-default-500">服务端计算大小与 SHA-256；设为最新后客户端才会收到升级提示。</span>
            </Modal.Header>
            <Modal.Body className="gap-4">
              <label
                htmlFor="client-package-file"
                className={`flex min-h-32 cursor-pointer flex-col items-center justify-center rounded-lg border border-dashed px-5 py-6 text-center transition ${dragging ? "border-primary bg-primary-50 dark:bg-primary-500/10" : "border-default-300 bg-default-50 hover:border-primary"}`}
                onDragEnter={(event) => { event.preventDefault(); setDragging(true); }}
                onDragOver={(event) => event.preventDefault()}
                onDragLeave={() => setDragging(false)}
                onDrop={acceptDroppedFile}
              >
                <input
                  id="client-package-file"
                  className="sr-only"
                  type="file"
                  onChange={(event) => {
                    const selected = event.target.files?.item(0);
                    if (selected) selectPackageFile(selected);
                  }}
                />
                <span className="font-medium text-foreground">{file ? file.name : "拖入发布包，或点击选择文件"}</span>
                <span className="mt-1 text-tiny text-default-500">{file ? formatBytes(file.size) : "APK、JAR、ZIP、tar.gz 均按二进制原样托管"}</span>
              </label>

            <div className="grid gap-3 sm:grid-cols-3">
              <Select onSelectionChange={(keys) => {
                const value = (keys == null ? undefined : String(keys)) as ClientImplementation | undefined;
                if (value) chooseImplementation(value);
              }} selectedKey={implementation}>
                <Label>实现</Label>
                <SelectTrigger>
                  <SelectValue />
                  <SelectIndicator />
                </SelectTrigger>
            <SelectPopover>
              <ListBox>
                <ListBoxItem id="go">Go</ListBoxItem>
            <ListBoxItem id="csharp">.NET</ListBoxItem>
            <ListBoxItem id="java">Java</ListBoxItem>
            <ListBoxItem id="android">Android</ListBoxItem>
              </ListBox>
            </SelectPopover>
            </Select>
            <Select isDisabled={implementation === "android"} onSelectionChange={(keys) => {
              const value = (keys == null ? undefined : String(keys)) as ClientPlatform | undefined;
              if (value) setPlatform(value);
            }} selectedKey={platform}>
              <Label>操作系统</Label>
              <SelectTrigger>
                <SelectValue />
                <SelectIndicator />
            </SelectTrigger>
            <SelectPopover>
              <ListBox>
                <ListBoxItem id="any">跨平台</ListBoxItem>
            <ListBoxItem id="windows">Windows</ListBoxItem>
            <ListBoxItem id="linux">Linux</ListBoxItem>
            <ListBoxItem id="macos">macOS</ListBoxItem>
            <ListBoxItem isDisabled={implementation !== "android"} id="android">Android</ListBoxItem>
              </ListBox>
            </SelectPopover>
            </Select>
            <Select isDisabled={implementation === "android"} onSelectionChange={(keys) => {
              const value = (keys == null ? undefined : String(keys)) as ClientArch | undefined;
              if (value) setArch(value);
            }} selectedKey={arch}>
              <Label>架构</Label>
              <SelectTrigger>
                <SelectValue />
                <SelectIndicator />
            </SelectTrigger>
            <SelectPopover>
              <ListBox>
                <ListBoxItem id="any">跨架构</ListBoxItem>
            <ListBoxItem id="x64">x86_64</ListBoxItem>
            <ListBoxItem id="arm64">ARM64</ListBoxItem>
              </ListBox>
            </SelectPopover>
            </Select>
            </div>

            <div className="grid gap-3 sm:grid-cols-2">
              <TextField value={version} onChange={setVersion} isRequired>
                <Label>版本号</Label>
                <Input maxLength={32} placeholder="1.4.0" />
              </TextField>
            <TextField value={displayName} onChange={setDisplayName} isRequired>
              <Label>显示名称</Label>
              <Input placeholder="Android 客户端 1.4.0" />
            </TextField>
            <TextField value={minSupportedVersion} onChange={setMinSupportedVersion}>
              <Label>最低支持版本（可选）</Label>
              <Input maxLength={32} placeholder="1.2.0" />
            </TextField>
            <TextField value={changelogUrl} onChange={setChangelogUrl}>
              <Label>更新说明 URL（可选）</Label>
              <Input placeholder="https://…" />
            </TextField>
            </div>
            <TextField value={description} onChange={setDescription}>
              <Label>版本说明（可选）</Label>
              <TextArea />
            </TextField>
            <div className="flex flex-wrap gap-5 rounded-md border border-default-200 bg-default-50 p-3">
              <Switch isDisabled={!enabled} isSelected={isLatest} onChange={setIsLatest}>设为此目标的最新版本</Switch>
              <Switch isSelected={enabled} onChange={(value) => {
                setEnabled(value);
                if (!value) setIsLatest(false);
              }}>公开下载</Switch>
            </div>
            </Modal.Body>
            <Modal.Footer>
              <Button variant="secondary" onPress={onClose} isDisabled={saving}>取消</Button>
              <Button variant="primary" onPress={() => void upload()} isDisabled={saving}>{saving ? <Spinner size="sm" /> : null}校验并上传</Button>
            </Modal.Footer>
            </>
            )}

          </Modal.Dialog>
        </Modal.Container>
      </Modal.Backdrop>
    </Modal.Root>
  );
}

interface EditClientDownloadModalProps {
  disclosure: ReturnType<typeof useOverlayState>;
  link: ClientDownloadLink | null;
  onSaved: () => void;
}

function EditClientDownloadModal({ disclosure, link, onSaved }: EditClientDownloadModalProps) {
  const [implementation, setImplementation] = useState<ClientImplementation>("java");
  const [platform, setPlatform] = useState<ClientPlatform>("any");
  const [arch, setArch] = useState<ClientArch>("any");
  const [displayName, setDisplayName] = useState("");
  const [downloadUrl, setDownloadUrl] = useState("");
  const [sha256, setSha256] = useState("");
  const [fileSize, setFileSize] = useState("");
  const [description, setDescription] = useState("");
  const [displayOrder, setDisplayOrder] = useState("0");
  const [enabled, setEnabled] = useState(true);
  const [version, setVersion] = useState("");
  const [isLatest, setIsLatest] = useState(false);
  const [changelogUrl, setChangelogUrl] = useState("");
  const [minSupportedVersion, setMinSupportedVersion] = useState("");
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!disclosure.isOpen) {
      return;
    }
    if (link) {
      setImplementation(link.implementation);
      setPlatform(link.platform);
      setArch(link.arch);
      setDisplayName(link.displayName);
      setDownloadUrl(link.downloadUrl);
      setSha256(link.sha256 ?? "");
      setFileSize(link.fileSize ? String(link.fileSize) : "");
      setDescription(link.description ?? "");
      setDisplayOrder(String(link.displayOrder));
      setEnabled(link.enabled);
      setVersion(link.version ?? "");
      setIsLatest(link.isLatest === true);
      setChangelogUrl(link.changelogUrl ?? "");
      setMinSupportedVersion(link.minSupportedVersion ?? "");
    } else {
      setImplementation("java");
      setPlatform("any");
      setArch("any");
      setDisplayName("");
      setDownloadUrl("");
      setSha256("");
      setFileSize("");
      setDescription("");
      setDisplayOrder("0");
      setEnabled(true);
      setVersion("");
      setIsLatest(false);
      setChangelogUrl("");
      setMinSupportedVersion("");
    }
  }, [disclosure.isOpen, link]);

  const chooseImplementation = (value: ClientImplementation) => {
    setImplementation(value);
    if (value === "android") {
      setPlatform("android");
      setArch("any");
    } else if (platform === "android") {
      setPlatform("any");
    }
  };

  const save = async () => {
    if (!displayName.trim() || !downloadUrl.trim() || !version.trim()) {
      notify("请填写版本号、名称和下载 URL", "error");
      return;
    }
    const normalizedSha256 = sha256.trim().toLowerCase();
    const normalizedFileSize = fileSize.trim() ? Number(fileSize) : null;
    if (!link?.hosted && normalizedSha256 && !/^[0-9a-f]{64}$/.test(normalizedSha256)) {
      notify("SHA-256 必须是 64 位十六进制字符", "error");
      return;
    }
    if (!link?.hosted && normalizedFileSize !== null
      && (!Number.isSafeInteger(normalizedFileSize) || normalizedFileSize <= 0)) {
      notify("文件字节数必须是正整数", "error");
      return;
    }
    if (!link?.hosted && isLatest && (!normalizedSha256 || normalizedFileSize === null)) {
      notify("发布外部最新版本前，请填写 Release 资产的 SHA-256 和文件字节数", "error");
      return;
    }
    setSaving(true);
    const body: ClientDownloadLinkMutation = {
      implementation,
      platform,
      arch,
      displayName: displayName.trim(),
      downloadUrl: downloadUrl.trim(),
      description: description.trim() || null,
      displayOrder: Number(displayOrder) || 0,
      enabled,
      version: version.trim().replace(/^v/, ""),
      ...(!link?.hosted ? {
        sha256: normalizedSha256 || null,
        fileSize: normalizedFileSize,
      } : {}),
      isLatest,
      changelogUrl: changelogUrl.trim() || null,
      minSupportedVersion: minSupportedVersion.trim().replace(/^v/, "") || null,
    };
    try {
      if (link) {
        await adminApi.updateClientDownload(link.id, body);
        notify("已更新");
      } else {
        await adminApi.createClientDownload(body);
        notify("已创建");
      }
      disclosure.close();
      onSaved();
    } catch (error) {
      notifyError(error, "保存失败");
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal.Root isOpen={disclosure.isOpen} onOpenChange={disclosure.setOpen}>
      <Modal.Backdrop>
        <Modal.Container size="lg">
          <Modal.Dialog>
            {({ close: onClose }) => (
            <>
            <Modal.Header>{link ? `编辑下载链接 #${link.id}` : "新增下载链接"}</Modal.Header>
            <Modal.Body className="gap-3">
              <div className="grid gap-3 sm:grid-cols-3">
                <Select
                  onSelectionChange={(keys) => {
                    const value = (keys == null ? undefined : String(keys)) as ClientImplementation | undefined;
                    if (value) chooseImplementation(value);
                  }} selectedKey={implementation}>
                  <Label>实现</Label>
                  <SelectTrigger>
                    <SelectValue />
                    <SelectIndicator />
                  </SelectTrigger>
            <SelectPopover>
              <ListBox>
                <ListBoxItem id="java">Java</ListBoxItem>
            <ListBoxItem id="go">Go</ListBoxItem>
            <ListBoxItem id="csharp">.NET</ListBoxItem>
            <ListBoxItem id="android">Android</ListBoxItem>
              </ListBox>
            </SelectPopover>
            </Select>
            <Select
            isDisabled={implementation === "android"}
            onSelectionChange={(keys) => {
            const value = (keys == null ? undefined : String(keys)) as ClientPlatform | undefined;
            if (value) setPlatform(value);
            }} selectedKey={platform}>
            <Label>操作系统</Label>
            <SelectTrigger>
              <SelectValue />
            <SelectIndicator />
            </SelectTrigger>
            <SelectPopover>
              <ListBox>
                <ListBoxItem id="any">跨平台</ListBoxItem>
            <ListBoxItem id="windows">Windows</ListBoxItem>
            <ListBoxItem id="linux">Linux</ListBoxItem>
            <ListBoxItem id="macos">macOS</ListBoxItem>
            <ListBoxItem isDisabled={implementation !== "android"} id="android">Android</ListBoxItem>
              </ListBox>
            </SelectPopover>
            </Select>
            <Select
            isDisabled={implementation === "android"}
            onSelectionChange={(keys) => {
            const value = (keys == null ? undefined : String(keys)) as ClientArch | undefined;
            if (value) setArch(value);
            }} selectedKey={arch}>
            <Label>架构</Label>
            <SelectTrigger>
              <SelectValue />
            <SelectIndicator />
            </SelectTrigger>
            <SelectPopover>
              <ListBox>
                <ListBoxItem id="any">跨架构</ListBoxItem>
            <ListBoxItem id="x64">x86_64</ListBoxItem>
            <ListBoxItem id="arm64">ARM64</ListBoxItem>
              </ListBox>
            </SelectPopover>
            </Select>
            </div>
            <TextField value={version} onChange={setVersion} isRequired>
              <Label>版本号</Label>
              <Input maxLength={32}
              placeholder="1.4.0" />
            </TextField>
            <TextField value={displayName} onChange={setDisplayName} isRequired>
              <Label>名称</Label>
              <Input maxLength={120}
              placeholder="例如：Java 客户端 1.2.0" />
            </TextField>
            <TextField value={downloadUrl} onChange={setDownloadUrl} isRequired isDisabled={link?.hosted === true}>
              <Label>下载 URL</Label>
              <Input maxLength={1024}
              placeholder="https://..." />
            </TextField>
            <div className="grid gap-3 sm:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
              <TextField value={sha256} onChange={setSha256} isDisabled={link?.hosted === true}>
                <Label>SHA-256</Label>
                <Input maxLength={64}
                placeholder="Release 资产的 64 位摘要" />
              </TextField>
              <TextField value={fileSize} onChange={setFileSize} isDisabled={link?.hosted === true} type="number">
                <Label>文件字节数</Label>
                <Input min={1}
                placeholder="例如 18432000" />
              </TextField>
            </div>
            <p className="text-tiny text-default-500">
              {link?.hosted
                ? "托管包的地址、摘要和大小由服务端计算，不能手动修改。"
                : "GitHub Release 外链标记为最新版本时，摘要和字节数必填；客户端会在安装前校验。"}
            </p>
            <TextField value={description} onChange={setDescription}>
              <Label>说明（可选）</Label>
              <TextArea
              placeholder="哈希值、签名说明等" />
            </TextField>
            <div className="grid gap-3 sm:grid-cols-2">
              <TextField value={minSupportedVersion} onChange={setMinSupportedVersion}>
                <Label>最低支持版本（可选）</Label>
                <Input maxLength={32} />
              </TextField>
            <TextField value={changelogUrl} onChange={setChangelogUrl}>
              <Label>更新说明 URL（可选）</Label>
              <Input />
            </TextField>
            </div>
            <div className="grid gap-3 sm:grid-cols-[120px_1fr] sm:items-center">
              <TextField value={displayOrder} onChange={setDisplayOrder} type="number">
                <Label>排序</Label>
                <Input />
              </TextField>
            <div className="flex flex-wrap gap-4">
              <Switch isSelected={enabled} onChange={(value) => {
                setEnabled(value);
                if (!value) setIsLatest(false);
              }}>启用</Switch>
              <Switch isDisabled={!enabled} isSelected={isLatest} onChange={setIsLatest}>最新版本</Switch>
            </div>
            </div>
            </Modal.Body>
            <Modal.Footer>
              <Button variant="secondary" onPress={onClose}>
                取消
              </Button>
              <Button variant="primary" onPress={() => void save()} isDisabled={saving}>{saving ? <Spinner size="sm" /> : null}
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

function roleText(role: ManagementRole) {
  return role === "ADMIN" ? "管理员" : "普通用户";
}
