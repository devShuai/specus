import { useEffect, useState } from "react";
import {
  Button,
  Card,
  CardBody,
  CardHeader,
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
  Textarea,
  useDisclosure,
} from "@heroui/react";
import { adminApi } from "../../api/client";
import type {
  ClientArch,
  ClientDownloadLink,
  ClientDownloadLinkMutation,
  ClientImplementation,
  ClientPlatform,
  ManagementRole,
  ManagementUser,
  ManagementUserMutation,
} from "../../api/types";
import { formatDateTime } from "../../lib/format";
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

  // ---- GitHub Releases 不可用时的备用下载链接管理 ----
  const [downloadLinks, setDownloadLinks] = useState<ClientDownloadLink[]>([]);
  const [loadingDownloads, setLoadingDownloads] = useState(false);
  const [editingLink, setEditingLink] = useState<ClientDownloadLink | null>(null);
  const linkModal = useDisclosure();

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
    linkModal.onOpen();
  };

  const openEditLink = (link: ClientDownloadLink) => {
    setEditingLink(link);
    linkModal.onOpen();
  };

  const [pendingLinkIds, setPendingLinkIds] = useState<Set<number>>(new Set());

  /** 乐观更新 + 失败回滚；切换期间该行开关禁用。 */
  const toggleLinkEnabled = async (link: ClientDownloadLink) => {
    if (pendingLinkIds.has(link.id)) {
      return;
    }
    setPendingLinkIds((prev) => new Set(prev).add(link.id));
    setDownloadLinks((prev) => prev.map((item) => (item.id === link.id ? { ...item, enabled: !link.enabled } : item)));
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

  const deleteLink = (link: ClientDownloadLink) => {
    setConfirm({
      title: "删除下载链接",
      description: `确定删除「${link.displayName}」吗？删除后 GitHub Releases 不可用时将无法回退到该链接。`,
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
      <Card shadow="none" className="rounded-md border border-default-200 bg-content1">
        <CardHeader className="flex items-center justify-between gap-4 px-5 pb-2 pt-5">
          <div>
            <h2 className="text-lg font-semibold text-foreground">用户管理</h2>
            <p className="mt-1 text-small text-default-500">数据库用户、角色和启用状态</p>
          </div>
          <Button radius="sm" variant="flat" isLoading={loadingUsers} onPress={() => void loadUsers()}>
            刷新
          </Button>
        </CardHeader>
        <CardBody className="gap-4 px-5 pb-5 pt-2">
          <div className="grid gap-3 rounded-md border border-default-200 bg-default-50 p-3 lg:grid-cols-[1fr_1fr_150px_auto_auto]">
            <Input
              label="用户名"
              radius="sm"
              size="sm"
              value={userForm.username || ""}
              onValueChange={(username) => setUserForm((prev) => ({ ...prev, username }))}
            />
            <Input
              label="密码"
              radius="sm"
              size="sm"
              type="password"
              value={userForm.password || ""}
              onValueChange={(password) => setUserForm((prev) => ({ ...prev, password }))}
            />
            <Select
              label="角色"
              radius="sm"
              selectedKeys={[userForm.role || "USER"]}
              size="sm"
              onSelectionChange={(keys) => {
                const role = Array.from(keys)[0]?.toString() as ManagementRole | undefined;
                setUserForm((prev) => ({ ...prev, role: role || "USER" }));
              }}
            >
              <SelectItem key="USER">普通用户</SelectItem>
              <SelectItem key="ADMIN">管理员</SelectItem>
            </Select>
            <Switch
              className="self-center"
              isSelected={userForm.enabled !== false}
              size="sm"
              onValueChange={(enabled) => setUserForm((prev) => ({ ...prev, enabled }))}
            >
              启用
            </Switch>
            <Button
              className="self-center"
              color="primary"
              isLoading={savingUser}
              radius="sm"
              onPress={() => void createUser()}
            >
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
                        <Button isDisabled={user.builtIn} radius="sm" size="sm" variant="flat" onPress={() => confirmToggleRole(user)}>
                          {user.role === "ADMIN" ? "设为普通" : "设为管理员"}
                        </Button>
                        <Button isDisabled={user.builtIn} radius="sm" size="sm" variant="flat" onPress={() => confirmToggleEnabled(user)}>
                          {user.enabled ? "停用" : "启用"}
                        </Button>
                        <Button isDisabled={user.builtIn} radius="sm" size="sm" variant="flat" onPress={() => setResetTarget(user)}>
                          重置密码
                        </Button>
                        <Button color="danger" isDisabled={user.builtIn} radius="sm" size="sm" variant="flat" onPress={() => deleteUser(user)}>
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
              aria-label="管理用户"
              isHeaderSticky
              removeWrapper
              classNames={{
                th: "bg-default-100",
                td: "align-middle",
              }}
            >
              <TableHeader>
                <TableColumn>用户名</TableColumn>
                <TableColumn>租户</TableColumn>
                <TableColumn>角色</TableColumn>
                <TableColumn>状态</TableColumn>
                <TableColumn>更新时间</TableColumn>
                <TableColumn className="text-right">操作</TableColumn>
              </TableHeader>
              <TableBody emptyContent={<EmptyState icon="clients" title="暂无用户" />} isLoading={loadingUsers} items={users}>
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
                          radius="sm"
                          size="sm"
                          variant="flat"
                          onPress={() => confirmToggleRole(user)}
                        >
                          {user.role === "ADMIN" ? "设为普通" : "设为管理员"}
                        </Button>
                        <Button
                          isDisabled={user.builtIn}
                          radius="sm"
                          size="sm"
                          variant="flat"
                          onPress={() => confirmToggleEnabled(user)}
                        >
                          {user.enabled ? "停用" : "启用"}
                        </Button>
                        <Button
                          isDisabled={user.builtIn}
                          radius="sm"
                          size="sm"
                          variant="flat"
                          onPress={() => setResetTarget(user)}
                        >
                          重置密码
                        </Button>
                        <Button
                          color="danger"
                          isDisabled={user.builtIn}
                          radius="sm"
                          size="sm"
                          variant="flat"
                          onPress={() => deleteUser(user)}
                        >
                          删除
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </div>
        </CardBody>
      </Card>

      <Card shadow="none" className="rounded-md border border-default-200 bg-content1">
        <CardHeader className="flex items-center justify-between gap-4 px-5 pb-2 pt-5">
          <div>
            <h2 className="text-lg font-semibold text-foreground">数据库</h2>
            <p className="mt-1 text-small text-default-500">基础数据维护</p>
          </div>
          <Button
            color="primary"
            isLoading={initializing}
            radius="sm"
            variant="flat"
            onPress={() => void onInitializeDatabase()}
          >
            初始化数据库
          </Button>
        </CardHeader>
        <CardBody className="px-5 pb-5 pt-2">
          <div className="rounded-md border border-default-200 bg-default-50 p-4 text-small text-default-600">
            初始化会补齐管理端所需的基础数据，操作前会再次确认。
          </div>
        </CardBody>
      </Card>
    </div>

    <Card shadow="none" className="rounded-md border border-default-200 bg-content1">
      <CardHeader className="flex items-center justify-between gap-4 px-5 pb-2 pt-5">
        <div>
          <h2 className="text-lg font-semibold text-foreground">备用下载链接</h2>
          <p className="mt-1 text-small text-default-500">
            站点默认读取 GitHub Releases；仅在 GitHub 不可用时使用这里的链接。
          </p>
        </div>
        <div className="flex gap-2">
          <Button radius="sm" variant="flat" isLoading={loadingDownloads} onPress={() => void loadDownloadLinks()}>
            刷新
          </Button>
          <Button radius="sm" color="primary" onPress={openCreateLink}>
            新增链接
          </Button>
        </div>
      </CardHeader>
      <CardBody className="gap-4 px-5 pb-5 pt-2">
        {/* mobile: 下载链接卡片 */}
        <div className="lg:hidden">
          <MobileListCardList
            items={downloadLinks}
            isLoading={loadingDownloads}
            emptyContent={<EmptyState icon="generic" title="暂无备用链接" description="GitHub Releases 不可用时将显示空状态" />}
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
                      <Chip size="sm" variant="flat" color="primary">
                        {implementationLabel(link.implementation)}
                      </Chip>
                      <Chip size="sm" variant="flat">{platformLabel(link.platform)}</Chip>
                      <Chip size="sm" variant="flat">{archLabel(link.arch)}</Chip>
                      <Switch
                        size="sm"
                        isSelected={link.enabled}
                        isDisabled={pending}
                        onValueChange={() => void toggleLinkEnabled(link)}
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
                  ]}
                  actions={
                    <>
                      <Button size="sm" radius="sm" variant="flat" onPress={() => openEditLink(link)}>
                        编辑
                      </Button>
                      <Button
                        size="sm"
                        radius="sm"
                        color="danger"
                        variant="flat"
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
            aria-label="客户端下载链接"
            isHeaderSticky
            removeWrapper
            classNames={{ th: "bg-default-100", td: "align-middle" }}
          >
            <TableHeader>
              <TableColumn>实现</TableColumn>
              <TableColumn>平台 / 架构</TableColumn>
              <TableColumn>名称</TableColumn>
              <TableColumn>URL</TableColumn>
              <TableColumn>排序</TableColumn>
              <TableColumn>启用</TableColumn>
              <TableColumn className="text-right">操作</TableColumn>
            </TableHeader>
            <TableBody emptyContent={<EmptyState icon="generic" title="暂无备用链接" description="GitHub Releases 不可用时将显示空状态" />} isLoading={loadingDownloads} items={downloadLinks}>
              {(link) => {
                const pending = pendingLinkIds.has(link.id);
                return (
                <TableRow key={link.id}>
                  <TableCell>
                    <Chip size="sm" variant="flat" color="primary">
                      {implementationLabel(link.implementation)}
                    </Chip>
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      <Chip size="sm" variant="flat">{platformLabel(link.platform)}</Chip>
                      <Chip size="sm" variant="flat">{archLabel(link.arch)}</Chip>
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="font-medium">{link.displayName}</div>
                    {link.description ? (
                      <div className="text-tiny text-default-500">{link.description}</div>
                    ) : null}
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
                  <TableCell>{link.displayOrder}</TableCell>
                  <TableCell>
                    <Switch
                      aria-label="启用"
                      size="sm"
                      isSelected={link.enabled}
                      isDisabled={pending}
                      onValueChange={() => void toggleLinkEnabled(link)}
                    />
                  </TableCell>
                  <TableCell>
                    <div className="flex justify-end gap-2">
                      <Button size="sm" radius="sm" variant="flat" onPress={() => openEditLink(link)}>
                        编辑
                      </Button>
                      <Button
                        size="sm"
                        radius="sm"
                        color="danger"
                        variant="flat"
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
          </Table>
        </div>
      </CardBody>
    </Card>

    <EditClientDownloadModal
      disclosure={linkModal}
      link={editingLink}
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
    <Modal isOpen={user != null} onClose={onClose} size="sm" placement="center">
      <ModalContent>
        <ModalHeader className="text-base">重置密码「{user?.username}」</ModalHeader>
        <ModalBody className="gap-3">
          <Input
            autoComplete="new-password"
            label="新密码"
            type="password"
            value={password}
            onValueChange={setPassword}
            isInvalid={Boolean(password && passwordError)}
            errorMessage={password ? passwordError : ""}
          />
          <Input
            autoComplete="new-password"
            label="确认新密码"
            type="password"
            value={confirmPassword}
            onValueChange={setConfirmPassword}
            isInvalid={Boolean(confirmError)}
            errorMessage={confirmError}
          />
        </ModalBody>
        <ModalFooter>
          <Button variant="flat" onPress={onClose} isDisabled={saving}>
            取消
          </Button>
          <Button color="primary" isDisabled={invalid} isLoading={saving} onPress={() => void submit()}>
            重置密码
          </Button>
        </ModalFooter>
      </ModalContent>
    </Modal>
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
    default:
      return impl;
  }
}

interface EditClientDownloadModalProps {
  disclosure: ReturnType<typeof useDisclosure>;
  link: ClientDownloadLink | null;
  onSaved: () => void;
}

function EditClientDownloadModal({ disclosure, link, onSaved }: EditClientDownloadModalProps) {
  const [implementation, setImplementation] = useState<ClientImplementation>("java");
  const [platform, setPlatform] = useState<ClientPlatform>("any");
  const [arch, setArch] = useState<ClientArch>("any");
  const [displayName, setDisplayName] = useState("");
  const [downloadUrl, setDownloadUrl] = useState("");
  const [description, setDescription] = useState("");
  const [displayOrder, setDisplayOrder] = useState("0");
  const [enabled, setEnabled] = useState(true);
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
      setDescription(link.description ?? "");
      setDisplayOrder(String(link.displayOrder));
      setEnabled(link.enabled);
    } else {
      setImplementation("java");
      setPlatform("any");
      setArch("any");
      setDisplayName("");
      setDownloadUrl("");
      setDescription("");
      setDisplayOrder("0");
      setEnabled(true);
    }
  }, [disclosure.isOpen, link]);

  const save = async () => {
    if (!displayName.trim() || !downloadUrl.trim()) {
      notify("请填写名称和下载 URL", "error");
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
    };
    try {
      if (link) {
        await adminApi.updateClientDownload(link.id, body);
        notify("已更新");
      } else {
        await adminApi.createClientDownload(body);
        notify("已创建");
      }
      disclosure.onClose();
      onSaved();
    } catch (error) {
      notifyError(error, "保存失败");
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal isOpen={disclosure.isOpen} onOpenChange={disclosure.onOpenChange} size="lg">
      <ModalContent>
        {(onClose) => (
          <>
            <ModalHeader>{link ? `编辑下载链接 #${link.id}` : "新增下载链接"}</ModalHeader>
            <ModalBody className="gap-3">
              <div className="grid gap-3 sm:grid-cols-3">
                <Select
                  label="实现"
                  selectedKeys={[implementation]}
                  onSelectionChange={(keys) => {
                    const value = Array.from(keys)[0]?.toString() as ClientImplementation | undefined;
                    if (value) setImplementation(value);
                  }}
                >
                  <SelectItem key="java">Java</SelectItem>
                  <SelectItem key="go">Go</SelectItem>
                  <SelectItem key="csharp">.NET</SelectItem>
                </Select>
                <Select
                  label="操作系统"
                  selectedKeys={[platform]}
                  onSelectionChange={(keys) => {
                    const value = Array.from(keys)[0]?.toString() as ClientPlatform | undefined;
                    if (value) setPlatform(value);
                  }}
                >
                  <SelectItem key="any">跨平台</SelectItem>
                  <SelectItem key="windows">Windows</SelectItem>
                  <SelectItem key="linux">Linux</SelectItem>
                  <SelectItem key="macos">macOS</SelectItem>
                </Select>
                <Select
                  label="架构"
                  selectedKeys={[arch]}
                  onSelectionChange={(keys) => {
                    const value = Array.from(keys)[0]?.toString() as ClientArch | undefined;
                    if (value) setArch(value);
                  }}
                >
                  <SelectItem key="any">跨架构</SelectItem>
                  <SelectItem key="x64">x86_64</SelectItem>
                  <SelectItem key="arm64">ARM64</SelectItem>
                </Select>
              </div>
              <Input
                label="名称"
                value={displayName}
                onValueChange={setDisplayName}
                maxLength={120}
                isRequired
                placeholder="例如：Java 客户端 1.2.0"
              />
              <Input
                label="下载 URL"
                value={downloadUrl}
                onValueChange={setDownloadUrl}
                maxLength={1024}
                isRequired
                placeholder="https://..."
              />
              <Textarea
                label="说明（可选）"
                value={description}
                onValueChange={setDescription}
                maxRows={3}
                placeholder="哈希值、签名说明等"
              />
              <div className="grid gap-3 sm:grid-cols-[120px_1fr] sm:items-center">
                <Input
                  label="排序"
                  type="number"
                  value={displayOrder}
                  onValueChange={setDisplayOrder}
                />
                <Switch isSelected={enabled} onValueChange={setEnabled}>
                  启用
                </Switch>
              </div>
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

function roleText(role: ManagementRole) {
  return role === "ADMIN" ? "管理员" : "普通用户";
}
