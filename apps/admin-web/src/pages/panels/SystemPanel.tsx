import { useEffect, useId, useState, type DragEvent } from "react";
import { PageHeader } from "../../components/PageHeader";
import {
  Button,
  Modal,
  ModalBody,
  ModalContent,
  ModalFooter,
  ModalHeader,
  useDisclosure,
} from "@heroui/react";
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
import { formatBytes } from "../../lib/format";
import { notify, notifyError } from "../../components/toast";
import { ConfirmModal } from "../../components/ConfirmModal";
import { Alert, Card, CardBody, CardHeader, Empty, Icon, RelativeTime, Section, TableWrap, Tag } from "../../components/ui";
import { archLabel, platformLabel } from "./ClientDownloadsPanel";
import { Field, SelectField, TableLoadingRow, TableStateRow, TextField, Toggle } from "./meshSystemParts";

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
      title: toAdmin ? `把 ${user.username} 设为管理员？` : `把 ${user.username} 降为普通用户？`,
      description: toAdmin
        ? `管理员可管理全部用户、客户端与系统配置。`
        : `${user.username} 的管理权限会立即失效。`,
      confirmLabel: toAdmin ? "设为管理员" : "设为普通",
      danger: toAdmin,
      action: () => updateUser(user, { role: toAdmin ? "ADMIN" : "USER" }),
    });
  };

  const confirmToggleEnabled = (user: ManagementUser) => {
    setConfirm({
      title: user.enabled ? `停用 ${user.username}？` : `恢复启用 ${user.username}？`,
      description: user.enabled
        ? `停用后该用户将无法登录管理后台。`
        : `启用后该用户可以重新登录管理后台。`,
      confirmLabel: user.enabled ? "停用" : "启用",
      danger: Boolean(user.enabled),
      action: () => updateUser(user, { enabled: !user.enabled }),
    });
  };

  const deleteUser = (user: ManagementUser) => {
    setConfirm({
      title: `删除用户 ${user.username}？`,
      description: `该操作不可恢复。`,
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
  const linkModal = useDisclosure();
  const packageModal = useDisclosure();

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
      title: `删除「${link.displayName}」？`,
      description: `删除后公开下载和版本检查将不再返回该条目。`,
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
    <div className="ms-page flex min-w-0 flex-col">
      <PageHeader title="系统管理" description="用户、数据库与客户端发布。" />

      <Section
        title="用户管理"
        description="数据库用户、角色和启用状态；配置文件内置的账号只能在配置文件里改。"
        actions={(
          <Button variant="flat" isLoading={loadingUsers} startContent={loadingUsers ? null : <Icon name="refresh" />} onPress={() => void loadUsers()}>
            刷新
          </Button>
        )}
      >
        <Card className="ms-block">
          <CardHeader title="新建用户" description="创建后对方用这里的用户名和密码登录管理后台。" />
          <CardBody>
            <div className="bd-form-grid ms-user-form">
              <TextField
                label="用户名"
                autoComplete="off"
                value={userForm.username || ""}
                onChange={(username) => setUserForm((prev) => ({ ...prev, username }))}
              />
              <TextField
                label="密码"
                type="password"
                autoComplete="new-password"
                value={userForm.password || ""}
                onChange={(password) => setUserForm((prev) => ({ ...prev, password }))}
              />
              <SelectField
                label="角色"
                value={(userForm.role || "USER") as ManagementRole}
                onChange={(role) => setUserForm((prev) => ({ ...prev, role: role || "USER" }))}
                options={[
                  { value: "USER", label: "普通用户" },
                  { value: "ADMIN", label: "管理员" },
                ]}
              />
              <div className="ms-form-action ms-user-actions">
                <Toggle
                  checked={userForm.enabled !== false}
                  onChange={(enabled) => setUserForm((prev) => ({ ...prev, enabled }))}
                >
                  启用
                </Toggle>
                <Button color="primary" isLoading={savingUser} startContent={savingUser ? null : <Icon name="plus" />} onPress={() => void createUser()}>
                  创建用户
                </Button>
              </div>
            </div>
          </CardBody>
        </Card>

        <TableWrap>
          <table className="bd-table jd-stack ms-table" aria-label="管理用户">
            <thead>
              <tr>
                <th scope="col">用户名</th>
                <th scope="col">租户</th>
                <th scope="col">角色</th>
                <th scope="col">状态</th>
                <th scope="col">更新时间</th>
                <th scope="col" className="ms-col-actions">操作</th>
              </tr>
            </thead>
            <tbody>
              {loadingUsers && users.length === 0 ? <TableLoadingRow colSpan={6} /> : null}
              {!loadingUsers && users.length === 0 ? (
                <TableStateRow colSpan={6}>
                  <Empty icon="users" title="暂无用户" description="用上面的表单新建第一个用户。" />
                </TableStateRow>
              ) : null}
              {users.map((user) => (
                <tr key={user.username}>
                  <td>
                    <div className="ms-cell-main">
                      <span className="ms-cell-title">{user.username}</span>
                      {user.builtIn ? <span className="ms-cell-sub">配置文件内置账号</span> : null}
                    </div>
                  </td>
                  <td data-label="租户">{user.tenantId}</td>
                  <td>
                    <Tag tone={user.admin ? "info" : "neutral"}>{roleText(user.role)}</Tag>
                  </td>
                  <td>
                    <Tag tone={user.enabled ? "success" : "neutral"} plain={!user.enabled}>{user.enabled ? "启用" : "停用"}</Tag>
                  </td>
                  <td data-label="更新" className={user.updatedAt ? undefined : "is-empty"}>
                    {user.updatedAt ? <RelativeTime value={user.updatedAt} className="jd-muted" /> : "—"}
                  </td>
                  <td className="jd-cell-actions ms-actions-row ms-col-actions">
                    <div className="ms-row-actions">
                      <Button isDisabled={user.builtIn} size="sm" variant="flat" onPress={() => confirmToggleRole(user)}>
                        {user.role === "ADMIN" ? "设为普通" : "设为管理员"}
                      </Button>
                      <Button isDisabled={user.builtIn} size="sm" variant="flat" onPress={() => confirmToggleEnabled(user)}>
                        {user.enabled ? "停用" : "启用"}
                      </Button>
                      <Button isDisabled={user.builtIn} size="sm" variant="flat" onPress={() => setResetTarget(user)}>
                        重置密码
                      </Button>
                      <Button color="danger" isDisabled={user.builtIn} size="sm" variant="light" onPress={() => deleteUser(user)}>
                        删除
                      </Button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      </Section>

      <Section title="数据库" description="基础数据维护">
        <Alert
          tone="warning"
          title="初始化会按当前配置重建数据库结构"
          actions={(
            <Button color="danger" variant="flat" isLoading={initializing} startContent={initializing ? null : <Icon name="database" />} onPress={() => void onInitializeDatabase()}>
              初始化数据库
            </Button>
          )}
        >
          它会补齐管理端所需的基础数据，可能影响现有数据，执行后无法撤销；点下按钮后还会再确认一次。
        </Alert>
      </Section>

      <Section
        title="客户端发布"
        description="上传受校验的发布包，按实现、平台与架构维护版本轨道；设为最新后客户端才会收到升级提示。"
        actions={<>
          <Button variant="flat" isLoading={loadingDownloads} startContent={loadingDownloads ? null : <Icon name="refresh" />} onPress={() => void loadDownloadLinks()}>
            刷新
          </Button>
          <Button variant="bordered" startContent={<Icon name="link" />} onPress={openCreateLink}>
            新增外链
          </Button>
          <Button color="primary" startContent={<Icon name="upload" />} onPress={packageModal.onOpen}>
            上传发布包
          </Button>
        </>}
      >
        <TableWrap>
          <table className="bd-table jd-stack ms-table ms-release-table" aria-label="客户端发布版本">
            <thead>
              <tr>
                <th scope="col">名称</th>
                <th scope="col">实现 / 平台</th>
                <th scope="col">版本</th>
                <th scope="col">校验</th>
                <th scope="col">启用</th>
                <th scope="col" className="ms-col-actions">操作</th>
              </tr>
            </thead>
            <tbody>
              {loadingDownloads && downloadLinks.length === 0 ? <TableLoadingRow colSpan={6} /> : null}
              {!loadingDownloads && downloadLinks.length === 0 ? (
                <TableStateRow colSpan={6}>
                  <Empty
                    icon="upload"
                    title="暂无客户端版本"
                    description="上传第一个发布包后会出现在公开下载页。"
                    actions={<Button color="primary" size="sm" startContent={<Icon name="upload" size={14} />} onPress={packageModal.onOpen}>上传发布包</Button>}
                  />
                </TableStateRow>
              ) : null}
              {downloadLinks.map((link) => {
                const pending = pendingLinkIds.has(link.id);
                return (
                  <tr key={link.id}>
                    <td className="ms-wrap">
                      <div className="ms-cell-main">
                        <span className="ms-cell-title">{link.displayName}</span>
                        {link.description ? <span className="ms-cell-sub">{link.description}</span> : null}
                        <a className="jd-link ms-mono ms-url" href={link.downloadUrl} rel="noopener noreferrer" target="_blank" title={link.downloadUrl}>
                          {link.downloadUrl}
                        </a>
                      </div>
                    </td>
                    <td>
                      <span className="ms-tags">
                        <Tag tone="info" plain>{implementationLabel(link.implementation)}</Tag>
                        <span>{platformLabel(link.platform)} · {archLabel(link.arch)}</span>
                      </span>
                    </td>
                    <td>
                      <span className="ms-tags">
                        <Tag tone="neutral" plain className="bd-num">{link.version ? `v${link.version}` : "未标版本"}</Tag>
                        {link.isLatest ? <Tag tone="success">最新</Tag> : null}
                        {link.hosted ? <Tag tone="info">托管</Tag> : null}
                      </span>
                    </td>
                    <td data-label="校验">
                      <div className="ms-cell-main">
                        <span className="bd-num">{link.fileSize ? formatBytes(link.fileSize) : "外部文件"}</span>
                        {link.sha256 ? <span className="ms-mono ms-cell-sub ms-sha" title={link.sha256}>{link.sha256}</span> : null}
                      </div>
                    </td>
                    <td>
                      <Toggle
                        label={`启用 ${link.displayName}`}
                        checked={link.enabled}
                        disabled={pending}
                        busy={pending}
                        onChange={() => void toggleLinkEnabled(link)}
                      />
                    </td>
                    <td className="jd-cell-actions ms-col-actions">
                      <div className="ms-row-actions">
                        <Button size="sm" variant="flat" onPress={() => openEditLink(link)}>
                          编辑
                        </Button>
                        {!link.isLatest && link.version ? (
                          <Button size="sm" variant="flat" onPress={() => void markLinkLatest(link)}>
                            设为最新
                          </Button>
                        ) : null}
                        <Button size="sm" color="danger" variant="light" onPress={() => deleteLink(link)}>
                          删除
                        </Button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </TableWrap>
      </Section>

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
    ? "填写新密码"
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
        <ModalHeader className="ms-modal-title">重置「{user?.username}」的密码</ModalHeader>
        <ModalBody className="ms-modal-body">
          <TextField
            autoComplete="new-password"
            label="新密码"
            type="password"
            value={password}
            onChange={setPassword}
            help="至少 6 位"
            error={password ? passwordError : ""}
          />
          <TextField
            autoComplete="new-password"
            label="确认新密码"
            type="password"
            value={confirmPassword}
            onChange={setConfirmPassword}
            error={confirmError}
          />
        </ModalBody>
        <ModalFooter>
          <Button variant="light" onPress={onClose} isDisabled={saving}>
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
    case "android":
      return "Android";
    default:
      return impl;
  }
}

const IMPLEMENTATION_OPTIONS: Array<{ value: ClientImplementation; label: string }> = [
  { value: "go", label: "Go" },
  { value: "csharp", label: ".NET" },
  { value: "java", label: "Java" },
  { value: "android", label: "Android" },
];

function platformOptions(implementation: ClientImplementation): Array<{ value: ClientPlatform; label: string; disabled?: boolean }> {
  return [
    { value: "any", label: "跨平台" },
    { value: "windows", label: "Windows" },
    { value: "linux", label: "Linux" },
    { value: "macos", label: "macOS" },
    { value: "android", label: "Android", disabled: implementation !== "android" },
  ];
}

const ARCH_OPTIONS: Array<{ value: ClientArch; label: string }> = [
  { value: "any", label: "跨架构" },
  { value: "x64", label: "x86_64" },
  { value: "arm64", label: "ARM64" },
];

function TextAreaField({ label, value, onChange, placeholder, optional }: {
  label: string; value: string; onChange: (value: string) => void; placeholder?: string; optional?: boolean;
}) {
  const id = useId();
  return (
    <Field label={label} htmlFor={id} optional={optional}>
      <textarea id={id} className="bd-input" rows={3} value={value} placeholder={placeholder} onChange={(event) => onChange(event.target.value)} />
    </Field>
  );
}

interface UploadClientPackageModalProps {
  disclosure: ReturnType<typeof useDisclosure>;
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
      notify("还缺发布包、版本号或显示名称：补齐后再上传", "error");
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
      disclosure.onClose();
      onSaved();
    } catch (error) {
      notifyError(error, "发布包上传失败");
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal isOpen={disclosure.isOpen} onOpenChange={disclosure.onOpenChange} size="2xl" scrollBehavior="inside">
      <ModalContent>
        {(onClose) => (
          <>
            <ModalHeader className="ms-modal-head">
              <span className="ms-modal-title">上传客户端发布包</span>
              <span className="ms-modal-desc">服务端计算大小与 SHA-256；设为最新后客户端才会收到升级提示。</span>
            </ModalHeader>
            <ModalBody className="ms-modal-body">
              <label
                htmlFor="client-package-file"
                className="ms-drop"
                data-dragging={dragging || undefined}
                data-filled={file ? true : undefined}
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
                <span className="ms-drop-icon" aria-hidden="true"><Icon name={file ? "file" : "upload"} size={22} /></span>
                <span className="ms-drop-title">{file ? file.name : "拖入发布包，或选择文件"}</span>
                <span className="ms-drop-desc bd-num">{file ? `${formatBytes(file.size)} · 换一个文件就再拖入或选择` : "APK、JAR、ZIP、tar.gz 均按二进制原样托管"}</span>
              </label>

              <div className="bd-form-grid ms-modal-grid3">
                <SelectField
                  label="实现"
                  value={implementation}
                  onChange={(value) => { if (value) chooseImplementation(value); }}
                  options={IMPLEMENTATION_OPTIONS}
                />
                <SelectField
                  label="操作系统"
                  disabled={implementation === "android"}
                  value={platform}
                  onChange={(value) => { if (value) setPlatform(value); }}
                  options={platformOptions(implementation)}
                />
                <SelectField
                  label="架构"
                  disabled={implementation === "android"}
                  value={arch}
                  onChange={(value) => { if (value) setArch(value); }}
                  options={ARCH_OPTIONS}
                />
              </div>

              <div className="bd-form-grid">
                <TextField required label="版本号" maxLength={32} placeholder="1.4.0" value={version} onChange={setVersion} />
                <TextField required label="显示名称" placeholder="Android 客户端 1.4.0" value={displayName} onChange={setDisplayName} />
                <TextField optional label="最低支持版本" maxLength={32} placeholder="1.2.0" value={minSupportedVersion} onChange={setMinSupportedVersion} />
                <TextField optional label="更新说明 URL" placeholder="https://…" value={changelogUrl} onChange={setChangelogUrl} />
              </div>
              <TextAreaField optional label="版本说明" value={description} onChange={setDescription} />
              <div className="ms-toggle-row">
                <Toggle checked={enabled} onChange={(value) => {
                  setEnabled(value);
                  if (!value) setIsLatest(false);
                }}>公开下载</Toggle>
                <Toggle disabled={!enabled} checked={isLatest} onChange={setIsLatest}>设为此目标的最新版本</Toggle>
              </div>
            </ModalBody>
            <ModalFooter>
              <Button variant="light" onPress={onClose} isDisabled={saving}>取消</Button>
              <Button color="primary" isLoading={saving} startContent={saving ? null : <Icon name="upload" />} onPress={() => void upload()}>校验并上传</Button>
            </ModalFooter>
          </>
        )}
      </ModalContent>
    </Modal>
  );
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
      notify("还缺版本号、名称或下载 URL：补齐后再保存", "error");
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
      notify("外部链接要设为最新版本，先填 Release 资产的 SHA-256 和文件字节数", "error");
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
      disclosure.onClose();
      onSaved();
    } catch (error) {
      notifyError(error, "保存失败");
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal isOpen={disclosure.isOpen} onOpenChange={disclosure.onOpenChange} size="lg" scrollBehavior="inside">
      <ModalContent>
        {(onClose) => (
          <>
            <ModalHeader className="ms-modal-title">{link ? `编辑下载链接 #${link.id}` : "新增下载链接"}</ModalHeader>
            <ModalBody className="ms-modal-body">
              <div className="bd-form-grid ms-modal-grid3">
                <SelectField
                  label="实现"
                  value={implementation}
                  onChange={(value) => { if (value) chooseImplementation(value); }}
                  options={[
                    { value: "java", label: "Java" },
                    { value: "go", label: "Go" },
                    { value: "csharp", label: ".NET" },
                    { value: "android", label: "Android" },
                  ]}
                />
                <SelectField
                  label="操作系统"
                  disabled={implementation === "android"}
                  value={platform}
                  onChange={(value) => { if (value) setPlatform(value); }}
                  options={platformOptions(implementation)}
                />
                <SelectField
                  label="架构"
                  disabled={implementation === "android"}
                  value={arch}
                  onChange={(value) => { if (value) setArch(value); }}
                  options={ARCH_OPTIONS}
                />
              </div>
              <TextField label="版本号" value={version} onChange={setVersion} maxLength={32} required placeholder="1.4.0" />
              <TextField label="名称" value={displayName} onChange={setDisplayName} maxLength={120} required placeholder="Java 客户端 1.2.0" />
              <TextField
                disabled={link?.hosted === true}
                label="下载 URL"
                value={downloadUrl}
                onChange={setDownloadUrl}
                maxLength={1024}
                required
                placeholder="https://..."
              />
              <div className="bd-form-grid ms-sha-grid">
                <TextField
                  disabled={link?.hosted === true}
                  label="SHA-256"
                  value={sha256}
                  onChange={setSha256}
                  maxLength={64}
                  placeholder="Release 资产的 64 位摘要"
                />
                <TextField
                  disabled={link?.hosted === true}
                  label="文件字节数"
                  type="number"
                  min={1}
                  value={fileSize}
                  onChange={setFileSize}
                  placeholder="18432000"
                />
                <div className="bd-col-full bd-help">
                  {link?.hosted
                    ? "托管包的地址、摘要和大小由服务端计算，不能手动修改。"
                    : "GitHub Release 外链标记为最新版本时，摘要和字节数必填；客户端会在安装前校验。"}
                </div>
              </div>
              <TextAreaField
                optional
                label="说明"
                value={description}
                onChange={setDescription}
                placeholder="哈希值、签名说明等"
              />
              <div className="bd-form-grid">
                <TextField optional label="最低支持版本" maxLength={32} value={minSupportedVersion} onChange={setMinSupportedVersion} />
                <TextField optional label="更新说明 URL" value={changelogUrl} onChange={setChangelogUrl} />
              </div>
              <div className="ms-order-row">
                <TextField
                  label="排序"
                  type="number"
                  value={displayOrder}
                  onChange={setDisplayOrder}
                  className="ms-order-field"
                />
                <div className="ms-toggle-row">
                  <Toggle checked={enabled} onChange={(value) => {
                    setEnabled(value);
                    if (!value) setIsLatest(false);
                  }}>启用</Toggle>
                  <Toggle disabled={!enabled} checked={isLatest} onChange={setIsLatest}>最新版本</Toggle>
                </div>
              </div>
            </ModalBody>
            <ModalFooter>
              <Button variant="light" onPress={onClose}>
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
