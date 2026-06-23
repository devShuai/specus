import { useEffect, useState } from "react";
import {
  Button,
  Card,
  CardBody,
  CardHeader,
  Chip,
  Input,
  Select,
  SelectItem,
  Switch,
  Table,
  TableBody,
  TableCell,
  TableColumn,
  TableHeader,
  TableRow,
} from "@heroui/react";
import { adminApi } from "../../api/client";
import type { ManagementRole, ManagementUser, ManagementUserMutation } from "../../api/types";
import { notify, notifyError } from "../../components/toast";

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

  const updateUser = async (user: ManagementUser, patch: ManagementUserMutation) => {
    try {
      await adminApi.updateUser(user.username, patch);
      notify("用户已更新");
      await loadUsers();
    } catch (error) {
      notifyError(error, "更新用户失败");
    }
  };

  const resetPassword = async (user: ManagementUser) => {
    const password = window.prompt(`输入 ${user.username} 的新密码`);
    if (!password) {
      return;
    }
    await updateUser(user, { password });
  };

  const deleteUser = async (user: ManagementUser) => {
    if (!window.confirm(`确定删除用户 ${user.username} 吗？`)) {
      return;
    }
    try {
      await adminApi.deleteUser(user.username);
      notify("用户已删除");
      await loadUsers();
    } catch (error) {
      notifyError(error, "删除用户失败");
    }
  };

  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1.5fr)_minmax(360px,0.8fr)]">
      <Card shadow="none" className="rounded-md border border-default-200 bg-content1">
        <CardHeader className="flex items-start justify-between gap-4 px-5 pb-2 pt-5">
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

          <div className="overflow-x-auto">
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
              <TableBody emptyContent="暂无用户" isLoading={loadingUsers} items={users}>
                {(user) => (
                  <TableRow key={user.username}>
                    <TableCell>
                      <div className="font-medium text-foreground">{user.username}</div>
                      {user.builtIn ? <div className="text-tiny text-default-500">配置文件内置账号</div> : null}
                    </TableCell>
                    <TableCell>{user.tenantId}</TableCell>
                    <TableCell>
                      <Chip color={user.admin ? "primary" : "default"} size="sm" variant="flat">
                        {roleText(user.role)}
                      </Chip>
                    </TableCell>
                    <TableCell>
                      <Chip color={user.enabled ? "success" : "danger"} size="sm" variant="flat">
                        {user.enabled ? "启用" : "停用"}
                      </Chip>
                    </TableCell>
                    <TableCell className="whitespace-nowrap text-default-500">{formatTime(user.updatedAt)}</TableCell>
                    <TableCell>
                      <div className="flex justify-end gap-2">
                        <Button
                          isDisabled={user.builtIn}
                          radius="sm"
                          size="sm"
                          variant="flat"
                          onPress={() => void updateUser(user, { role: user.role === "ADMIN" ? "USER" : "ADMIN" })}
                        >
                          {user.role === "ADMIN" ? "设为普通" : "设为管理员"}
                        </Button>
                        <Button
                          isDisabled={user.builtIn}
                          radius="sm"
                          size="sm"
                          variant="flat"
                          onPress={() => void updateUser(user, { enabled: !user.enabled })}
                        >
                          {user.enabled ? "停用" : "启用"}
                        </Button>
                        <Button
                          isDisabled={user.builtIn}
                          radius="sm"
                          size="sm"
                          variant="flat"
                          onPress={() => void resetPassword(user)}
                        >
                          重置密码
                        </Button>
                        <Button
                          color="danger"
                          isDisabled={user.builtIn}
                          radius="sm"
                          size="sm"
                          variant="flat"
                          onPress={() => void deleteUser(user)}
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
        <CardHeader className="flex items-start justify-between gap-4 px-5 pb-2 pt-5">
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
  );
}

function roleText(role: ManagementRole) {
  return role === "ADMIN" ? "管理员" : "普通用户";
}

function formatTime(value: string | null) {
  if (!value) {
    return "-";
  }
  return new Date(value).toLocaleString();
}
