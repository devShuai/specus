import { useState, type FormEvent } from "react";
import { Button, Card, CardBody, CardHeader, Divider, Input } from "@heroui/react";
import { useAuth } from "../auth/AuthContext";
import { notifyError } from "../components/toast";

export function LoginPage() {
  const { oidcConfig, loginHint, passwordLogin, startOidcLogin } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const passwordEnabled = oidcConfig?.passwordLoginEnabled ?? true;
  const oidcEnabled = oidcConfig?.configured ?? false;

  const onSubmit = async (event: FormEvent) => {
    event.preventDefault();
    setSubmitting(true);
    try {
      await passwordLogin(username, password);
    } catch (error) {
      notifyError(error, "登录失败");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center p-4">
      <Card className="w-full max-w-md">
        <CardHeader className="flex flex-col items-start gap-1">
          <h1 className="text-xl font-semibold">shuai-tunnel 管理后台</h1>
          <p className="text-small text-default-500">{loginHint}</p>
        </CardHeader>
        <CardBody className="gap-4">
          {passwordEnabled && (
            <form className="flex flex-col gap-3" onSubmit={onSubmit}>
              <Input
                label="用户名"
                value={username}
                onValueChange={setUsername}
                autoComplete="username"
                isRequired
              />
              <Input
                label="密码"
                type="password"
                value={password}
                onValueChange={setPassword}
                autoComplete="current-password"
                isRequired
              />
              <Button type="submit" color="primary" isLoading={submitting}>
                登录
              </Button>
            </form>
          )}

          {passwordEnabled && oidcEnabled && (
            <div className="flex items-center gap-3 text-tiny text-default-400">
              <Divider className="flex-1" />
              <span>或</span>
              <Divider className="flex-1" />
            </div>
          )}

          {oidcEnabled && (
            <Button variant="bordered" onPress={() => void startOidcLogin()}>
              使用 OIDC 登录
            </Button>
          )}

          {!passwordEnabled && !oidcEnabled && (
            <p className="text-small text-danger">
              未配置任何登录方式：请设置用户名/密码或 OIDC
            </p>
          )}
        </CardBody>
      </Card>
    </div>
  );
}
