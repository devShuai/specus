export const HTTP_ROUTE_AUTH_USERNAME_MAX_LENGTH = 120;
export const HTTP_ROUTE_AUTH_PASSWORD_MAX_LENGTH = 256;

export interface HttpRouteAuthDraft {
  enabled: boolean;
  username: string;
  password: string;
  passwordConfigured: boolean;
}

export interface HttpRouteAuthMutationFields {
  authEnabled: boolean;
  authUsername?: string;
  authPassword?: string;
}

/**
 * Validates the browser-facing HTTP Basic credentials without normalizing the password.
 * The password is deliberately kept byte-for-byte as entered; trim is only used to reject
 * a credential made entirely from whitespace.
 */
export function validateHttpRouteAuth(draft: HttpRouteAuthDraft): string {
  if (!draft.enabled) {
    return "";
  }

  const username = draft.username.trim();
  if (!username) {
    return "请输入访问用户名";
  }
  if (username.length > HTTP_ROUTE_AUTH_USERNAME_MAX_LENGTH) {
    return `访问用户名不能超过 ${HTTP_ROUTE_AUTH_USERNAME_MAX_LENGTH} 个字符`;
  }
  if (username.includes(":")) {
    return "访问用户名不能包含冒号";
  }
  if (/[\r\n]/u.test(username)) {
    return "访问用户名不能包含换行符";
  }

  const passwordProvided = Boolean(draft.password.trim());
  if (!draft.passwordConfigured && !passwordProvided) {
    return "请输入访问密码";
  }
  if (passwordProvided && draft.password.length > HTTP_ROUTE_AUTH_PASSWORD_MAX_LENGTH) {
    return `访问密码不能超过 ${HTTP_ROUTE_AUTH_PASSWORD_MAX_LENGTH} 个字符`;
  }
  return "";
}

/**
 * Disabling authentication only flips the gate and intentionally retains stored credentials.
 * An empty password is omitted so editing an existing route cannot erase its password hash.
 */
export function buildHttpRouteAuthMutation(draft: HttpRouteAuthDraft): HttpRouteAuthMutationFields {
  if (!draft.enabled) {
    return { authEnabled: false };
  }

  return {
    authEnabled: true,
    authUsername: draft.username.trim(),
    ...(draft.password.trim() ? { authPassword: draft.password } : {}),
  };
}
