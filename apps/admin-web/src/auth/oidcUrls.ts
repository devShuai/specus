import type { OidcConfig } from "../api/types";

export function buildOidcRegistrationUrl(
  config: OidcConfig,
  authorizationUrl: URL,
): URL {
  if (!config.registrationEndpoint) {
    throw new Error("OIDC 注册地址未配置");
  }
  const registrationUrl = new URL(config.registrationEndpoint);
  const authorizationEndpoint = new URL(config.authorizationEndpoint);
  if (registrationUrl.origin !== authorizationEndpoint.origin) {
    throw new Error("OIDC 注册地址必须与授权地址同源");
  }
  registrationUrl.searchParams.set(
    "continue",
    `${authorizationUrl.pathname}${authorizationUrl.search}`,
  );
  registrationUrl.searchParams.set("client_id", config.clientId);
  return registrationUrl;
}
