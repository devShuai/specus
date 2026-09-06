export const CLIENT_ONBOARDING_STEPS = [
  { title: "下载客户端", detail: "在目标设备上选择对应系统和架构，安装客户端。", href: "#/downloads", action: "选择平台与下载" },
  { title: "创建接入凭证并保存配置", detail: "在“客户端”页新建接入凭证，保存仅显示一次的 client.jsonc。此时尚未生成客户端实例。", href: "#/clients", action: "创建接入凭证" },
  { title: "启动客户端，确认设备上线", detail: "使用配置启动客户端；首次登录后自动生成实例。回到实例列表检查是否在线，再发布服务。", href: "#/help/go", action: "查看启动说明" },
  { title: "发布服务并验证访问", detail: "选择已注册的客户端实例，明确访问范围后创建 HTTP 路由或端口映射；打开访问地址，亲自确认目标应用可用。", href: "#/http-routes", action: "发布 HTTP 服务" },
] as const;

/** The generated config is sensitive: callers must keep it in memory only. */
export function buildClientStartupConfig(serverBaseUrl: string, apiKey: string, secret: string): string {
  let url: URL;
  try {
    url = new URL(serverBaseUrl.trim());
  } catch {
    throw new Error("请输入完整的 HTTP/HTTPS 服务端地址，例如 https://server.example");
  }
  if (!/^https?:$/.test(url.protocol) || url.username || url.password || url.search || url.hash) {
    throw new Error("请使用不含用户名、密码、查询参数或片段的 HTTP/HTTPS 服务端地址");
  }
  if (!apiKey.trim() || !secret) throw new Error("接入凭证不完整，请重新创建或重置凭证");
  return JSON.stringify({ serverBaseUrl: url.href.replace(/\/+$/, ""), apiKey: apiKey.trim(), secret }, null, 2) + "\n";
}

export function clientOnboardingStatus(input: { loading: boolean; error: boolean; online: number; registered: number; credentials: number }) {
  if (input.loading) return "正在检查接入状态…";
  if (input.error) return "接入状态未知，请重新加载后再继续。";
  if (input.online > 0) return `已有 ${input.online} 台设备在线，可选择实例发布服务；目标应用仍需实际验证。`;
  if (input.registered > 0) return "已注册的设备均未上线，请启动客户端并检查网络。";
  if (input.credentials > 0) return "凭证已就绪，尚无客户端实例；请先启动客户端，不必先创建路由。";
  return "从下载客户端开始，完成接入后再发布第一个服务。";
}
