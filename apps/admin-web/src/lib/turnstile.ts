import type { OidcConfig } from "../api/types";

type TurnstileAction = "login" | "register";

interface TurnstileRenderOptions {
  sitekey: string;
  action: TurnstileAction;
  execution: "execute";
  appearance: "interaction-only";
  theme: "auto";
  language: "auto";
  size: "flexible" | "compact";
  responseField: false;
  callback(token: string): void;
  "error-callback"(errorCode?: string): void;
  "expired-callback"(): void;
  "timeout-callback"(): void;
}

interface TurnstileApi {
  render(container: HTMLElement, options: TurnstileRenderOptions): string;
  execute(widgetId: string): void;
  remove(widgetId: string): void;
}

declare global {
  interface Window {
    turnstile?: TurnstileApi;
  }
}

const SCRIPT_MARKER = "data-specus-turnstile";
const CONTAINER_ID = "auth-turnstile";
const LOAD_TIMEOUT_MS = 12_000;
const CHALLENGE_TIMEOUT_MS = 120_000;
let loading: Promise<TurnstileApi> | null = null;

export async function executeTurnstile(
  config: OidcConfig | null,
  action: TurnstileAction,
): Promise<string> {
  if (!config?.turnstileEnabled) {
    return "";
  }
  const siteKey = config.turnstileSiteKey?.trim() ?? "";
  if (!siteKey) {
    throw new Error("人机验证未正确配置");
  }
  const container = document.getElementById(CONTAINER_ID);
  if (!container) {
    throw new Error("人机验证区域尚未就绪");
  }
  const api = await loadTurnstile();
  container.replaceChildren();

  return new Promise<string>((resolve, reject) => {
    let widgetId = "";
    let settled = false;
    const finish = (token?: string, message?: string) => {
      if (settled) return;
      settled = true;
      window.clearTimeout(timeout);
      if (widgetId) {
        try {
          api.remove(widgetId);
        } catch {
          container.replaceChildren();
        }
      }
      if (token) {
        resolve(token);
      } else {
        reject(new Error(message || "人机验证失败，请重试"));
      }
    };
    const timeout = window.setTimeout(
      () => finish(undefined, "人机验证超时，请重试"),
      CHALLENGE_TIMEOUT_MS,
    );

    try {
      widgetId = api.render(container, {
        sitekey: siteKey,
        action,
        execution: "execute",
        appearance: "interaction-only",
        theme: "auto",
        language: "auto",
        size: window.matchMedia("(max-width: 359px)").matches ? "compact" : "flexible",
        responseField: false,
        callback: (token) => finish(token),
        "error-callback": () => finish(undefined, "人机验证失败，请重试"),
        "expired-callback": () => finish(undefined, "人机验证已过期，请重试"),
        "timeout-callback": () => finish(undefined, "人机验证超时，请重试"),
      });
      api.execute(widgetId);
    } catch {
      finish(undefined, "人机验证初始化失败");
    }
  });
}

function loadTurnstile(): Promise<TurnstileApi> {
  if (typeof window === "undefined" || typeof document === "undefined") {
    return Promise.reject(new Error("当前环境无法执行人机验证"));
  }
  if (window.turnstile) {
    return Promise.resolve(window.turnstile);
  }
  if (loading) {
    return loading;
  }

  loading = new Promise<TurnstileApi>((resolve, reject) => {
    let settled = false;
    const finish = (error?: Error) => {
      if (settled) return;
      settled = true;
      window.clearTimeout(timeout);
      const api = window.turnstile;
      if (error || !api) {
        document.querySelector<HTMLScriptElement>(`script[${SCRIPT_MARKER}]`)?.remove();
        loading = null;
        reject(error || new Error("人机验证服务加载失败"));
        return;
      }
      resolve(api);
    };
    const timeout = window.setTimeout(
      () => finish(new Error("人机验证服务加载超时，请检查网络后重试")),
      LOAD_TIMEOUT_MS,
    );
    const existing = document.querySelector<HTMLScriptElement>(`script[${SCRIPT_MARKER}]`);
    if (existing) {
      existing.addEventListener("load", () => finish(), { once: true });
      existing.addEventListener("error", () => finish(new Error("人机验证服务加载失败")), { once: true });
      return;
    }

    const script = document.createElement("script");
    script.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
    script.async = true;
    script.defer = true;
    script.setAttribute(SCRIPT_MARKER, "true");
    script.addEventListener("load", () => finish(), { once: true });
    script.addEventListener("error", () => finish(new Error("人机验证服务加载失败")), { once: true });
    document.head.appendChild(script);
  });
  return loading;
}
