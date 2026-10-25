import { useCallback, useEffect, useRef, useState } from "react";
import { Button, Input, Modal, ModalBody, ModalContent, ModalFooter, ModalHeader } from "@heroui/react";
import { adminApi } from "../../api/client";
import type { HttpRoute } from "../../api/types";
import {
  describeConnectivityRefusal,
  formatCheckTime,
  OUTCOME_LABELS,
  validCheckPath,
  type ConnectivityCheckRefusal,
  type ConnectivityCheckResult,
} from "../../lib/connectivityCheck";
import { ConnectivityCheckResultView } from "./ConnectivityCheckResult";
import { Alert, Icon } from "../../components/ui";

const OUTCOME_TAG = { succeeded: "bd-tag--success", failed: "bd-tag--danger", unverified: "bd-tag--warning" } as const;

/** The latest check of one route, kept in page state only (never localStorage). */
export interface RouteCheckState {
  running: boolean;
  path: string;
  result?: ConnectivityCheckResult;
  refusal?: ConnectivityCheckRefusal;
  error?: string;
  /** Epoch ms until which the server asked to wait (Retry-After). */
  retryUntil?: number;
}

export interface RouteConnectivityChecks {
  state: (routeId: number) => RouteCheckState | undefined;
  start: (route: HttpRoute, path?: string) => void;
  open: (route: HttpRoute) => void;
  close: () => void;
  openRoute: HttpRoute | null;
  now: number;
}

/**
 * Connectivity checks of the routes on this page. A check starts only from start(), i.e. a click;
 * nothing here runs on mount, reload or polling (service-connectivity-check.md section 10).
 */
export function useRouteConnectivityChecks(): RouteConnectivityChecks {
  const [states, setStates] = useState<Record<number, RouteCheckState>>({});
  const runningRef = useRef<Set<number>>(new Set());
  const [openRoute, setOpenRoute] = useState<HttpRoute | null>(null);
  const [now, setNow] = useState(() => Date.now());

  const waiting = Object.values(states).some((state) => state.retryUntil !== undefined && state.retryUntil > now);
  useEffect(() => {
    if (!waiting) return undefined;
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [waiting]);

  const start = useCallback((route: HttpRoute, path?: string) => {
    if (runningRef.current.has(route.id)) return;
    const checkPath = path ?? "/";
    runningRef.current.add(route.id);
    setOpenRoute(route);
    setStates((current) => ({ ...current, [route.id]: { ...current[route.id], running: true, path: checkPath, error: undefined } }));
    void (async () => {
      let next: RouteCheckState;
      try {
        const answer = await adminApi.checkHttpRouteConnectivity(route.id, checkPath);
        if (answer.kind === "result") {
          next = { running: false, path: checkPath, result: answer.result };
        } else {
          const seconds = answer.refusal.retryAfterSeconds;
          next = {
            running: false,
            path: checkPath,
            refusal: answer.refusal,
            retryUntil: seconds && (answer.refusal.status === 429 || answer.refusal.status === 503)
              ? Date.now() + seconds * 1000
              : undefined,
          };
        }
      } catch (error) {
        next = { running: false, path: checkPath, error: error instanceof Error ? error.message : "检查请求失败" };
      } finally {
        runningRef.current.delete(route.id);
      }
      setNow(Date.now());
      setStates((current) => ({
        ...current,
        // A refusal keeps the last real result visible below its message.
        [route.id]: { ...next, result: next.result ?? (next.refusal || next.error ? current[route.id]?.result : undefined) },
      }));
    })();
  }, []);

  return {
    state: (routeId) => states[routeId],
    start,
    open: setOpenRoute,
    close: () => setOpenRoute(null),
    openRoute,
    now,
  };
}

function waitSeconds(state: RouteCheckState | undefined, now: number): number {
  if (!state?.retryUntil || state.retryUntil <= now) return 0;
  return Math.ceil((state.retryUntil - now) / 1000);
}

/** The per-route button: starts a check, then offers the latest result. */
export function RouteCheckButtons({ route, checks, compact = false }: { route: HttpRoute; checks: RouteConnectivityChecks; compact?: boolean }) {
  const state = checks.state(route.id);
  const wait = waitSeconds(state, checks.now);
  const label = state?.running ? "正在检查" : wait > 0 ? `${wait} 秒后可检查` : "检查连通性";
  return (
    <>
      <Button
        className={compact ? "min-w-0 px-2" : undefined}
        size="sm"
        variant="flat"
        isDisabled={Boolean(state?.running) || wait > 0}
        isLoading={Boolean(state?.running)}
        startContent={state?.running || wait > 0 ? null : <Icon name="activity" size={14} />}
        onPress={() => checks.start(route, state?.path)}
      >
        {label}
      </Button>
      {state && !state.running && (state.result || state.refusal || state.error) ? (
        <Button className={compact ? "min-w-0 px-2 acc-cc-result" : "acc-cc-result"} size="sm" variant="light" onPress={() => checks.open(route)}>
          {state.result ? (
            <>
              <span className={`bd-tag ${OUTCOME_TAG[state.result.outcome] ?? ""}`}>{OUTCOME_LABELS[state.result.outcome]}</span>
              <span className="bd-num jd-subtle"><span className="jd-sr-only">·</span>{formatCheckTime(state.result.checkedAt)}</span>
            </>
          ) : "查看结果"}
        </Button>
      ) : null}
    </>
  );
}

export function ConnectivityCheckModal({ checks }: { checks: RouteConnectivityChecks }) {
  const route = checks.openRoute;
  const state = route ? checks.state(route.id) : undefined;
  const [path, setPath] = useState("/");
  useEffect(() => {
    setPath(state?.path ?? "/");
    // Reset the field when another route opens, not on every state change of this one.
  }, [route?.id]);
  const wait = waitSeconds(state, checks.now);
  const pathValid = validCheckPath(path);
  const refusal = state?.refusal ? describeConnectivityRefusal(state.refusal) : null;
  return (
    <Modal isOpen={route != null} onClose={checks.close} size="lg" scrollBehavior="inside">
      <ModalContent>
        {() => (
          <>
            <ModalHeader className="flex flex-col gap-1">
              <span>连通性检查</span>
              {route ? (
                <span className="acc-dialog-sub">
                  {route.clientName} · <code className="font-mono">{route.route}</code>
                </span>
              ) : null}
            </ModalHeader>
            <ModalBody className="acc-dialog-body">
              <p className="bd-help acc-tight">
                从服务端经设备向目标发一次 HEAD（目标不支持时改发一次 GET），不读取响应内容、不携带凭据，最长 10 秒。
              </p>
              {state?.running ? <p role="status" className="acc-cc-running"><Icon name="loader" size={16} />正在检查…</p> : null}
              {refusal ? (
                <Alert role="alert" tone={refusal.unsupported ? "info" : "warning"}>
                  {refusal.message}
                  {wait > 0 ? `（${wait} 秒）` : ""}
                </Alert>
              ) : null}
              {state?.error ? <Alert role="alert" tone="danger" title="检查请求没有完成">{state.error}</Alert> : null}
              {state?.result ? <ConnectivityCheckResultView result={state.result} /> : null}
              {!state ? <p className="jd-muted">尚未检查。用下方的“开始检查”发起一次。</p> : null}
              <Input
                label="检查路径"
                description="默认为 /；可以填写健康检查地址，例如 /healthz。只能在该路由的目标地址之下。"
                value={path}
                onValueChange={setPath}
                isInvalid={!pathValid}
                errorMessage={pathValid ? undefined : "须以 / 开头，不含 ?、#、空白，也不能有 . 或 .. 路径段"}
                classNames={{ input: "font-mono" }}
              />
            </ModalBody>
            <ModalFooter>
              <Button variant="flat" onPress={checks.close}>
                关闭
              </Button>
              <Button
                color="primary"
                isDisabled={!route || !pathValid || Boolean(state?.running) || wait > 0}
                isLoading={Boolean(state?.running)}
                onPress={() => route && checks.start(route, path)}
              >
                {state?.running ? "正在检查" : wait > 0 ? `${wait} 秒后可检查` : state ? "重新检查" : "开始检查"}
              </Button>
            </ModalFooter>
          </>
        )}
      </ModalContent>
    </Modal>
  );
}
