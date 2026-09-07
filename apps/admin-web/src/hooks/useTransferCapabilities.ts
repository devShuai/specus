import { useEffect, useState } from "react";
import { fetchTransferCapabilities, tokenStore } from "../api/client";
import { parseTransferCapabilities, type TransferCapabilities } from "../lib/transferCapabilities";

export interface TransferCapabilityState {
  loading: boolean;
  snapshot: TransferCapabilities | null;
  error: string | null;
  refresh: () => void;
}

/** Scoped to this open confirmation and session; never persist account quotas or accept late responses. */
export function useTransferCapabilities(enabled: boolean): TransferCapabilityState {
  const token = enabled ? tokenStore.get() : null;
  const [revision, setRevision] = useState(0);
  const [state, setState] = useState<{ token: string | null; revision: number; loading: boolean; snapshot: TransferCapabilities | null; error: string | null } | null>(null);
  useEffect(() => {
    if (!enabled || !token) { setState(null); return; }
    const controller = new AbortController();
    let active = true;
    let expiry: ReturnType<typeof setTimeout> | undefined;
    const timeout = setTimeout(() => controller.abort(), 8000);
    setState({ token, revision, loading: true, snapshot: null, error: null });
    void fetchTransferCapabilities(controller.signal).then(parseTransferCapabilities).then((snapshot) => {
      if (!active || tokenStore.get() !== token) return;
      setState({ token, revision, loading: false, snapshot, error: null });
      // Snapshot is advisory. Do not leave an old account quota appearing current indefinitely.
      expiry = setTimeout(() => {
        if (active) setState({ token, revision, loading: false, snapshot: null, error: "额度快照已过时，请刷新额度；未重新核验前以实际上传结果为准。" });
      }, 60_000);
    }).catch((error: unknown) => {
      if (!active || tokenStore.get() !== token) return;
      setState({ token, revision, loading: false, snapshot: null,
        error: controller.signal.aborted ? "额度查询超时，请重试；当前额度未核验。" : error instanceof Error ? error.message : "额度读取失败，请重试。" });
    }).finally(() => clearTimeout(timeout));
    return () => { active = false; controller.abort(); clearTimeout(timeout); clearTimeout(expiry); };
  }, [enabled, token, revision]);
  const current = enabled && token && state?.token === token && state.revision === revision ? state : null;
  return { loading: Boolean(enabled && token && (!current || current.loading)), snapshot: current?.snapshot ?? null,
    error: current?.error ?? null, refresh: () => setRevision((value) => value + 1) };
}
