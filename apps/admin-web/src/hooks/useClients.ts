import { useCallback, useEffect, useRef, useState } from "react";
import { adminApi } from "../api/client";
import type { Client } from "../api/types";
import { notifyError } from "../components/toast";
import { watchOwnershipChanges } from "../lib/ownershipChanges";

// useClients loads the client list used by selects/filters across panels.
export function useClients(): { clients: Client[]; loading: boolean; error: string | null; reload: () => Promise<void> } {
  const readId = useRef(0);
  const [clients, setClients] = useState<Client[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const reload = useCallback(async () => {
    const read = ++readId.current;
    setLoading(true);
    try {
      const next = await adminApi.listClients();
      if (read !== readId.current) return;
      setClients(next);
      setError(null);
    } catch (cause) {
      if (read !== readId.current) return;
      setError(cause instanceof Error ? cause.message : "加载客户端失败");
      notifyError(cause, "加载客户端失败");
    } finally {
      if (read === readId.current) setLoading(false);
    }
  }, []);
  useEffect(() => {
    void reload();
  }, [reload]);
  useEffect(() => watchOwnershipChanges(() => { setClients([]); void reload(); }), [reload]);
  return { clients, loading, error, reload };
}
