import { useCallback, useEffect, useState } from "react";
import { adminApi } from "../api/client";
import type { Client } from "../api/types";
import { notifyError } from "../components/toast";

// useClients loads the client list used by selects/filters across panels.
export function useClients(): { clients: Client[]; loading: boolean; error: string | null; reload: () => Promise<void> } {
  const [clients, setClients] = useState<Client[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const reload = useCallback(async () => {
    setLoading(true);
    try {
      setClients(await adminApi.listClients());
      setError(null);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "加载客户端失败");
      notifyError(cause, "加载客户端失败");
    } finally {
      setLoading(false);
    }
  }, []);
  useEffect(() => {
    void reload();
  }, [reload]);
  return { clients, loading, error, reload };
}
