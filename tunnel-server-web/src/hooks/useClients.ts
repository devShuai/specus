import { useCallback, useEffect, useState } from "react";
import { adminApi } from "../api/client";
import type { Client } from "../api/types";
import { notifyError } from "../components/toast";

// useClients loads the client list used by selects/filters across panels.
export function useClients(): { clients: Client[]; reload: () => Promise<void> } {
  const [clients, setClients] = useState<Client[]>([]);
  const reload = useCallback(async () => {
    try {
      setClients(await adminApi.listClients());
    } catch (error) {
      notifyError(error, "加载客户端失败");
    }
  }, []);
  useEffect(() => {
    void reload();
  }, [reload]);
  return { clients, reload };
}
