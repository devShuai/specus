import { useEffect, useRef } from "react";
import { tokenStore } from "../api/client";
import type { LiveConnectionEvent } from "../api/types";

const RECONNECT_DELAYS_MS = [1000, 2000, 5000, 10000];
const AUTH_CLOSE_CODE = 4401;

interface FeedOptions {
  enabled: boolean;
  onEvent: (event: LiveConnectionEvent) => void;
  onAuthError: () => void;
}

// useConnectionsFeed maintains the /ws/connections subscription with backoff reconnect.
// The token is passed as a query param because browsers cannot set WS request headers.
export function useConnectionsFeed({ enabled, onEvent, onAuthError }: FeedOptions): void {
  const onEventRef = useRef(onEvent);
  const onAuthErrorRef = useRef(onAuthError);
  onEventRef.current = onEvent;
  onAuthErrorRef.current = onAuthError;

  useEffect(() => {
    if (!enabled) {
      return;
    }
    let socket: WebSocket | null = null;
    let attempt = 0;
    let reconnectTimer: number | null = null;
    let closed = false;

    const connect = () => {
      const token = tokenStore.get();
      if (!token) {
        return;
      }
      const proto = window.location.protocol === "https:" ? "wss" : "ws";
      const url = `${proto}://${window.location.host}/ws/connections?token=${encodeURIComponent(token)}`;
      socket = new WebSocket(url);

      socket.onopen = () => {
        attempt = 0;
      };
      socket.onmessage = (message) => {
        try {
          const event = JSON.parse(message.data as string) as LiveConnectionEvent;
          if (event && event.connection) {
            onEventRef.current(event);
          }
        } catch {
          // Ignore malformed frames.
        }
      };
      socket.onclose = (event) => {
        socket = null;
        if (closed) {
          return;
        }
        if (event.code === AUTH_CLOSE_CODE) {
          onAuthErrorRef.current();
          return;
        }
        const delay = RECONNECT_DELAYS_MS[Math.min(attempt, RECONNECT_DELAYS_MS.length - 1)];
        attempt += 1;
        reconnectTimer = window.setTimeout(connect, delay);
      };
      socket.onerror = () => {
        socket?.close();
      };
    };

    connect();

    return () => {
      closed = true;
      if (reconnectTimer !== null) {
        window.clearTimeout(reconnectTimer);
      }
      socket?.close();
    };
  }, [enabled]);
}
