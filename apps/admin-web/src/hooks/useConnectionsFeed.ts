import { useEffect, useRef } from "react";
import { adminApi, tokenStore } from "../api/client";
import type { LiveConnectionEvent } from "../api/types";

const RECONNECT_DELAYS_MS = [1000, 2000, 5000, 10000];
const AUTH_CLOSE_CODE = 4401;
const MAX_BUFFERED_EVENTS = 4096;
const SNAPSHOT_INTERVAL_MS = 60_000;
const SNAPSHOT_RETRY_MS = 2_000;

interface FeedOptions {
  enabled: boolean;
  onEvent: (event: LiveConnectionEvent) => void;
  onResync: () => Promise<void>;
  onAuthError: () => void;
}

// useConnectionsFeed maintains the /ws/connections subscription with backoff reconnect.
export function useConnectionsFeed({ enabled, onEvent, onResync, onAuthError }: FeedOptions): void {
  const onEventRef = useRef(onEvent);
  const onResyncRef = useRef(onResync);
  const onAuthErrorRef = useRef(onAuthError);
  onEventRef.current = onEvent;
  onResyncRef.current = onResync;
  onAuthErrorRef.current = onAuthError;

  useEffect(() => {
    if (!enabled) {
      return;
    }
    let socket: WebSocket | null = null;
    let attempt = 0;
    let reconnectTimer: number | null = null;
    let snapshotTimer: number | null = null;
    let closed = false;
    let syncGeneration = 0;
    let syncing = false;
    let syncOverflowed = false;
    let bufferedEvents: LiveConnectionEvent[] = [];

    const dispatch = (event: LiveConnectionEvent) => {
      if (syncing) {
        if (bufferedEvents.length >= MAX_BUFFERED_EVENTS) {
          bufferedEvents = [];
          syncOverflowed = true;
          return;
        }
        bufferedEvents.push(event);
        return;
      }
      onEventRef.current(event);
    };

    const resync = async (currentSocket: WebSocket) => {
      const generation = syncGeneration + 1;
      syncGeneration = generation;
      syncing = true;
      bufferedEvents = [];
      syncOverflowed = false;
      for (;;) {
        try {
          await onResyncRef.current();
        } catch {
          if (
            closed
            || socket !== currentSocket
            || syncGeneration !== generation
            || currentSocket.readyState !== WebSocket.OPEN
          ) {
            return;
          }
          await new Promise<void>((resolve) => window.setTimeout(resolve, SNAPSHOT_RETRY_MS));
          continue;
        }
        if (
          closed
          || socket !== currentSocket
          || syncGeneration !== generation
          || currentSocket.readyState !== WebSocket.OPEN
        ) {
          return;
        }
        if (syncOverflowed) {
          bufferedEvents = [];
          syncOverflowed = false;
          continue;
        }
        const replay = bufferedEvents;
        bufferedEvents = [];
        syncing = false;
        replay.forEach((event) => onEventRef.current(event));
        return;
      }
    };

    const connect = async () => {
      const token = tokenStore.get();
      if (!token) {
        return;
      }
      let ticket: string;
      try {
        ticket = (await adminApi.createWebSocketTicket("connections")).ticket;
      } catch {
        if (!closed) {
          const delay = RECONNECT_DELAYS_MS[Math.min(attempt, RECONNECT_DELAYS_MS.length - 1)];
          attempt += 1;
          reconnectTimer = window.setTimeout(() => void connect(), delay);
        }
        return;
      }
      if (closed) {
        return;
      }
      const proto = window.location.protocol === "https:" ? "wss" : "ws";
      const url = `${proto}://${window.location.host}/ws/connections?ticket=${encodeURIComponent(ticket)}`;
      socket = new WebSocket(url);

      socket.onopen = () => {
        attempt = 0;
        const currentSocket = socket as WebSocket;
        const scheduleSnapshot = () => {
          if (closed || socket !== currentSocket || currentSocket.readyState !== WebSocket.OPEN) {
            return;
          }
          snapshotTimer = window.setTimeout(() => {
            void resync(currentSocket).finally(scheduleSnapshot);
          }, SNAPSHOT_INTERVAL_MS);
        };
        void resync(currentSocket).finally(scheduleSnapshot);
      };
      socket.onmessage = (message) => {
        try {
          const event = JSON.parse(message.data as string) as LiveConnectionEvent;
          if (event && event.connection) {
            dispatch(event);
          }
        } catch {
          // Ignore malformed frames.
        }
      };
      socket.onclose = (event) => {
        socket = null;
        if (snapshotTimer !== null) {
          window.clearTimeout(snapshotTimer);
          snapshotTimer = null;
        }
        syncGeneration += 1;
        syncing = false;
        bufferedEvents = [];
        syncOverflowed = false;
        if (closed) {
          return;
        }
        if (event.code === AUTH_CLOSE_CODE) {
          onAuthErrorRef.current();
          return;
        }
        const delay = RECONNECT_DELAYS_MS[Math.min(attempt, RECONNECT_DELAYS_MS.length - 1)];
        attempt += 1;
        reconnectTimer = window.setTimeout(() => void connect(), delay);
      };
      socket.onerror = () => {
        socket?.close();
      };
    };

    void connect();

    return () => {
      closed = true;
      syncGeneration += 1;
      if (reconnectTimer !== null) {
        window.clearTimeout(reconnectTimer);
      }
      if (snapshotTimer !== null) {
        window.clearTimeout(snapshotTimer);
      }
      socket?.close();
    };
  }, [enabled]);
}
