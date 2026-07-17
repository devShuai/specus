import { useCallback, useEffect, useMemo, useRef } from "react";
import { SyncedDiagram } from "../components/SyncedDiagram";
import type { DiagramEmbedApi } from "../components/SyncedDiagram";
import type { WhiteboardInboundEvent } from "../components/SyncedWhiteboard";

/**
 * 可嵌入网页的流程图编辑器（iframe + postMessage 协议）。
 *
 * 宿主页面通过 `<iframe src="…/diagram-embed?origin=<宿主 origin>">` 嵌入，
 * 消息均为 JSON 对象，子页面发出的消息带 `source: "shuai-diagram-embed"`：
 *
 * 子页面 → 宿主：
 *   { event: "init" }                     编辑器就绪，可以发送 load
 *   { event: "change" }                   本地内容有改动（节流约 800ms）
 *   { event: "load", ok: true }           load 完成
 *   { event: "save", update }             save 结果，update 为 base64 文档快照
 *   { event: "export", format, data }     export 结果，svg 为源码、png 为 dataURL
 *   { event: "error", action?, message }  指令执行失败
 *
 * 宿主 → 子页面（可附带 id 字段，回复原样带回，用于请求配对）：
 *   { action: "load", update? }           载入 base64 快照，缺省表示空白文档
 *   { action: "save" }                    请求当前文档快照
 *   { action: "export", format? }         导出 "svg"（默认）或 "png"
 *
 * 安全：带 `origin` 参数时只与该 origin 通信；否则锁定第一条有效消息的
 * 来源。含文档数据的消息只会发往已锁定的 origin，不会广播。
 */

const EMBED_MESSAGE_SOURCE = "shuai-diagram-embed";
const EMBED_CHANGE_THROTTLE_MS = 800;
const EMBED_EVENTS: WhiteboardInboundEvent[] = [];

function noopSend() {
  // 嵌入模式没有协作房间，丢弃同步载荷。
}

function createEmbedPeerId() {
  const uuid = globalThis.crypto?.randomUUID?.();
  return `embed-${uuid ?? `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 10)}`}`;
}

function blobToDataUrl(blob: Blob) {
  return new Promise<string>((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result));
    reader.onerror = () => reject(reader.error ?? new Error("读取导出数据失败"));
    reader.readAsDataURL(blob);
  });
}

export function DiagramEmbedPage() {
  const config = useMemo(() => {
    const params = new URLSearchParams(window.location.search);
    return {
      origin: params.get("origin")?.trim() || null,
      readOnly: params.get("readonly") === "1",
      boardKey: `embed:${params.get("key")?.trim() || "default"}`,
    };
  }, []);
  const peerId = useMemo(createEmbedPeerId, []);
  const isEmbedded = window.parent !== window;

  const apiRef = useRef<DiagramEmbedApi | null>(null);
  const lockedOriginRef = useRef<string | null>(config.origin);
  const announcedInitRef = useRef(false);
  const changeTimerRef = useRef<number | null>(null);

  const postToHost = useCallback((message: Record<string, unknown>, targetOrigin?: string) => {
    if (!isEmbedded) return;
    window.parent.postMessage(
      { source: EMBED_MESSAGE_SOURCE, ...message },
      targetOrigin ?? lockedOriginRef.current ?? "*",
    );
  }, [isEmbedded]);

  const handleEmbedApiChange = useCallback((api: DiagramEmbedApi | null) => {
    apiRef.current = api;
    if (api && !announcedInitRef.current) {
      announcedInitRef.current = true;
      postToHost({ event: "init" });
    }
  }, [postToHost]);

  const handleLocalChange = useCallback(() => {
    if (!isEmbedded || changeTimerRef.current !== null) return;
    changeTimerRef.current = window.setTimeout(() => {
      changeTimerRef.current = null;
      postToHost({ event: "change" });
    }, EMBED_CHANGE_THROTTLE_MS);
  }, [isEmbedded, postToHost]);

  useEffect(() => () => {
    if (changeTimerRef.current !== null) {
      window.clearTimeout(changeTimerRef.current);
      changeTimerRef.current = null;
    }
  }, []);

  useEffect(() => {
    if (!isEmbedded) return;
    const handleMessage = (event: MessageEvent) => {
      if (event.source !== window.parent) return;
      const data = event.data as Record<string, unknown> | null;
      if (!data || typeof data !== "object" || typeof data.action !== "string") return;
      if (lockedOriginRef.current) {
        if (event.origin !== lockedOriginRef.current) return;
      } else {
        lockedOriginRef.current = event.origin;
      }
      const reply = (message: Record<string, unknown>) => postToHost(
        data.id === undefined ? message : { ...message, id: data.id },
        event.origin,
      );
      const fail = (action: string, error: unknown) => reply({
        event: "error",
        action,
        message: error instanceof Error ? error.message : "指令执行失败",
      });
      const api = apiRef.current;
      if (!api) {
        fail(data.action, new Error("编辑器尚未就绪"));
        return;
      }
      switch (data.action) {
        case "load": {
          try {
            if (typeof data.update === "string" && data.update.length > 0) {
              api.loadSnapshot(data.update);
            }
            reply({ event: "load", ok: true });
          } catch (error) {
            fail("load", error);
          }
          return;
        }
        case "save": {
          try {
            reply({ event: "save", update: api.getSnapshot() });
          } catch (error) {
            fail("save", error);
          }
          return;
        }
        case "export": {
          const format = data.format === "png" ? "png" : "svg";
          try {
            if (format === "svg") {
              reply({ event: "export", format, data: api.exportSvg() });
            } else {
              void api.exportPng()
                .then(blobToDataUrl)
                .then((dataUrl) => reply({ event: "export", format, data: dataUrl }))
                .catch((error) => fail("export", error));
            }
          } catch (error) {
            fail("export", error);
          }
          return;
        }
        default:
          fail(data.action, new Error(`不支持的指令：${data.action}`));
      }
    };
    window.addEventListener("message", handleMessage);
    return () => window.removeEventListener("message", handleMessage);
  }, [isEmbedded, postToHost]);

  return (
    <main className="h-[100dvh] overflow-hidden bg-zinc-100 text-zinc-950 dark:bg-zinc-950 dark:text-white">
      <SyncedDiagram
        standalone
        boardKey={config.boardKey}
        roomId=""
        roomToken=""
        roomRole={config.readOnly ? "VIEWER" : "OWNER"}
        peerId={peerId}
        peerCount={0}
        isConnected={false}
        events={EMBED_EVENTS}
        onSend={noopSend}
        onEmbedApiChange={handleEmbedApiChange}
        onLocalChange={handleLocalChange}
      />
    </main>
  );
}
