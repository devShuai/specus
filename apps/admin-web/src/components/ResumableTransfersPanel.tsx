import { useRef } from "react";
import { Button, Chip, Progress } from "@heroui/react";
import { formatBytes, formatDateTime } from "../lib/format";
import type { DirectOutgoingResume, DirectStoredReceive } from "../hooks/useDirectTransfer";

interface Props {
  storedReceives: DirectStoredReceive[];
  outgoingResumes: DirectOutgoingResume[];
  peerDisplayNames: Record<string, string>;
  onResumeOutgoing: (transferId: string, file?: File) => Promise<void>;
  onAbandonOutgoing: (transferId: string) => void;
  onAbandonReceive: (transferId: string) => void;
  onClearAll: () => void;
  onError: (message: string) => void;
}

function percent(done: number, total: number) {
  return total > 0 ? Math.min(100, Math.round((done / total) * 100)) : 100;
}

function expiryLabel(expiresAt: number | null) {
  return expiresAt ? `${formatDateTime(new Date(expiresAt).toISOString())} 前有效` : "";
}

/**
 * Interrupted chunked-resume transfers (protocol/spec/chunked-resume.md §9): receives kept in
 * this browser and sends that need the file selected again after a reload.
 */
export function ResumableTransfersPanel({
  storedReceives,
  outgoingResumes,
  peerDisplayNames,
  onResumeOutgoing,
  onAbandonOutgoing,
  onAbandonReceive,
  onClearAll,
  onError,
}: Props) {
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const reselectForRef = useRef("");
  const outgoing = outgoingResumes.filter((item) => !item.running || item.background);
  if (storedReceives.length === 0 && outgoing.length === 0) {
    return null;
  }
  const resume = (transferId: string, file?: File) => {
    void onResumeOutgoing(transferId, file).catch((error: unknown) => {
      onError(error instanceof Error ? error.message : "继续发送失败");
    });
  };

  return (
    <section className="mt-5 rounded-lg glass glass-border border p-4" aria-label="未完成的设备传输">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h2 className="text-base font-semibold text-zinc-950 dark:text-white">未完成的设备传输</h2>
          <div className="mt-1 text-tiny text-zinc-500 dark:text-zinc-400">
            已校验的分块保存在本机浏览器，24 小时内可从中断处继续；浏览器可能自行清除这些数据，过期数据在下次打开本页时删除。
          </div>
        </div>
        <Button size="sm" radius="sm" variant="light" onPress={onClearAll}>
          清除互传本地数据
        </Button>
      </div>
      <input
        ref={fileInputRef}
        type="file"
        className="hidden"
        aria-hidden="true"
        tabIndex={-1}
        onChange={(event) => {
          const file = event.target.files?.[0];
          event.target.value = "";
          if (file && reselectForRef.current) resume(reselectForRef.current, file);
          reselectForRef.current = "";
        }}
      />
      {storedReceives.length > 0 ? (
        <div className="mt-3 grid gap-2 md:grid-cols-2">
          {storedReceives.map((item) => (
            <div key={`receive:${item.transferId}`} className="rounded-lg border border-black/[0.07] p-3 dark:border-white/[0.08]">
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0">
                  <div className="truncate text-small font-medium">{item.fileName}</div>
                  <div className="mt-1 text-tiny text-zinc-500">
                    来自 {peerDisplayNames[item.sourcePeerId] ?? (item.sourceName || "对方设备")} · {formatBytes(item.receivedBytes)} / {formatBytes(item.sizeBytes)}
                  </div>
                </div>
                <Chip size="sm" radius="sm" variant="flat">{item.storage === "persistent" ? "已暂停" : "已暂停（仅内存）"}</Chip>
              </div>
              <Progress className="mt-2" aria-label={`${item.fileName} 已接收`} size="sm" value={percent(item.receivedBytes, item.sizeBytes)} />
              <div className="mt-2 text-tiny text-zinc-500">
                对方重新连接并继续发送后会自动续传，无需再次同意。{expiryLabel(item.expiresAt)}
              </div>
              <div className="mt-2 flex justify-end">
                <Button size="sm" radius="sm" variant="flat" onPress={() => onAbandonReceive(item.transferId)}>
                  放弃并删除
                </Button>
              </div>
            </div>
          ))}
        </div>
      ) : null}
      {outgoing.length > 0 ? (
        <div className="mt-3 grid gap-2 md:grid-cols-2">
          {outgoing.map((item) => (
            <div key={`send:${item.transferId}`} className="rounded-lg border border-black/[0.07] p-3 dark:border-white/[0.08]">
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0">
                  <div className="truncate text-small font-medium">{item.fileName}</div>
                  <div className="mt-1 text-tiny text-zinc-500">
                    发给 {peerDisplayNames[item.targetPeerId] ?? (item.targetName || "对方设备")} · 对方已收 {formatBytes(item.ackedBytes)} / {formatBytes(item.sizeBytes)}
                  </div>
                </div>
                <Chip size="sm" radius="sm" variant="flat" color={item.running ? "primary" : "default"}>
                  {item.running ? "续传中" : "未完成的发送"}
                </Chip>
              </div>
              <Progress className="mt-2" aria-label={`${item.fileName} 对方已收`} size="sm" value={percent(item.ackedBytes, item.sizeBytes)} />
              <div className="mt-2 text-tiny text-zinc-500">
                {item.hasSource
                  ? "原文件仍在本页，可以继续发送。"
                  : "页面刷新后需要重新选择同一文件（大小必须一致，内容会逐块核对）。"}
                {expiryLabel(item.expiresAt)}
              </div>
              {!item.running ? (
                <div className="mt-2 flex justify-end gap-2">
                  <Button size="sm" radius="sm" variant="flat" onPress={() => onAbandonOutgoing(item.transferId)}>
                    放弃
                  </Button>
                  {item.hasSource ? (
                    <Button size="sm" radius="sm" color="primary" onPress={() => resume(item.transferId)}>
                      继续发送
                    </Button>
                  ) : (
                    <Button
                      size="sm"
                      radius="sm"
                      color="primary"
                      onPress={() => {
                        reselectForRef.current = item.transferId;
                        fileInputRef.current?.click();
                      }}
                    >
                      重新选择文件继续
                    </Button>
                  )}
                </div>
              ) : null}
            </div>
          ))}
        </div>
      ) : null}
    </section>
  );
}
