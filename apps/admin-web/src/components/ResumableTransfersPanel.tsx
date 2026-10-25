import { useRef } from "react";
import { formatBytes } from "../lib/format";
import type { DirectOutgoingResume, DirectStoredReceive } from "../hooks/useDirectTransfer";
import { Icon, Progress, RelativeTime, Tag } from "./ui";
import { fileKindIcon } from "./transferFileKind";

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

/** True when there is something for the panel to show; the page uses it to decide on the tasks section. */
export function hasResumableTransfers(storedReceives: DirectStoredReceive[], outgoingResumes: DirectOutgoingResume[]) {
  return storedReceives.length > 0 || outgoingResumes.some((item) => !item.running || item.background);
}

/**
 * Interrupted chunked-resume transfers (protocol/spec/chunked-resume.md §9): receives kept in
 * this browser and sends that need the file selected again after a reload. Drawn as task rows, in
 * the same list language as the page's transfer tasks.
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
    <section className="tr-subsection" aria-label="未完成的设备传输">
      <div className="tr-subsection-head">
        <div className="min-w-0">
          <h3>未完成的设备传输</h3>
          <p>已校验的分块保存在本机浏览器，24 小时内可从中断处继续；浏览器可能自行清除这些数据，过期数据在下次打开本页时删除。</p>
        </div>
        <button type="button" className="bd-btn bd-btn--ghost bd-btn--sm" onClick={onClearAll}>
          <Icon name="trash" /><span>清除互传本地数据</span>
        </button>
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
      <div className="tr-task-list">
        {storedReceives.map((item) => (
          <article key={`receive:${item.transferId}`} className="tr-task">
            <span className="tr-task-thumb" aria-hidden="true"><Icon name={fileKindIcon(item.fileName)} size={18} /></span>
            <div className="tr-task-main">
              <div className="tr-task-head">
                <span className="tr-task-kind is-receive">接收</span>
                <span className="tr-task-title">{item.fileName}</span>
              </div>
              <Progress value={percent(item.receivedBytes, item.sizeBytes)} label={`${item.fileName} 已接收`} />
              <p className="tr-task-msg">对方重新连接并继续发送后会自动续传，无需再次同意。</p>
              <div className="tr-task-meta">
                <Tag tone="warning">{item.storage === "persistent" ? "已暂停" : "已暂停（仅内存）"}</Tag>
                <span>来自 {peerDisplayNames[item.sourcePeerId] ?? (item.sourceName || "对方设备")}</span>
                <span className="bd-num">{formatBytes(item.receivedBytes)} / {formatBytes(item.sizeBytes)}</span>
                {item.expiresAt ? <span>到期 <RelativeTime value={item.expiresAt} /></span> : null}
              </div>
            </div>
            <div className="tr-task-actions">
              <button type="button" className="bd-btn bd-btn--ghost bd-btn--sm" onClick={() => onAbandonReceive(item.transferId)}>
                <Icon name="trash" /><span>放弃并删除</span>
              </button>
            </div>
          </article>
        ))}
        {outgoing.map((item) => (
          <article key={`send:${item.transferId}`} className={`tr-task${item.running ? " is-running" : ""}`}>
            <span className="tr-task-thumb" aria-hidden="true"><Icon name={fileKindIcon(item.fileName)} size={18} /></span>
            <div className="tr-task-main">
              <div className="tr-task-head">
                <span className="tr-task-kind is-send">发送</span>
                <span className="tr-task-title">{item.fileName}</span>
              </div>
              <Progress value={percent(item.ackedBytes, item.sizeBytes)} label={`${item.fileName} 对方已收`} />
              <p className="tr-task-msg">
                {item.hasSource
                  ? "原文件仍在本页，可以继续发送。"
                  : "页面刷新后需要重新选择同一文件（大小必须一致，内容会逐块核对）。"}
              </p>
              <div className="tr-task-meta">
                <Tag tone={item.running ? "info" : "warning"}>{item.running ? "续传中" : "未完成的发送"}</Tag>
                <span>发给 {peerDisplayNames[item.targetPeerId] ?? (item.targetName || "对方设备")}</span>
                <span className="bd-num">对方已收 {formatBytes(item.ackedBytes)} / {formatBytes(item.sizeBytes)}</span>
                {item.expiresAt ? <span>到期 <RelativeTime value={item.expiresAt} /></span> : null}
              </div>
            </div>
            {!item.running ? (
              <div className="tr-task-actions">
                <button type="button" className="bd-btn bd-btn--ghost bd-btn--sm" onClick={() => onAbandonOutgoing(item.transferId)}>放弃</button>
                {item.hasSource ? (
                  <button type="button" className="bd-btn bd-btn--secondary bd-btn--sm" onClick={() => resume(item.transferId)}>
                    <Icon name="play" /><span>继续发送</span>
                  </button>
                ) : (
                  <button
                    type="button"
                    className="bd-btn bd-btn--secondary bd-btn--sm"
                    onClick={() => {
                      reselectForRef.current = item.transferId;
                      fileInputRef.current?.click();
                    }}
                  >
                    <Icon name="folder" /><span>重新选择文件继续</span>
                  </button>
                )}
              </div>
            ) : null}
          </article>
        ))}
      </div>
    </section>
  );
}
