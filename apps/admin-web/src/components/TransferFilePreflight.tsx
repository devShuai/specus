import { Checkbox, Modal, ModalBody, ModalContent, ModalFooter, ModalHeader } from "@heroui/react";
import { formatBytes, formatDateTime } from "../lib/format";
import type { TransferCapabilityState } from "../hooks/useTransferCapabilities";
import { checkFilePreflight, type FilePreflightInput } from "../lib/transferPreflight";
import { Icon } from "./ui";
import { fileKindIcon } from "./transferFileKind";

interface Props {
  capabilities: TransferCapabilityState;
  input: FilePreflightInput;
  recipientLabel: string;
  allowCloud: boolean;
  canOfferCloudFallback: boolean;
  onAllowCloud: (value: boolean) => void;
  onModeChange: () => void;
  onRemove: (index: number) => void;
  onCancel: () => void;
  onConfirm: () => void;
  onLogin: () => void;
}

/**
 * 发送前确认：只看文件的名字和大小，检查接收方、单文件上限和传输方式；确认之前不读文件内容、
 * 不申请上传、不占额度。取消即放弃这批文件。
 */
export function TransferFilePreflight(props: Props) {
  const { input, recipientLabel, allowCloud, canOfferCloudFallback, onAllowCloud, onModeChange, onRemove, onCancel, onConfirm, onLogin } = props;
  const result = checkFilePreflight(input);
  const cloud = input.mode === "link" || (canOfferCloudFallback && allowCloud);
  // Above the 128 MiB memory limit only when this browser can send with chunked resume.
  const resumable = input.memoryLimitBytes > 128 * 1024 * 1024;
  const snapshot = props.capabilities.snapshot;
  return (
    <Modal isOpen onClose={onCancel} size="2xl" scrollBehavior="inside" placement="center" classNames={{ base: "tr-dialog" }}>
      <ModalContent>
        <ModalHeader className="tr-dialog-head">
          <span className="bd-dialog-title">发送前确认</span>
        </ModalHeader>
        <ModalBody className="tr-preflight [&>*]:shrink-0">
          <div className="tr-preflight-summary" role="status">
            <span className="tr-preflight-summary-icon" aria-hidden="true">
              <Icon name={input.mode === "device" ? "send" : "link"} size={18} />
            </span>
            <div className="min-w-0">
              <p className="tr-preflight-target">{input.mode === "device" ? `发送给：${recipientLabel}` : "生成文件链接 · 不直接发送给设备"}</p>
              <p className="tr-preflight-total">{input.files.length} 个文件 · 合计 <span className="bd-num">{formatBytes(result.totalBytes)}</span></p>
              <p className="tr-note">尚未发送任何文件内容。确认后顺序发送{resumable ? "；设备传输按 1 MiB 分块校验，中断后可以从缺失的块继续，详见常见问题。" : "，当前页面不支持断点续传。"}</p>
            </div>
          </div>
          <ul aria-label="待确认文件" className="tr-file-list tr-file-list--dialog">
            {input.files.map((file, index) => {
              const oversize = file.size > input.memoryLimitBytes && input.mode === "device";
              return (
                <li key={`${index}:${file.name}`} className={`tr-file-row${oversize ? " is-invalid" : ""}`}>
                  <span className="tr-file-icon" aria-hidden="true"><Icon name={fileKindIcon(file.name, "type" in file ? String(file.type) : "")} size={16} /></span>
                  <span className="tr-file-text">
                    <span className="tr-file-name">{file.name}</span>
                    <span className="tr-file-meta bd-num">{formatBytes(file.size)}{oversize ? " · 超过单文件上限" : ""}</span>
                  </span>
                  <button type="button" className="bd-btn bd-btn--ghost bd-btn--sm tr-file-remove" aria-label={`移除 ${file.name}`} onClick={() => onRemove(index)}>
                    <Icon name="x" /><span>移除</span>
                  </button>
                </li>
              );
            })}
          </ul>
          <dl className="tr-preflight-facts">
            <div>
              <dt>设备传输</dt>
              <dd>{resumable ? <>每个文件最多 {formatBytes(input.memoryLimitBytes)}，直连和 TURN 中继共享此上限。128 MiB 以内对方可以直接收进内存；更大的文件需要对方同意，写入其浏览器存储；对方页面是旧版本时上限仍为 128 MiB。</> : <>每个文件最多 {input.memoryLimitBytes / (1024 * 1024)} MiB，直连和 TURN 中继共享此上限；接收文件暂存在浏览器内存，收到后及时保存。实际可接收量还受对方内存影响。</>}</dd>
            </div>
            <div>
              <dt>本次方式</dt>
              <dd>{input.mode === "link" ? "上传到服务端配置的临时存储，生成文件链接；接收方需登录并持有链接和访问口令。" : cloud ? "优先直连 → TURN 中继；都失败后允许上传临时存储，对方需要登录下载。" : "直连 → TURN 中继；不会上传临时存储，失败后保留任务供重试。"}</dd>
            </div>
          </dl>
          {input.mode === "device" && canOfferCloudFallback ? (
            <Checkbox className="tr-preflight-consent" isSelected={allowCloud} onValueChange={onAllowCloud}>设备连接失败时，允许将这些文件上传临时存储</Checkbox>
          ) : null}
          {cloud ? <div data-testid="transfer-cloud-quota" className="tr-quota">
            {snapshot ? <>
              <p className="tr-quota-title">{snapshot.storageEnabled ? "临时存储已配置 · 额度快照" : "此服务端未启用临时存储"}</p>
              <dl className="tr-quota-grid">
                <div><dt>本批需要 / 剩余存储</dt><dd className="bd-num">{formatBytes(result.totalBytes)} / {formatBytes(snapshot.storageRemainingBytes)}</dd></div>
                <div><dt>单文件上传上限</dt><dd className="bd-num">{formatBytes(snapshot.maxAttachmentBytes)}</dd></div>
                <div><dt>文件保存时长</dt><dd>{snapshot.retentionHours} 小时（从申请上传起算）</dd></div>
                <div><dt>本账号本月剩余下载额度</dt><dd className="bd-num">{formatBytes(snapshot.monthlyDownloadRemainingBytes)}</dd></div>
              </dl>
              <p className="tr-note">查询时间：{formatDateTime(snapshot.checkedAt)}；下载额度重置：{formatDateTime(snapshot.downloadResetsAt)}（UTC 月初）。</p>
              <p className="tr-note">仅为查询时的快照，未预占额度，也未测试存储连接；其他任务可能改变额度，实际上传仍由服务端校验。</p>
            </> : <>
              <p className="tr-quota-title">{props.capabilities.loading ? "正在读取存储与额度…" : "存储与额度尚未核验"}</p>
              <p className="tr-note">{props.capabilities.loading ? "只读取当前账号的限制，不申请上传、不预占额度。" : props.capabilities.error || "登录不代表存储可用；服务端可能尚未支持额度查询。"}</p>
              {!props.capabilities.loading ? <p className="tr-note">仍可明确确认后由服务端校验；额度不足或未配置存储会阻止上传。</p> : null}
            </>}
            <button type="button" className={`bd-btn bd-btn--secondary bd-btn--sm tr-quota-refresh${props.capabilities.loading ? " is-busy" : ""}`} disabled={props.capabilities.loading} onClick={props.capabilities.refresh}>
              <Icon name="refresh" /><span>刷新额度</span>
            </button>
            <p className="tr-note">文件实际有效期以生成结果为准，不等于房间邀请有效期。下载方受其自身账号额度限制；临时下载地址为一次性授权，不是文件只能分享一次。</p>
          </div> : null}
          {result.errors.length > 0 ? (
            <ul role="alert" className="tr-preflight-errors">
              {result.errors.map((message) => <li key={message}><Icon name="circle-alert" /><span>{message}</span></li>)}
            </ul>
          ) : null}
          <p className="tr-note">取消不会发起传输，也不会申请上传地址或占用存储额度。刷新、关闭页面或断线重试不会恢复传输进度；浏览器可能无法弹出离开提醒，尤其在手机上。</p>
        </ModalBody>
        <ModalFooter className="tr-dialog-foot">
          <button type="button" className="bd-btn bd-btn--ghost" onClick={onCancel}>取消发送</button>
          <span className="tr-dialog-foot-spacer" />
          {input.mode === "device" ? <button type="button" className="bd-btn bd-btn--secondary" onClick={onModeChange}>改为生成文件链接</button> : null}
          {!input.signedIn && input.mode === "link" ? <button type="button" className="bd-btn bd-btn--secondary" onClick={onLogin}>登录账号</button> : null}
          <button type="button" className="bd-btn bd-btn--primary" disabled={!result.canSend} onClick={onConfirm}>
            <Icon name={input.mode === "link" ? "upload" : "send"} />
            <span>{input.mode === "link" ? snapshot ? "确认上传并生成链接" : "确认上传（额度未核验）" : "确认发送"}</span>
          </button>
        </ModalFooter>
      </ModalContent>
    </Modal>
  );
}
