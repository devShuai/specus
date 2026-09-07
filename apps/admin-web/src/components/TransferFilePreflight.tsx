import { Button, Checkbox, Modal, ModalBody, ModalContent, ModalFooter, ModalHeader } from "@heroui/react";
import { formatBytes, formatDateTime } from "../lib/format";
import type { TransferCapabilityState } from "../hooks/useTransferCapabilities";
import { checkFilePreflight, type FilePreflightInput } from "../lib/transferPreflight";

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

export function TransferFilePreflight(props: Props) {
  const { input, recipientLabel, allowCloud, canOfferCloudFallback, onAllowCloud, onModeChange, onRemove, onCancel, onConfirm, onLogin } = props;
  const result = checkFilePreflight(input);
  const cloud = input.mode === "link" || (canOfferCloudFallback && allowCloud);
  return (
    <Modal isOpen onClose={onCancel} size="2xl" scrollBehavior="inside" placement="center">
      <ModalContent>
        <ModalHeader>发送前确认</ModalHeader>
        <ModalBody className="gap-4 [overflow-wrap:anywhere] [&>*]:shrink-0">
          <div className="rounded-lg border border-primary-200 bg-primary-50/40 p-3" role="status">
            <p className="text-base font-semibold">{input.mode === "device" ? `发送给：${recipientLabel}` : "生成文件链接 · 不直接发送给设备"}</p>
            <p className="mt-1 text-small">{input.files.length} 个文件 · 合计 <span className="font-mono">{formatBytes(result.totalBytes)}</span></p>
            <p className="mt-1 text-tiny text-default-500">尚未发送任何文件内容。确认后顺序发送，不支持断点续传。</p>
          </div>
          <ul aria-label="待确认文件" className="max-h-48 space-y-2 overflow-y-auto">
            {input.files.map((file, index) => (
              <li key={`${index}:${file.name}`} className="flex items-center gap-2 rounded-md border border-default-200 p-2">
                <span className="min-w-0 flex-1">
                  <span className="block break-all text-small">{file.name}</span>
                  <span className={`font-mono text-tiny ${file.size > input.memoryLimitBytes && input.mode === "device" ? "text-danger" : "text-default-500"}`}>{formatBytes(file.size)}</span>
                </span>
                <Button size="sm" variant="light" aria-label={`移除 ${file.name}`} onPress={() => onRemove(index)}>移除</Button>
              </li>
            ))}
          </ul>
          <div className="space-y-2 text-small">
            <p><strong>设备传输：</strong>每个文件最多 {input.memoryLimitBytes / (1024 * 1024)} MiB，直连和 TURN 中继共享此上限；接收文件暂存在浏览器内存，请及时保存。实际可接收量还受对方内存影响。</p>
            <p><strong>本次方式：</strong>{input.mode === "link" ? "上传到服务端配置的临时存储，生成文件链接；接收方需登录并持有链接和访问口令。" : cloud ? "优先直连 → TURN 中继；都失败后允许上传临时存储，对方需要登录下载。" : "直连 → TURN 中继；不会上传临时存储，失败后保留任务供重试。"}</p>
            {input.mode === "device" && canOfferCloudFallback ? <Checkbox isSelected={allowCloud} onValueChange={onAllowCloud}>设备连接失败时，允许将这些文件上传临时存储</Checkbox> : null}
            {cloud ? <div data-testid="transfer-cloud-quota" className="rounded-md border border-default-200 bg-default-50/30 p-3 text-tiny leading-5">
              {props.capabilities.snapshot ? <>
                <p className="font-semibold">{props.capabilities.snapshot.storageEnabled ? "临时存储已配置 · 额度快照" : "此服务端未启用临时存储"}</p>
                <dl className="mt-2 grid grid-cols-1 gap-2 sm:grid-cols-2">
                  <div><dt>本批需要 / 剩余存储</dt><dd className="font-mono text-small">{formatBytes(result.totalBytes)} / {formatBytes(props.capabilities.snapshot.storageRemainingBytes)}</dd></div>
                  <div><dt>单文件上传上限</dt><dd className="font-mono text-small">{formatBytes(props.capabilities.snapshot.maxAttachmentBytes)}</dd></div>
                  <div><dt>文件保存时长</dt><dd>{props.capabilities.snapshot.retentionHours} 小时（从申请上传起算）</dd></div>
                  <div><dt>本账号本月剩余下载额度</dt><dd className="font-mono">{formatBytes(props.capabilities.snapshot.monthlyDownloadRemainingBytes)}</dd></div>
                </dl>
                <p className="mt-2">查询时间：{formatDateTime(props.capabilities.snapshot.checkedAt)}；下载额度重置：{formatDateTime(props.capabilities.snapshot.downloadResetsAt)}（UTC 月初）。</p>
                <p className="mt-1">仅为查询时的快照，未预占额度，也未测试存储连接；其他任务可能改变额度，实际上传仍由服务端校验。</p>
              </> : <>
                <p className="font-semibold">{props.capabilities.loading ? "正在读取存储与额度…" : "存储与额度尚未核验"}</p>
                <p>{props.capabilities.loading ? "只读取当前账号的限制，不申请上传、不预占额度。" : props.capabilities.error || "登录不代表存储可用；服务端可能尚未支持额度查询。"}</p>
                {!props.capabilities.loading ? <p>仍可明确确认后由服务端校验；额度不足或未配置存储会阻止上传。</p> : null}
              </>}
              <Button size="sm" variant="flat" className="mt-2" isLoading={props.capabilities.loading} onPress={props.capabilities.refresh}>刷新额度</Button>
              <p className="mt-2">文件实际有效期以生成结果为准，不等于房间邀请有效期。下载方受其自身账号额度限制；临时下载地址为一次性授权，不是文件只能分享一次。</p>
            </div> : null}
          </div>
          {result.errors.length > 0 ? <ul role="alert" className="space-y-1 rounded-md border border-danger-200 p-3 text-small text-danger">{result.errors.map((message) => <li key={message}>{message}</li>)}</ul> : null}
          <p className="text-tiny text-default-500">取消不会发起传输，也不会申请上传地址或占用存储额度。刷新、关闭页面或断线重试不会恢复传输进度；浏览器可能无法弹出离开提醒，尤其在手机上。</p>
        </ModalBody>
        <ModalFooter className="flex-wrap">
          <Button variant="flat" onPress={onCancel}>取消发送</Button>
          {input.mode === "device" ? <Button variant="light" onPress={onModeChange}>改为生成文件链接</Button> : null}
          {!input.signedIn && input.mode === "link" ? <Button variant="flat" onPress={onLogin}>登录账号</Button> : null}
          <Button color="primary" isDisabled={!result.canSend} onPress={onConfirm}>{input.mode === "link" ? props.capabilities.snapshot ? "确认上传并生成链接" : "确认上传（额度未核验）" : "确认发送"}</Button>
        </ModalFooter>
      </ModalContent>
    </Modal>
  );
}
