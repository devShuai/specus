import { Modal, ModalBody, ModalContent, ModalHeader } from "@heroui/react";
import type { PeerTransportPath } from "../hooks/useDirectTransfer";

/**
 * 内网互传的设备操作面板。
 *
 * 信息架构以「设备」为主体：先选人，再选做什么——这与 AirDrop 一致，也贴合内网互传的
 * 真实心智（"发给客厅那台电脑"，而不是"打开文件工具再挑设备"）。三项能力共用一个面板，
 * 避免用户在顶部页签和设备列表之间来回切换。
 */

export type NearbyDeviceAction = "files" | "clipboard" | "whiteboard";

interface NearbyDeviceActionsProps {
  isOpen: boolean;
  deviceName: string;
  transportPath?: PeerTransportPath;
  /** 只读房间等场景下禁止发起写操作，但仍允许查看白板 */
  canSend: boolean;
  onClose: () => void;
  onSelect: (action: NearbyDeviceAction) => void;
}

const ACTIONS: Array<{
  key: NearbyDeviceAction;
  label: string;
  detail: string;
  icon: string;
  /** 需要写权限 */
  requiresSend: boolean;
}> = [
  { key: "files", label: "传文件", detail: "选择文件直接发送到这台设备", icon: "↑", requiresSend: true },
  { key: "clipboard", label: "同步剪贴板", detail: "粘贴文字或图片即时同步", icon: "⧉", requiresSend: true },
  { key: "whiteboard", label: "同步白板", detail: "一起画图，实时同步", icon: "✎", requiresSend: false },
];

export function NearbyDeviceActions({
  isOpen,
  deviceName,
  transportPath,
  canSend,
  onClose,
  onSelect,
}: NearbyDeviceActionsProps) {
  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      placement="center"
      size="sm"
      backdrop="blur"
    >
      <ModalContent>
        <ModalHeader className="flex flex-col gap-1 pb-2">
          <span className="text-medium font-semibold">{deviceName}</span>
          <span className="text-tiny font-normal text-zinc-500 dark:text-zinc-400">
            {transportPath === "turn"
              ? "经备用通道连接"
              : transportPath === "direct"
                ? "设备直连"
                : "同一网络中的设备"}
          </span>
        </ModalHeader>
        <ModalBody className="gap-2 pb-5">
          {ACTIONS.map((action) => {
            const disabled = action.requiresSend && !canSend;
            return (
              <button
                key={action.key}
                type="button"
                disabled={disabled}
                onClick={() => onSelect(action.key)}
                className="nearby-action flex min-h-14 items-center gap-3 rounded-xl border border-black/[0.07] px-3 py-2.5 text-left transition disabled:cursor-not-allowed disabled:opacity-45 dark:border-white/[0.08]"
              >
                <span
                  aria-hidden="true"
                  className="grid h-9 w-9 shrink-0 place-items-center rounded-full bg-[var(--app-apple-blue-soft,rgba(0,102,204,0.12))] text-[15px] text-[var(--app-apple-blue,#0066cc)]"
                >
                  {action.icon}
                </span>
                <span className="min-w-0">
                  <span className="block text-small font-medium text-zinc-900 dark:text-white">{action.label}</span>
                  <span className="mt-0.5 block text-tiny leading-4 text-zinc-500 dark:text-zinc-400">
                    {disabled ? "当前房间为只读，无法发送" : action.detail}
                  </span>
                </span>
              </button>
            );
          })}
        </ModalBody>
      </ModalContent>
    </Modal>
  );
}
