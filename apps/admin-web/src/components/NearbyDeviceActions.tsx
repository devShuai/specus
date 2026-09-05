import { Modal, ModalBody, ModalContent, ModalHeader } from "@heroui/react";
import type { PeerTransportPath } from "../hooks/useDirectTransfer";

/**
 * 设备列表的操作面板。
 *
 * 这里只提供发送到单台设备的动作。多人白板拥有独立、显式的成员范围，不能混入设备菜单。
 */

export type NearbyDeviceAction = "files" | "clipboard";

interface NearbyDeviceActionsProps {
  isOpen: boolean;
  deviceName: string;
  transportPath?: PeerTransportPath;
  /** 与本机同一公网出口时展示自动发现提示 */
  sameLan?: boolean;
  /** 只读房间等场景下禁止发起发送操作 */
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
  { key: "clipboard", label: "发文字与链接", detail: "先编辑内容，再发送给这台设备", icon: "⧉", requiresSend: true },
];

export function NearbyDeviceActions({
  isOpen,
  deviceName,
  transportPath,
  sameLan,
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
              ? "中继传输"
              : transportPath === "direct"
                ? "设备直连"
                : sameLan
                  ? "自动发现的设备（同一公网出口）"
                  : "远程设备"}
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
