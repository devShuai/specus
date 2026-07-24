import { useState } from "react";
import { Button, Modal, ModalBody, ModalContent, ModalFooter, ModalHeader } from "@heroui/react";

export interface ConfirmModalProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: () => void | Promise<void>;
  title: string;
  /** 后果说明，向用户明确该操作的影响范围与是否可逆 */
  description?: React.ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  /** 危险操作使用红色确认按钮 */
  danger?: boolean;
}

/**
 * 全站统一的确认对话框，替代原生 window.confirm。
 * 危险操作传 danger，并在 description 里说明不可逆后果。
 */
export function ConfirmModal({
  isOpen,
  onClose,
  onConfirm,
  title,
  description,
  confirmLabel = "确认",
  cancelLabel = "取消",
  danger = false,
}: ConfirmModalProps) {
  const [pending, setPending] = useState(false);

  const handleConfirm = async () => {
    if (pending) return;
    setPending(true);
    try {
      await onConfirm();
      onClose();
    } finally {
      setPending(false);
    }
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} size="sm" placement="center">
      <ModalContent>
        <ModalHeader className="text-base">{title}</ModalHeader>
        <ModalBody>
          {description ? (
            <div className="text-small text-default-600">{description}</div>
          ) : (
            <p className="text-small text-default-600">该操作执行后无法撤销，请确认。</p>
          )}
        </ModalBody>
        <ModalFooter>
          <Button variant="flat" onPress={onClose} isDisabled={pending}>
            {cancelLabel}
          </Button>
          <Button color={danger ? "danger" : "primary"} onPress={() => void handleConfirm()} isLoading={pending}>
            {confirmLabel}
          </Button>
        </ModalFooter>
      </ModalContent>
    </Modal>
  );
}
