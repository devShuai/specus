import { useState } from "react";
import { Button, Modal, Spinner } from "@heroui/react";

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
    <Modal.Root isOpen={isOpen} onOpenChange={(open) => { if (!open) (onClose)(); }}>
      <Modal.Backdrop>
        <Modal.Container size="sm" placement="center">
          <Modal.Dialog>
            <Modal.Header className="text-base">{title}</Modal.Header>
            <Modal.Body>
              {description ? (
                <div className="text-small text-default-600">{description}</div>
              ) : (
                <p className="text-small text-default-600">该操作执行后无法撤销，请确认。</p>
              )}
            </Modal.Body>
            <Modal.Footer>
              <Button variant="secondary" onPress={onClose} isDisabled={pending}>
                {cancelLabel}
              </Button>
              <Button
                variant={danger ? "danger" : "primary"}
                onPress={() => void handleConfirm()}
                isDisabled={pending}
              >
                {pending ? <Spinner size="sm" /> : null}
            {confirmLabel}
            </Button>
            </Modal.Footer>

          </Modal.Dialog>
        </Modal.Container>
      </Modal.Backdrop>
    </Modal.Root>
  );
}
