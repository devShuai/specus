import { useCallback, useEffect, useState, type FormEvent } from "react";
import {
  Button,
  Chip,
  Input,
  Modal,
  ModalBody,
  ModalContent,
  ModalFooter,
  ModalHeader,
  Switch,
  Table,
  TableBody,
  TableCell,
  TableColumn,
  TableHeader,
  TableRow,
  useDisclosure,
} from "@heroui/react";
import { adminApi } from "../../api/client";
import type { ClientCredential } from "../../api/types";
import { notify, notifyError } from "../../components/toast";
import { formatDateTime } from "../../lib/format";

export function ClientCredentialsPanel() {
  const [items, setItems] = useState<ClientCredential[]>([]);
  const [loading, setLoading] = useState(true);
  const [apiKey, setApiKey] = useState("");
  const [secret, setSecret] = useState("");
  const [maxOnline, setMaxOnline] = useState("2");
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<ClientCredential | null>(null);
  const [revealed, setRevealed] = useState("");
  const editModal = useDisclosure();
  const secretModal = useDisclosure();

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setItems(await adminApi.listClientCredentials());
    } catch (error) {
      notifyError(error, "加载客户端凭证失败");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const showSecret = (value?: string) => {
    if (!value) {
      return;
    }
    setRevealed(value);
    secretModal.onOpen();
  };

  const create = async (event: FormEvent) => {
    event.preventDefault();
    setCreating(true);
    try {
      const result = await adminApi.createClientCredential({
        apiKey: apiKey.trim() || undefined,
        secret: secret.trim() || null,
        maxOnlineInstances: Number(maxOnline) || 2,
        enabled: true,
      });
      setApiKey("");
      setSecret("");
      setMaxOnline("2");
      showSecret(result.secret);
      notify("客户端凭证已创建");
      await load();
    } catch (error) {
      notifyError(error, "创建失败");
    } finally {
      setCreating(false);
    }
  };

  const openEdit = (item: ClientCredential) => {
    setEditing(item);
    editModal.onOpen();
  };

  const remove = async (item: ClientCredential) => {
    if (!window.confirm(`确定删除凭证「${item.apiKey}」吗？已安装客户端将无法继续登录。`)) {
      return;
    }
    try {
      await adminApi.deleteClientCredential(item.id);
      notify("客户端凭证已删除");
      await load();
    } catch (error) {
      notifyError(error, "删除失败");
    }
  };

  return (
    <div className="mt-4 flex flex-col gap-4">
      <form className="flex flex-wrap items-end gap-3" onSubmit={create}>
        <Input className="w-64" label="apiKey" placeholder="留空自动生成" value={apiKey} onValueChange={setApiKey} />
        <Input className="w-56" label="secret" placeholder="留空自动生成" value={secret} onValueChange={setSecret} />
        <Input className="w-44" type="number" label="在线实例上限" min={1} max={10000} value={maxOnline} onValueChange={setMaxOnline} />
        <Button type="submit" color="primary" isLoading={creating}>
          新建凭证
        </Button>
        <Button variant="flat" onPress={() => void load()}>
          刷新
        </Button>
      </form>

      <Table aria-label="客户端凭证列表" isHeaderSticky removeWrapper>
        <TableHeader>
          <TableColumn>ID</TableColumn>
          <TableColumn>apiKey</TableColumn>
          <TableColumn>状态</TableColumn>
          <TableColumn>在线实例上限</TableColumn>
          <TableColumn>创建时间</TableColumn>
          <TableColumn>操作</TableColumn>
        </TableHeader>
        <TableBody items={items} isLoading={loading} emptyContent="暂无数据">
          {(item) => (
            <TableRow key={item.id}>
              <TableCell>{item.id}</TableCell>
              <TableCell className="font-mono">{item.apiKey}</TableCell>
              <TableCell>
                <Chip size="sm" color={item.enabled ? "success" : "default"} variant="flat">
                  {item.enabled ? "启用" : "停用"}
                </Chip>
              </TableCell>
              <TableCell>{item.maxOnlineInstances}</TableCell>
              <TableCell>{formatDateTime(item.createdAt)}</TableCell>
              <TableCell>
                <div className="flex gap-2">
                  <Button size="sm" variant="flat" onPress={() => openEdit(item)}>
                    编辑
                  </Button>
                  <Button size="sm" color="danger" variant="flat" onPress={() => void remove(item)}>
                    删除
                  </Button>
                </div>
              </TableCell>
            </TableRow>
          )}
        </TableBody>
      </Table>

      <EditCredentialModal disclosure={editModal} credential={editing} onSaved={(secret) => {
        showSecret(secret);
        void load();
      }} />

      <Modal isOpen={secretModal.isOpen} onOpenChange={secretModal.onOpenChange}>
        <ModalContent>
          {(onClose) => (
            <>
              <ModalHeader>客户端 secret（仅显示一次）</ModalHeader>
              <ModalBody>
                <Input value={revealed} isReadOnly />
              </ModalBody>
              <ModalFooter>
                <Button
                  variant="flat"
                  onPress={() => {
                    void navigator.clipboard?.writeText(revealed);
                    notify("已复制");
                  }}
                >
                  复制
                </Button>
                <Button color="primary" onPress={onClose}>
                  我已保存
                </Button>
              </ModalFooter>
            </>
          )}
        </ModalContent>
      </Modal>
    </div>
  );
}

interface EditCredentialModalProps {
  disclosure: ReturnType<typeof useDisclosure>;
  credential: ClientCredential | null;
  onSaved: (secret?: string) => void;
}

function EditCredentialModal({ disclosure, credential, onSaved }: EditCredentialModalProps) {
  const [apiKey, setApiKey] = useState("");
  const [secret, setSecret] = useState("");
  const [enabled, setEnabled] = useState(true);
  const [maxOnline, setMaxOnline] = useState("2");
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (credential) {
      setApiKey(credential.apiKey);
      setSecret("");
      setEnabled(credential.enabled);
      setMaxOnline(String(credential.maxOnlineInstances));
    }
  }, [credential]);

  const save = async () => {
    if (!credential) {
      return;
    }
    setSaving(true);
    try {
      const result = await adminApi.updateClientCredential(credential.id, {
        apiKey: apiKey.trim(),
        secret: secret.trim() || null,
        enabled,
        maxOnlineInstances: Number(maxOnline) || 2,
      });
      notify("客户端凭证已更新");
      disclosure.onClose();
      onSaved(result.secret);
    } catch (error) {
      notifyError(error, "更新失败");
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal isOpen={disclosure.isOpen} onOpenChange={disclosure.onOpenChange}>
      <ModalContent>
        {(onClose) => (
          <>
            <ModalHeader>编辑凭证「{credential?.apiKey}」</ModalHeader>
            <ModalBody className="gap-3">
              <Input label="apiKey" value={apiKey} onValueChange={setApiKey} isRequired />
              <Input label="secret" placeholder="留空保留原 secret" value={secret} onValueChange={setSecret} />
              <Input type="number" label="在线实例上限" min={1} max={10000} value={maxOnline} onValueChange={setMaxOnline} />
              <Switch isSelected={enabled} onValueChange={setEnabled}>
                启用
              </Switch>
            </ModalBody>
            <ModalFooter>
              <Button variant="flat" onPress={onClose}>
                取消
              </Button>
              <Button color="primary" isLoading={saving} onPress={() => void save()}>
                保存
              </Button>
            </ModalFooter>
          </>
        )}
      </ModalContent>
    </Modal>
  );
}
