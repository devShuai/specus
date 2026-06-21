import { useCallback, useEffect, useState } from "react";
import { Button, Card, CardBody, Spinner } from "@heroui/react";
import { adminApi } from "../../api/client";
import type { Overview } from "../../api/types";
import { formatBytes } from "../../lib/format";
import { notifyError } from "../../components/toast";

export function OverviewPanel() {
  const [overview, setOverview] = useState<Overview | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setOverview(await adminApi.overview());
    } catch (error) {
      notifyError(error, "加载概览失败");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  if (loading && !overview) {
    return <Spinner className="mt-6" label="加载中…" />;
  }

  const cards: Array<{ label: string; value: string }> = overview
    ? [
        { label: "客户端", value: String(overview.clients) },
        { label: "在线", value: String(overview.onlineClients) },
        { label: "成功连接", value: String(overview.successfulConnections) },
        { label: "失败连接", value: String(overview.failedConnections) },
        { label: "代理连接", value: String(overview.externalConnections) },
        { label: "拒绝连接", value: String(overview.rejectedExternalConnections) },
        { label: "上传", value: formatBytes(overview.uploadBytes) },
        { label: "下载", value: formatBytes(overview.downloadBytes) },
      ]
    : [];

  return (
    <div className="mt-4 flex flex-col gap-4">
      <div className="flex justify-end">
        <Button size="sm" variant="flat" onPress={() => void load()}>
          刷新
        </Button>
      </div>
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-4">
        {cards.map((card) => (
          <Card key={card.label} shadow="sm">
            <CardBody className="gap-1">
              <span className="text-small text-default-500">{card.label}</span>
              <span className="text-2xl font-semibold">{card.value}</span>
            </CardBody>
          </Card>
        ))}
      </div>
    </div>
  );
}
