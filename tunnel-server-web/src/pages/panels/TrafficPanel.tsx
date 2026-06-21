import { useCallback, useEffect, useState } from "react";
import {
  Button,
  Table,
  TableBody,
  TableCell,
  TableColumn,
  TableHeader,
  TableRow,
} from "@heroui/react";
import { adminApi } from "../../api/client";
import type { TrafficUsage } from "../../api/types";
import { formatBytes, formatDateTime } from "../../lib/format";
import { notifyError } from "../../components/toast";

export function TrafficPanel() {
  const [rows, setRows] = useState<TrafficUsage[]>([]);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setRows(await adminApi.listTraffic(100));
    } catch (error) {
      notifyError(error, "加载流量失败");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <div className="mt-4 flex flex-col gap-4">
      <div className="flex justify-end">
        <Button size="sm" variant="flat" onPress={() => void load()}>
          刷新
        </Button>
      </div>
      <Table aria-label="流量使用" isHeaderSticky removeWrapper>
        <TableHeader>
          <TableColumn>ID</TableColumn>
          <TableColumn>客户端</TableColumn>
          <TableColumn>日期（UTC）</TableColumn>
          <TableColumn>上传</TableColumn>
          <TableColumn>下载</TableColumn>
          <TableColumn>更新时间</TableColumn>
        </TableHeader>
        <TableBody items={rows} isLoading={loading} emptyContent="暂无数据">
          {(row) => (
            <TableRow key={row.id}>
              <TableCell>{row.id}</TableCell>
              <TableCell>{row.clientName}</TableCell>
              <TableCell>{row.usageDate}</TableCell>
              <TableCell>{formatBytes(row.uploadBytes)}</TableCell>
              <TableCell>{formatBytes(row.downloadBytes)}</TableCell>
              <TableCell>{formatDateTime(row.updatedAt)}</TableCell>
            </TableRow>
          )}
        </TableBody>
      </Table>
    </div>
  );
}
