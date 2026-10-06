import { useCallback, useEffect, useState } from "react";
import {
  Button,
  Card,
  CardBody,
  CardHeader,
  Checkbox,
  Chip,
  Input,
  Modal,
  ModalBody,
  ModalContent,
  ModalFooter,
  ModalHeader,
  Spinner,
} from "@heroui/react";
import { adminApi } from "../../api/client";
import type { ProductMetricsSettings, ProductMetricsSummary, ProductMetricsTally } from "../../api/types";
import { ConfirmModal } from "../../components/ConfirmModal";
import { ProductMetricsDisclosure } from "../../components/ProductMetricsDisclosure";
import { notify, notifyError } from "../../components/toast";
import { formatDateTime } from "../../lib/format";
import {
  DURATION_BUCKET_LABELS,
  ONBOARDING_STEP_LABELS,
  TRANSFER_ATTEMPT_LABELS,
  TRANSFER_MODE_LABELS,
  TRANSFER_PATH_LABELS,
  TRANSFER_SIZE_LABELS,
  defaultSummaryRange,
  formatRateBp,
  type TransferMetricsAttempt,
  type TransferMetricsMode,
  type TransferMetricsPath,
  type TransferMetricsSizeBucket,
} from "../../lib/productMetrics";

/**
 * Opt-in product metrics of this tenant (protocol/spec/product-metrics.md): the switch an admin
 * turns on after confirming the disclosure, the purge, and the summary -- onboarding funnel and
 * completion times of new accounts, transfer success by path, size range, send mode and attempt.
 * Only daily counts are shown; there is no per-person or per-transfer view.
 */
export function ProductMetricsPanel() {
  const [settings, setSettings] = useState<ProductMetricsSettings | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [range, setRange] = useState(() => defaultSummaryRange());
  const [summary, setSummary] = useState<ProductMetricsSummary | null>(null);
  const [summaryLoading, setSummaryLoading] = useState(false);
  const [summaryError, setSummaryError] = useState<string | null>(null);
  const [enableOpen, setEnableOpen] = useState(false);
  const [disableOpen, setDisableOpen] = useState(false);
  const [purgeOpen, setPurgeOpen] = useState(false);

  const loadSummary = useCallback(async (next: { from: string; to: string }) => {
    setSummaryLoading(true);
    setSummaryError(null);
    try {
      setSummary(await adminApi.productMetricsSummary(next));
    } catch (error) {
      setSummary(null);
      setSummaryError(error instanceof Error ? error.message : "读取汇总失败");
    } finally {
      setSummaryLoading(false);
    }
  }, []);

  const reload = useCallback(async () => {
    try {
      setSettings(await adminApi.productMetricsSettings());
      setLoadError(null);
    } catch (error) {
      setLoadError(error instanceof Error ? error.message : "读取设置失败");
    }
  }, []);

  useEffect(() => {
    void reload();
    void loadSummary(defaultSummaryRange());
  }, [reload, loadSummary]);

  const enable = async () => {
    try {
      setSettings(await adminApi.setProductMetricsEnabled(true));
      notify("已开启产品指标：从现在起开始统计");
      void loadSummary(range);
    } catch (error) {
      notifyError(error, "开启失败");
      throw error;
    }
  };

  const disable = async (purge: boolean) => {
    try {
      setSettings(await adminApi.setProductMetricsEnabled(false));
      if (purge) {
        await adminApi.purgeProductMetrics();
        notify("已关闭产品指标并清除已收集的数据");
      } else {
        notify("已关闭产品指标；已有计数保留到期满，可随时清除");
      }
      void loadSummary(range);
    } catch (error) {
      notifyError(error, "关闭失败");
      throw error;
    }
  };

  const purge = async () => {
    try {
      await adminApi.purgeProductMetrics();
      notify("已清除本组织的全部产品指标数据");
      void reload();
      void loadSummary(range);
    } catch (error) {
      notifyError(error, "清除失败");
      throw error;
    }
  };

  return (
    <div className="mt-4 flex flex-col gap-4">
      <div>
        <h2 className="text-lg font-semibold">产品指标</h2>
        <p className="text-small text-default-500">
          由管理员显式开启，只保存按天汇总的计数，用来了解新成员的接入进度与互传的成功率。
        </p>
      </div>

      <Card shadow="none" className="border border-default-200">
        <CardHeader className="flex flex-wrap items-center gap-3">
          <span className="font-semibold">开关</span>
          {settings ? (
            <Chip size="sm" color={settings.enabled ? "success" : "default"} variant="flat">
              {settings.enabled ? "已开启" : "未开启"}
            </Chip>
          ) : null}
          <div className="ml-auto flex flex-wrap gap-2">
            {settings?.enabled ? (
              <Button size="sm" variant="flat" onPress={() => setDisableOpen(true)}>关闭</Button>
            ) : (
              <Button size="sm" color="primary" isDisabled={!settings} onPress={() => setEnableOpen(true)}>开启…</Button>
            )}
            <Button size="sm" color="danger" variant="light" isDisabled={!settings} onPress={() => setPurgeOpen(true)}>
              清除已收集的数据
            </Button>
          </div>
        </CardHeader>
        <CardBody className="pt-0 text-small text-default-600">
          {loadError ? <p className="text-danger">{loadError}</p> : null}
          {settings ? (
            <p>
              计数保存 {settings.retentionDays} 天；接入进度在 {settings.onboardingWindowDays} 天窗口内按账号暂存，结束即汇总并删除。
              {settings.updatedAt ? ` 最近一次由 ${settings.updatedBy ?? "管理员"} 于 ${formatDateTime(settings.updatedAt)} 更改。` : " 从未开启过。"}
            </p>
          ) : !loadError ? <Spinner size="sm" /> : null}
        </CardBody>
      </Card>

      <Card shadow="none" className="border border-default-200">
        <CardHeader className="flex flex-wrap items-end gap-3">
          <span className="font-semibold">汇总</span>
          <Input
            aria-label="开始日期（UTC）"
            className="w-40"
            label="开始（UTC）"
            labelPlacement="outside"
            size="sm"
            type="date"
            value={range.from}
            onValueChange={(from) => setRange((current) => ({ ...current, from }))}
          />
          <Input
            aria-label="结束日期（UTC）"
            className="w-40"
            label="结束（UTC）"
            labelPlacement="outside"
            size="sm"
            type="date"
            value={range.to}
            onValueChange={(to) => setRange((current) => ({ ...current, to }))}
          />
          <Button size="sm" variant="flat" isLoading={summaryLoading} onPress={() => void loadSummary(range)}>查询</Button>
        </CardHeader>
        <CardBody className="gap-6 pt-0">
          {summaryError ? <p className="text-small text-danger">{summaryError}</p> : null}
          {summary ? <ProductMetricsSummaryView summary={summary} /> : summaryLoading ? <Spinner size="sm" /> : null}
        </CardBody>
      </Card>

      <EnableModal isOpen={enableOpen} onClose={() => setEnableOpen(false)} onConfirm={enable} />
      <DisableModal isOpen={disableOpen} onClose={() => setDisableOpen(false)} onConfirm={disable} />
      <ConfirmModal
        isOpen={purgeOpen}
        onClose={() => setPurgeOpen(false)}
        onConfirm={purge}
        title="清除已收集的数据"
        description="删除本组织的全部接入进度与按天计数。这是硬删除，无法恢复；数据库备份里的副本按部署自身的备份保留策略过期。开关保持当前状态。"
        confirmLabel="清除"
        danger
      />
    </div>
  );
}

function EnableModal({ isOpen, onClose, onConfirm }: { isOpen: boolean; onClose: () => void; onConfirm: () => Promise<void> }) {
  const [acknowledged, setAcknowledged] = useState(false);
  const [pending, setPending] = useState(false);
  useEffect(() => {
    if (isOpen) setAcknowledged(false);
  }, [isOpen]);
  const confirm = async () => {
    setPending(true);
    try {
      await onConfirm();
      onClose();
    } catch {
      // The toast already explained it; the dialog stays open.
    } finally {
      setPending(false);
    }
  };
  return (
    <Modal isOpen={isOpen} onClose={onClose} size="lg" placement="center" scrollBehavior="inside">
      <ModalContent>
        <ModalHeader className="text-base">开启产品指标</ModalHeader>
        <ModalBody>
          <p className="text-small text-default-600">开启后只统计从现在起发生的事；开启前创建的账号和开启前的传输不会补算。</p>
          <ProductMetricsDisclosure />
          <Checkbox isSelected={acknowledged} onValueChange={setAcknowledged} size="sm">
            我已阅读以上说明，确认为本组织开启
          </Checkbox>
        </ModalBody>
        <ModalFooter>
          <Button variant="flat" onPress={onClose} isDisabled={pending}>取消</Button>
          <Button color="primary" isDisabled={!acknowledged} isLoading={pending} onPress={() => void confirm()}>开启</Button>
        </ModalFooter>
      </ModalContent>
    </Modal>
  );
}

function DisableModal({ isOpen, onClose, onConfirm }: { isOpen: boolean; onClose: () => void; onConfirm: (purge: boolean) => Promise<void> }) {
  const [purge, setPurge] = useState(false);
  const [pending, setPending] = useState(false);
  useEffect(() => {
    if (isOpen) setPurge(false);
  }, [isOpen]);
  const confirm = async () => {
    setPending(true);
    try {
      await onConfirm(purge);
      onClose();
    } catch {
      // The toast already explained it; the dialog stays open.
    } finally {
      setPending(false);
    }
  };
  return (
    <Modal isOpen={isOpen} onClose={onClose} size="md" placement="center">
      <ModalContent>
        <ModalHeader className="text-base">关闭产品指标</ModalHeader>
        <ModalBody>
          <p className="text-small text-default-600">
            关闭后立即停止采集，进行中的接入进度会被删除。已有的按天计数默认保留到期满，也可以现在一并清除。
          </p>
          <Checkbox isSelected={purge} onValueChange={setPurge} size="sm">
            同时清除已收集的数据（硬删除，无法恢复）
          </Checkbox>
        </ModalBody>
        <ModalFooter>
          <Button variant="flat" onPress={onClose} isDisabled={pending}>取消</Button>
          <Button color={purge ? "danger" : "primary"} isLoading={pending} onPress={() => void confirm()}>关闭</Button>
        </ModalFooter>
      </ModalContent>
    </Modal>
  );
}

export function ProductMetricsSummaryView({ summary }: { summary: ProductMetricsSummary }) {
  const onboarding = summary.onboarding;
  const transfers = summary.transfers;
  const retry = transfers.byAttempt.find((row) => row.attempt === "retry_after_failure");
  return (
    <>
      <p className="text-tiny text-default-500">
        {summary.from} 至 {summary.to}（UTC）· 生成于 {formatDateTime(summary.generatedAt)}
        {summary.enabled ? "" : " · 当前未开启，显示的是保留的数据"}
      </p>

      <section aria-label="首次接入">
        <h3 className="mb-2 text-small font-semibold">首次接入（按账号创建日期统计，窗口 {onboarding.windowDays} 天）</h3>
        {!onboarding.final ? (
          <p className="mb-2 text-tiny text-warning-600">
            还有 {onboarding.pendingUsers} 个账号在窗口内，完成率仍会变化。
          </p>
        ) : null}
        <div className="overflow-x-auto">
          <table className="w-full min-w-[420px] text-left text-small">
            <thead className="text-tiny text-default-500">
              <tr><th className="py-1 pr-4 font-medium">步骤</th><th className="py-1 pr-4 font-medium">到达人数</th><th className="py-1 font-medium">相对上一步</th></tr>
            </thead>
            <tbody>
              {onboarding.steps.map((step) => (
                <tr key={step.step} className="border-t border-default-100">
                  <td className="py-1 pr-4">{ONBOARDING_STEP_LABELS[step.step] ?? step.step}</td>
                  <td className="py-1 pr-4 tabular-nums">{step.users}</td>
                  <td className="py-1 tabular-nums">{formatRateBp(step.fromPreviousRateBp)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="mt-2 text-small">
          完成 {onboarding.completed} / {onboarding.cohortUsers}（{formatRateBp(onboarding.completionRateBp)}）；
          完成耗时中位区间：{onboarding.medianDurationBucket ? DURATION_BUCKET_LABELS[onboarding.medianDurationBucket] ?? onboarding.medianDurationBucket : "—"}
        </p>
        <div className="mt-2 flex flex-wrap gap-2">
          {onboarding.durations.map((bucket) => (
            <Chip key={bucket.bucket} size="sm" variant="flat">
              {DURATION_BUCKET_LABELS[bucket.bucket] ?? bucket.bucket}：{bucket.users}
            </Chip>
          ))}
        </div>
      </section>

      <section aria-label="互传结果">
        <h3 className="mb-2 text-small font-semibold">互传结果（已登录成员浏览器上报，下界）</h3>
        <p className="mb-2 text-small">
          总成功率 {formatRateBp(transfers.total.successRateBp)}（成功 {transfers.total.success} · 失败 {transfers.total.failure} · 取消 {transfers.total.cancelled}，取消不计入成功率）；
          失败后重试的成功率 {formatRateBp(retry?.successRateBp)}
        </p>
        <TallyTable
          caption="按路径与文件大小"
          firstColumn="路径 · 大小"
          rows={transfers.cells.map((cell) => ({
            key: `${cell.path}/${cell.sizeBucket}`,
            label: `${TRANSFER_PATH_LABELS[cell.path as TransferMetricsPath] ?? cell.path} · ${TRANSFER_SIZE_LABELS[cell.sizeBucket as TransferMetricsSizeBucket] ?? cell.sizeBucket}`,
            tally: cell,
          }))}
          empty="区间内没有上报"
        />
        <TallyTable
          caption="按发送方式"
          firstColumn="方式"
          rows={transfers.byMode.map((row) => ({
            key: row.mode,
            label: TRANSFER_MODE_LABELS[row.mode as TransferMetricsMode] ?? row.mode,
            tally: row,
          }))}
        />
        <TallyTable
          caption="按尝试"
          firstColumn="尝试"
          rows={transfers.byAttempt.map((row) => ({
            key: row.attempt,
            label: TRANSFER_ATTEMPT_LABELS[row.attempt as TransferMetricsAttempt] ?? row.attempt,
            tally: row,
          }))}
        />
      </section>
    </>
  );
}

function TallyTable({ caption, firstColumn, rows, empty }: {
  caption: string;
  firstColumn: string;
  rows: { key: string; label: string; tally: ProductMetricsTally }[];
  empty?: string;
}) {
  return (
    <div className="mt-3 overflow-x-auto">
      <table className="w-full min-w-[480px] text-left text-small">
        <caption className="mb-1 text-left text-tiny font-medium text-default-500">{caption}</caption>
        <thead className="text-tiny text-default-500">
          <tr>
            <th className="py-1 pr-4 font-medium">{firstColumn}</th>
            <th className="py-1 pr-4 font-medium">成功</th>
            <th className="py-1 pr-4 font-medium">失败</th>
            <th className="py-1 pr-4 font-medium">取消</th>
            <th className="py-1 font-medium">成功率</th>
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 && empty ? (
            <tr className="border-t border-default-100"><td className="py-1 text-default-500" colSpan={5}>{empty}</td></tr>
          ) : rows.map((row) => (
            <tr key={row.key} className="border-t border-default-100">
              <td className="py-1 pr-4">{row.label}</td>
              <td className="py-1 pr-4 tabular-nums">{row.tally.success}</td>
              <td className="py-1 pr-4 tabular-nums">{row.tally.failure}</td>
              <td className="py-1 pr-4 tabular-nums">{row.tally.cancelled}</td>
              <td className="py-1 tabular-nums">{formatRateBp(row.tally.successRateBp)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
