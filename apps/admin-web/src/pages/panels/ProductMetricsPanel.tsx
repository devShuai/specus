import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "../../components/PageHeader";
import {
  Button,
  Modal,
  ModalBody,
  ModalContent,
  ModalFooter,
  ModalHeader,
} from "@heroui/react";
import { adminApi } from "../../api/client";
import type { ProductMetricsSettings, ProductMetricsSummary, ProductMetricsTally } from "../../api/types";
import { ConfirmModal } from "../../components/ConfirmModal";
import { ProductMetricsDisclosure } from "../../components/ProductMetricsDisclosure";
import { notify, notifyError } from "../../components/toast";
import { Alert, Card, FilterBar, Icon, RelativeTime, Section, SectionHead, Stat, StatGrid, TableWrap, Tag } from "../../components/ui";
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
import { Check, Fold, SettingRow, Toggle } from "./meshSystemParts";

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
    <div className="ms-page flex min-w-0 flex-col">
      <PageHeader
        title="产品指标"
        description="由管理员显式开启，只保存按天汇总的计数，用来了解新成员的接入进度与互传的成功率。"
      />

      <Section title="采集开关" description="开启前会先列出统计范围并要你确认；关闭时可以一并清除数据。">
        <Card className="ms-settings">
          <SettingRow
            title={<span className="ms-switch-title">采集产品指标{settings ? (
              <Tag tone={settings.enabled ? "success" : "neutral"} plain={!settings.enabled}>{settings.enabled ? "已开启" : "未开启"}</Tag>
            ) : null}</span>}
            descriptionId="product-metrics-switch-help"
            description={settings ? (
              <>
                计数保存 {settings.retentionDays} 天；接入进度在 {settings.onboardingWindowDays} 天窗口内按账号暂存，结束即汇总并删除。
                {settings.updatedAt ? <> 最近一次由 {settings.updatedBy ?? "管理员"} 于 <RelativeTime value={settings.updatedAt} /> 更改。</> : " 从未开启过。"}
              </>
            ) : loadError ? null : "正在读取设置…"}
            control={(
              <Toggle
                label="采集产品指标"
                describedBy="product-metrics-switch-help"
                checked={Boolean(settings?.enabled)}
                disabled={!settings}
                onChange={(enabled) => (enabled ? setEnableOpen(true) : setDisableOpen(true))}
              />
            )}
          >
            {loadError ? (
              <Alert tone="danger" role="alert" title="读不到产品指标设置" className="ms-inline-alert" actions={<Button size="sm" variant="flat" onPress={() => void reload()}>重新读取</Button>}>
                {loadError}。检查后台连接后重新读取；在此之前开关不可用。
              </Alert>
            ) : null}
          </SettingRow>
          <SettingRow
            title="清除已收集的数据"
            description="删除本组织的全部接入进度与按天计数，开关保持当前状态。硬删除，无法恢复。"
            control={(
              <Button size="sm" color="danger" variant="flat" startContent={<Icon name="trash" size={14} />} isDisabled={!settings} onPress={() => setPurgeOpen(true)}>
                清除数据
              </Button>
            )}
          />
          <div className="ms-setting-fold">
            <Fold title="统计什么、怎么保存、谁能看" icon="info-circle">
              <ProductMetricsDisclosure />
            </Fold>
          </div>
        </Card>
      </Section>

      <Section title="汇总" description="按 UTC 日期统计；只显示按天汇总的计数，没有个人或单次传输的明细。">
        <FilterBar end={summaryLoading ? <span className="ms-loading"><span className="ms-spinner" aria-hidden="true" />正在查询</span> : null}>
          <label className="ms-date">
            <span>开始（UTC）</span>
            <input
              aria-label="开始日期（UTC）"
              className="bd-input"
              type="date"
              value={range.from}
              onChange={(event) => setRange((current) => ({ ...current, from: event.target.value }))}
            />
          </label>
          <label className="ms-date">
            <span>结束（UTC）</span>
            <input
              aria-label="结束日期（UTC）"
              className="bd-input"
              type="date"
              value={range.to}
              onChange={(event) => setRange((current) => ({ ...current, to: event.target.value }))}
            />
          </label>
          <Button size="sm" variant="flat" isLoading={summaryLoading} startContent={summaryLoading ? null : <Icon name="search" size={14} />} onPress={() => void loadSummary(range)}>查询</Button>
        </FilterBar>
        {summaryError ? (
          <Alert tone="danger" role="alert" title="汇总没有读出来">
            {summaryError}。检查日期区间后重新查询。
          </Alert>
        ) : null}
        {!summary && summaryLoading ? (
          <div className="ms-loading ms-pad" role="status"><span className="ms-spinner" aria-hidden="true" />正在读取汇总…</div>
        ) : null}
      </Section>

      {summary ? <ProductMetricsSummaryView summary={summary} /> : null}

      <EnableModal isOpen={enableOpen} onClose={() => setEnableOpen(false)} onConfirm={enable} />
      <DisableModal isOpen={disableOpen} onClose={() => setDisableOpen(false)} onConfirm={disable} />
      <ConfirmModal
        isOpen={purgeOpen}
        onClose={() => setPurgeOpen(false)}
        onConfirm={purge}
        title="清除已收集的数据？"
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
        <ModalHeader className="ms-modal-title">为本组织开启产品指标？</ModalHeader>
        <ModalBody className="ms-modal-body">
          <p className="jd-muted">开启后只统计从现在起发生的事；开启前创建的账号和开启前的传输不会补算。</p>
          <div className="ms-disclosure-box">
            <ProductMetricsDisclosure />
          </div>
          <Check checked={acknowledged} onChange={setAcknowledged}>
            我已阅读以上说明，确认为本组织开启
          </Check>
        </ModalBody>
        <ModalFooter>
          <Button variant="light" onPress={onClose} isDisabled={pending}>取消</Button>
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
        <ModalHeader className="ms-modal-title">关闭产品指标？</ModalHeader>
        <ModalBody className="ms-modal-body">
          <p className="jd-muted">
            关闭后立即停止采集，进行中的接入进度会被删除。已有的按天计数默认保留到期满，也可以现在一并清除。
          </p>
          <Check checked={purge} onChange={setPurge}>
            同时清除已收集的数据（硬删除，无法恢复）
          </Check>
        </ModalBody>
        <ModalFooter>
          <Button variant="light" onPress={onClose} isDisabled={pending}>取消</Button>
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
  const funnelBase = onboarding.steps[0]?.users || onboarding.cohortUsers || 0;
  return (
    <>
      <section className="jd-section ms-summary-overview" aria-label="汇总概览">
        <p className="ms-summary-meta">
          <span className="bd-num">{summary.from} 至 {summary.to}</span>（UTC）· 生成于 <RelativeTime value={summary.generatedAt} />
          {summary.enabled ? "" : " · 当前未开启，显示的是保留的数据"}
        </p>
        <StatGrid>
          <Stat label="新账号" value={onboarding.cohortUsers} meta={`按账号创建日期，窗口 ${onboarding.windowDays} 天`} />
          <Stat label="完成接入" value={formatRateBp(onboarding.completionRateBp)} meta={<>完成 {onboarding.completed} / {onboarding.cohortUsers}</>} />
          <Stat
            label="互传成功率"
            value={formatRateBp(transfers.total.successRateBp)}
            meta={`成功 ${transfers.total.success} · 失败 ${transfers.total.failure} · 取消 ${transfers.total.cancelled}`}
          />
          <Stat label="失败后重试" value={formatRateBp(retry?.successRateBp)} meta="失败过一次后再发的成功率" />
        </StatGrid>
      </section>

      <section className="jd-section" aria-label="首次接入">
        <SectionHead title="首次接入" description={`按账号创建日期统计，窗口 ${onboarding.windowDays} 天`} />
        {!onboarding.final ? (
          <Alert tone="warning" title="结果还不是最终的" className="ms-block">
            还有 {onboarding.pendingUsers} 个账号在窗口内，完成率仍会变化。
          </Alert>
        ) : null}
        <TableWrap className="ms-block">
          <table className="bd-table jd-stack ms-table ms-funnel" aria-label="首次接入漏斗">
            <thead>
              <tr>
                <th scope="col">步骤</th>
                <th scope="col" className="bd-col-num">到达人数</th>
                <th scope="col" className="bd-col-num">相对上一步</th>
                <th scope="col" className="ms-funnel-bar-col"><span className="jd-sr-only">占新账号的比例</span></th>
              </tr>
            </thead>
            <tbody>
              {onboarding.steps.map((step) => (
                <tr key={step.step}>
                  <td>{ONBOARDING_STEP_LABELS[step.step] ?? step.step}</td>
                  <td className="bd-col-num" data-label="到达">{step.users}</td>
                  <td className="bd-col-num" data-label="相对上一步">{formatRateBp(step.fromPreviousRateBp)}</td>
                  <td className="ms-funnel-bar-col" aria-hidden="true">
                    <span className="ms-funnel-bar"><span style={{ width: `${funnelBase > 0 ? Math.min(100, (step.users / funnelBase) * 100) : 0}%` }} /></span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
        <p className="ms-summary-line">
          完成 {onboarding.completed} / {onboarding.cohortUsers}（{formatRateBp(onboarding.completionRateBp)}）；
          完成耗时中位区间：{onboarding.medianDurationBucket ? DURATION_BUCKET_LABELS[onboarding.medianDurationBucket] ?? onboarding.medianDurationBucket : "—"}
        </p>
        {onboarding.durations.length > 0 ? (
          <div className="ms-tag-row">
            <span className="ms-tag-row-label">完成耗时</span>
            {onboarding.durations.map((bucket) => (
              <Tag key={bucket.bucket} plain>
                {DURATION_BUCKET_LABELS[bucket.bucket] ?? bucket.bucket}：{bucket.users}
              </Tag>
            ))}
          </div>
        ) : null}
      </section>

      <section className="jd-section" aria-label="互传结果">
        <SectionHead title="互传结果" description="已登录成员浏览器上报，是下界" />
        <p className="ms-summary-line ms-block">
          总成功率 {formatRateBp(transfers.total.successRateBp)}（成功 {transfers.total.success} · 失败 {transfers.total.failure} · 取消 {transfers.total.cancelled}，取消不计入成功率）；
          失败后重试的成功率 {formatRateBp(retry?.successRateBp)}
        </p>
        <div className="ms-tally-grid">
          <TallyTable
            caption="按路径与文件大小"
            firstColumn="路径 · 大小"
            rows={transfers.cells.map((cell) => ({
              key: `${cell.path}/${cell.sizeBucket}`,
              label: `${TRANSFER_PATH_LABELS[cell.path as TransferMetricsPath] ?? cell.path} · ${TRANSFER_SIZE_LABELS[cell.sizeBucket as TransferMetricsSizeBucket] ?? cell.sizeBucket}`,
              tally: cell,
            }))}
            empty="区间内没有上报"
            wide
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
        </div>
      </section>
    </>
  );
}

function TallyTable({ caption, firstColumn, rows, empty, wide }: {
  caption: string;
  firstColumn: string;
  rows: { key: string; label: string; tally: ProductMetricsTally }[];
  empty?: string;
  wide?: boolean;
}) {
  return (
    <TableWrap className={wide ? "ms-tally ms-tally--wide" : "ms-tally"}>
      <table className="bd-table bd-table--compact jd-stack ms-table">
        <caption>{caption}</caption>
        <thead>
          <tr>
            <th scope="col">{firstColumn}</th>
            <th scope="col" className="bd-col-num">成功</th>
            <th scope="col" className="bd-col-num">失败</th>
            <th scope="col" className="bd-col-num">取消</th>
            <th scope="col" className="bd-col-num">成功率</th>
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 && empty ? (
            <tr className="ms-table-state"><td colSpan={5} className="ms-tally-empty">{empty}</td></tr>
          ) : rows.map((row) => (
            <tr key={row.key}>
              <td>{row.label}</td>
              <td className="bd-col-num" data-label="成功">{row.tally.success}</td>
              <td className="bd-col-num" data-label="失败">{row.tally.failure}</td>
              <td className="bd-col-num" data-label="取消">{row.tally.cancelled}</td>
              <td className="bd-col-num ms-strong" data-label="成功率">{formatRateBp(row.tally.successRateBp)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </TableWrap>
  );
}
