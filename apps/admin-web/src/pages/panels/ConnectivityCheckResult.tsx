import {
  describeConnectivityCheck,
  type ConnectivityCheckResult,
  type ConnectivityStageResult,
} from "../../lib/connectivityCheck";

const RESULT_CLASSES: Record<ConnectivityStageResult, string> = {
  passed: "border-success-200 bg-success-50 text-success-700",
  failed: "border-danger-200 bg-danger-50 text-danger-700",
  unverified: "border-warning-200 bg-warning-50 text-warning-700",
  skipped: "border-default-200 bg-default-50 text-default-400",
};

const OUTCOME_CLASSES = {
  success: "text-success-700",
  danger: "text-danger-700",
  warning: "text-warning-700",
} as const;

/**
 * One connectivity check result: the four stages in their fixed order, each with its result and code,
 * the first stage that did not pass highlighted with the next step. It shows only what the server
 * returned -- never the target address -- and labels the time of the check, because a result is a
 * snapshot, not the route's current state.
 */
export function ConnectivityCheckResultView({ result }: { result: ConnectivityCheckResult }) {
  const view = describeConnectivityCheck(result);
  return (
    <section className="flex flex-col gap-3 text-small" aria-label="连通性检查结果" data-outcome={view.outcome}>
      <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <strong className={`text-medium ${OUTCOME_CLASSES[view.tone]}`}>{view.outcomeLabel}</strong>
        <span className="text-default-600">{view.summary}</span>
      </div>
      <p className="text-tiny text-default-500">
        {view.checkedAtText} · 用时 {view.totalMs} ms · {view.requestsText}
        {view.statusClass ? ` · 目标状态类别 ${view.statusClass}` : ""}
      </p>
      <ol className="flex flex-col gap-2">
        {view.stages.map((stage, index) => (
          <li
            key={stage.stage}
            className={`rounded-medium border p-2 ${RESULT_CLASSES[stage.result]} ${stage.decisive ? "ring-2 ring-offset-1 ring-current" : ""}`}
            data-stage={stage.stage}
            data-result={stage.result}
            data-decisive={stage.decisive ? "true" : undefined}
          >
            <div className="flex flex-wrap items-baseline justify-between gap-2">
              <span className="font-semibold">
                {index + 1}. {stage.label}
              </span>
              <span>
                {stage.resultLabel}
                {stage.atMs !== undefined ? <span className="ml-2 text-tiny opacity-80">{stage.atMs} ms</span> : null}
              </span>
            </div>
            {stage.code ? (
              <p className="mt-1 [overflow-wrap:anywhere]">
                {stage.codeLabel} <code className="text-tiny opacity-80">{stage.code}</code>
              </p>
            ) : null}
            {stage.next ? <p className="mt-1 font-medium text-default-700">下一步：{stage.next}</p> : null}
          </li>
        ))}
      </ol>
      {view.notes.map((note) => (
        <p key={note} className="text-default-600">{note}</p>
      ))}
    </section>
  );
}
