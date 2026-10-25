import {
  describeConnectivityCheck,
  type ConnectivityCheckResult,
  type ConnectivityStageResult,
} from "../../lib/connectivityCheck";
import type { ReactNode } from "react";

/** Each stage result as a Tag of the design: passed success, failed danger, unverified warning, skipped plain. */
const RESULT_TAG: Record<ConnectivityStageResult, string> = {
  passed: "bd-tag--success",
  failed: "bd-tag--danger",
  unverified: "bd-tag--warning",
  skipped: "bd-tag--plain",
};

// The design's check, x, alert and more-h icons (components/ui/Icon.tsx), drawn inline without an
// xmlns attribute: the rendered result must not contain any URL.
const RESULT_ICON: Record<ConnectivityStageResult, ReactNode> = {
  passed: <polyline points="20 6 9 17 4 12" />,
  failed: <><path d="M18 6 6 18" /><path d="m6 6 12 12" /></>,
  unverified: <><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z" /><path d="M12 9v4" /><path d="M12 17h.01" /></>,
  skipped: <><circle cx="5" cy="12" r="1.6" /><circle cx="12" cy="12" r="1.6" /><circle cx="19" cy="12" r="1.6" /></>,
};

function StageMark({ result }: { result: ConnectivityStageResult }) {
  return (
    <span className="acc-stage-mark" aria-hidden="true">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.75} strokeLinecap="round" strokeLinejoin="round" focusable="false">
        {RESULT_ICON[result]}
      </svg>
    </span>
  );
}

const OUTCOME_TAG = {
  success: "bd-tag--success",
  danger: "bd-tag--danger",
  warning: "bd-tag--warning",
} as const;

/**
 * One connectivity check result: the four stages in their fixed order (已配置 → 设备在线 → 目标可达 →
 * 访问成功) as a staged list, each with its result Tag and code, the first stage that did not pass
 * highlighted with the next step. It shows only what the server returned -- never the target address --
 * and labels the time of the check, because a result is a snapshot, not the route's current state.
 */
export function ConnectivityCheckResultView({ result }: { result: ConnectivityCheckResult }) {
  const view = describeConnectivityCheck(result);
  return (
    <section className="acc-cc" aria-label="连通性检查结果" data-outcome={view.outcome}>
      <div className="acc-cc-head">
        <span className={`bd-tag acc-cc-outcome ${OUTCOME_TAG[view.tone]}`}>{view.outcomeLabel}</span>
        <span className="acc-cc-summary">{view.summary}</span>
      </div>
      <p className="acc-cc-meta bd-num">
        {view.checkedAtText} · 用时 {view.totalMs} ms · {view.requestsText}
        {view.statusClass ? ` · 目标状态类别 ${view.statusClass}` : ""}
      </p>
      <ol className="acc-stages">
        {view.stages.map((stage, index) => (
          <li
            key={stage.stage}
            className={`acc-stage is-${stage.result}${stage.decisive ? " is-decisive" : ""}`}
            data-stage={stage.stage}
            data-result={stage.result}
            data-decisive={stage.decisive ? "true" : undefined}
          >
            <StageMark result={stage.result} />
            <div className="acc-stage-body">
              <div className="acc-stage-head">
                <span className="acc-stage-label">
                  <span className="bd-num jd-subtle">{index + 1}.</span> {stage.label}
                </span>
                <span className={`bd-tag ${RESULT_TAG[stage.result]}`}>{stage.resultLabel}</span>
                {stage.atMs !== undefined ? <span className="acc-stage-time bd-num">{stage.atMs} ms</span> : null}
              </div>
              {stage.code ? (
                <p className="acc-stage-code">
                  {stage.codeLabel} <code className="font-mono">{stage.code}</code>
                </p>
              ) : null}
              {stage.next ? <p className="acc-stage-next">下一步：{stage.next}</p> : null}
            </div>
          </li>
        ))}
      </ol>
      {view.notes.map((note) => (
        <p key={note} className="acc-cc-note">{note}</p>
      ))}
    </section>
  );
}
