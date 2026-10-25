import { useState } from "react";
import { Button } from "@heroui/react";
import { CLIENT_ONBOARDING_STEPS, clientOnboardingStatus } from "../lib/clientOnboarding";
import { Icon } from "./ui";

type StepState = "done" | "current" | "todo";

/**
 * Where each step stands, from what the page has read: a registered instance means the client was
 * downloaded and started with a credential; an online one means step 3 is done. Publishing is never
 * marked done, because only opening the access link proves it. Nothing is marked while the state is
 * loading or unknown.
 */
function stepStates(input: { loading: boolean; error: boolean; online: number; registered: number; credentials: number }): StepState[] | null {
  if (input.loading || input.error) return null;
  const done = [input.registered > 0, input.credentials > 0 || input.registered > 0, input.online > 0, false];
  const current = done.indexOf(false);
  return done.map((isDone, index) => (isDone ? "done" : index === current ? "current" : "todo"));
}

const STATE_LABEL: Record<StepState, string> = { done: "已完成", current: "下一步", todo: "" };

export function ClientOnboardingGuide({ loading, error, online, registered, credentials, onRefresh }: {
  loading: boolean; error: boolean; online: number; registered: number; credentials: number; onRefresh: () => void;
}) {
  const [expanded, setExpanded] = useState<boolean | null>(null);
  const showSteps = expanded ?? registered === 0;
  const states = stepStates({ loading, error, online, registered, credentials });
  const ready = online > 0 && !error;
  return <section aria-label="设备接入引导" className={`bd-card acc-onboard${error ? " is-error" : ready ? " is-ready" : ""}`}>
    <div className="acc-onboard-head">
      <span className="acc-onboard-icon" aria-hidden="true"><Icon name={error ? "circle-alert" : ready ? "circle-check" : "zap"} size={18} /></span>
      <div className="min-w-0 flex-1">
        <h2 className="acc-onboard-title">接入设备 → 发布第一个服务</h2>
        <p className="acc-onboard-status" role="status">{clientOnboardingStatus({ loading, error, online, registered, credentials })}</p>
      </div>
      <div className="acc-onboard-actions">
        <Button size="sm" variant="flat" isLoading={loading} startContent={loading ? null : <Icon name="refresh" size={14} />} onPress={onRefresh}>
          {error ? "重新加载接入状态" : "检查设备上线"}
        </Button>
        <Button size="sm" variant="light" aria-expanded={showSteps} aria-controls="client-onboarding-steps"
          endContent={<Icon name={showSteps ? "chevron-down" : "chevron-right"} size={14} />} onPress={() => setExpanded(!showSteps)}>
          {showSteps ? "收起接入步骤" : "查看接入步骤"}
        </Button>
        {ready ? <Button as="a" href="#/http-routes" size="sm" color="primary" startContent={<Icon name="globe" size={14} />}>发布 HTTP 服务</Button> : null}
      </div>
    </div>
    <ol id="client-onboarding-steps" className={showSteps ? "acc-steps" : "hidden"}>
      {CLIENT_ONBOARDING_STEPS.map((step, index) => {
        const state = states?.[index] ?? "todo";
        return <li key={step.title} className={`acc-step is-${state}`}>
          <span className="acc-step-mark bd-num" aria-hidden="true">{state === "done" ? <Icon name="check" size={14} /> : index + 1}</span>
          <div className="min-w-0">
            <h3 className="acc-step-title">
              {step.title}
              {STATE_LABEL[state] ? <span className="jd-sr-only">（{STATE_LABEL[state]}）</span> : null}
            </h3>
            <p className="acc-step-detail">{step.detail}</p>
            <div className="acc-step-links">
              <a className="jd-link" href={step.href}>{step.action}</a>
              {index === 3 ? <a className="jd-link" href="#/specusMappings">端口映射</a> : null}
            </div>
          </div>
        </li>;
      })}
    </ol>
  </section>;
}
