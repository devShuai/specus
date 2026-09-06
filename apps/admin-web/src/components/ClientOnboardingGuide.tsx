import { useState } from "react";
import { Button } from "@heroui/react";
import { CLIENT_ONBOARDING_STEPS, clientOnboardingStatus } from "../lib/clientOnboarding";

export function ClientOnboardingGuide({ loading, error, online, registered, credentials, onRefresh }: {
  loading: boolean; error: boolean; online: number; registered: number; credentials: number; onRefresh: () => void;
}) {
  const [expanded, setExpanded] = useState<boolean | null>(null);
  const showSteps = expanded ?? registered === 0;
  return <section aria-label="设备接入引导" className="rounded-lg border border-primary-200 bg-primary-50/40 p-4">
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div>
        <h2 className="text-base font-semibold">接入设备 → 发布第一个服务</h2>
        <p className="mt-1 text-small text-default-600" role="status">{clientOnboardingStatus({ loading, error, online, registered, credentials })}</p>
      </div>
      <div className="flex flex-wrap gap-2">
        <Button size="sm" variant="flat" isLoading={loading} onPress={onRefresh}>{error ? "重新加载接入状态" : "检查设备上线"}</Button>
        <Button size="sm" variant="light" aria-expanded={showSteps} aria-controls="client-onboarding-steps" onPress={() => setExpanded(!showSteps)}>{showSteps ? "收起接入步骤" : "查看接入步骤"}</Button>
        {online > 0 && !error ? <Button as="a" href="#/http-routes" size="sm" variant="flat" color="primary">发布 HTTP 服务</Button> : null}
      </div>
    </div>
    <ol id="client-onboarding-steps" className={showSteps ? "mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4" : "hidden"}>
      {CLIENT_ONBOARDING_STEPS.map((step, index) => <li key={step.title} className="min-w-0 border-l-2 border-primary-200 pl-3">
        <h3 className="text-small font-semibold"><span className="mr-2 font-mono text-primary">{index + 1}</span>{step.title}</h3>
        <p className="my-2 text-tiny leading-5 text-default-500">{step.detail}</p>
        <a className="inline-flex min-h-11 items-center text-small text-primary underline underline-offset-4 focus-visible:outline-primary" href={step.href}>{step.action}</a>
        {index === 3 ? <a className="ml-3 inline-flex min-h-11 items-center text-small text-primary underline underline-offset-4" href="#/specusMappings">端口映射</a> : null}
      </li>)}
    </ol>
  </section>;
}
