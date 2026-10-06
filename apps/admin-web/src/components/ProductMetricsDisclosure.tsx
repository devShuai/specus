import { PRODUCT_METRICS_DISCLOSURE, PRODUCT_METRICS_DISCLOSURE_HREF, PRODUCT_METRICS_MEMBER_NOTICE } from "../lib/productMetrics";

/** The full disclosure of protocol/spec/product-metrics.md section 3.1, item by item. */
export function ProductMetricsDisclosure({ compact = false }: { compact?: boolean }) {
  return (
    <dl className={compact ? "space-y-2 text-small" : "space-y-3 text-small"}>
      {PRODUCT_METRICS_DISCLOSURE.map((item) => (
        <div key={item.title}>
          <dt className="font-semibold text-foreground">{item.title}</dt>
          <dd className="mt-0.5 text-default-600">{item.detail}</dd>
        </div>
      ))}
    </dl>
  );
}

/** The one-line member notice shown while the organisation collects, linking the full disclosure. */
export function ProductMetricsMemberNotice({ className = "", children }: { className?: string; children?: React.ReactNode }) {
  return (
    <p className={`text-tiny text-default-500 ${className}`} role="note">
      {PRODUCT_METRICS_MEMBER_NOTICE}。
      <a className="ml-1 text-primary underline-offset-2 hover:underline" href={PRODUCT_METRICS_DISCLOSURE_HREF}>完整说明</a>
      {children}
    </p>
  );
}
