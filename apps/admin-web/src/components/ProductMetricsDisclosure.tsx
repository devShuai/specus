import { PRODUCT_METRICS_DISCLOSURE, PRODUCT_METRICS_DISCLOSURE_HREF, PRODUCT_METRICS_MEMBER_NOTICE } from "../lib/productMetrics";

/** The full disclosure of protocol/spec/product-metrics.md section 3.1, item by item. */
export function ProductMetricsDisclosure({ compact = false }: { compact?: boolean }) {
  return (
    <dl className={compact ? "ms-disclosure ms-disclosure--compact" : "ms-disclosure"}>
      {PRODUCT_METRICS_DISCLOSURE.map((item) => (
        <div key={item.title} className="ms-disclosure-item">
          <dt>{item.title}</dt>
          <dd>{item.detail}</dd>
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
