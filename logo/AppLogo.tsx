type AppLogoProps = {
  className?: string;
  label?: string;
  markClassName?: string;
  subtitle?: string;
};

export function AppLogo({
  className = "",
  label = "shuai-tunnel",
  markClassName = "h-9 w-9",
  subtitle,
}: AppLogoProps) {
  return (
    <div className={`flex min-w-0 items-center gap-3 ${className}`}>
      <svg
        className={`shrink-0 ${markClassName}`}
        viewBox="0 0 64 64"
        role="img"
        aria-label="shuai-tunnel"
      >
        <rect width="64" height="64" rx="14" fill="#14161F" />
        <rect x="10.5" y="10.5" width="43" height="43" rx="12" fill="none" stroke="#F2F3F7" strokeWidth="4" />
        <rect x="18" y="18" width="28" height="28" rx="8.5" fill="none" stroke="#F2F3F7" strokeWidth="4" opacity=".62" />
        <rect x="24.5" y="24.5" width="15" height="15" rx="5.5" fill="none" stroke="#F2F3F7" strokeWidth="4" opacity=".34" />
        <rect x="29" y="29" width="6" height="6" rx="2" fill="#9B82FF" />
      </svg>
      <span className="min-w-0">
        <span className="block truncate text-small font-semibold text-zinc-950 dark:text-white">{label}</span>
        {subtitle && <span className="block truncate text-tiny text-zinc-600 dark:text-zinc-400">{subtitle}</span>}
      </span>
    </div>
  );
}
