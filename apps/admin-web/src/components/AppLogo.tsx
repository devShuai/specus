type AppLogoProps = {
  className?: string;
  label?: string;
  markClassName?: string;
  subtitle?: string;
};

export function AppLogo({
  className = "",
  label = "specus",
  markClassName = "h-9 w-9",
  subtitle,
}: AppLogoProps) {
  return (
    <div className={`flex min-w-0 items-center gap-3 ${className}`}>
      <svg
        className={`shrink-0 ${markClassName}`}
        viewBox="0 0 64 64"
        role="img"
        aria-label="specus 引水渠"
      >
        <rect width="64" height="64" rx="14" fill="#14161F" />
        <path d="M7 14 H57" fill="none" stroke="#F2F3F7" strokeWidth="4.5" strokeLinecap="round" />
        <path d="M8 52 V36 A6 6 0 0 1 20 36 V52" fill="none" stroke="#F2F3F7" strokeWidth="4.5" strokeLinecap="round" strokeLinejoin="round" opacity=".5" />
        <path d="M20 52 V36 A12 12 0 0 1 44 36 V52" fill="none" stroke="#F2F3F7" strokeWidth="4.5" strokeLinecap="round" strokeLinejoin="round" />
        <path d="M44 52 V36 A6 6 0 0 1 56 36 V52" fill="none" stroke="#F2F3F7" strokeWidth="4.5" strokeLinecap="round" strokeLinejoin="round" opacity=".5" />
        <circle cx="32" cy="42" r="4" fill="#2997FF" />
      </svg>
      <span className="min-w-0">
        <span className="block truncate text-small font-semibold text-zinc-950 dark:text-white">{label}</span>
        {subtitle && <span className="block truncate text-tiny text-zinc-600 dark:text-zinc-400">{subtitle}</span>}
      </span>
    </div>
  );
}
