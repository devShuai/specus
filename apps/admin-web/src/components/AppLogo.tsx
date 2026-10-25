type AppLogoProps = {
  className?: string;
  label?: string;
  markClassName?: string;
  subtitle?: string;
};

export function AppLogo({
  className = "",
  label = "specus",
  markClassName = "h-7 w-7",
  subtitle,
}: AppLogoProps) {
  return (
    <div className={`flex min-w-0 items-center gap-2.5 ${className}`}>
      <svg
        className={`shrink-0 ${markClassName}`}
        viewBox="0 0 64 64"
        role="img"
        aria-label="specus 引水渠"
      >
        {/* 底色与渠线走 --logo-mark-* 变量：文字色的圆角方块上用页面底色画渠线（设计规范的品牌标） */}
        <rect width="64" height="64" rx="20" fill="var(--logo-mark-bg, #14161F)" />
        <path d="M7 14 H57" fill="none" stroke="var(--logo-mark-fg, #F2F3F7)" strokeWidth="4.5" strokeLinecap="round" />
        <path d="M8 52 V36 A6 6 0 0 1 20 36 V52" fill="none" stroke="var(--logo-mark-fg, #F2F3F7)" strokeWidth="4.5" strokeLinecap="round" strokeLinejoin="round" opacity=".5" />
        <path d="M20 52 V36 A12 12 0 0 1 44 36 V52" fill="none" stroke="var(--logo-mark-fg, #F2F3F7)" strokeWidth="4.5" strokeLinecap="round" strokeLinejoin="round" />
        <path d="M44 52 V36 A6 6 0 0 1 56 36 V52" fill="none" stroke="var(--logo-mark-fg, #F2F3F7)" strokeWidth="4.5" strokeLinecap="round" strokeLinejoin="round" opacity=".5" />
        <circle cx="32" cy="42" r="4" fill="var(--accent, #2997FF)" />
      </svg>
      <span className="min-w-0">
        <span className="block truncate text-[16px] font-bold leading-5 text-[var(--text)]">{label}</span>
        {subtitle && <span className="block truncate text-[12px] leading-4 text-[var(--text-subtle)]">{subtitle}</span>}
      </span>
    </div>
  );
}
