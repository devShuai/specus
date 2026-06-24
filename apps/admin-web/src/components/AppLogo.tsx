import { useId } from "react";

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
  const id = useId().replace(/:/g, "");
  const bgId = `${id}-app-logo-bg`;
  const tunnelId = `${id}-app-logo-tunnel`;
  const cyanId = `${id}-app-logo-cyan`;
  const amberId = `${id}-app-logo-amber`;

  return (
    <div className={`flex min-w-0 items-center gap-3 ${className}`}>
      <svg
        className={`shrink-0 ${markClassName}`}
        viewBox="0 0 64 64"
        role="img"
        aria-label="shuai-tunnel"
      >
        <defs>
          <linearGradient id={bgId} x1="10" y1="6" x2="54" y2="58" gradientUnits="userSpaceOnUse">
            <stop stopColor="#07111f" />
            <stop offset="1" stopColor="#05070c" />
          </linearGradient>
          <linearGradient id={tunnelId} x1="22" y1="14" x2="42" y2="50" gradientUnits="userSpaceOnUse">
            <stop stopColor="#f0fdff" />
            <stop offset=".48" stopColor="#67e8f9" />
            <stop offset="1" stopColor="#0e7490" />
          </linearGradient>
          <linearGradient id={cyanId} x1="33" y1="28" x2="56" y2="17" gradientUnits="userSpaceOnUse">
            <stop stopColor="#67e8f9" />
            <stop offset="1" stopColor="#0891b2" />
          </linearGradient>
          <linearGradient id={amberId} x1="33" y1="36" x2="56" y2="47" gradientUnits="userSpaceOnUse">
            <stop stopColor="#fbbf24" />
            <stop offset="1" stopColor="#f97316" />
          </linearGradient>
        </defs>
        <rect width="64" height="64" rx="14" fill={`url(#${bgId})`} />
        <path d="M11 18h9M44 18h9M11 46h9M44 46h9" fill="none" stroke="#164e63" strokeWidth="1.5" strokeLinecap="round" opacity=".52" />
        <path d="M10 32h14" fill="none" stroke="#e5faff" strokeWidth="4.5" strokeLinecap="round" opacity=".96" />
        <ellipse cx="32" cy="32" rx="11.5" ry="17" fill="#082f49" opacity=".42" />
        <ellipse cx="32" cy="32" rx="11.5" ry="17" fill="none" stroke={`url(#${tunnelId})`} strokeWidth="4" />
        <ellipse cx="32" cy="32" rx="5.7" ry="9" fill="none" stroke="#bae6fd" strokeWidth="2" opacity=".82" />
        <path d="M37 27c5-5 10-7 16-7" fill="none" stroke={`url(#${cyanId})`} strokeWidth="4.5" strokeLinecap="round" />
        <path d="M37 37c5 5 10 7 16 7" fill="none" stroke={`url(#${amberId})`} strokeWidth="4.5" strokeLinecap="round" />
        <circle cx="10" cy="32" r="4" fill="#f8fafc" />
        <circle cx="53" cy="20" r="4" fill="#67e8f9" />
        <circle cx="53" cy="44" r="4" fill="#fbbf24" />
      </svg>
      <span className="min-w-0">
        <span className="block truncate text-small font-semibold text-zinc-950 dark:text-white">{label}</span>
        {subtitle && <span className="block truncate text-tiny text-zinc-600 dark:text-zinc-400">{subtitle}</span>}
      </span>
    </div>
  );
}
