import { useEffect, useState } from "react";

/** 静止态下三束流光停靠的位置，沿输水槽均匀分布。 */
const RESTING_FLOW_X = [150, 336, 520];

/**
 * specus 主视觉：罗马引水渠。
 *
 * 品牌标识本身就是这条渠——顶部输水槽、三连拱、拱心一点流光。落地页把它放大成主视觉，
 * 让"specus（拉丁语：地道 / 引水渠）"这个名字在第一屏就自我解释：
 * 渠体承载水流，正如控制面承载流量；拱与拱之间是被打通的洞。
 *
 * 三个光点分别沿渠道流过，对应产品的三条链路（HTTP 路由 / 端口映射 / 对端互联）。
 * 尊重 prefers-reduced-motion：关闭动效后光点静止在渠上，构图不塌。
 */
export function SpecusAqueduct({ className = "" }: { className?: string }) {
  // 用 JS 判定而非纯 CSS：SMIL 的 animateMotion 不受 `display: none` 约束，
  // 若同时保留 CSS transform 与动画元素，两者会叠加把光点推出画面。
  // 这里让两种状态各自渲染，互不重叠。
  const [reduceMotion, setReduceMotion] = useState(false);

  useEffect(() => {
    const query = window.matchMedia("(prefers-reduced-motion: reduce)");
    const sync = () => setReduceMotion(query.matches);
    sync();
    query.addEventListener("change", sync);
    return () => query.removeEventListener("change", sync);
  }, []);

  return (
    <svg
      className={`specus-aqueduct ${className}`}
      viewBox="0 0 640 300"
      fill="none"
      role="img"
      aria-label="specus 引水渠：流量经由控制面穿过拱券抵达内网"
    >
      <defs>
        <linearGradient id="specus-channel" x1="0" y1="0" x2="640" y2="0" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="var(--specus-stroke)" stopOpacity="0.25" />
          <stop offset="0.5" stopColor="var(--specus-stroke)" />
          <stop offset="1" stopColor="var(--specus-stroke)" stopOpacity="0.25" />
        </linearGradient>
        <radialGradient id="specus-glow">
          <stop offset="0" stopColor="var(--specus-accent)" stopOpacity="0.55" />
          <stop offset="1" stopColor="var(--specus-accent)" stopOpacity="0" />
        </radialGradient>
        {/* 光点沿渠道行进的轨迹：与输水槽同一条线 */}
        <path id="specus-flow-path" d="M24 78 H616" />
      </defs>

      {/* 输水槽：渠顶的水道 */}
      <path
        d="M24 78 H616"
        stroke="url(#specus-channel)"
        strokeWidth="6"
        strokeLinecap="round"
      />

      {/* 拱券：外侧两组半跨拱托住中央主拱，与 logo 的比例一致 */}
      <g stroke="var(--specus-stroke)" strokeWidth="6" strokeLinecap="round" strokeLinejoin="round" fill="none">
        <path d="M32 268 V196 A44 44 0 0 1 120 196 V268" opacity="0.38" />
        <path d="M120 268 V186 A64 64 0 0 1 248 186 V268" opacity="0.62" />
        <path d="M248 268 V172 A88 88 0 0 1 424 172 V268" />
        <path d="M424 268 V186 A64 64 0 0 1 552 186 V268" opacity="0.62" />
        <path d="M552 268 V196 A44 44 0 0 1 608 196 V268" opacity="0.38" />
      </g>

      {/* 地平线 */}
      <path d="M8 268 H632" stroke="var(--specus-stroke)" strokeWidth="4" strokeLinecap="round" opacity="0.28" />

      {/* 主拱拱心的驻留光：标识里那颗紫点 */}
      <circle cx="336" cy="212" r="34" fill="url(#specus-glow)" />
      <circle cx="336" cy="212" r="7" fill="var(--specus-accent)" />

      {/* 三束流光：延迟错开，读起来像连续不断的水流 */}
      {RESTING_FLOW_X.map((restingX, index) => (
        reduceMotion ? (
          <circle
            key={restingX}
            cx={restingX}
            cy="78"
            r="5"
            fill="var(--specus-accent)"
            opacity="0.55"
          />
        ) : (
          <circle key={restingX} r="5" fill="var(--specus-accent)">
            <animateMotion dur="4.8s" begin={`${index * 1.6}s`} repeatCount="indefinite">
              <mpath href="#specus-flow-path" />
            </animateMotion>
            <animate
              attributeName="opacity"
              values="0;1;1;0"
              keyTimes="0;0.12;0.88;1"
              dur="4.8s"
              begin={`${index * 1.6}s`}
              repeatCount="indefinite"
            />
          </circle>
        )
      ))}
    </svg>
  );
}
