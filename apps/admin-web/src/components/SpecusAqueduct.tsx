import { useEffect, useState } from "react";

/** 静止态下三束流光在输水槽上停靠的位置。 */
const RESTING_FLOW_X = [140, 360, 580];

/** 下层三连拱的拱心横坐标，与三条产品链路一一对应。 */
const ARCH_CENTERS = [160, 360, 560];

const ARCH_LABELS = ["HTTP 路由", "端口映射", "对端互联"];

/** 拱洞落光 / 涟漪的节奏：三拱错开，读起来像持续不断的来水。 */
const DROP_DURATION = "2.8s";

/** 上层小拱廊：等宽拱 + 等宽墩，由基准 x 步进生成，避免手写十几条 path。 */
const ARCADE_START_X = 70;
const ARCADE_ARCH_WIDTH = 34;
const ARCADE_STEP = 42;
const ARCADE_COUNT = 14;

function buildArcadePath(): string {
  const segments: string[] = [];
  for (let i = 0; i < ARCADE_COUNT; i += 1) {
    const x = ARCADE_START_X + i * ARCADE_STEP;
    segments.push(`M${x} 180 V135 A17 17 0 0 1 ${x + ARCADE_ARCH_WIDTH} 135 V180`);
  }
  return segments.join(" ");
}

/** 下层拱墩上的砌缝短划，给出石材的尺度感。 */
const PIER_FACE_X = [90, 230, 290, 430, 490, 630];
const PIER_JOINT_Y = [275, 296];

/**
 * specus 主视觉：罗马引水渠。
 *
 * 品牌标识本身就是这条渠——顶部输水槽、三连拱、拱心一点流光。落地页把它放大成主视觉，
 * 让"specus（拉丁语：地道 / 引水渠）"这个名字在第一屏就自我解释：
 *
 *  - 输水槽里有活水流动，三束流光沿水面滑行，对应三条链路（HTTP 路由 / 端口映射 / 对端互联）；
 *  - 上层小拱廊托住水槽，下层三连拱是"被打通的洞"；
 *  - 光从每个拱洞坠入下方水面、激起涟漪——渠送水，洞通流，每一段水流都看得见。
 *
 * 尊重 prefers-reduced-motion：关闭动效后水面静止、光点驻留，构图不塌。
 * SMIL 的 animateMotion / animate 不受 CSS display 约束，所以静止态由 JS 分支渲染，
 * 不与动画元素同时存在，避免两种状态叠加把光点推出画面。
 */
export function SpecusAqueduct({ className = "" }: { className?: string }) {
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
      viewBox="0 0 720 380"
      fill="none"
      role="img"
      aria-label="specus 引水渠：活水沿输水槽经过三连拱，光从拱洞落入内网水面"
    >
      <defs>
        <linearGradient id="specus-channel" x1="48" y1="0" x2="672" y2="0" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="var(--specus-stroke)" stopOpacity="0.25" />
          <stop offset="0.5" stopColor="var(--specus-stroke)" />
          <stop offset="1" stopColor="var(--specus-stroke)" stopOpacity="0.25" />
        </linearGradient>
        {/* 槽中水面：上亮下暗的一层薄水 */}
        <linearGradient id="specus-water-fill" x1="0" y1="89" x2="0" y2="99" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="var(--specus-water-bright)" stopOpacity="0.85" />
          <stop offset="1" stopColor="var(--specus-water)" stopOpacity="0.3" />
        </linearGradient>
        <radialGradient id="specus-glow">
          <stop offset="0" stopColor="var(--specus-accent)" stopOpacity="0.55" />
          <stop offset="1" stopColor="var(--specus-accent)" stopOpacity="0" />
        </radialGradient>
        {/* 拱下水潭：一团淡淡的水光 */}
        <radialGradient id="specus-pool">
          <stop offset="0" stopColor="var(--specus-water)" stopOpacity="0.4" />
          <stop offset="1" stopColor="var(--specus-water)" stopOpacity="0" />
        </radialGradient>
        {/* 流光沿渠道行进的轨迹：与水面同一条线 */}
        <path id="specus-flow-path" d="M48 94 H672" />
      </defs>

      {/* 拱下水潭：三团水光先铺在桥体后面 */}
      {ARCH_CENTERS.map((cx) => (
        <ellipse key={`pool-${cx}`} cx={cx} cy="322" rx="52" ry="12" fill="url(#specus-pool)" />
      ))}

      {/* 地平线 */}
      <path d="M24 320 H696" stroke="var(--specus-stroke)" strokeWidth="4" strokeLinecap="round" opacity="0.28" />

      {/* 下层三连拱：中拱完整，两侧拱略淡，与 logo 的层次一致 */}
      <g stroke="var(--specus-stroke)" strokeWidth="8" strokeLinecap="round" strokeLinejoin="round" fill="none">
        <path d="M90 320 V250 A70 70 0 0 1 230 250 V320" opacity="0.6" />
        <path d="M290 320 V250 A70 70 0 0 1 430 250 V320" />
        <path d="M490 320 V250 A70 70 0 0 1 630 250 V320" opacity="0.6" />
      </g>

      {/* 拱墩砌缝 */}
      <g stroke="var(--specus-stroke)" strokeWidth="4" strokeLinecap="round" opacity="0.22">
        {PIER_FACE_X.flatMap((x) =>
          PIER_JOINT_Y.map((y) => <path key={`joint-${x}-${y}`} d={`M${x - 7} ${y} H${x + 7}`} />),
        )}
      </g>

      {/* 下层桥面（同时是上层拱廊的基线） */}
      <path d="M60 180 H660" stroke="var(--specus-stroke)" strokeWidth="5" strokeLinecap="round" opacity="0.85" />

      {/* 上层小拱廊 */}
      <path
        d={buildArcadePath()}
        stroke="var(--specus-stroke)"
        strokeWidth="4"
        strokeLinecap="round"
        strokeLinejoin="round"
        fill="none"
        opacity="0.5"
      />

      {/* 拱廊上方的檐部双线 */}
      <path d="M56 118 H664" stroke="var(--specus-stroke)" strokeWidth="4" strokeLinecap="round" opacity="0.7" />
      <path d="M56 100 H664" stroke="var(--specus-stroke)" strokeWidth="4" strokeLinecap="round" opacity="0.55" />

      {/* 输水槽：槽壁 + 两端封口 */}
      <path d="M48 88 H672" stroke="url(#specus-channel)" strokeWidth="5" strokeLinecap="round" />
      <path d="M48 100 H672" stroke="var(--specus-stroke)" strokeWidth="4" strokeLinecap="round" opacity="0.55" />
      <path d="M48 88 V100 M672 88 V100" stroke="var(--specus-stroke)" strokeWidth="4" strokeLinecap="round" opacity="0.55" />

      {/* 槽中活水：水带 + 流动的高光（dash march，CSS 驱动，reduced-motion 下自动静止） */}
      <rect x="50" y="89.5" width="620" height="9" fill="url(#specus-water-fill)" />
      <path
        d="M50 94 H670"
        stroke="var(--specus-water-bright)"
        strokeWidth="3"
        strokeLinecap="round"
        className="specus-water-march"
        opacity="0.75"
      />

      {/* 主拱拱心的驻留光：标识里那颗蓝点 */}
      <circle cx="360" cy="212" r="34" fill="url(#specus-glow)" />
      <circle cx="360" cy="212" r="7" fill="var(--specus-accent)" />

      {/* 三束流光：延迟错开，沿水面滑行 */}
      {RESTING_FLOW_X.map((restingX, index) =>
        reduceMotion ? (
          <circle
            key={restingX}
            cx={restingX}
            cy="94"
            r="5"
            fill="var(--specus-accent)"
            opacity="0.55"
          />
        ) : (
          <circle key={restingX} r="5" fill="var(--specus-accent)">
            <animateMotion dur="5.2s" begin={`${index * 1.73}s`} repeatCount="indefinite">
              <mpath href="#specus-flow-path" />
            </animateMotion>
            <animate
              attributeName="opacity"
              values="0;1;1;0"
              keyTimes="0;0.12;0.88;1"
              dur="5.2s"
              begin={`${index * 1.73}s`}
              repeatCount="indefinite"
            />
          </circle>
        ),
      )}

      {/* 拱洞落光与涟漪：光穿过拱洞坠入水潭——洞通流 */}
      {ARCH_CENTERS.map((cx, index) =>
        reduceMotion ? (
          <g key={`drop-${cx}`}>
            <circle cx={cx} cy="255" r="4" fill="var(--specus-accent)" opacity="0.45" />
            <ellipse cx={cx} cy="322" rx="26" ry="6" stroke="var(--specus-water)" strokeWidth="2" opacity="0.3" />
          </g>
        ) : (
          <g key={`drop-${cx}`}>
            <circle cx={cx} cy="196" r="4" fill="var(--specus-accent)">
              <animate
                attributeName="cy"
                values="196;316"
                dur={DROP_DURATION}
                begin={`${index * 0.93}s`}
                repeatCount="indefinite"
              />
              <animate
                attributeName="opacity"
                values="0;1;1;0"
                keyTimes="0;0.18;0.82;1"
                dur={DROP_DURATION}
                begin={`${index * 0.93}s`}
                repeatCount="indefinite"
              />
            </circle>
            <ellipse cx={cx} cy="322" rx="8" ry="2.5" stroke="var(--specus-water)" strokeWidth="2" fill="none">
              <animate
                attributeName="rx"
                values="8;42"
                dur={DROP_DURATION}
                begin={`${index * 0.93}s`}
                repeatCount="indefinite"
              />
              <animate
                attributeName="ry"
                values="2.5;9"
                dur={DROP_DURATION}
                begin={`${index * 0.93}s`}
                repeatCount="indefinite"
              />
              <animate
                attributeName="opacity"
                values="0;0;0.5;0"
                keyTimes="0;0.72;0.82;1"
                dur={DROP_DURATION}
                begin={`${index * 0.93}s`}
                repeatCount="indefinite"
              />
            </ellipse>
          </g>
        ),
      )}

      {/* 三拱对应的三条链路 */}
      {ARCH_CENTERS.map((cx, index) => (
        <text
          key={`label-${cx}`}
          x={cx}
          y="354"
          textAnchor="middle"
          fontSize="12"
          fill="currentColor"
          opacity="0.55"
        >
          {ARCH_LABELS[index]}
        </text>
      ))}
    </svg>
  );
}
