import { useEffect, useState } from "react";

/** 画面逻辑宽度：贯穿屏幕的通栏画布，居中构图、两侧拱券渐隐。 */
const SCENE_WIDTH = 1440;
const SCENE_CENTER = SCENE_WIDTH / 2;

/** 静止态下流光在输水槽上停靠的位置，沿全宽均匀分布。 */
const RESTING_FLOW_X = [180, 540, 900, 1260];

/** 带链路标注的三连拱（画面中央），与三条产品链路一一对应。 */
const LABELED_ARCHES = [
  { cx: 520, label: "HTTP 路由" },
  { cx: 720, label: "端口映射" },
  { cx: 920, label: "对端互联" },
];

/** 全宽拱券：中央三连拱 + 两侧延伸拱，opacity 随离画面中心的距离衰减。 */
const ARCH_OPACITY_BY_DISTANCE: Record<number, number> = {
  0: 1,
  200: 0.6,
  400: 0.38,
  600: 0.2,
};
const ARCH_STEP = 200;
const ARCH_CENTERS: Array<{ cx: number; opacity: number }> = [];
for (let offset = 0; offset <= SCENE_CENTER; offset += ARCH_STEP) {
  for (const cx of offset === 0 ? [SCENE_CENTER] : [SCENE_CENTER - offset, SCENE_CENTER + offset]) {
    ARCH_CENTERS.push({ cx, opacity: ARCH_OPACITY_BY_DISTANCE[offset] ?? 0.2 });
  }
}
ARCH_CENTERS.sort((a, b) => a.cx - b.cx);

/** 拱洞落光 / 涟漪的节奏：三拱错开，读起来像持续不断的来水。 */
const DROP_DURATION = "2.8s";

/** 上层小拱廊：等宽拱 + 等宽墩，按步进铺满全宽。 */
const ARCADE_ARCH_WIDTH = 34;
const ARCADE_STEP = 42;

function buildArcadePath(): string {
  const segments: string[] = [];
  for (let x = -8; x <= SCENE_WIDTH; x += ARCADE_STEP) {
    segments.push(`M${x} 180 V135 A17 17 0 0 1 ${x + ARCADE_ARCH_WIDTH} 135 V180`);
  }
  return segments.join(" ");
}

/** 拱墩上的砌缝短划，给出石材的尺度感。 */
const PIER_JOINT_Y = [275, 296];

/**
 * specus 主视觉：贯穿屏幕的罗马引水渠。
 *
 * 品牌标识本身就是这条渠——顶部输水槽、连拱、水流。落地页把它拉成通栏长卷：
 * 水槽与拱券横贯整个视口、向两侧渐隐，如同延伸进山谷的渠体；
 * 中央三连拱对应三条产品链路（HTTP 路由 / 端口映射 / 对端互联），
 * 光从拱洞坠入下方水面、激起涟漪——渠送水，洞通流，每一段水流都看得见。
 *
 * preserveAspectRatio="xMidYMid slice"：窄屏裁掉两侧拱券而非整体缩小，
 * 中央构图在任何视口宽度下都保持可读。
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
      viewBox={`0 0 ${SCENE_WIDTH} 380`}
      preserveAspectRatio="xMidYMid slice"
      fill="none"
      role="img"
      aria-label="specus 引水渠：活水沿通栏输水槽经过连拱，光从拱洞落入内网水面"
    >
      <defs>
        {/* 槽壁 / 地平的描边渐变：两端渐隐，让渠体延伸出画面 */}
        <linearGradient id="specus-channel" x1="0" y1="0" x2={SCENE_WIDTH} y2="0" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="var(--specus-stroke)" stopOpacity="0" />
          <stop offset="0.12" stopColor="var(--specus-stroke)" stopOpacity="0.9" />
          <stop offset="0.5" stopColor="var(--specus-stroke)" />
          <stop offset="0.88" stopColor="var(--specus-stroke)" stopOpacity="0.9" />
          <stop offset="1" stopColor="var(--specus-stroke)" stopOpacity="0" />
        </linearGradient>
        {/* 槽中水面：上亮下暗的一层薄水，两端随渠体渐隐 */}
        <linearGradient id="specus-water-fill" x1="0" y1="0" x2={SCENE_WIDTH} y2="0" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="var(--specus-water-bright)" stopOpacity="0" />
          <stop offset="0.1" stopColor="var(--specus-water-bright)" stopOpacity="0.85" />
          <stop offset="0.9" stopColor="var(--specus-water-bright)" stopOpacity="0.85" />
          <stop offset="1" stopColor="var(--specus-water-bright)" stopOpacity="0" />
        </linearGradient>
        {/* 拱下水潭：一团淡淡的水光 */}
        <radialGradient id="specus-pool">
          <stop offset="0" stopColor="var(--specus-water)" stopOpacity="0.4" />
          <stop offset="1" stopColor="var(--specus-water)" stopOpacity="0" />
        </radialGradient>
        {/* 流光沿渠道行进的轨迹：与水面同一条线，贯穿全宽 */}
        <path id="specus-flow-path" d={`M0 94 H${SCENE_WIDTH}`} />
      </defs>

      {/* 拱下水潭：三团水光先铺在桥体后面 */}
      {LABELED_ARCHES.map(({ cx }) => (
        <ellipse key={`pool-${cx}`} cx={cx} cy="322" rx="52" ry="12" fill="url(#specus-pool)" />
      ))}

      {/* 地平线 */}
      <path d={`M0 320 H${SCENE_WIDTH}`} stroke="url(#specus-channel)" strokeWidth="4" strokeLinecap="round" opacity="0.3" />

      {/* 下层拱券：中央三连拱完整，两侧延伸拱渐隐入山谷 */}
      <g stroke="var(--specus-stroke)" strokeWidth="8" strokeLinecap="round" strokeLinejoin="round" fill="none">
        {ARCH_CENTERS.map(({ cx, opacity }) => (
          <path key={`arch-${cx}`} d={`M${cx - 70} 320 V250 A70 70 0 0 1 ${cx + 70} 250 V320`} opacity={opacity} />
        ))}
      </g>

      {/* 拱墩砌缝（只画中央三连拱，远处拱墩淡到看不出砌缝） */}
      <g stroke="var(--specus-stroke)" strokeWidth="4" strokeLinecap="round" opacity="0.22">
        {LABELED_ARCHES.flatMap(({ cx }) =>
          [cx - 70, cx + 70].flatMap((x) =>
            PIER_JOINT_Y.map((y) => <path key={`joint-${x}-${y}`} d={`M${x - 7} ${y} H${x + 7}`} />),
          ),
        )}
      </g>

      {/* 下层桥面（同时是上层拱廊的基线） */}
      <path d={`M0 180 H${SCENE_WIDTH}`} stroke="url(#specus-channel)" strokeWidth="5" strokeLinecap="round" opacity="0.85" />

      {/* 上层小拱廊：铺满全宽 */}
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
      <path d={`M0 118 H${SCENE_WIDTH}`} stroke="url(#specus-channel)" strokeWidth="4" strokeLinecap="round" opacity="0.7" />
      <path d={`M0 100 H${SCENE_WIDTH}`} stroke="url(#specus-channel)" strokeWidth="4" strokeLinecap="round" opacity="0.55" />

      {/* 输水槽：槽壁横贯全宽 */}
      <path d={`M0 88 H${SCENE_WIDTH}`} stroke="url(#specus-channel)" strokeWidth="5" strokeLinecap="round" />
      <path d={`M0 100 H${SCENE_WIDTH}`} stroke="url(#specus-channel)" strokeWidth="4" strokeLinecap="round" opacity="0.55" />

      {/* 槽中活水：水带 + 流动的高光（dash march，CSS 驱动，reduced-motion 下自动静止） */}
      <rect x="0" y="89.5" width={SCENE_WIDTH} height="9" fill="url(#specus-water-fill)" />
      <path
        d={`M8 94 H${SCENE_WIDTH - 8}`}
        stroke="var(--specus-water-bright)"
        strokeWidth="3"
        strokeLinecap="round"
        className="specus-water-march"
        opacity="0.75"
      />

      {/* 流光：延迟错开，沿水面横贯全屏 */}
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
            <animateMotion dur="9.6s" begin={`${index * 2.4}s`} repeatCount="indefinite">
              <mpath href="#specus-flow-path" />
            </animateMotion>
            <animate
              attributeName="opacity"
              values="0;1;1;0"
              keyTimes="0;0.06;0.94;1"
              dur="9.6s"
              begin={`${index * 2.4}s`}
              repeatCount="indefinite"
            />
          </circle>
        ),
      )}

      {/* 拱洞落光与涟漪：光穿过中央三连拱坠入水潭——洞通流 */}
      {LABELED_ARCHES.map(({ cx }, index) =>
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

      {/* 中央三连拱对应的三条链路 */}
      {LABELED_ARCHES.map(({ cx, label }) => (
        <text
          key={`label-${cx}`}
          x={cx}
          y="354"
          textAnchor="middle"
          fontSize="12"
          fill="currentColor"
          opacity="0.55"
        >
          {label}
        </text>
      ))}
    </svg>
  );
}
