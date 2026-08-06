import type { PeerTransportPath } from "../hooks/useDirectTransfer";

/**
 * 互传设备列表的 AirDrop 式设备选择。
 *
 * 同一网络里此刻在线的设备会自动出现，远程设备通过邀请链接加入，统一按头像网格呈现：
 * 一眼看清有几台、点一下就选中。没有设备时显示扫描态而不是空列表——用户需要知道
 * "正在找"，而不是以为功能坏了。
 */

export interface NearbyDevice {
  peerId: string;
  displayName: string;
  /** 与本机同一公网出口（同一网络）时展示徽标，并按仅直连策略传输 */
  sameLan?: boolean;
}

interface NearbyDeviceGridProps {
  devices: NearbyDevice[];
  selectedPeerId: string;
  transportPaths: Record<string, PeerTransportPath | undefined>;
  discoverable: boolean;
  onSelect: (device: NearbyDevice) => void;
  /** 未开启"允许被发现"时，提供一个直达设置的入口 */
  onOpenSettings?: () => void;
}

/** 头像底色按 peerId 稳定派生，同一台设备在多次会话中颜色一致，便于肉眼识别。 */
function deviceAccent(peerId: string) {
  let hash = 0;
  for (let index = 0; index < peerId.length; index += 1) {
    hash = (hash * 31 + peerId.charCodeAt(index)) % 360;
  }
  return `hsl(${hash} 62% 46%)`;
}

function deviceInitial(name: string) {
  const trimmed = name.trim();
  if (!trimmed) return "?";
  // 中文取首字，拉丁字母取首字母大写
  return /^[a-z]/i.test(trimmed) ? trimmed[0].toUpperCase() : trimmed[0];
}

export function NearbyDeviceGrid({
  devices,
  selectedPeerId,
  transportPaths,
  discoverable,
  onSelect,
  onOpenSettings,
}: NearbyDeviceGridProps) {
  if (devices.length === 0) {
    return (
      <div className="nearby-empty flex flex-col items-center gap-3 rounded-xl border border-black/[0.07] px-4 py-8 text-center dark:border-white/[0.08]">
        <span className="nearby-radar" aria-hidden="true" />
        <div>
          <div className="text-small font-medium text-zinc-700 dark:text-zinc-200">正在查找设备…</div>
          <p className="mt-1 text-tiny leading-5 text-zinc-500 dark:text-zinc-400">
            同一网络的设备打开本页面会自动出现，远程设备可通过邀请链接加入。
          </p>
        </div>
        {!discoverable && onOpenSettings ? (
          <button
            type="button"
            onClick={onOpenSettings}
            className="min-h-9 rounded-md px-3 text-tiny font-medium text-[var(--diagram-apple-blue,#0066cc)] hover:bg-black/[0.04] dark:hover:bg-white/[0.06]"
          >
            你当前不可被发现，去开启
          </button>
        ) : null}
      </div>
    );
  }

  return (
    <div
      className="nearby-grid grid grid-cols-3 gap-x-2 gap-y-4 sm:grid-cols-4"
      role="radiogroup"
      aria-label="在线设备"
    >
      {devices.map((device) => {
        const selected = device.peerId === selectedPeerId;
        const path = transportPaths[device.peerId];
        return (
          <button
            key={device.peerId}
            type="button"
            role="radio"
            aria-checked={selected}
            onClick={() => onSelect(device)}
            className="nearby-device group flex min-h-11 flex-col items-center gap-1.5 rounded-lg p-1.5 text-center transition"
          >
            <span
              className={`nearby-avatar grid h-14 w-14 place-items-center rounded-full text-[19px] font-semibold text-white transition ${
                selected ? "is-selected" : ""
              }`}
              style={{ backgroundColor: deviceAccent(device.peerId) }}
            >
              {deviceInitial(device.displayName)}
            </span>
            <span className="w-full truncate text-[12px] font-medium text-zinc-700 dark:text-zinc-200">
              {device.displayName}
            </span>
            {device.sameLan ? (
              <span className="rounded bg-emerald-500/15 px-1.5 py-0.5 text-[10px] font-medium text-emerald-700 dark:text-emerald-200">
                同一网络
              </span>
            ) : null}
            {path ? (
              <span className="text-[11px] text-zinc-400">
                {path === "turn" ? "备用通道" : "直连"}
              </span>
            ) : null}
          </button>
        );
      })}
    </div>
  );
}
