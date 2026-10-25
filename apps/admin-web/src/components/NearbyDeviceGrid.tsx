import { useEffect, useId, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import type { PeerTransportPath } from "../hooks/useDirectTransfer";
import { Icon, Tag, type Tone } from "./ui";

/**
 * 互传的接收方选择：AirDrop 式的设备磁贴。
 *
 * 自动发现和邀请加入的设备都是一块磁贴：头像首字、名字、编号后四位和连接标签。
 * 发现不代表选中：只有用户点了磁贴才成为接收方；选中的设备离线后仍留在原位标成“离线”，
 * 不会被别的设备顶替。没有设备时区分正在寻找、连接失败，并说清楚怎么把设备加进来。
 */

export interface NearbyDevice {
  peerId: string;
  displayName: string;
  /** 与本机同一公网出口：自动发现的设备，不保证局域网可达。 */
  sameLan?: boolean;
  /** 页面第一次看到这台设备的时间，用来区分“连接中”和“在线”。 */
  firstSeenAt?: number;
}

export type DiscoveryStatus = "connecting" | "online" | "reconnecting" | "offline" | "name-conflict" | "permission-denied";

interface NearbyDeviceGridProps {
  devices: NearbyDevice[];
  selectedPeerId: string;
  /** 已选中但离线的接收方：留在列表里，绝不自动换成别的设备。 */
  offlineSelection?: { peerId: string; displayName: string } | null;
  transportPaths: Record<string, PeerTransportPath | undefined>;
  discoverable: boolean;
  discoveryStatus: DiscoveryStatus;
  onSelect: (device: NearbyDevice) => void;
  /** 未开启“允许被发现”时，提供一个直达设置的入口 */
  onOpenSettings?: () => void;
  onAddDevice: () => void;
  onRetry: () => void;
  /** 没有设备时显示的加入方式（二维码、配对码）。 */
  emptyAddon?: ReactNode;
}

/** 新出现的设备在这段时间内还没有连接路径时显示“连接中”，之后显示“在线”。 */
const CONNECTING_GRACE_MS = 15_000;

/** 头像底色按 peerId 稳定派生，取设计的分类色，同一台设备每次颜色一致。 */
export function deviceColor(peerId: string) {
  let hash = 0;
  for (let index = 0; index < peerId.length; index += 1) {
    hash = (hash * 31 + peerId.charCodeAt(index)) % 997;
  }
  return `var(--chart-${(hash % 6) + 1})`;
}

/** 把“名字 · 编号后四位”拆开显示；自定义名字也补上编号后四位，方便核对。 */
export function splitDeviceName(displayName: string, peerId: string) {
  const tail = peerId.slice(-4);
  const suffix = ` · ${tail}`;
  const name = tail && displayName.endsWith(suffix) ? displayName.slice(0, -suffix.length) : displayName;
  return { name: name || displayName, tail };
}

function deviceInitial(name: string) {
  const trimmed = name.trim();
  if (!trimmed) return "?";
  // 中文取首字，拉丁字母取首字母大写
  return /^[a-z]/i.test(trimmed) ? trimmed[0].toUpperCase() : Array.from(trimmed)[0];
}

export function connectionTag(
  path: PeerTransportPath | undefined,
  options: { offline?: boolean; firstSeenAt?: number; now: number },
): { label: string; tone: Tone; plain?: boolean } {
  if (options.offline) return { label: "离线", tone: "neutral", plain: true };
  if (path === "direct") return { label: "直连", tone: "success" };
  if (path === "turn") return { label: "中继", tone: "neutral" };
  if (options.firstSeenAt !== undefined && options.now - options.firstSeenAt < CONNECTING_GRACE_MS) {
    return { label: "连接中", tone: "info" };
  }
  return { label: "在线", tone: "neutral", plain: true };
}

export function DeviceAvatar({ peerId, name, size = "md", selected = false, offline = false }: {
  peerId: string; name: string; size?: "sm" | "md"; selected?: boolean; offline?: boolean;
}) {
  return (
    <span
      className={`nearby-avatar nearby-avatar--${size}${selected ? " is-selected" : ""}${offline ? " is-offline" : ""}`}
      style={{ ["--k" as string]: deviceColor(peerId) }}
      aria-hidden="true"
    >
      {deviceInitial(name)}
      {selected ? <span className="nearby-check"><Icon name="check" size={size === "sm" ? 9 : 12} /></span> : null}
    </span>
  );
}

export function NearbyDeviceGrid({
  devices,
  selectedPeerId,
  offlineSelection,
  transportPaths,
  discoverable,
  discoveryStatus,
  onSelect,
  onOpenSettings,
  onAddDevice,
  onRetry,
  emptyAddon,
}: NearbyDeviceGridProps) {
  const idPrefix = useId();
  const tileRefs = useRef<Array<HTMLButtonElement | null>>([]);
  // Re-render while a new device may still show "连接中", so the tag turns into "在线" on time.
  const [now, setNow] = useState(() => Date.now());
  const connectingSoon = devices.some((device) => device.firstSeenAt !== undefined
    && now - device.firstSeenAt < CONNECTING_GRACE_MS && !transportPaths[device.peerId]);
  useEffect(() => {
    if (!connectingSoon) return undefined;
    const timer = window.setInterval(() => setNow(Date.now()), 2000);
    return () => window.clearInterval(timer);
  }, [connectingSoon]);
  const connecting = discoveryStatus === "connecting" || discoveryStatus === "reconnecting";
  const failed = !connecting && discoveryStatus !== "online";
  const hiddenHint = !discoverable && onOpenSettings ? (
    <button type="button" className="nearby-hidden-hint" onClick={onOpenSettings}>
      <Icon name="eye-off" size={14} />
      <span>你当前不可被发现，其他设备看不到你</span>
      <span className="jd-link">去开启</span>
    </button>
  ) : null;

  if (devices.length === 0 && !offlineSelection) {
    return (
      <div className="nearby-empty" data-state={failed ? "failed" : connecting ? "connecting" : "searching"}>
        {failed ? (
          <div className="bd-empty-icon nearby-empty-icon"><Icon name="wifi" size={24} /></div>
        ) : (
          <span className="nearby-radar" aria-hidden="true"><Icon name="monitor" size={20} /></span>
        )}
        <div className="nearby-empty-title" role={failed ? undefined : "status"}>
          {connecting ? "正在连接设备发现服务" : failed ? "暂时无法发现设备" : "正在寻找附近设备"}
        </div>
        <p className="nearby-empty-desc">
          {failed
            ? "检查网络，或检查邀请链接是否仍然有效，然后重试连接。"
            : <>在另一台设备上打开本页，<b>同一网络</b>的设备会自动出现在这里；不在同一网络时，扫码或输入配对码。</>}
        </p>
        {!failed && emptyAddon ? <div className="nearby-empty-addon">{emptyAddon}</div> : null}
        <div className="bd-row nearby-empty-actions">
          {failed ? (
            <button type="button" className="bd-btn bd-btn--primary bd-btn--sm" onClick={onRetry}>
              <Icon name="refresh" /><span>重试连接</span>
            </button>
          ) : null}
          <button type="button" className={`bd-btn bd-btn--sm ${failed ? "bd-btn--ghost" : "bd-btn--secondary"}`} onClick={onAddDevice}>
            <Icon name="key" /><span>输入配对码</span>
          </button>
        </div>
        {hiddenHint}
      </div>
    );
  }

  const tiles: Array<NearbyDevice & { offline?: boolean }> = offlineSelection
    && !devices.some((device) => device.peerId === offlineSelection.peerId)
    ? [{ peerId: offlineSelection.peerId, displayName: offlineSelection.displayName, offline: true }, ...devices]
    : devices;
  const focusIndex = Math.max(0, tiles.findIndex((tile) => tile.peerId === selectedPeerId));

  const move = (event: KeyboardEvent<HTMLButtonElement>, index: number) => {
    const delta = event.key === "ArrowRight" || event.key === "ArrowDown" ? 1
      : event.key === "ArrowLeft" || event.key === "ArrowUp" ? -1 : 0;
    if (!delta) return;
    event.preventDefault();
    for (let step = 1; step <= tiles.length; step += 1) {
      const next = (index + delta * step + tiles.length * step) % tiles.length;
      if (!tiles[next].offline) {
        tileRefs.current[next]?.focus();
        onSelect(tiles[next]);
        return;
      }
    }
  };

  return (
    <div className="nearby-wrap">
      <div className="nearby-grid" role="radiogroup" aria-label="发送目标设备">
        {tiles.map((device, index) => {
          const selected = device.peerId === selectedPeerId;
          const { name, tail } = splitDeviceName(device.displayName, device.peerId);
          const tag = connectionTag(transportPaths[device.peerId], { offline: device.offline, firstSeenAt: device.firstSeenAt, now });
          const metaId = `${idPrefix}-${index}`;
          return (
            <button
              key={device.peerId}
              ref={(element) => { tileRefs.current[index] = element; }}
              type="button"
              role="radio"
              aria-checked={selected}
              aria-disabled={device.offline || undefined}
              aria-label={device.displayName}
              aria-describedby={metaId}
              tabIndex={index === focusIndex ? 0 : -1}
              className={`nearby-tile${selected ? " is-selected" : ""}${device.offline ? " is-offline" : ""}`}
              onClick={() => { if (!device.offline) onSelect(device); }}
              onKeyDown={(event) => move(event, index)}
            >
              <DeviceAvatar peerId={device.peerId} name={name} selected={selected} offline={device.offline} />
              <span className="nearby-name" title={device.displayName}>{name}</span>
              <span className="nearby-id bd-num">{tail}</span>
              <span id={metaId} className="nearby-meta">
                <Tag tone={tag.tone} plain={tag.plain}>{tag.label}</Tag>
                {device.sameLan && !device.offline ? <span className="jd-sr-only">，同一网络</span> : null}
                {selected ? <span className="jd-sr-only">，当前接收方</span> : null}
              </span>
            </button>
          );
        })}
      </div>
      {discoveryStatus === "online" ? (
        <div className="nearby-scan" aria-hidden="true">
          <span className="nearby-scan-dot" />
          <span>正在寻找更多设备</span>
        </div>
      ) : null}
      {hiddenHint}
    </div>
  );
}
