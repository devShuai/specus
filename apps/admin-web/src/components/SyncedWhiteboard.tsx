import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Button, Chip } from "@heroui/react";

export interface WhiteboardPoint {
  x: number;
  y: number;
}

export interface WhiteboardStroke {
  strokeId: string;
  sourcePeerId: string;
  color: string;
  width: number;
  points: WhiteboardPoint[];
  updatedAt: number;
}

export type WhiteboardPayload =
  | {
      type: "STWB1";
      kind: "stroke-start";
      strokeId: string;
      color: string;
      width: number;
      point: WhiteboardPoint;
      createdAt: number;
    }
  | {
      type: "STWB1";
      kind: "stroke-points" | "stroke-end";
      strokeId: string;
      points: WhiteboardPoint[];
      createdAt: number;
    }
  | {
      type: "STWB1";
      kind: "remove-stroke";
      strokeId: string;
      createdAt: number;
    }
  | {
      type: "STWB1";
      kind: "clear";
      clearId: string;
      createdAt: number;
    }
  | {
      type: "STWB1";
      kind: "snapshot";
      strokes: WhiteboardStroke[];
      createdAt: number;
    };

export interface WhiteboardInboundEvent {
  eventId: string;
  sourcePeerId: string;
  payload: WhiteboardPayload;
  receivedAt: number;
}

interface SyncedWhiteboardProps {
  boardKey: string;
  peerId: string;
  peerCount: number;
  isConnected: boolean;
  events: WhiteboardInboundEvent[];
  onSend: (payload: WhiteboardPayload) => void;
}

const WHITEBOARD_COLORS = [
  { label: "墨色", value: "#172033" },
  { label: "蓝色", value: "#2563eb" },
  { label: "绿色", value: "#059669" },
  { label: "橙色", value: "#ea580c" },
  { label: "红色", value: "#dc2626" },
];
const WHITEBOARD_WIDTHS = [
  { label: "细", value: 3 },
  { label: "中", value: 6 },
  { label: "粗", value: 10 },
  { label: "很粗", value: 16 },
];
const WHITEBOARD_SYNC_INTERVAL_MS = 220;
const MIN_POINT_DISTANCE = 0.0025;
const MAX_STROKES = 120;
const MAX_POINTS_PER_STROKE = 900;
const MAX_EVENT_POINTS = 160;
const MAX_SNAPSHOT_STROKES = 24;
const MAX_SNAPSHOT_POINTS = 120;
const ERASER_COLOR = "#ffffff";

export function SyncedWhiteboard({
  boardKey,
  peerId,
  peerCount,
  isConnected,
  events,
  onSend,
}: SyncedWhiteboardProps) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const strokesRef = useRef<WhiteboardStroke[]>([]);
  const activeStrokeIdRef = useRef<string | null>(null);
  const pendingPointsRef = useRef<WhiteboardPoint[]>([]);
  const flushTimerRef = useRef<number | null>(null);
  const seenEventsRef = useRef<Set<string>>(new Set());
  const lastPeerCountRef = useRef(peerCount);
  const [strokes, setStrokes] = useState<WhiteboardStroke[]>([]);
  const [selectedColor, setSelectedColor] = useState(WHITEBOARD_COLORS[0].value);
  const [selectedWidth, setSelectedWidth] = useState(WHITEBOARD_WIDTHS[1].value);
  const [eraserEnabled, setEraserEnabled] = useState(false);

  const activeColor = eraserEnabled ? ERASER_COLOR : selectedColor;
  const totalPeers = peerCount + 1;

  const updateStrokes = useCallback((updater: (current: WhiteboardStroke[]) => WhiteboardStroke[]) => {
    setStrokes((current) => {
      const next = updater(current).slice(-MAX_STROKES);
      strokesRef.current = next;
      return next;
    });
  }, []);

  const redraw = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas) {
      return;
    }
    const rect = canvas.getBoundingClientRect();
    const width = Math.max(1, Math.floor(rect.width));
    const height = Math.max(1, Math.floor(rect.height));
    const ratio = window.devicePixelRatio || 1;
    const backingWidth = Math.max(1, Math.floor(width * ratio));
    const backingHeight = Math.max(1, Math.floor(height * ratio));
    if (canvas.width !== backingWidth || canvas.height !== backingHeight) {
      canvas.width = backingWidth;
      canvas.height = backingHeight;
    }
    const context = canvas.getContext("2d");
    if (!context) {
      return;
    }
    context.setTransform(ratio, 0, 0, ratio, 0, 0);
    context.clearRect(0, 0, width, height);
    drawPaper(context, width, height);
    for (const stroke of strokesRef.current) {
      drawStroke(context, stroke, width, height);
    }
  }, []);

  useEffect(() => {
    strokesRef.current = strokes;
    redraw();
  }, [redraw, strokes]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) {
      return;
    }
    const observer = new ResizeObserver(() => redraw());
    observer.observe(canvas);
    redraw();
    return () => observer.disconnect();
  }, [redraw]);

  useEffect(() => {
    strokesRef.current = [];
    setStrokes([]);
    seenEventsRef.current.clear();
    lastPeerCountRef.current = peerCount;
    activeStrokeIdRef.current = null;
    pendingPointsRef.current = [];
    if (flushTimerRef.current !== null) {
      window.clearTimeout(flushTimerRef.current);
      flushTimerRef.current = null;
    }
  }, [boardKey]);

  const appendStrokePoints = useCallback((strokeId: string, sourcePeerId: string, points: WhiteboardPoint[]) => {
    if (points.length === 0) {
      return;
    }
    updateStrokes((current) => {
      const index = current.findIndex((stroke) => stroke.strokeId === strokeId);
      if (index < 0) {
        return [
          ...current,
          {
            strokeId,
            sourcePeerId,
            color: WHITEBOARD_COLORS[0].value,
            width: WHITEBOARD_WIDTHS[1].value,
            points: trimStrokePoints(points),
            updatedAt: Date.now(),
          },
        ];
      }
      const next = [...current];
      const stroke = next[index];
      next[index] = {
        ...stroke,
        points: trimStrokePoints([...stroke.points, ...points]),
        updatedAt: Date.now(),
      };
      return next;
    });
  }, [updateStrokes]);

  const applyRemotePayload = useCallback((event: WhiteboardInboundEvent) => {
    const payload = event.payload;
    if (event.sourcePeerId === peerId) {
      return;
    }
    if (payload.kind === "stroke-start") {
      updateStrokes((current) => {
        if (current.some((stroke) => stroke.strokeId === payload.strokeId)) {
          return current;
        }
        return [
          ...current,
          {
            strokeId: payload.strokeId,
            sourcePeerId: event.sourcePeerId,
            color: payload.color,
            width: payload.width,
            points: [payload.point],
            updatedAt: payload.createdAt,
          },
        ];
      });
      return;
    }
    if (payload.kind === "stroke-points" || payload.kind === "stroke-end") {
      appendStrokePoints(payload.strokeId, event.sourcePeerId, payload.points);
      return;
    }
    if (payload.kind === "remove-stroke") {
      updateStrokes((current) => current.filter((stroke) => stroke.strokeId !== payload.strokeId));
      return;
    }
    if (payload.kind === "clear") {
      updateStrokes(() => []);
      return;
    }
    if (payload.kind === "snapshot") {
      updateStrokes((current) => mergeSnapshot(current, payload.strokes));
    }
  }, [appendStrokePoints, peerId, updateStrokes]);

  useEffect(() => {
    for (const event of events) {
      if (seenEventsRef.current.has(event.eventId)) {
        continue;
      }
      seenEventsRef.current.add(event.eventId);
      applyRemotePayload(event);
    }
    if (seenEventsRef.current.size > 800) {
      seenEventsRef.current = new Set(Array.from(seenEventsRef.current).slice(-500));
    }
  }, [applyRemotePayload, events]);

  useEffect(() => {
    const previousPeerCount = lastPeerCountRef.current;
    lastPeerCountRef.current = peerCount;
    if (!isConnected || peerCount <= previousPeerCount || strokesRef.current.length === 0) {
      return;
    }
    const timer = window.setTimeout(() => {
      onSend({
        type: "STWB1",
        kind: "snapshot",
        strokes: compactSnapshot(strokesRef.current),
        createdAt: Date.now(),
      });
    }, 180 + Math.floor(Math.random() * 260));
    return () => window.clearTimeout(timer);
  }, [isConnected, onSend, peerCount]);

  const flushPendingPoints = useCallback((kind: "stroke-points" | "stroke-end" = "stroke-points") => {
    if (flushTimerRef.current !== null) {
      window.clearTimeout(flushTimerRef.current);
      flushTimerRef.current = null;
    }
    const strokeId = activeStrokeIdRef.current;
    if (!strokeId) {
      pendingPointsRef.current = [];
      return;
    }
    const points = pendingPointsRef.current.splice(0, MAX_EVENT_POINTS);
    if (points.length === 0 && kind === "stroke-points") {
      return;
    }
    onSend({
      type: "STWB1",
      kind,
      strokeId,
      points,
      createdAt: Date.now(),
    });
  }, [onSend]);

  const scheduleFlush = useCallback(() => {
    if (flushTimerRef.current !== null) {
      return;
    }
    flushTimerRef.current = window.setTimeout(() => flushPendingPoints("stroke-points"), WHITEBOARD_SYNC_INTERVAL_MS);
  }, [flushPendingPoints]);

  const startStroke = useCallback((event: React.PointerEvent<HTMLCanvasElement>) => {
    if (event.button !== 0 && event.pointerType === "mouse") {
      return;
    }
    const point = pointFromEvent(event);
    if (!point) {
      return;
    }
    event.currentTarget.setPointerCapture(event.pointerId);
    const strokeId = `${peerId}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
    const stroke: WhiteboardStroke = {
      strokeId,
      sourcePeerId: peerId,
      color: activeColor,
      width: selectedWidth,
      points: [point],
      updatedAt: Date.now(),
    };
    activeStrokeIdRef.current = strokeId;
    pendingPointsRef.current = [];
    updateStrokes((current) => [...current, stroke]);
    onSend({
      type: "STWB1",
      kind: "stroke-start",
      strokeId,
      color: activeColor,
      width: selectedWidth,
      point,
      createdAt: stroke.updatedAt,
    });
  }, [activeColor, onSend, peerId, selectedWidth, updateStrokes]);

  const moveStroke = useCallback((event: React.PointerEvent<HTMLCanvasElement>) => {
    const strokeId = activeStrokeIdRef.current;
    if (!strokeId) {
      return;
    }
    const point = pointFromEvent(event);
    if (!point) {
      return;
    }
    let accepted = false;
    updateStrokes((current) => {
      const index = current.findIndex((stroke) => stroke.strokeId === strokeId);
      if (index < 0) {
        return current;
      }
      const stroke = current[index];
      if (!shouldKeepPoint(stroke.points[stroke.points.length - 1], point)) {
        return current;
      }
      const next = [...current];
      next[index] = {
        ...stroke,
        points: trimStrokePoints([...stroke.points, point]),
        updatedAt: Date.now(),
      };
      accepted = true;
      return next;
    });
    if (accepted) {
      pendingPointsRef.current.push(point);
      scheduleFlush();
    }
  }, [scheduleFlush, updateStrokes]);

  const endStroke = useCallback((event: React.PointerEvent<HTMLCanvasElement>) => {
    if (!activeStrokeIdRef.current) {
      return;
    }
    moveStroke(event);
    flushPendingPoints("stroke-end");
    activeStrokeIdRef.current = null;
    pendingPointsRef.current = [];
    if (event.currentTarget.hasPointerCapture(event.pointerId)) {
      event.currentTarget.releasePointerCapture(event.pointerId);
    }
  }, [flushPendingPoints, moveStroke]);

  const clearBoard = () => {
    updateStrokes(() => []);
    onSend({
      type: "STWB1",
      kind: "clear",
      clearId: `${peerId}-${Date.now().toString(36)}`,
      createdAt: Date.now(),
    });
  };

  const undoLastLocalStroke = () => {
    const lastLocal = [...strokesRef.current].reverse().find((stroke) => stroke.sourcePeerId === peerId);
    if (!lastLocal) {
      return;
    }
    updateStrokes((current) => current.filter((stroke) => stroke.strokeId !== lastLocal.strokeId));
    onSend({
      type: "STWB1",
      kind: "remove-stroke",
      strokeId: lastLocal.strokeId,
      createdAt: Date.now(),
    });
  };

  const strokeCountLabel = useMemo(() => `${strokes.length} 笔`, [strokes.length]);

  return (
    <section className="mt-5 rounded-lg glass glass-border border p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h2 className="text-base font-semibold text-zinc-950 dark:text-white">同步白板</h2>
          <div className="mt-1 text-tiny leading-5 text-zinc-500 dark:text-zinc-400">
            {totalPeers} 台设备 · {strokeCountLabel}
          </div>
        </div>
        <Chip size="sm" radius="sm" variant="flat" color={isConnected ? "success" : "default"}>
          {isConnected ? "直连优先" : "本地绘制"}
        </Chip>
      </div>

      <div className="mt-3 flex flex-col gap-3 rounded-lg border border-black/10 bg-white/65 p-3 dark:border-white/10 dark:bg-white/[0.04]">
        <div className="flex flex-wrap items-center gap-2">
          {WHITEBOARD_COLORS.map((color) => (
            <button
              key={color.value}
              type="button"
              aria-label={`选择${color.label}`}
              title={color.label}
              onClick={() => {
                setSelectedColor(color.value);
                setEraserEnabled(false);
              }}
              className={`h-8 w-8 rounded-full border transition-transform focus:outline-none focus:ring-2 focus:ring-cyan-400 ${
                !eraserEnabled && selectedColor === color.value
                  ? "scale-110 border-zinc-950 ring-2 ring-cyan-400 dark:border-white"
                  : "border-black/15 dark:border-white/20"
              }`}
              style={{ backgroundColor: color.value }}
            />
          ))}
          <Button
            size="sm"
            radius="sm"
            variant={eraserEnabled ? "solid" : "flat"}
            color={eraserEnabled ? "primary" : "default"}
            onPress={() => setEraserEnabled((value) => !value)}
          >
            橡皮
          </Button>
          <div className="mx-1 hidden h-6 w-px bg-black/10 dark:bg-white/10 sm:block" />
          {WHITEBOARD_WIDTHS.map((width) => (
            <Button
              key={width.value}
              size="sm"
              radius="sm"
              variant={selectedWidth === width.value ? "solid" : "flat"}
              color={selectedWidth === width.value ? "primary" : "default"}
              onPress={() => setSelectedWidth(width.value)}
            >
              {width.label}
            </Button>
          ))}
          <div className="flex-1" />
          <Button size="sm" radius="sm" variant="flat" onPress={undoLastLocalStroke} isDisabled={!strokes.some((stroke) => stroke.sourcePeerId === peerId)}>
            撤销
          </Button>
          <Button size="sm" radius="sm" color="danger" variant="flat" onPress={clearBoard} isDisabled={strokes.length === 0}>
            清空
          </Button>
        </div>
        <div className="overflow-hidden rounded-lg border border-zinc-200 bg-white shadow-inner dark:border-white/10">
          <canvas
            ref={canvasRef}
            className="block w-full cursor-crosshair touch-none bg-white"
            style={{ height: "clamp(240px, 48dvh, 420px)" }}
            aria-label="同步白板画布"
            onPointerDown={startStroke}
            onPointerMove={moveStroke}
            onPointerUp={endStroke}
            onPointerCancel={endStroke}
            onPointerLeave={(event) => {
              if (activeStrokeIdRef.current && event.pointerType === "mouse") {
                endStroke(event);
              }
            }}
          />
        </div>
      </div>
    </section>
  );
}

export function isWhiteboardPayload(value: unknown): value is WhiteboardPayload {
  if (!isRecord(value) || value.type !== "STWB1" || typeof value.kind !== "string") {
    return false;
  }
  if (value.kind === "stroke-start") {
    return typeof value.strokeId === "string"
      && isColor(value.color)
      && isWidth(value.width)
      && isPoint(value.point)
      && typeof value.createdAt === "number";
  }
  if (value.kind === "stroke-points" || value.kind === "stroke-end") {
    return typeof value.strokeId === "string"
      && isPointArray(value.points, MAX_EVENT_POINTS)
      && typeof value.createdAt === "number";
  }
  if (value.kind === "remove-stroke") {
    return typeof value.strokeId === "string" && typeof value.createdAt === "number";
  }
  if (value.kind === "clear") {
    return typeof value.clearId === "string" && typeof value.createdAt === "number";
  }
  if (value.kind === "snapshot") {
    return Array.isArray(value.strokes)
      && value.strokes.length <= MAX_SNAPSHOT_STROKES
      && value.strokes.every(isStroke)
      && typeof value.createdAt === "number";
  }
  return false;
}

function pointFromEvent(event: React.PointerEvent<HTMLCanvasElement>): WhiteboardPoint | null {
  const rect = event.currentTarget.getBoundingClientRect();
  if (rect.width <= 0 || rect.height <= 0) {
    return null;
  }
  return {
    x: clamp((event.clientX - rect.left) / rect.width, 0, 1),
    y: clamp((event.clientY - rect.top) / rect.height, 0, 1),
  };
}

function drawPaper(context: CanvasRenderingContext2D, width: number, height: number) {
  context.fillStyle = "#ffffff";
  context.fillRect(0, 0, width, height);
  context.save();
  context.strokeStyle = "rgba(14, 116, 144, 0.08)";
  context.lineWidth = 1;
  const grid = 24;
  for (let x = grid; x < width; x += grid) {
    context.beginPath();
    context.moveTo(x, 0);
    context.lineTo(x, height);
    context.stroke();
  }
  for (let y = grid; y < height; y += grid) {
    context.beginPath();
    context.moveTo(0, y);
    context.lineTo(width, y);
    context.stroke();
  }
  context.restore();
}

function drawStroke(context: CanvasRenderingContext2D, stroke: WhiteboardStroke, width: number, height: number) {
  if (stroke.points.length === 0) {
    return;
  }
  context.save();
  context.strokeStyle = stroke.color;
  context.lineWidth = stroke.width;
  context.lineCap = "round";
  context.lineJoin = "round";
  context.globalCompositeOperation = "source-over";
  const first = stroke.points[0];
  context.beginPath();
  context.moveTo(first.x * width, first.y * height);
  if (stroke.points.length === 1) {
    context.lineTo(first.x * width + 0.1, first.y * height + 0.1);
  } else {
    for (const point of stroke.points.slice(1)) {
      context.lineTo(point.x * width, point.y * height);
    }
  }
  context.stroke();
  context.restore();
}

function shouldKeepPoint(previous: WhiteboardPoint | undefined, next: WhiteboardPoint) {
  if (!previous) {
    return true;
  }
  const dx = previous.x - next.x;
  const dy = previous.y - next.y;
  return Math.sqrt(dx * dx + dy * dy) >= MIN_POINT_DISTANCE;
}

function trimStrokePoints(points: WhiteboardPoint[]) {
  if (points.length <= MAX_POINTS_PER_STROKE) {
    return points;
  }
  return samplePoints(points, MAX_POINTS_PER_STROKE);
}

function samplePoints(points: WhiteboardPoint[], maxPoints: number) {
  if (points.length <= maxPoints) {
    return points;
  }
  if (maxPoints <= 2) {
    return points.slice(0, maxPoints);
  }
  const sampled: WhiteboardPoint[] = [];
  const last = points.length - 1;
  for (let index = 0; index < maxPoints; index += 1) {
    const sourceIndex = Math.round((index / (maxPoints - 1)) * last);
    sampled.push(points[sourceIndex]);
  }
  return sampled;
}

function compactSnapshot(strokes: WhiteboardStroke[]) {
  return strokes.slice(-MAX_SNAPSHOT_STROKES).map((stroke) => ({
    ...stroke,
    points: samplePoints(stroke.points, MAX_SNAPSHOT_POINTS),
  }));
}

function mergeSnapshot(current: WhiteboardStroke[], snapshot: WhiteboardStroke[]) {
  const byId = new Map(current.map((stroke) => [stroke.strokeId, stroke]));
  for (const stroke of snapshot) {
    const existing = byId.get(stroke.strokeId);
    if (!existing || existing.points.length < stroke.points.length || existing.updatedAt < stroke.updatedAt) {
      byId.set(stroke.strokeId, {
        ...stroke,
        points: trimStrokePoints(stroke.points),
      });
    }
  }
  return Array.from(byId.values()).sort((a, b) => a.updatedAt - b.updatedAt).slice(-MAX_STROKES);
}

function isStroke(value: unknown): value is WhiteboardStroke {
  return isRecord(value)
    && typeof value.strokeId === "string"
    && typeof value.sourcePeerId === "string"
    && isColor(value.color)
    && isWidth(value.width)
    && isPointArray(value.points, MAX_SNAPSHOT_POINTS)
    && typeof value.updatedAt === "number";
}

function isPointArray(value: unknown, maxLength: number): value is WhiteboardPoint[] {
  return Array.isArray(value) && value.length <= maxLength && value.every(isPoint);
}

function isPoint(value: unknown): value is WhiteboardPoint {
  return isRecord(value)
    && typeof value.x === "number"
    && Number.isFinite(value.x)
    && value.x >= 0
    && value.x <= 1
    && typeof value.y === "number"
    && Number.isFinite(value.y)
    && value.y >= 0
    && value.y <= 1;
}

function isColor(value: unknown): value is string {
  return typeof value === "string" && /^#[0-9a-fA-F]{6}$/.test(value);
}

function isWidth(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 1 && value <= 32;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function clamp(value: number, min: number, max: number) {
  return Math.max(min, Math.min(max, value));
}
