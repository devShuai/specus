import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
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

interface WhiteboardObjectBase {
  objectId: string;
  sourcePeerId: string;
  x: number;
  y: number;
  width: number;
  height: number;
  color: string;
  strokeWidth: number;
  updatedAt: number;
}

export interface WhiteboardTextObject extends WhiteboardObjectBase {
  kind: "text";
  text: string;
  fontSize: number;
}

export interface WhiteboardShapeObject extends WhiteboardObjectBase {
  kind: "shape";
  shapeKind: WhiteboardShapeKind;
}

export interface WhiteboardImageObject extends WhiteboardObjectBase {
  kind: "image";
  dataUrl: string;
  fileName: string;
}

export type WhiteboardObject = WhiteboardTextObject | WhiteboardShapeObject | WhiteboardImageObject;
export type WhiteboardShapeKind = "rectangle" | "ellipse" | "arrow";

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
      kind: "object-upsert";
      object: WhiteboardObject;
      createdAt: number;
    }
  | {
      type: "STWB1";
      kind: "remove-object";
      objectId: string;
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
  isActive?: boolean;
  events: WhiteboardInboundEvent[];
  onSend: (payload: WhiteboardPayload) => void;
}

type WhiteboardTool = "select" | "pen" | "eraser" | "text" | WhiteboardShapeKind;

interface ObjectDragState {
  objectId: string;
  start: WhiteboardPoint;
  original: WhiteboardObject;
}

interface ObjectResizeState {
  objectId: string;
  original: WhiteboardObject;
}

interface ShapeDraftState {
  objectId: string;
  start: WhiteboardPoint;
}

interface TextDraft {
  x: number;
  y: number;
  text: string;
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
const MAX_OBJECTS = 80;
const MAX_SYNC_OBJECTS = 32;
const MAX_TEXT_LENGTH = 500;
const MAX_IMAGE_SOURCE_BYTES = 15 * 1024 * 1024;
const MAX_IMAGE_DATA_URL_LENGTH = 48 * 1024;
const ERASER_COLOR = "#ffffff";

export function SyncedWhiteboard({
  boardKey,
  peerId,
  peerCount,
  isConnected,
  isActive = true,
  events,
  onSend,
}: SyncedWhiteboardProps) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const imageInputRef = useRef<HTMLInputElement | null>(null);
  const strokesRef = useRef<WhiteboardStroke[]>([]);
  const objectsRef = useRef<WhiteboardObject[]>([]);
  const activeStrokeIdRef = useRef<string | null>(null);
  const pendingPointsRef = useRef<WhiteboardPoint[]>([]);
  const flushTimerRef = useRef<number | null>(null);
  const seenEventsRef = useRef<Set<string>>(new Set());
  const lastPeerCountRef = useRef(peerCount);
  const selectedObjectIdRef = useRef<string | null>(null);
  const objectDragRef = useRef<ObjectDragState | null>(null);
  const objectResizeRef = useRef<ObjectResizeState | null>(null);
  const shapeDraftRef = useRef<ShapeDraftState | null>(null);
  const imageCacheRef = useRef<Map<string, HTMLImageElement>>(new Map());
  const redrawRef = useRef<() => void>(() => undefined);

  const [strokes, setStrokes] = useState<WhiteboardStroke[]>([]);
  const [objects, setObjects] = useState<WhiteboardObject[]>([]);
  const [selectedColor, setSelectedColor] = useState(WHITEBOARD_COLORS[0].value);
  const [selectedWidth, setSelectedWidth] = useState(WHITEBOARD_WIDTHS[1].value);
  const [selectedTool, setSelectedTool] = useState<WhiteboardTool>("pen");
  const [selectedObjectId, setSelectedObjectId] = useState<string | null>(null);
  const [textDraft, setTextDraft] = useState<TextDraft | null>(null);
  const [isExpanded, setIsExpanded] = useState(false);
  const [isImportingImage, setIsImportingImage] = useState(false);
  const [boardMessage, setBoardMessage] = useState("画笔已就绪，可直接在画布上绘制。");

  const activeColor = selectedTool === "eraser" ? ERASER_COLOR : selectedColor;
  const totalPeers = peerCount + 1;

  const selectObject = useCallback((objectId: string | null) => {
    selectedObjectIdRef.current = objectId;
    setSelectedObjectId(objectId);
  }, []);

  const updateStrokes = useCallback((updater: (current: WhiteboardStroke[]) => WhiteboardStroke[]) => {
    const next = updater(strokesRef.current).slice(-MAX_STROKES);
    strokesRef.current = next;
    setStrokes(next);
  }, []);

  const updateObjects = useCallback((updater: (current: WhiteboardObject[]) => WhiteboardObject[]) => {
    const next = updater(objectsRef.current).slice(-MAX_OBJECTS);
    objectsRef.current = next;
    setObjects(next);
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
    for (const object of objectsRef.current) {
      drawBoardObject(context, object, width, height, imageCacheRef.current, () => redrawRef.current());
    }
    const selected = objectsRef.current.find((object) => object.objectId === selectedObjectIdRef.current);
    if (selected) {
      drawObjectSelection(context, selected, width, height);
    }
  }, []);
  redrawRef.current = redraw;

  useEffect(() => {
    strokesRef.current = strokes;
    objectsRef.current = objects;
    redraw();
  }, [objects, redraw, selectedObjectId, strokes]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) {
      return;
    }
    const observer = new ResizeObserver(() => redraw());
    observer.observe(canvas);
    redraw();
    return () => observer.disconnect();
  }, [isExpanded, redraw]);

  useEffect(() => {
    if (!isActive) {
      return;
    }
    const frame = window.requestAnimationFrame(redraw);
    return () => window.cancelAnimationFrame(frame);
  }, [isActive, isExpanded, redraw]);

  useEffect(() => {
    if (!isExpanded) {
      return;
    }
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !textDraft) {
        setIsExpanded(false);
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => {
      document.body.style.overflow = previousOverflow;
      window.removeEventListener("keydown", handleKeyDown);
    };
  }, [isExpanded, textDraft]);

  useEffect(() => {
    if (!isActive) {
      setIsExpanded(false);
    }
  }, [isActive]);

  useEffect(() => {
    strokesRef.current = [];
    objectsRef.current = [];
    setStrokes([]);
    setObjects([]);
    selectObject(null);
    setTextDraft(null);
    setBoardMessage("已切换到新的房间白板。");
    imageCacheRef.current.clear();
    seenEventsRef.current.clear();
    lastPeerCountRef.current = peerCount;
    activeStrokeIdRef.current = null;
    objectDragRef.current = null;
    objectResizeRef.current = null;
    shapeDraftRef.current = null;
    pendingPointsRef.current = [];
    if (flushTimerRef.current !== null) {
      window.clearTimeout(flushTimerRef.current);
      flushTimerRef.current = null;
    }
  }, [boardKey, selectObject]);

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
        const index = current.findIndex((stroke) => stroke.strokeId === payload.strokeId);
        if (index >= 0) {
          const next = [...current];
          const stroke = next[index];
          const points = stroke.points.length > 0 && shouldKeepPoint(payload.point, stroke.points[0])
            ? [payload.point, ...stroke.points]
            : stroke.points.length > 0 ? stroke.points : [payload.point];
          next[index] = {
            ...stroke,
            sourcePeerId: event.sourcePeerId,
            color: payload.color,
            width: payload.width,
            points: trimStrokePoints(points),
            updatedAt: Math.max(stroke.updatedAt, payload.createdAt),
          };
          return next;
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
    if (payload.kind === "object-upsert") {
      const remoteObject = { ...payload.object, sourcePeerId: event.sourcePeerId };
      updateObjects((current) => {
        const index = current.findIndex((object) => object.objectId === remoteObject.objectId);
        if (index < 0) {
          return [...current, remoteObject];
        }
        if (current[index].updatedAt > remoteObject.updatedAt) {
          return current;
        }
        const next = [...current];
        next[index] = remoteObject;
        return next;
      });
      return;
    }
    if (payload.kind === "remove-object") {
      updateObjects((current) => current.filter((object) => object.objectId !== payload.objectId));
      if (selectedObjectIdRef.current === payload.objectId) {
        selectObject(null);
      }
      return;
    }
    if (payload.kind === "clear") {
      updateStrokes(() => []);
      updateObjects(() => []);
      selectObject(null);
      return;
    }
    if (payload.kind === "snapshot") {
      updateStrokes((current) => mergeSnapshot(current, payload.strokes));
    }
  }, [appendStrokePoints, peerId, selectObject, updateObjects, updateStrokes]);

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
    if (!isConnected
      || peerCount <= previousPeerCount
      || (strokesRef.current.length === 0 && objectsRef.current.length === 0)) {
      return;
    }
    const timers: number[] = [];
    timers.push(window.setTimeout(() => {
      if (strokesRef.current.length > 0) {
        onSend({
          type: "STWB1",
          kind: "snapshot",
          strokes: compactSnapshot(strokesRef.current),
          createdAt: Date.now(),
        });
      }
      objectsRef.current.slice(-MAX_SYNC_OBJECTS).forEach((object, index) => {
        timers.push(window.setTimeout(() => {
          onSend({
            type: "STWB1",
            kind: "object-upsert",
            object,
            createdAt: Date.now(),
          });
        }, 40 * index));
      });
    }, 180 + Math.floor(Math.random() * 260)));
    return () => timers.forEach((timer) => window.clearTimeout(timer));
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
    if (pendingPointsRef.current.length === 0 && kind === "stroke-points") {
      return;
    }
    let batchIndex = 0;
    while (pendingPointsRef.current.length > 0) {
      const points = pendingPointsRef.current.splice(0, MAX_EVENT_POINTS);
      onSend({
        type: "STWB1",
        kind: kind === "stroke-end" && pendingPointsRef.current.length === 0 ? "stroke-end" : "stroke-points",
        strokeId,
        points,
        createdAt: Date.now() + batchIndex,
      });
      batchIndex += 1;
    }
    if (kind === "stroke-end" && batchIndex === 0) {
      onSend({
        type: "STWB1",
        kind: "stroke-end",
        strokeId,
        points: [],
        createdAt: Date.now(),
      });
    }
  }, [onSend]);

  const scheduleFlush = useCallback(() => {
    if (flushTimerRef.current !== null) {
      return;
    }
    flushTimerRef.current = window.setTimeout(() => flushPendingPoints("stroke-points"), WHITEBOARD_SYNC_INTERVAL_MS);
  }, [flushPendingPoints]);

  const sendObject = useCallback((object: WhiteboardObject) => {
    onSend({
      type: "STWB1",
      kind: "object-upsert",
      object,
      createdAt: object.updatedAt,
    });
  }, [onSend]);

  const removeObject = useCallback((objectId: string) => {
    updateObjects((current) => current.filter((object) => object.objectId !== objectId));
    if (selectedObjectIdRef.current === objectId) {
      selectObject(null);
    }
    onSend({
      type: "STWB1",
      kind: "remove-object",
      objectId,
      createdAt: Date.now(),
    });
  }, [onSend, selectObject, updateObjects]);

  const startStroke = useCallback((
    event: React.PointerEvent<HTMLCanvasElement>,
    point: WhiteboardPoint,
  ) => {
    event.currentTarget.setPointerCapture(event.pointerId);
    const strokeId = createWhiteboardId(peerId, "stroke");
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

  const moveStroke = useCallback((point: WhiteboardPoint) => {
    const strokeId = activeStrokeIdRef.current;
    if (!strokeId) {
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

  const updateShapeDraft = useCallback((point: WhiteboardPoint) => {
    const draft = shapeDraftRef.current;
    if (!draft) {
      return;
    }
    updateObjects((current) => current.map((object) => (
      object.objectId === draft.objectId
        ? resizeShapeObject(object as WhiteboardShapeObject, draft.start, point)
        : object
    )));
  }, [updateObjects]);

  const updateObjectDrag = useCallback((point: WhiteboardPoint) => {
    const drag = objectDragRef.current;
    if (!drag) {
      return;
    }
    updateObjects((current) => current.map((object) => (
      object.objectId === drag.objectId ? moveBoardObject(drag.original, drag.start, point) : object
    )));
  }, [updateObjects]);

  const updateObjectResize = useCallback((point: WhiteboardPoint) => {
    const resize = objectResizeRef.current;
    if (!resize) {
      return;
    }
    updateObjects((current) => current.map((object) => (
      object.objectId === resize.objectId ? resizeBoardObject(resize.original, point) : object
    )));
  }, [updateObjects]);

  const handlePointerDown = useCallback((event: React.PointerEvent<HTMLCanvasElement>) => {
    if (event.button !== 0 && event.pointerType === "mouse") {
      return;
    }
    const point = pointFromEvent(event);
    if (!point) {
      return;
    }
    if (selectedTool === "text") {
      setTextDraft({
        x: clamp(point.x, 0.02, 0.7),
        y: clamp(point.y, 0.02, 0.78),
        text: "",
      });
      setBoardMessage("输入文本，按 Ctrl/⌘ + Enter 插入，Esc 取消。");
      return;
    }
    if (selectedTool === "select") {
      const currentSelection = objectsRef.current.find((object) => object.objectId === selectedObjectIdRef.current);
      if (currentSelection && isResizeHandleAtPoint(currentSelection, point)) {
        objectResizeRef.current = { objectId: currentSelection.objectId, original: currentSelection };
        event.currentTarget.setPointerCapture(event.pointerId);
        setBoardMessage("拖动缩放手柄调整对象大小。");
        return;
      }
      const selected = findObjectAtPoint(objectsRef.current, point);
      selectObject(selected?.objectId ?? null);
      if (selected) {
        objectDragRef.current = { objectId: selected.objectId, start: point, original: selected };
        event.currentTarget.setPointerCapture(event.pointerId);
        setBoardMessage("拖动已选对象调整位置，按 Delete 可删除。");
      } else {
        setBoardMessage("未选中对象。可切换画笔、文本或图形工具继续编辑。");
      }
      return;
    }
    if (selectedTool === "rectangle" || selectedTool === "ellipse" || selectedTool === "arrow") {
      const object = createShapeObject(peerId, selectedTool, point, selectedColor, selectedWidth);
      shapeDraftRef.current = { objectId: object.objectId, start: point };
      updateObjects((current) => [...current, object]);
      selectObject(object.objectId);
      event.currentTarget.setPointerCapture(event.pointerId);
      setBoardMessage("拖动确定图形大小，松开后会同步给房间设备。");
      return;
    }
    if (selectedTool === "eraser") {
      const object = findObjectAtPoint(objectsRef.current, point);
      if (object) {
        removeObject(object.objectId);
        setBoardMessage("已删除对象。");
        return;
      }
    }
    selectObject(null);
    startStroke(event, point);
  }, [peerId, removeObject, selectObject, selectedColor, selectedTool, selectedWidth, startStroke, updateObjects]);

  const handlePointerMove = useCallback((event: React.PointerEvent<HTMLCanvasElement>) => {
    const point = pointFromEvent(event);
    if (!point) {
      return;
    }
    if (activeStrokeIdRef.current) {
      moveStroke(point);
    } else if (shapeDraftRef.current) {
      updateShapeDraft(point);
    } else if (objectResizeRef.current) {
      updateObjectResize(point);
    } else if (objectDragRef.current) {
      updateObjectDrag(point);
    }
  }, [moveStroke, updateObjectDrag, updateObjectResize, updateShapeDraft]);

  const handlePointerEnd = useCallback((event: React.PointerEvent<HTMLCanvasElement>) => {
    const point = pointFromEvent(event);
    if (activeStrokeIdRef.current) {
      if (point) {
        moveStroke(point);
      }
      flushPendingPoints("stroke-end");
      activeStrokeIdRef.current = null;
      pendingPointsRef.current = [];
    } else if (shapeDraftRef.current) {
      if (point) {
        updateShapeDraft(point);
      }
      const objectId = shapeDraftRef.current.objectId;
      const object = objectsRef.current.find((item) => item.objectId === objectId);
      if (object?.kind === "shape") {
        const finalized = ensureShapeSize(object);
        updateObjects((current) => current.map((item) => item.objectId === objectId ? finalized : item));
        sendObject(finalized);
      }
      shapeDraftRef.current = null;
      setSelectedTool("select");
      setBoardMessage("图形已插入。使用选择工具可以继续拖动。");
    } else if (objectResizeRef.current) {
      if (point) {
        updateObjectResize(point);
      }
      const objectId = objectResizeRef.current.objectId;
      const object = objectsRef.current.find((item) => item.objectId === objectId);
      if (object) {
        const updated = { ...object, updatedAt: Date.now() };
        updateObjects((current) => current.map((item) => item.objectId === objectId ? updated : item));
        sendObject(updated);
      }
      objectResizeRef.current = null;
      setBoardMessage("对象大小已调整并同步。");
    } else if (objectDragRef.current) {
      if (point) {
        updateObjectDrag(point);
      }
      const objectId = objectDragRef.current.objectId;
      const object = objectsRef.current.find((item) => item.objectId === objectId);
      if (object) {
        const updated = { ...object, updatedAt: Date.now() };
        updateObjects((current) => current.map((item) => item.objectId === objectId ? updated : item));
        sendObject(updated);
      }
      objectDragRef.current = null;
    }
    if (event.currentTarget.hasPointerCapture(event.pointerId)) {
      event.currentTarget.releasePointerCapture(event.pointerId);
    }
  }, [flushPendingPoints, moveStroke, sendObject, updateObjectDrag, updateObjectResize, updateObjects, updateShapeDraft]);

  const commitTextDraft = useCallback(() => {
    if (!textDraft) {
      return;
    }
    const text = textDraft.text.trim();
    if (!text) {
      setTextDraft(null);
      setBoardMessage("已取消空文本框。");
      return;
    }
    const width = 0.3;
    const height = clamp(0.1 + Math.ceil(text.length / 24) * 0.035, 0.12, 0.32);
    const object: WhiteboardTextObject = {
      objectId: createWhiteboardId(peerId, "text"),
      sourcePeerId: peerId,
      kind: "text",
      x: clamp(textDraft.x, 0, 1 - width),
      y: clamp(textDraft.y, 0, 1 - height),
      width,
      height,
      color: selectedColor,
      strokeWidth: 2,
      text,
      fontSize: 22,
      updatedAt: Date.now(),
    };
    updateObjects((current) => [...current, object]);
    selectObject(object.objectId);
    sendObject(object);
    setTextDraft(null);
    setSelectedTool("select");
    setBoardMessage("文本框已插入，可使用选择工具拖动。");
  }, [peerId, selectObject, selectedColor, sendObject, textDraft, updateObjects]);

  const importImage = useCallback(async (file: File) => {
    if (!file.type.startsWith("image/")) {
      setBoardMessage("请选择图片文件。");
      return;
    }
    if (file.size > MAX_IMAGE_SOURCE_BYTES) {
      setBoardMessage("图片超过 15 MB，请压缩后再插入。");
      return;
    }
    setIsImportingImage(true);
    setBoardMessage("正在压缩图片，确保直连和回退通道都能同步...");
    try {
      const compressed = await compressWhiteboardImage(file);
      const canvasRect = canvasRef.current?.getBoundingClientRect();
      const boardAspect = canvasRect && canvasRect.height > 0 ? canvasRect.width / canvasRect.height : 1.6;
      let objectWidth = 0.38;
      let objectHeight = objectWidth * (compressed.height / compressed.width) * boardAspect;
      if (objectHeight > 0.55) {
        objectWidth *= 0.55 / objectHeight;
        objectHeight = 0.55;
      }
      objectWidth = clamp(objectWidth, 0.16, 0.55);
      objectHeight = clamp(objectHeight, 0.14, 0.55);
      const object: WhiteboardImageObject = {
        objectId: createWhiteboardId(peerId, "image"),
        sourcePeerId: peerId,
        kind: "image",
        x: (1 - objectWidth) / 2,
        y: (1 - objectHeight) / 2,
        width: objectWidth,
        height: objectHeight,
        color: selectedColor,
        strokeWidth: 2,
        dataUrl: compressed.dataUrl,
        fileName: file.name.slice(0, 120) || "image.jpg",
        updatedAt: Date.now(),
      };
      updateObjects((current) => [...current, object]);
      selectObject(object.objectId);
      sendObject(object);
      setSelectedTool("select");
      setBoardMessage("图片已压缩并插入，可拖动调整位置。");
    } catch (error) {
      setBoardMessage(error instanceof Error ? error.message : "图片插入失败");
    } finally {
      setIsImportingImage(false);
    }
  }, [peerId, selectObject, selectedColor, sendObject, updateObjects]);

  const handleImageInput = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.currentTarget.files?.[0];
    event.currentTarget.value = "";
    if (file) {
      void importImage(file);
    }
  };

  const handleBoardPaste = (event: React.ClipboardEvent<HTMLElement>) => {
    if (event.target instanceof HTMLTextAreaElement || event.target instanceof HTMLInputElement) {
      return;
    }
    const image = Array.from(event.clipboardData.items)
      .find((item) => item.kind === "file" && item.type.startsWith("image/"))
      ?.getAsFile();
    if (!image) {
      return;
    }
    event.preventDefault();
    event.stopPropagation();
    void importImage(image);
  };

  const handleImageDrop = (event: React.DragEvent<HTMLDivElement>) => {
    const file = Array.from(event.dataTransfer.files).find((item) => item.type.startsWith("image/"));
    if (!file) {
      return;
    }
    event.preventDefault();
    event.stopPropagation();
    void importImage(file);
  };

  const clearBoard = () => {
    updateStrokes(() => []);
    updateObjects(() => []);
    selectObject(null);
    onSend({
      type: "STWB1",
      kind: "clear",
      clearId: createWhiteboardId(peerId, "clear"),
      createdAt: Date.now(),
    });
    setBoardMessage("白板已清空。");
  };

  const undoLastLocalElement = () => {
    const lastStroke = [...strokesRef.current].reverse().find((stroke) => stroke.sourcePeerId === peerId);
    const lastObject = [...objectsRef.current].reverse().find((object) => object.sourcePeerId === peerId);
    if (!lastStroke && !lastObject) {
      return;
    }
    if (lastObject && (!lastStroke || lastObject.updatedAt >= lastStroke.updatedAt)) {
      removeObject(lastObject.objectId);
      setBoardMessage("已撤销最近插入的对象。");
      return;
    }
    if (lastStroke) {
      updateStrokes((current) => current.filter((stroke) => stroke.strokeId !== lastStroke.strokeId));
      onSend({
        type: "STWB1",
        kind: "remove-stroke",
        strokeId: lastStroke.strokeId,
        createdAt: Date.now(),
      });
      setBoardMessage("已撤销最近一笔。");
    }
  };

  const handleCanvasKeyDown = (event: React.KeyboardEvent<HTMLCanvasElement>) => {
    if ((event.key === "Delete" || event.key === "Backspace") && selectedObjectIdRef.current) {
      event.preventDefault();
      removeObject(selectedObjectIdRef.current);
      setBoardMessage("已删除所选对象。");
      return;
    }
    const shortcut = event.key.toLowerCase();
    const shortcuts: Partial<Record<string, WhiteboardTool>> = {
      v: "select",
      p: "pen",
      e: "eraser",
      t: "text",
      r: "rectangle",
      o: "ellipse",
      a: "arrow",
    };
    if (shortcuts[shortcut]) {
      event.preventDefault();
      setSelectedTool(shortcuts[shortcut]);
    }
  };

  const localElementExists = strokes.some((stroke) => stroke.sourcePeerId === peerId)
    || objects.some((object) => object.sourcePeerId === peerId);
  const boardCountLabel = useMemo(
    () => strokes.length + " 笔 · " + objects.length + " 个对象",
    [objects.length, strokes.length],
  );
  const cursorClass = selectedTool === "select"
    ? "cursor-default"
    : selectedTool === "text"
      ? "cursor-text"
      : "cursor-crosshair";

  const board = (
    <section
      className={
        (isExpanded
          ? "fixed inset-0 z-[90] m-0 flex h-[100dvh] flex-col overflow-hidden rounded-none border-0 bg-zinc-100 p-3 dark:bg-zinc-950 sm:p-4"
          : "mt-5 rounded-xl glass glass-border border p-3 sm:p-4")
        + (isActive ? "" : " hidden")
      }
      aria-hidden={!isActive}
      onPaste={handleBoardPaste}
    >
      <div className="flex shrink-0 flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="text-base font-semibold text-zinc-950 dark:text-white">同步白板</h2>
            <Chip size="sm" radius="sm" variant="flat" color={isConnected ? "success" : "default"}>
              {isConnected ? "实时同步" : "本地绘制"}
            </Chip>
            <Chip size="sm" radius="sm" variant="flat">
              {totalPeers} 台 · {boardCountLabel}
            </Chip>
          </div>
          <div className="mt-1 text-tiny leading-5 text-zinc-500 dark:text-zinc-400">
            插入的文本、图形和压缩图片会与笔画一起同步给房间设备。
          </div>
        </div>
        <Button
          size="sm"
          radius="sm"
          color={isExpanded ? "primary" : "default"}
          variant="flat"
          onPress={() => setIsExpanded((value) => !value)}
        >
          <span className="mr-1.5"><ToolGlyph name={isExpanded ? "collapse" : "fullscreen"} /></span>
          {isExpanded ? "退出全屏" : "全屏白板"}
        </Button>
      </div>

      <div
        className={
          "mt-3 flex min-h-0 flex-col overflow-hidden rounded-xl border border-black/10 bg-white/70 shadow-sm dark:border-white/10 dark:bg-white/[0.04]"
          + (isExpanded ? " flex-1" : "")
        }
      >
        <div className="shrink-0 border-b border-black/10 bg-white/80 p-2.5 dark:border-white/10 dark:bg-zinc-900/90">
          <div className="flex items-center gap-1.5 overflow-x-auto pb-1" role="toolbar" aria-label="白板工具">
            <WhiteboardToolButton tool="select" label="选择" activeTool={selectedTool} onSelect={setSelectedTool} />
            <WhiteboardToolButton tool="pen" label="画笔" activeTool={selectedTool} onSelect={setSelectedTool} />
            <WhiteboardToolButton tool="eraser" label="橡皮" activeTool={selectedTool} onSelect={setSelectedTool} />
            <span className="mx-1 h-8 w-px shrink-0 bg-black/10 dark:bg-white/10" aria-hidden />
            <WhiteboardToolButton tool="text" label="文本" activeTool={selectedTool} onSelect={setSelectedTool} />
            <WhiteboardToolButton tool="rectangle" label="矩形" activeTool={selectedTool} onSelect={setSelectedTool} />
            <WhiteboardToolButton tool="ellipse" label="圆形" activeTool={selectedTool} onSelect={setSelectedTool} />
            <WhiteboardToolButton tool="arrow" label="箭头" activeTool={selectedTool} onSelect={setSelectedTool} />
            <button
              type="button"
              className="flex h-10 shrink-0 items-center gap-1.5 rounded-md px-2.5 text-tiny font-medium text-zinc-700 transition hover:bg-cyan-50 hover:text-cyan-900 focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400 disabled:opacity-50 dark:text-zinc-200 dark:hover:bg-cyan-300/10 dark:hover:text-cyan-100"
              onClick={() => imageInputRef.current?.click()}
              disabled={isImportingImage}
            >
              <ToolGlyph name="image" />
              {isImportingImage ? "处理中" : "图片"}
            </button>
            <input ref={imageInputRef} type="file" accept="image/*" hidden onChange={handleImageInput} />
          </div>

          <div className="mt-2 flex flex-wrap items-center gap-2 border-t border-black/5 pt-2 dark:border-white/5">
            <div className="flex items-center gap-1.5" aria-label="画笔颜色">
              {WHITEBOARD_COLORS.map((color) => (
                <button
                  key={color.value}
                  type="button"
                  aria-label={"选择" + color.label}
                  title={color.label}
                  onClick={() => {
                    setSelectedColor(color.value);
                    if (selectedTool === "eraser") {
                      setSelectedTool("pen");
                    }
                  }}
                  className={
                    "h-7 w-7 rounded-full border transition-transform focus:outline-none focus:ring-2 focus:ring-cyan-400 "
                    + (selectedColor === color.value && selectedTool !== "eraser"
                      ? "scale-110 border-zinc-950 ring-2 ring-cyan-400 dark:border-white"
                      : "border-black/15 dark:border-white/20")
                  }
                  style={{ backgroundColor: color.value }}
                />
              ))}
            </div>
            <span className="mx-0.5 h-6 w-px bg-black/10 dark:bg-white/10" aria-hidden />
            <div className="flex items-center gap-1">
              {WHITEBOARD_WIDTHS.map((width) => (
                <Button
                  key={width.value}
                  size="sm"
                  radius="sm"
                  className="h-8 min-w-9 px-2"
                  variant={selectedWidth === width.value ? "solid" : "light"}
                  color={selectedWidth === width.value ? "primary" : "default"}
                  title={width.label + "线条"}
                  onPress={() => setSelectedWidth(width.value)}
                >
                  <span
                    className="block w-5 rounded-full bg-current"
                    style={{ height: Math.max(2, width.value / 2) }}
                    aria-hidden
                  />
                </Button>
              ))}
            </div>
            <div className="min-w-2 flex-1" />
            <Button size="sm" radius="sm" variant="light" onPress={undoLastLocalElement} isDisabled={!localElementExists}>
              撤销
            </Button>
            <Button
              size="sm"
              radius="sm"
              variant="light"
              isDisabled={!selectedObjectId}
              onPress={() => selectedObjectId && removeObject(selectedObjectId)}
            >
              删除所选
            </Button>
            <Button size="sm" radius="sm" color="danger" variant="flat" onPress={clearBoard} isDisabled={strokes.length === 0 && objects.length === 0}>
              清空
            </Button>
          </div>
        </div>

        <div
          className={"relative min-h-0 overflow-hidden bg-white" + (isExpanded ? " flex-1" : "")}
          onDragOver={(event) => {
            if (Array.from(event.dataTransfer.items).some((item) => item.kind === "file" && item.type.startsWith("image/"))) {
              event.preventDefault();
            }
          }}
          onDrop={handleImageDrop}
        >
          <canvas
            ref={canvasRef}
            className={"block w-full touch-none bg-white outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-cyan-400 " + cursorClass}
            style={{ height: isExpanded ? "100%" : "clamp(320px, 58dvh, 680px)" }}
            aria-label="同步白板画布"
            tabIndex={0}
            onKeyDown={handleCanvasKeyDown}
            onPointerDown={handlePointerDown}
            onPointerMove={handlePointerMove}
            onPointerUp={handlePointerEnd}
            onPointerCancel={handlePointerEnd}
            onPointerLeave={(event) => {
              if ((activeStrokeIdRef.current || shapeDraftRef.current || objectResizeRef.current || objectDragRef.current) && event.pointerType === "mouse") {
                handlePointerEnd(event);
              }
            }}
          />
          {textDraft ? (
            <textarea
              autoFocus
              value={textDraft.text}
              maxLength={MAX_TEXT_LENGTH}
              placeholder="输入文本..."
              aria-label="白板文本框内容"
              className="absolute z-20 h-28 w-[min(18rem,72%)] resize-none rounded-lg border-2 border-cyan-500 bg-white/95 p-3 text-small text-zinc-950 shadow-xl outline-none ring-4 ring-cyan-500/10"
              style={{ left: textDraft.x * 100 + "%", top: textDraft.y * 100 + "%" }}
              onChange={(event) => {
                const value = event.currentTarget.value;
                setTextDraft((current) => current ? { ...current, text: value } : current);
              }}
              onPointerDown={(event) => event.stopPropagation()}
              onBlur={() => commitTextDraft()}
              onKeyDown={(event) => {
                if (event.key === "Escape") {
                  event.preventDefault();
                  setTextDraft(null);
                  setBoardMessage("已取消文本框。");
                } else if (event.key === "Enter" && (event.metaKey || event.ctrlKey)) {
                  event.preventDefault();
                  commitTextDraft();
                }
              }}
            />
          ) : null}
        </div>

        <div className="flex shrink-0 flex-wrap items-center justify-between gap-2 border-t border-black/10 bg-white/80 px-3 py-2 text-tiny text-zinc-500 dark:border-white/10 dark:bg-zinc-900/90 dark:text-zinc-400">
          <span>{boardMessage}</span>
          <span className="hidden font-mono text-[10px] sm:inline">V 选择 · P 画笔 · T 文本 · Delete 删除</span>
        </div>
      </div>
    </section>
  );
  return isExpanded ? createPortal(board, document.body) : board;
}

function WhiteboardToolButton({
  tool,
  label,
  activeTool,
  onSelect,
}: {
  tool: WhiteboardTool;
  label: string;
  activeTool: WhiteboardTool;
  onSelect: (tool: WhiteboardTool) => void;
}) {
  const active = tool === activeTool;
  return (
    <button
      type="button"
      aria-pressed={active}
      className={
        "flex h-10 shrink-0 items-center gap-1.5 rounded-md px-2.5 text-tiny font-medium transition focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400 "
        + (active
          ? "bg-cyan-500 text-white shadow-sm dark:bg-cyan-300 dark:text-zinc-950"
          : "text-zinc-700 hover:bg-cyan-50 hover:text-cyan-900 dark:text-zinc-200 dark:hover:bg-cyan-300/10 dark:hover:text-cyan-100")
      }
      onClick={() => onSelect(tool)}
    >
      <ToolGlyph name={tool} />
      {label}
    </button>
  );
}

function ToolGlyph({ name }: { name: WhiteboardTool | "image" | "fullscreen" | "collapse" }) {
  const common = {
    className: "h-4 w-4 shrink-0",
    fill: "none",
    stroke: "currentColor",
    strokeLinecap: "round" as const,
    strokeLinejoin: "round" as const,
    strokeWidth: 1.8,
    viewBox: "0 0 24 24",
    "aria-hidden": true,
  };
  if (name === "select") {
    return <svg {...common}><path d="M5 3l12 9-6 1.5L8.5 20 5 3z" /></svg>;
  }
  if (name === "pen") {
    return <svg {...common}><path d="M4 20l4.5-1 10-10a2.1 2.1 0 00-3-3l-10 10L4 20zM14 7l3 3" /></svg>;
  }
  if (name === "eraser") {
    return <svg {...common}><path d="M7 18l-3-3 8-10a2 2 0 013 0l4 4a2 2 0 010 3l-6 6H7zM10 18h10" /></svg>;
  }
  if (name === "text") {
    return <svg {...common}><path d="M5 5h14M12 5v14M8 19h8" /></svg>;
  }
  if (name === "rectangle") {
    return <svg {...common}><rect x="4" y="5" width="16" height="14" rx="1" /></svg>;
  }
  if (name === "ellipse") {
    return <svg {...common}><ellipse cx="12" cy="12" rx="8" ry="6.5" /></svg>;
  }
  if (name === "arrow") {
    return <svg {...common}><path d="M4 17L19 6M13 6h6v6" /></svg>;
  }
  if (name === "image") {
    return <svg {...common}><rect x="3" y="4" width="18" height="16" rx="2" /><circle cx="8" cy="9" r="1.5" /><path d="M4 17l5-5 4 4 3-3 5 5" /></svg>;
  }
  if (name === "collapse") {
    return <svg {...common}><path d="M9 4v5H4M15 4v5h5M9 20v-5H4M15 20v-5h5" /></svg>;
  }
  return <svg {...common}><path d="M9 4H4v5M15 4h5v5M9 20H4v-5M15 20h5v-5" /></svg>;
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
  if (value.kind === "object-upsert") {
    return isWhiteboardObject(value.object) && typeof value.createdAt === "number";
  }
  if (value.kind === "remove-object") {
    return isIdentifier(value.objectId) && typeof value.createdAt === "number";
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

function createWhiteboardId(peerId: string, kind: string) {
  return peerId + "-" + kind + "-" + Date.now().toString(36) + "-" + Math.random().toString(36).slice(2, 8);
}

function createShapeObject(
  peerId: string,
  shapeKind: WhiteboardShapeKind,
  point: WhiteboardPoint,
  color: string,
  strokeWidth: number,
): WhiteboardShapeObject {
  return {
    objectId: createWhiteboardId(peerId, shapeKind),
    sourcePeerId: peerId,
    kind: "shape",
    shapeKind,
    x: point.x,
    y: point.y,
    width: 0.001,
    height: 0.001,
    color,
    strokeWidth,
    updatedAt: Date.now(),
  };
}

function resizeShapeObject(
  object: WhiteboardShapeObject,
  start: WhiteboardPoint,
  end: WhiteboardPoint,
): WhiteboardShapeObject {
  if (object.shapeKind === "arrow") {
    return {
      ...object,
      x: start.x,
      y: start.y,
      width: end.x - start.x,
      height: end.y - start.y,
      updatedAt: Date.now(),
    };
  }
  return {
    ...object,
    x: Math.min(start.x, end.x),
    y: Math.min(start.y, end.y),
    width: Math.max(0.001, Math.abs(end.x - start.x)),
    height: Math.max(0.001, Math.abs(end.y - start.y)),
    updatedAt: Date.now(),
  };
}

function ensureShapeSize(object: WhiteboardShapeObject): WhiteboardShapeObject {
  if (Math.abs(object.width) >= 0.015 || Math.abs(object.height) >= 0.015) {
    return { ...object, updatedAt: Date.now() };
  }
  if (object.shapeKind === "arrow") {
    return {
      ...object,
      width: object.x > 0.78 ? -0.18 : 0.18,
      height: object.y > 0.86 ? -0.1 : 0.1,
      updatedAt: Date.now(),
    };
  }
  const width = Math.min(0.18, 1 - object.x);
  const height = Math.min(0.12, 1 - object.y);
  return { ...object, width, height, updatedAt: Date.now() };
}

function moveBoardObject(
  object: WhiteboardObject,
  start: WhiteboardPoint,
  point: WhiteboardPoint,
): WhiteboardObject {
  const bounds = normalizedObjectBounds(object);
  const deltaX = clamp(point.x - start.x, -bounds.x, 1 - bounds.x - bounds.width);
  const deltaY = clamp(point.y - start.y, -bounds.y, 1 - bounds.y - bounds.height);
  return {
    ...object,
    x: object.x + deltaX,
    y: object.y + deltaY,
    updatedAt: Date.now(),
  };
}

function resizeBoardObject(object: WhiteboardObject, point: WhiteboardPoint): WhiteboardObject {
  if (object.kind === "shape" && object.shapeKind === "arrow") {
    const width = point.x - object.x;
    const height = point.y - object.y;
    return {
      ...object,
      width: Math.abs(width) < 0.015 ? (width < 0 ? -0.015 : 0.015) : width,
      height: Math.abs(height) < 0.015 ? (height < 0 ? -0.015 : 0.015) : height,
      updatedAt: Date.now(),
    };
  }
  return {
    ...object,
    width: clamp(point.x - object.x, 0.05, 1 - object.x),
    height: clamp(point.y - object.y, 0.05, 1 - object.y),
    updatedAt: Date.now(),
  };
}

function isResizeHandleAtPoint(object: WhiteboardObject, point: WhiteboardPoint) {
  const handle = { x: object.x + object.width, y: object.y + object.height };
  return Math.hypot(point.x - handle.x, point.y - handle.y) <= 0.025;
}

function findObjectAtPoint(objects: WhiteboardObject[], point: WhiteboardPoint) {
  return [...objects].reverse().find((object) => objectContainsPoint(object, point));
}

function objectContainsPoint(object: WhiteboardObject, point: WhiteboardPoint) {
  if (object.kind === "shape" && object.shapeKind === "arrow") {
    return distanceToSegment(
      point,
      { x: object.x, y: object.y },
      { x: object.x + object.width, y: object.y + object.height },
    ) <= 0.025;
  }
  const bounds = normalizedObjectBounds(object);
  const padding = 0.012;
  return point.x >= bounds.x - padding
    && point.x <= bounds.x + bounds.width + padding
    && point.y >= bounds.y - padding
    && point.y <= bounds.y + bounds.height + padding;
}

function normalizedObjectBounds(object: WhiteboardObject) {
  const endX = object.x + object.width;
  const endY = object.y + object.height;
  return {
    x: Math.min(object.x, endX),
    y: Math.min(object.y, endY),
    width: Math.abs(object.width),
    height: Math.abs(object.height),
  };
}

function distanceToSegment(point: WhiteboardPoint, start: WhiteboardPoint, end: WhiteboardPoint) {
  const dx = end.x - start.x;
  const dy = end.y - start.y;
  if (dx === 0 && dy === 0) {
    return Math.hypot(point.x - start.x, point.y - start.y);
  }
  const ratio = clamp(((point.x - start.x) * dx + (point.y - start.y) * dy) / (dx * dx + dy * dy), 0, 1);
  return Math.hypot(point.x - (start.x + ratio * dx), point.y - (start.y + ratio * dy));
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

function drawBoardObject(
  context: CanvasRenderingContext2D,
  object: WhiteboardObject,
  width: number,
  height: number,
  imageCache: Map<string, HTMLImageElement>,
  onImageReady: () => void,
) {
  if (object.kind === "shape") {
    drawShape(context, object, width, height);
  } else if (object.kind === "text") {
    drawTextObject(context, object, width, height);
  } else {
    drawImageObject(context, object, width, height, imageCache, onImageReady);
  }
}

function drawShape(
  context: CanvasRenderingContext2D,
  object: WhiteboardShapeObject,
  width: number,
  height: number,
) {
  const x = object.x * width;
  const y = object.y * height;
  const objectWidth = object.width * width;
  const objectHeight = object.height * height;
  context.save();
  context.strokeStyle = object.color;
  context.fillStyle = colorWithAlpha(object.color, 0.1);
  context.lineWidth = object.strokeWidth;
  context.lineJoin = "round";
  context.lineCap = "round";
  if (object.shapeKind === "rectangle") {
    context.beginPath();
    context.roundRect(x, y, objectWidth, objectHeight, Math.min(12, Math.abs(objectWidth) / 5, Math.abs(objectHeight) / 5));
    context.fill();
    context.stroke();
  } else if (object.shapeKind === "ellipse") {
    context.beginPath();
    context.ellipse(
      x + objectWidth / 2,
      y + objectHeight / 2,
      Math.abs(objectWidth / 2),
      Math.abs(objectHeight / 2),
      0,
      0,
      Math.PI * 2,
    );
    context.fill();
    context.stroke();
  } else {
    const endX = x + objectWidth;
    const endY = y + objectHeight;
    const angle = Math.atan2(endY - y, endX - x);
    const headLength = Math.max(10, Math.min(24, Math.hypot(objectWidth, objectHeight) * 0.16));
    context.beginPath();
    context.moveTo(x, y);
    context.lineTo(endX, endY);
    context.moveTo(endX, endY);
    context.lineTo(endX - headLength * Math.cos(angle - Math.PI / 6), endY - headLength * Math.sin(angle - Math.PI / 6));
    context.moveTo(endX, endY);
    context.lineTo(endX - headLength * Math.cos(angle + Math.PI / 6), endY - headLength * Math.sin(angle + Math.PI / 6));
    context.stroke();
  }
  context.restore();
}

function drawTextObject(
  context: CanvasRenderingContext2D,
  object: WhiteboardTextObject,
  width: number,
  height: number,
) {
  const x = object.x * width;
  const y = object.y * height;
  const boxWidth = Math.max(80, object.width * width);
  const boxHeight = Math.max(50, object.height * height);
  const padding = 12;
  context.save();
  context.fillStyle = "rgba(255, 255, 255, 0.94)";
  context.strokeStyle = colorWithAlpha(object.color, 0.55);
  context.lineWidth = Math.max(1, object.strokeWidth);
  context.beginPath();
  context.roundRect(x, y, boxWidth, boxHeight, 10);
  context.fill();
  context.stroke();
  context.fillStyle = object.color;
  context.font = "600 " + object.fontSize + "px Inter, system-ui, sans-serif";
  context.textBaseline = "top";
  const lineHeight = object.fontSize * 1.35;
  const lines = wrapCanvasText(context, object.text, boxWidth - padding * 2);
  const maxLines = Math.max(1, Math.floor((boxHeight - padding * 2) / lineHeight));
  lines.slice(0, maxLines).forEach((line, index) => {
    const suffix = index === maxLines - 1 && lines.length > maxLines ? "…" : "";
    context.fillText(line + suffix, x + padding, y + padding + index * lineHeight, boxWidth - padding * 2);
  });
  context.restore();
}

function drawImageObject(
  context: CanvasRenderingContext2D,
  object: WhiteboardImageObject,
  width: number,
  height: number,
  imageCache: Map<string, HTMLImageElement>,
  onImageReady: () => void,
) {
  const x = object.x * width;
  const y = object.y * height;
  const boxWidth = Math.max(60, object.width * width);
  const boxHeight = Math.max(50, object.height * height);
  context.save();
  context.fillStyle = "#f4f4f5";
  context.strokeStyle = colorWithAlpha(object.color, 0.45);
  context.lineWidth = Math.max(1, object.strokeWidth);
  context.beginPath();
  context.roundRect(x, y, boxWidth, boxHeight, 10);
  context.fill();
  context.clip();
  let image = imageCache.get(object.dataUrl);
  if (!image) {
    image = new Image();
    imageCache.set(object.dataUrl, image);
    image.onload = onImageReady;
    image.src = object.dataUrl;
  }
  if (image.complete && image.naturalWidth > 0) {
    const scale = Math.min(boxWidth / image.naturalWidth, boxHeight / image.naturalHeight);
    const renderWidth = image.naturalWidth * scale;
    const renderHeight = image.naturalHeight * scale;
    context.drawImage(
      image,
      x + (boxWidth - renderWidth) / 2,
      y + (boxHeight - renderHeight) / 2,
      renderWidth,
      renderHeight,
    );
  } else {
    context.fillStyle = "#71717a";
    context.font = "500 13px Inter, system-ui, sans-serif";
    context.textAlign = "center";
    context.textBaseline = "middle";
    context.fillText("图片载入中", x + boxWidth / 2, y + boxHeight / 2);
  }
  context.restore();
  context.save();
  context.strokeStyle = colorWithAlpha(object.color, 0.45);
  context.lineWidth = Math.max(1, object.strokeWidth);
  context.beginPath();
  context.roundRect(x, y, boxWidth, boxHeight, 10);
  context.stroke();
  context.restore();
}

function drawObjectSelection(
  context: CanvasRenderingContext2D,
  object: WhiteboardObject,
  width: number,
  height: number,
) {
  const bounds = normalizedObjectBounds(object);
  const x = bounds.x * width;
  const y = bounds.y * height;
  const boxWidth = Math.max(8, bounds.width * width);
  const boxHeight = Math.max(8, bounds.height * height);
  context.save();
  context.strokeStyle = "#06b6d4";
  context.lineWidth = 2;
  context.setLineDash([6, 4]);
  context.strokeRect(x - 5, y - 5, boxWidth + 10, boxHeight + 10);
  context.setLineDash([]);
  context.fillStyle = "#ffffff";
  context.strokeStyle = "#0891b2";
  const handleX = object.kind === "shape" && object.shapeKind === "arrow"
    ? (object.x + object.width) * width
    : x + boxWidth + 5;
  const handleY = object.kind === "shape" && object.shapeKind === "arrow"
    ? (object.y + object.height) * height
    : y + boxHeight + 5;
  context.beginPath();
  context.rect(handleX - 4, handleY - 4, 8, 8);
  context.fill();
  context.stroke();
  context.restore();
}

function wrapCanvasText(context: CanvasRenderingContext2D, text: string, maxWidth: number) {
  const lines: string[] = [];
  for (const paragraph of text.split(/\r?\n/)) {
    if (!paragraph) {
      lines.push("");
      continue;
    }
    let line = "";
    for (const character of paragraph) {
      const candidate = line + character;
      if (line && context.measureText(candidate).width > maxWidth) {
        lines.push(line);
        line = character;
      } else {
        line = candidate;
      }
    }
    lines.push(line);
  }
  return lines;
}

function colorWithAlpha(color: string, alpha: number) {
  const red = Number.parseInt(color.slice(1, 3), 16);
  const green = Number.parseInt(color.slice(3, 5), 16);
  const blue = Number.parseInt(color.slice(5, 7), 16);
  return "rgba(" + red + ", " + green + ", " + blue + ", " + alpha + ")";
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

function isWhiteboardObject(value: unknown): value is WhiteboardObject {
  if (!isRecord(value)
    || !isIdentifier(value.objectId)
    || !isIdentifier(value.sourcePeerId)
    || typeof value.x !== "number"
    || !Number.isFinite(value.x)
    || value.x < 0
    || value.x > 1
    || typeof value.y !== "number"
    || !Number.isFinite(value.y)
    || value.y < 0
    || value.y > 1
    || typeof value.width !== "number"
    || !Number.isFinite(value.width)
    || typeof value.height !== "number"
    || !Number.isFinite(value.height)
    || !isColor(value.color)
    || !isWidth(value.strokeWidth)
    || typeof value.updatedAt !== "number") {
    return false;
  }
  if (value.kind === "shape") {
    if (value.shapeKind !== "rectangle" && value.shapeKind !== "ellipse" && value.shapeKind !== "arrow") {
      return false;
    }
    const endX = value.x + value.width;
    const endY = value.y + value.height;
    return value.width !== 0
      && value.height !== 0
      && endX >= 0
      && endX <= 1
      && endY >= 0
      && endY <= 1
      && (value.shapeKind === "arrow" || (value.width > 0 && value.height > 0));
  }
  if (value.width <= 0 || value.height <= 0 || value.x + value.width > 1 || value.y + value.height > 1) {
    return false;
  }
  if (value.kind === "text") {
    return typeof value.text === "string"
      && value.text.length > 0
      && value.text.length <= MAX_TEXT_LENGTH
      && typeof value.fontSize === "number"
      && value.fontSize >= 12
      && value.fontSize <= 64;
  }
  if (value.kind === "image") {
    return typeof value.fileName === "string"
      && value.fileName.length > 0
      && value.fileName.length <= 120
      && typeof value.dataUrl === "string"
      && value.dataUrl.length <= MAX_IMAGE_DATA_URL_LENGTH
      && /^data:image\/jpeg;base64,[a-zA-Z0-9+/=]+$/.test(value.dataUrl);
  }
  return false;
}

function isIdentifier(value: unknown) {
  return typeof value === "string" && value.length > 0 && value.length <= 180 && value.trim() === value;
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

async function compressWhiteboardImage(file: File) {
  const image = await loadImageFile(file);
  const sourceWidth = image.naturalWidth;
  const sourceHeight = image.naturalHeight;
  if (sourceWidth <= 0 || sourceHeight <= 0) {
    throw new Error("无法读取图片尺寸");
  }
  let scale = Math.min(1, 1200 / Math.max(sourceWidth, sourceHeight));
  let quality = 0.82;
  const canvas = document.createElement("canvas");
  const context = canvas.getContext("2d");
  if (!context) {
    throw new Error("当前浏览器无法处理图片");
  }
  for (let attempt = 0; attempt < 14; attempt += 1) {
    const width = Math.max(1, Math.round(sourceWidth * scale));
    const height = Math.max(1, Math.round(sourceHeight * scale));
    canvas.width = width;
    canvas.height = height;
    context.fillStyle = "#ffffff";
    context.fillRect(0, 0, width, height);
    context.drawImage(image, 0, 0, width, height);
    const dataUrl = canvas.toDataURL("image/jpeg", quality);
    if (dataUrl.length <= MAX_IMAGE_DATA_URL_LENGTH) {
      return { dataUrl, width, height };
    }
    if (quality > 0.42) {
      quality -= 0.1;
    } else {
      scale *= 0.78;
      quality = 0.72;
    }
  }
  throw new Error("图片内容过于复杂，压缩后仍无法通过白板同步通道");
}

function loadImageFile(file: File) {
  return new Promise<HTMLImageElement>((resolve, reject) => {
    const url = URL.createObjectURL(file);
    const image = new Image();
    image.onload = () => {
      URL.revokeObjectURL(url);
      resolve(image);
    };
    image.onerror = () => {
      URL.revokeObjectURL(url);
      reject(new Error("图片解码失败"));
    };
    image.src = url;
  });
}

function clamp(value: number, min: number, max: number) {
  return Math.max(min, Math.min(max, value));
}
