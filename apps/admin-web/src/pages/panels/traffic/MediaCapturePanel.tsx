import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Button, Chip, Dropdown, DropdownItem, DropdownMenu, DropdownPopover, DropdownTrigger, Modal, Spinner, Switch, Table, TableBody, TableCell, TableColumn, TableContent, TableHeader, TableRow, Tooltip, TooltipContent, TooltipTrigger } from "@heroui/react";
import { Pager } from "../../../components/Pager";
import {
  Gauge,
  LoaderCircle,
  Maximize,
  Minimize,
  Music2,
  Pause,
  PictureInPicture2,
  Play,
  RotateCcw,
  RotateCw,
  Volume2,
  VolumeX,
  X,
} from "lucide-react";
import { adminApi } from "../../../api/client";
import type {
  HttpMediaCapture,
  HttpMediaPlaybackTicket,
} from "../../../api/types";
import { notifyError } from "../../../components/toast";
import { formatBytes, formatDateTime } from "../../../lib/format";
import { MobileListCard, MobileListCardList } from "../../../components/MobileListCard";
import {
  estimateMediaTimeWindows,
  type IndexedMediaTimeWindow,
  type MediaTimeWindow,
  snapMediaTimeToWindow,
  windowStart,
} from "./mediaPlaybackTimeline";
import {
  loadMp4PlaybackIndex,
  supportsMp4Index,
} from "./mp4PlaybackIndex";

const PAGE_SIZE = 20;
const PLAYER_CONTROL_HIDE_MS = 2_800;
const PLAYER_FULLSCREEN_CONTROL_HIDE_MS = 1_650;
const PLAYER_RATES = [0.75, 1, 1.25, 1.5, 2];

export function MediaCapturePanel() {
  const [rows, setRows] = useState<HttpMediaCapture[]>([]);
  const [page, setPage] = useState(0);
  const [total, setTotal] = useState(0);
  const [totalPages, setTotalPages] = useState(1);
  const [loading, setLoading] = useState(true);
  const [playing, setPlaying] = useState<HttpMediaCapture | null>(null);
  const [ticket, setTicket] = useState<HttpMediaPlaybackTicket | null>(null);
  const [ticketLoadingId, setTicketLoadingId] = useState<number | null>(null);
  const [ticketUpdating, setTicketUpdating] = useState(false);

  const load = useCallback(async (background = false) => {
    if (!background) {
      setLoading(true);
    }
    try {
      const result = await adminApi.listHttpMediaCaptures(page, PAGE_SIZE);
      if (result.totalPages > 0 && page >= result.totalPages) {
        setPage(result.totalPages - 1);
        return;
      }
      setRows(result.items ?? []);
      setTotal(result.total);
      setTotalPages(Math.max(1, result.totalPages));
    } catch (error) {
      notifyError(error, "加载媒体采集记录失败");
    } finally {
      setLoading(false);
    }
  }, [page]);

  useEffect(() => {
    void load();
  }, [load]);

  const openPlayer = useCallback(async (row: HttpMediaCapture) => {
    setTicketLoadingId(row.id);
    try {
      const nextTicket = await adminApi.createHttpMediaPlaybackTicket(row.id);
      setPlaying(row);
      setTicket(nextTicket);
    } catch (error) {
      notifyError(error, "创建媒体播放会话失败");
    } finally {
      setTicketLoadingId(null);
    }
  }, []);

  const closePlayer = useCallback(() => {
    setPlaying(null);
    setTicket(null);
  }, []);

  const changeBackfillMode = useCallback(async (backfillMissing: boolean) => {
    if (!playing) {
      return;
    }
    setTicketUpdating(true);
    try {
      const nextTicket = await adminApi.createHttpMediaPlaybackTicket(
        playing.id,
        backfillMissing,
      );
      setTicket(nextTicket);
    } catch (error) {
      notifyError(error, "切换媒体补采模式失败");
    } finally {
      setTicketUpdating(false);
    }
  }, [playing]);

  const completeCount = useMemo(
    () => rows.filter((row) => row.playable).length,
    [rows],
  );
  const capturedBytes = useMemo(
    () => rows.reduce((sum, row) => sum + row.capturedBytes, 0),
    [rows],
  );

  return (
    <div className="flex min-w-0 flex-col gap-3">
      <div className="flex min-h-9 flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2 text-small text-default-500">
          <span>当前页 {rows.length} 条</span>
          <span>可回放 {completeCount} 条</span>
          <span>已采集 {formatBytes(capturedBytes)}</span>
        </div>
        <Button size="sm" variant="secondary" onPress={() => void load(true)} isDisabled={loading}>{loading ? <Spinner size="sm" /> : null}
          刷新
        </Button>
      </div>

      <div className="lg:hidden">
        <MobileListCardList
          items={rows}
          isLoading={loading}
          emptyContent="暂无媒体采集记录"
          renderCard={(raw) => {
            const row = raw as HttpMediaCapture;
            return (
              <MobileListCard
                key={row.id}
                title={<span className="break-all">{row.sourceUrl}</span>}
                subtitle={`${row.clientName} · ${row.route}`}
                badges={
                  <>
                    <MediaKindChip kind={row.mediaKind} />
                    <MediaStateChip row={row} />
                  </>
                }
                fields={[
                  { label: "采集大小", value: formatBytes(row.capturedBytes) },
                  { label: "源范围", value: mediaRangeLabel(row) },
                  { label: "采集时间", value: formatDateTime(row.capturedAt) },
                  { label: "保留至", value: formatDateTime(row.expiresAt) },
                  ...(row.failureReason ? [{ label: "失败原因", value: row.failureReason }] : []),
                  ...(row.playbackMessage
                    ? [{ label: "回放状态", value: row.playbackMessage }]
                    : []),
                ]}
                actions={
                  <Button
                    size="sm" variant="secondary" isDisabled={!canPlay(row) || ticketLoadingId === row.id}
                    onPress={() => void openPlayer(row)}
                  >{ticketLoadingId === row.id ? <Spinner size="sm" /> : null}
                    播放
                  </Button>
                }
              />
            );
          }}
        />
      </div>

      <div className="hidden min-w-0 overflow-x-auto lg:block">
        <Table>
          <TableContent aria-label="HTTP 媒体采集记录">
            <TableHeader>
              <TableColumn isRowHeader>来源</TableColumn>
              <TableColumn>类型</TableColumn>
              <TableColumn>状态</TableColumn>
              <TableColumn>范围</TableColumn>
              <TableColumn>大小</TableColumn>
              <TableColumn>时间</TableColumn>
              <TableColumn>操作</TableColumn>
            </TableHeader>
            <TableBody items={rows} renderEmptyState={() => (loading ? <Spinner size="sm" /> : "暂无媒体采集记录")}>
              {(row) => (
                <TableRow key={row.id}>
                  <TableCell>
                    <div className="flex max-w-[34rem] min-w-0 flex-col">
                      <span className="truncate font-medium" title={row.sourceUrl}>{row.sourceUrl}</span>
                      <span className="truncate text-tiny text-default-400">
                        {row.clientName} · {row.route} · #{row.id}
                      </span>
                    </div>
                  </TableCell>
                  <TableCell><MediaKindChip kind={row.mediaKind} /></TableCell>
                  <TableCell>
                    <div className="flex min-w-0 flex-col gap-1">
                      <MediaStateChip row={row} />
                      {row.failureReason ? (
                        <span className="max-w-52 truncate text-tiny text-danger" title={row.failureReason}>
                          {row.failureReason}
                        </span>
                      ) : null}
                      {row.playbackMessage ? (
                        <span
                          className={`max-w-52 truncate text-tiny ${
                            row.playable ? "text-warning-600" : "text-danger"
                          }`}
                          title={row.playbackMessage}
                        >
                          {row.playbackMessage}
                        </span>
                      ) : null}
                    </div>
                  </TableCell>
                  <TableCell><span className="whitespace-nowrap font-mono text-tiny">{mediaRangeLabel(row)}</span></TableCell>
                  <TableCell>{formatBytes(row.capturedBytes)}</TableCell>
                  <TableCell>
                    <div className="flex flex-col whitespace-nowrap">
                      <span>{formatDateTime(row.capturedAt)}</span>
                      <span className="text-tiny text-default-400">
                        保留至 {formatDateTime(row.expiresAt)}
                      </span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <Button
                      size="sm" variant="secondary" isDisabled={!canPlay(row) || ticketLoadingId === row.id}
                      onPress={() => void openPlayer(row)}
                    >{ticketLoadingId === row.id ? <Spinner size="sm" /> : null}
                      播放
                    </Button>
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
        
          </TableContent>
        </Table>
      </div>

      {totalPages > 1 ? (
        <div className="flex items-center justify-between gap-3">
          <span className="text-tiny text-default-400">共 {total} 条</span>
          <Pager page={page + 1} total={totalPages} onChange={(value) => setPage(value - 1)}  />
        </div>
      ) : null}

      <MediaPlayerModal
        capture={playing}
        ticket={ticket}
        ticketUpdating={ticketUpdating}
        onBackfillChange={changeBackfillMode}
        onClose={closePlayer}
      />
    </div>
  );
}

function MediaPlayerModal({
  capture,
  onBackfillChange,
  onClose,
  ticket,
  ticketUpdating,
}: {
  capture: HttpMediaCapture | null;
  onBackfillChange: (backfillMissing: boolean) => void;
  onClose: () => void;
  ticket: HttpMediaPlaybackTicket | null;
  ticketUpdating: boolean;
}) {
  return (
    <Modal.Root isOpen={capture != null && ticket != null} onOpenChange={(open) => {
        if (!open) {
          onClose();
        }
      }}>
      <Modal.Backdrop>
        <Modal.Container placement="center" size="cover">
          <Modal.Dialog>
            {
            capture && ticket ? (
            <MediaPlayer
            capture={capture}
            ticket={ticket}
            ticketUpdating={ticketUpdating}
            onBackfillChange={onBackfillChange}
            onClose={onClose}
            />
            ) : null
            }
    
          </Modal.Dialog>
        </Modal.Container>
      </Modal.Backdrop>
    </Modal.Root>
  );
}

function MediaPlayer({
  capture,
  onBackfillChange,
  onClose,
  ticket,
  ticketUpdating,
}: {
  capture: HttpMediaCapture;
  onBackfillChange: (backfillMissing: boolean) => void;
  onClose: () => void;
  ticket: HttpMediaPlaybackTicket;
  ticketUpdating: boolean;
}) {
  const mediaRef = useRef<HTMLMediaElement | null>(null);
  const playerRef = useRef<HTMLDivElement | null>(null);
  const controlsTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const initialOfflinePositionAppliedRef = useRef(false);
  const [error, setError] = useState("");
  const [paused, setPaused] = useState(true);
  const [waiting, setWaiting] = useState(true);
  const [currentTime, setCurrentTime] = useState(0);
  const [duration, setDuration] = useState(0);
  const [bufferedEnd, setBufferedEnd] = useState(0);
  const [volume, setVolume] = useState(1);
  const [muted, setMuted] = useState(false);
  const [playbackRate, setPlaybackRate] = useState(1);
  const [controlsVisible, setControlsVisible] = useState(true);
  const [fullscreen, setFullscreen] = useState(false);
  const [pictureInPicture, setPictureInPicture] = useState(false);
  const [offlineNotice, setOfflineNotice] = useState("");
  const [indexedOfflineTimeWindows, setIndexedOfflineTimeWindows] = useState<
    IndexedMediaTimeWindow[]
  >([]);
  const [offlineIndexState, setOfflineIndexState] = useState<
    "idle" | "loading" | "ready" | "unavailable"
  >("idle");
  const audioOnly = capture.contentType?.toLowerCase().startsWith("audio/") ?? false;
  const title = mediaDisplayTitle(capture.sourceUrl);
  const finiteDuration = Number.isFinite(duration) && duration > 0;
  const progressPercent = finiteDuration ? Math.min(100, (currentTime / duration) * 100) : 0;
  const bufferedPercent = finiteDuration ? Math.min(100, (bufferedEnd / duration) * 100) : 0;
  const useOfflineBlocks = capture.mediaKind === "PROGRESSIVE"
    && !capture.offlineReady
    && !ticket.backfillMissing;
  const offlineByteRanges = useMemo(() => {
    if (!useOfflineBlocks) {
      return [];
    }
    if (ticket.cachedRanges?.length) {
      return ticket.cachedRanges;
    }
    const start = capture.contentRangeStart ?? 0;
    const end = capture.contentRangeEnd
      ?? (capture.capturedBytes > 0 ? start + capture.capturedBytes - 1 : start);
    return capture.capturedBytes > 0 ? [{ start, end }] : [];
  }, [
    capture.capturedBytes,
    capture.contentRangeEnd,
    capture.contentRangeStart,
    ticket.cachedRanges,
    useOfflineBlocks,
  ]);
  const offlineTotalBytes = ticket.totalBytes || capture.totalBytes;
  const estimatedOfflineTimeWindows = useMemo(
    () => useOfflineBlocks
      ? estimateMediaTimeWindows(
          offlineByteRanges,
          offlineTotalBytes,
          duration,
        )
      : [],
    [duration, offlineByteRanges, offlineTotalBytes, useOfflineBlocks],
  );
  const offlineTimeWindows = indexedOfflineTimeWindows;
  const displayedOfflineTimeWindows = offlineTimeWindows.length > 0
    ? offlineTimeWindows
    : estimatedOfflineTimeWindows;
  const selectedOfflineTimeWindow = useMemo(
    () => {
      if (!useOfflineBlocks || offlineTimeWindows.length === 0) {
        return null;
      }
      const active = offlineTimeWindows.find((window) =>
        currentTime >= window.startSeconds - 0.15
          && currentTime <= window.endSeconds + 0.15);
      if (active) {
        return active;
      }
      const initialStart = ticket.initialRangeStart ?? capture.contentRangeStart ?? 0;
      return offlineTimeWindows.find((window) =>
        initialStart >= window.byteStart && initialStart <= window.byteEnd)
        ?? offlineTimeWindows[0];
    },
    [
      capture.contentRangeStart,
      currentTime,
      offlineTimeWindows,
      ticket.initialRangeStart,
      useOfflineBlocks,
    ],
  );
  const offlineTimeWindowLabel = selectedOfflineTimeWindow
    ? `当前块 ${formatMediaTime(selectedOfflineTimeWindow.startSeconds)}–${formatMediaTime(selectedOfflineTimeWindow.endSeconds)}`
    : "";
  const pictureInPictureSupported = !audioOnly
    && typeof document !== "undefined"
    && document.pictureInPictureEnabled;

  useEffect(() => {
    setIndexedOfflineTimeWindows([]);
    if (!useOfflineBlocks) {
      setOfflineIndexState("idle");
      return;
    }
    if (!supportsMp4Index(capture.contentType ?? null, capture.sourceUrl)) {
      setOfflineIndexState("unavailable");
      return;
    }

    const controller = new AbortController();
    setOfflineIndexState("loading");
    void loadMp4PlaybackIndex({
      cachedRanges: offlineByteRanges,
      playUrl: ticket.playUrl,
      signal: controller.signal,
    }).then((index) => {
      if (controller.signal.aborted) {
        return;
      }
      setIndexedOfflineTimeWindows(index.windows);
      setOfflineIndexState("ready");
      setOfflineNotice("");
    }).catch((reason: unknown) => {
      if (controller.signal.aborted) {
        return;
      }
      setOfflineIndexState("unavailable");
      setOfflineNotice(reason instanceof Error
        ? `缓存定位失败：${reason.message}`
        : "缓存定位失败");
    });
    return () => controller.abort();
  }, [
    capture.contentType,
    capture.sourceUrl,
    offlineByteRanges,
    ticket.playUrl,
    useOfflineBlocks,
  ]);

  const clearControlsTimer = useCallback(() => {
    if (controlsTimerRef.current) {
      clearTimeout(controlsTimerRef.current);
      controlsTimerRef.current = null;
    }
  }, []);

  const revealControls = useCallback(() => {
    clearControlsTimer();
    setControlsVisible(true);
    if (!paused || fullscreen) {
      controlsTimerRef.current = setTimeout(() => {
        setControlsVisible(false);
      }, fullscreen ? PLAYER_FULLSCREEN_CONTROL_HIDE_MS : PLAYER_CONTROL_HIDE_MS);
    }
  }, [clearControlsTimer, fullscreen, paused]);

  const syncTimeline = useCallback(() => {
    const element = mediaRef.current;
    if (!element) {
      return;
    }
    setCurrentTime(Number.isFinite(element.currentTime) ? element.currentTime : 0);
    setDuration(Number.isFinite(element.duration) ? element.duration : 0);
    let nextBufferedEnd = 0;
    for (let index = 0; index < element.buffered.length; index += 1) {
      nextBufferedEnd = Math.max(nextBufferedEnd, element.buffered.end(index));
    }
    setBufferedEnd(nextBufferedEnd);
    setVolume(element.volume);
    setMuted(element.muted);
    setPlaybackRate(element.playbackRate);
  }, []);

  const locateOfflineBlock = useCallback(() => {
    const element = mediaRef.current;
    if (!element) {
      return;
    }
    if (
      useOfflineBlocks
      && offlineTimeWindows.length > 0
      && !initialOfflinePositionAppliedRef.current
    ) {
      const initialStart = ticket.initialRangeStart ?? capture.contentRangeStart ?? 0;
      const targetWindow = offlineTimeWindows.find((window) =>
        initialStart >= window.byteStart && initialStart <= window.byteEnd)
        ?? offlineTimeWindows[0];
      if (targetWindow && Number.isFinite(element.duration) && element.duration > 0) {
        initialOfflinePositionAppliedRef.current = true;
        element.currentTime = windowStart(targetWindow);
      }
    }
    syncTimeline();
  }, [
    capture.contentRangeStart,
    offlineTimeWindows,
    syncTimeline,
    ticket.initialRangeStart,
    useOfflineBlocks,
  ]);

  useEffect(() => {
    locateOfflineBlock();
  }, [locateOfflineBlock]);

  const seekTo = useCallback((requestedSeconds: number, direction = 0) => {
    const element = mediaRef.current;
    if (!element || !Number.isFinite(element.duration)) {
      return;
    }
    const bounded = Math.max(0, Math.min(element.duration, requestedSeconds));
    if (useOfflineBlocks) {
      const seekableWindows = offlineTimeWindows.length > 0
        ? offlineTimeWindows
        : bufferedTimeWindows(element);
      if (seekableWindows.length === 0) {
        setOfflineNotice(offlineIndexState === "loading"
          ? "正在定位可播放的缓存块"
          : "当前位置尚未缓存");
        return;
      }
      element.currentTime = snapMediaTimeToWindow(
        bounded,
        seekableWindows,
        direction,
      );
    } else {
      element.currentTime = bounded;
    }
    setOfflineNotice("");
    syncTimeline();
  }, [offlineIndexState, offlineTimeWindows, syncTimeline, useOfflineBlocks]);

  const advanceOfflineBlock = useCallback(() => {
    const element = mediaRef.current;
    if (
      !element
      || !useOfflineBlocks
      || capture.offlineReady
      || offlineTimeWindows.length === 0
    ) {
      return false;
    }
    const current = element.currentTime;
    const activeIndex = offlineTimeWindows.findIndex((window) =>
      current >= window.startSeconds - 0.15
        && current <= window.endSeconds + 0.15);
    let nextIndex = -1;
    if (activeIndex >= 0) {
      const active = offlineTimeWindows[activeIndex];
      const threshold = Math.min(
        0.45,
        Math.max(0.12, (active.endSeconds - active.startSeconds) * 0.04),
      );
      if (current < active.endSeconds - threshold) {
        return false;
      }
      nextIndex = activeIndex + 1;
    } else {
      nextIndex = offlineTimeWindows.findIndex((window) =>
        window.startSeconds > current);
    }
    if (nextIndex >= 0 && nextIndex < offlineTimeWindows.length) {
      element.currentTime = windowStart(offlineTimeWindows[nextIndex]);
      setOfflineNotice(`已跳到缓存块 ${nextIndex + 1}/${offlineTimeWindows.length}`);
      setWaiting(true);
      return true;
    }
    if (activeIndex === offlineTimeWindows.length - 1) {
      element.pause();
      setWaiting(false);
      setOfflineNotice("已播放全部缓存块");
      return true;
    }
    return false;
  }, [capture.offlineReady, offlineTimeWindows, useOfflineBlocks]);

  const togglePlayback = useCallback(async () => {
    const element = mediaRef.current;
    if (!element) {
      return;
    }
    revealControls();
    if (element.paused) {
      try {
        await element.play();
      } catch {
        setError("浏览器阻止了自动播放，请再次点击播放");
      }
    } else {
      element.pause();
    }
  }, [revealControls]);

  const seekBy = useCallback((seconds: number) => {
    const element = mediaRef.current;
    if (!element || !Number.isFinite(element.duration)) {
      return;
    }
    seekTo(element.currentTime + seconds, Math.sign(seconds));
    revealControls();
  }, [revealControls, seekTo]);

  const toggleMute = useCallback(() => {
    const element = mediaRef.current;
    if (!element) {
      return;
    }
    element.muted = !element.muted;
    syncTimeline();
    revealControls();
  }, [revealControls, syncTimeline]);

  const changePlaybackRate = useCallback((rate: number) => {
    const element = mediaRef.current;
    if (!element) {
      return;
    }
    element.playbackRate = rate;
    setPlaybackRate(rate);
    revealControls();
  }, [revealControls]);

  const toggleFullscreen = useCallback(async () => {
    const player = playerRef.current;
    if (!player) {
      return;
    }
    try {
      if (document.fullscreenElement) {
        await document.exitFullscreen();
      } else {
        await player.requestFullscreen();
      }
    } catch {
      setError("当前浏览器无法进入全屏");
    }
  }, []);

  const togglePictureInPicture = useCallback(async () => {
    const video = mediaRef.current as HTMLVideoElement | null;
    if (!video || !pictureInPictureSupported) {
      return;
    }
    try {
      if (document.pictureInPictureElement) {
        await document.exitPictureInPicture();
      } else {
        await video.requestPictureInPicture();
      }
    } catch {
      setError("当前视频无法进入画中画");
    }
  }, [pictureInPictureSupported]);

  useEffect(() => {
    const element = mediaRef.current;
    if (!element) {
      return;
    }
    setError("");
    setWaiting(true);
    setPaused(true);
    setCurrentTime(0);
    setDuration(0);
    setBufferedEnd(0);
    setOfflineNotice("");
    initialOfflinePositionAppliedRef.current = false;
    let disposed = false;
    let hls: import("hls.js").default | null = null;
    let dash: import("dashjs").MediaPlayerClass | null = null;

    const initializePlayer = async () => {
      try {
        if (capture.mediaKind === "HLS_MANIFEST") {
          if (element.canPlayType("application/vnd.apple.mpegurl")) {
            element.src = ticket.manifestUrl;
            return;
          }
          const { default: Hls } = await import("hls.js");
          if (disposed) {
            return;
          }
          if (!Hls.isSupported()) {
            setWaiting(false);
            setError("当前浏览器不支持 HLS 播放");
            return;
          }
          hls = new Hls({ enableWorker: true, lowLatencyMode: capture.liveStream });
          hls.on(Hls.Events.ERROR, (_event, data) => {
            if (data.fatal) {
              setWaiting(false);
              setError(data.details || "HLS 播放失败");
            }
          });
          hls.loadSource(ticket.manifestUrl);
          hls.attachMedia(element);
          return;
        }
        if (capture.mediaKind === "DASH_MANIFEST") {
          const dashjs = await import("dashjs");
          if (disposed) {
            return;
          }
          dash = dashjs.MediaPlayer().create();
          dash.on(dashjs.MediaPlayer.events.ERROR, (event: { error?: { message?: string } }) => {
            setWaiting(false);
            setError(event?.error?.message || "DASH 播放失败");
          });
          dash.initialize(element, ticket.manifestUrl, true);
          return;
        }
        element.src = ticket.playUrl;
      } catch {
        if (!disposed) {
          setWaiting(false);
          setError("媒体播放组件加载失败，请刷新后重试");
        }
      }
    };

    void initializePlayer();

    return () => {
      disposed = true;
      hls?.destroy();
      dash?.destroy();
      element.pause();
      element.removeAttribute("src");
      element.load();
    };
  }, [capture, ticket]);

  useEffect(() => {
    const handleFullscreenChange = () => {
      setFullscreen(document.fullscreenElement === playerRef.current);
    };
    const element = mediaRef.current;
    const handleEnterPictureInPicture = () => setPictureInPicture(true);
    const handleLeavePictureInPicture = () => setPictureInPicture(false);
    document.addEventListener("fullscreenchange", handleFullscreenChange);
    element?.addEventListener("enterpictureinpicture", handleEnterPictureInPicture);
    element?.addEventListener("leavepictureinpicture", handleLeavePictureInPicture);
    return () => {
      document.removeEventListener("fullscreenchange", handleFullscreenChange);
      element?.removeEventListener("enterpictureinpicture", handleEnterPictureInPicture);
      element?.removeEventListener("leavepictureinpicture", handleLeavePictureInPicture);
    };
  }, [ticket]);

  useEffect(() => {
    revealControls();
    return clearControlsTimer;
  }, [clearControlsTimer, paused, revealControls]);

  const handleKeyboard = (event: React.KeyboardEvent<HTMLDivElement>) => {
    if ((event.target as HTMLElement).matches("input, button, [role='menuitem']")) {
      return;
    }
    if (event.key === " " || event.key === "Enter") {
      event.preventDefault();
      void togglePlayback();
    } else if (event.key === "ArrowLeft") {
      event.preventDefault();
      seekBy(-10);
    } else if (event.key === "ArrowRight") {
      event.preventDefault();
      seekBy(10);
    } else if (event.key.toLowerCase() === "m") {
      event.preventDefault();
      toggleMute();
    } else if (event.key.toLowerCase() === "f") {
      event.preventDefault();
      void toggleFullscreen();
    }
  };

  return (
    <div
      ref={playerRef}
      aria-label={`正在播放 ${title}`}
      className={`apple-tv-player ${audioOnly ? "is-audio" : ""} ${
        controlsVisible || waiting || error ? "is-controls-visible" : ""
      }`}
      role="region"
      tabIndex={0}
      onDoubleClick={(event) => {
        if ((event.target as HTMLElement).closest("[data-player-control]")) {
          return;
        }
        void toggleFullscreen();
      }}
      onKeyDown={handleKeyboard}
      onMouseLeave={() => {
        if (!paused) {
          clearControlsTimer();
          setControlsVisible(false);
        }
      }}
      onPointerMove={revealControls}
      onPointerDown={revealControls}
      onClick={(event) => {
        if ((event.target as HTMLElement).closest("[data-player-control]")) {
          return;
        }
        void togglePlayback();
      }}
    >
      {audioOnly ? (
        <div className="apple-tv-audio-stage" aria-hidden="true">
          <div className="apple-tv-audio-art"><Music2 size={54} strokeWidth={1.35} /></div>
          <div className="min-w-0 text-center">
            <div className="truncate text-xl font-semibold text-white sm:text-2xl">{title}</div>
            <div className="mt-1 text-small text-white/55">{capture.clientName} · {capture.route}</div>
          </div>
        </div>
      ) : (
        <video
          ref={(element) => {
            mediaRef.current = element;
          }}
          className="apple-tv-media"
          playsInline
          preload="metadata"
          onCanPlay={() => setWaiting(false)}
          onDurationChange={locateOfflineBlock}
          onEnded={() => {
            setPaused(true);
            if (useOfflineBlocks && !capture.offlineReady) {
              setOfflineNotice("已播放全部缓存块");
            }
            revealControls();
          }}
          onError={() => {
            setWaiting(false);
            setError((current) => current || "媒体解码或网络请求失败");
          }}
          onLoadedMetadata={locateOfflineBlock}
          onPause={() => setPaused(true)}
          onPlay={() => {
            setPaused(false);
            setWaiting(false);
          }}
          onPlaying={() => setWaiting(false)}
          onProgress={syncTimeline}
          onRateChange={syncTimeline}
          onTimeUpdate={() => {
            advanceOfflineBlock();
            syncTimeline();
          }}
          onVolumeChange={syncTimeline}
          onWaiting={() => {
            if (!advanceOfflineBlock()) {
              setWaiting(true);
            }
            syncTimeline();
          }}
        />
      )}
      {audioOnly ? (
        <audio
          ref={(element) => {
            mediaRef.current = element;
          }}
          preload="metadata"
          onCanPlay={() => setWaiting(false)}
          onDurationChange={locateOfflineBlock}
          onEnded={() => {
            setPaused(true);
            if (useOfflineBlocks && !capture.offlineReady) {
              setOfflineNotice("已播放全部缓存块");
            }
            revealControls();
          }}
          onError={() => {
            setWaiting(false);
            setError((current) => current || "媒体解码或网络请求失败");
          }}
          onLoadedMetadata={locateOfflineBlock}
          onPause={() => setPaused(true)}
          onPlay={() => {
            setPaused(false);
            setWaiting(false);
          }}
          onPlaying={() => setWaiting(false)}
          onProgress={syncTimeline}
          onRateChange={syncTimeline}
          onTimeUpdate={() => {
            advanceOfflineBlock();
            syncTimeline();
          }}
          onVolumeChange={syncTimeline}
          onWaiting={() => {
            if (!advanceOfflineBlock()) {
              setWaiting(true);
            }
            syncTimeline();
          }}
        />
      ) : null}

      <div className="apple-tv-chrome">
        <div className="apple-tv-topbar" data-player-control>
          <div className="min-w-0">
            <div className="flex min-w-0 items-center gap-2">
              <h2 className="truncate text-[15px] font-semibold text-white sm:text-lg">{title}</h2>
              {capture.liveStream ? <span className="apple-tv-live-badge">直播</span> : null}
            </div>
            <div className="mt-0.5 flex min-w-0 items-center gap-2 text-[11px] text-white/55 sm:text-xs">
              <span className="truncate">{capture.clientName} · {capture.route}</span>
              <span aria-hidden="true">·</span>
              <span className="shrink-0">
                {capture.offlineReady
                  ? "完整缓存"
                  : offlineByteRanges.length > 0
                    ? `已缓存 ${offlineByteRanges.length} 段`
                    : "缓存片段"}
              </span>
              {selectedOfflineTimeWindow ? (
                <>
                  <span aria-hidden="true">·</span>
                  <span className="apple-tv-offline-range shrink-0">{offlineTimeWindowLabel}</span>
                </>
              ) : null}
            </div>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            <div className="apple-tv-backfill">
              {ticketUpdating ? <LoaderCircle className="animate-spin text-white/60" size={14} /> : null}
              <span className="apple-tv-backfill-label">补采缺口</span>
              <Switch
                aria-label="缺失片段补采"
                isDisabled={ticketUpdating}
                isSelected={ticket.backfillMissing}
                onChange={onBackfillChange}
              />
            </div>
            <PlayerIconButton label="关闭播放器" onPress={onClose}>
              <X size={19} />
            </PlayerIconButton>
          </div>
        </div>

        <div className="apple-tv-center-control" data-player-control>
          {waiting && !error ? (
            <span className="apple-tv-loading" aria-label="正在缓冲">
              <LoaderCircle className="animate-spin" size={34} />
            </span>
          ) : paused && !error ? (
            <button
              type="button"
              aria-label="播放"
              className="apple-tv-primary-play"
              onClick={() => void togglePlayback()}
            >
              <Play fill="currentColor" size={34} />
            </button>
          ) : null}
        </div>

        <div className="apple-tv-control-dock" data-player-control>
          <div className="apple-tv-timeline">
            <span>{formatMediaTime(currentTime)}</span>
            <div className="apple-tv-seek">
              <span className="apple-tv-seek-buffered" style={{ width: `${bufferedPercent}%` }} />
              {displayedOfflineTimeWindows.map((window, index) => {
                const exact = "exact" in window && window.exact;
                const selected = selectedOfflineTimeWindow != null
                  && window.startPercent <= selectedOfflineTimeWindow.startPercent + 0.001
                  && window.endPercent >= selectedOfflineTimeWindow.endPercent - 0.001;
                const label = `缓存块 ${index + 1}/${displayedOfflineTimeWindows.length}，${
                  exact ? "" : "位置估算 "
                }${formatMediaTime(window.startSeconds)}–${formatMediaTime(window.endSeconds)}`;
                return (
                  <span
                    key={`${window.startPercent}-${window.endPercent}`}
                    className={`apple-tv-seek-window ${
                      selected ? "is-selected" : ""
                    } ${exact ? "" : "is-estimated"}`}
                    style={{
                      left: `${window.startPercent}%`,
                      width: `${window.endPercent - window.startPercent}%`,
                    }}
                    title={label}
                  />
                );
              })}
              <span className="apple-tv-seek-played" style={{ width: `${progressPercent}%` }} />
              <input
                aria-label={offlineByteRanges.length > 0
                  ? `播放进度，共 ${offlineByteRanges.length} 个缓存块，${offlineTimeWindowLabel}`
                  : "播放进度"}
                disabled={!finiteDuration}
                max={finiteDuration ? duration : 1}
                min={0}
                step={0.1}
                type="range"
                value={finiteDuration ? Math.min(currentTime, duration) : 0}
                onChange={(event) => {
                  seekTo(
                    Number(event.currentTarget.value),
                    Number(event.currentTarget.value) >= currentTime ? 1 : -1,
                  );
                }}
              />
            </div>
            <span>{capture.liveStream && !finiteDuration ? "直播" : formatMediaTime(duration)}</span>
          </div>

          <div className="apple-tv-control-row">
            <div className="flex items-center gap-1 sm:gap-2">
              <PlayerIconButton label="后退 10 秒" onPress={() => seekBy(-10)} disabled={!finiteDuration}>
                <RotateCcw size={19} />
                <span className="apple-tv-skip-label">10</span>
              </PlayerIconButton>
              <PlayerIconButton label={paused ? "播放" : "暂停"} emphasized onPress={() => void togglePlayback()}>
                {paused ? <Play fill="currentColor" size={22} /> : <Pause fill="currentColor" size={22} />}
              </PlayerIconButton>
              <PlayerIconButton label="前进 10 秒" onPress={() => seekBy(10)} disabled={!finiteDuration}>
                <RotateCw size={19} />
                <span className="apple-tv-skip-label">10</span>
              </PlayerIconButton>
            </div>

            <div className="flex items-center gap-1 sm:gap-2">
              <div className="apple-tv-volume">
                <PlayerIconButton label={muted ? "取消静音" : "静音"} onPress={toggleMute}>
                  {muted || volume === 0 ? <VolumeX size={19} /> : <Volume2 size={19} />}
                </PlayerIconButton>
                <input
                  aria-label="音量"
                  max={1}
                  min={0}
                  step={0.05}
                  type="range"
                  value={muted ? 0 : volume}
                  onChange={(event) => {
                    const element = mediaRef.current;
                    if (!element) {
                      return;
                    }
                    element.volume = Number(event.currentTarget.value);
                    element.muted = false;
                    syncTimeline();
                  }}
                />
              </div>

              <Dropdown>
                <DropdownTrigger>
                  <button
                    type="button"
                    aria-label={`播放速度 ${playbackRate} 倍`}
                    className="apple-tv-rate-button"
                  >
                    <Gauge size={18} />
                    <span>{playbackRate}×</span>
                  </button>
                </DropdownTrigger>
                <DropdownPopover placement="top end">
                  <DropdownMenu
                    aria-label="选择播放速度"
                    disallowEmptySelection
                    selectedKeys={new Set([String(playbackRate)])}
                    selectionMode="single"
                    onAction={(key) => changePlaybackRate(Number(key))}
                  >
                    {PLAYER_RATES.map((rate) => (
                      <DropdownItem key={String(rate)}>{rate}×</DropdownItem>
                    ))}
                  </DropdownMenu>
                </DropdownPopover>
              </Dropdown>

              {pictureInPictureSupported ? (
                <PlayerIconButton
                  label={pictureInPicture ? "退出画中画" : "画中画"}
                  onPress={() => void togglePictureInPicture()}
                >
                  <PictureInPicture2 size={19} />
                </PlayerIconButton>
              ) : null}
              <PlayerIconButton
                label={fullscreen ? "退出全屏" : "全屏"}
                onPress={() => void toggleFullscreen()}
              >
                {fullscreen ? <Minimize size={19} /> : <Maximize size={19} />}
              </PlayerIconButton>
            </div>
          </div>
          <div className="apple-tv-ticket">
            {offlineNotice ? `${offlineNotice} · ` : ""}
            播放授权至 {formatDateTime(ticket.expiresAt)}
          </div>
        </div>
      </div>

      {error ? (
        <div className="apple-tv-error" role="alert" data-player-control>
          <span>{error}</span>
          <button type="button" onClick={() => setError("")}>关闭</button>
        </div>
      ) : null}
    </div>
  );
}

function PlayerIconButton({
  children,
  disabled = false,
  emphasized = false,
  label,
  onPress,
}: {
  children: React.ReactNode;
  disabled?: boolean;
  emphasized?: boolean;
  label: string;
  onPress: () => void;
}) {
  return (
    <Tooltip delay={450}>
      <TooltipTrigger><button
        type="button"
        aria-label={label}
        className={`apple-tv-icon-button ${emphasized ? "is-emphasized" : ""}`}
        disabled={disabled}
        onClick={onPress}
      >
        {children}
      </button></TooltipTrigger>
      <TooltipContent placement="top">{label}</TooltipContent>
    </Tooltip>
  );
}

function bufferedTimeWindows(element: HTMLMediaElement): MediaTimeWindow[] {
  const duration = element.duration;
  if (!Number.isFinite(duration) || duration <= 0) {
    return [];
  }
  const windows: MediaTimeWindow[] = [];
  for (let index = 0; index < element.buffered.length; index += 1) {
    const startSeconds = element.buffered.start(index);
    const endSeconds = element.buffered.end(index);
    windows.push({
      endPercent: (endSeconds / duration) * 100,
      endSeconds,
      startPercent: (startSeconds / duration) * 100,
      startSeconds,
    });
  }
  return windows;
}

function formatMediaTime(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) {
    return "0:00";
  }
  const rounded = Math.floor(seconds);
  const hours = Math.floor(rounded / 3600);
  const minutes = Math.floor((rounded % 3600) / 60);
  const remainingSeconds = rounded % 60;
  return hours > 0
    ? `${hours}:${String(minutes).padStart(2, "0")}:${String(remainingSeconds).padStart(2, "0")}`
    : `${minutes}:${String(remainingSeconds).padStart(2, "0")}`;
}

function mediaDisplayTitle(sourceUrl: string): string {
  try {
    const url = new URL(sourceUrl, "https://media.local");
    const lastSegment = url.pathname.split("/").filter(Boolean).at(-1);
    return lastSegment ? decodeURIComponent(lastSegment) : "媒体回放";
  } catch {
    const cleanUrl = sourceUrl.split(/[?#]/, 1)[0];
    return cleanUrl.split("/").filter(Boolean).at(-1) || "媒体回放";
  }
}

function MediaKindChip({ kind }: { kind: string }) {
  const label = kind === "HLS_MANIFEST" ? "HLS"
    : kind === "DASH_MANIFEST" ? "DASH"
      : kind === "MEDIA_SEGMENT" ? "分段" : "Range 媒体";
  return <Chip size="sm" variant="soft">{label}</Chip>;
}

function MediaStateChip({ row }: { row: HttpMediaCapture }) {
  const color = row.state === "COMPLETE" && row.offlineReady ? "success"
    : row.state === "COMPLETE" && row.playable ? "accent"
      : row.state === "COMPLETE" ? "default"
        : row.state === "FAILED" || row.state === "INCOMPLETE" ? "danger"
      : "warning";
  const label = row.state === "COMPLETE" && row.offlineReady ? "完整缓存"
    : row.state === "COMPLETE" && row.playable ? "缓存片段"
      : row.state === "COMPLETE" ? "已采集"
        : row.state === "CAPTURING" || row.state === "STARTING" ? "采集中"
          : row.state === "INCOMPLETE" ? "不完整" : "失败";
  return <Chip color={color} size="sm" variant="soft">{label}</Chip>;
}

function mediaRangeLabel(row: HttpMediaCapture): string {
  if (row.contentRangeStart == null || row.contentRangeEnd == null) {
    return row.totalBytes ? `0-${row.totalBytes - 1}` : "-";
  }
  return `${row.contentRangeStart}-${row.contentRangeEnd}/${row.totalBytes ?? "*"}`;
}

function canPlay(row: HttpMediaCapture): boolean {
  return row.playable;
}
