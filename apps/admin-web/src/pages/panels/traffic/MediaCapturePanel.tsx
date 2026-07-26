import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Button,
  Chip,
  Modal,
  ModalBody,
  ModalContent,
  ModalFooter,
  ModalHeader,
  Pagination,
  Switch,
  Table,
  TableBody,
  TableCell,
  TableColumn,
  TableHeader,
  TableRow,
} from "@heroui/react";
import Hls from "hls.js";
import * as dashjs from "dashjs";
import { adminApi } from "../../../api/client";
import type {
  HttpMediaCapture,
  HttpMediaPlaybackTicket,
} from "../../../api/types";
import { notifyError } from "../../../components/toast";
import { formatBytes, formatDateTime } from "../../../lib/format";
import { MobileListCard, MobileListCardList } from "../../../components/MobileListCard";

const PAGE_SIZE = 20;

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
        <Button size="sm" variant="flat" isLoading={loading} onPress={() => void load(true)}>
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
                  ...(row.failureReason ? [{ label: "失败原因", value: row.failureReason }] : []),
                  ...(row.playbackMessage
                    ? [{ label: "回放状态", value: row.playbackMessage }]
                    : []),
                ]}
                actions={
                  <Button
                    size="sm"
                    color="primary"
                    variant="flat"
                    isDisabled={!canPlay(row)}
                    title={row.playbackMessage ?? undefined}
                    isLoading={ticketLoadingId === row.id}
                    onPress={() => void openPlayer(row)}
                  >
                    播放
                  </Button>
                }
              />
            );
          }}
        />
      </div>

      <div className="hidden min-w-0 overflow-x-auto lg:block">
        <Table aria-label="HTTP 媒体采集记录" isHeaderSticky removeWrapper>
          <TableHeader>
            <TableColumn>来源</TableColumn>
            <TableColumn>类型</TableColumn>
            <TableColumn>状态</TableColumn>
            <TableColumn>范围</TableColumn>
            <TableColumn>大小</TableColumn>
            <TableColumn>时间</TableColumn>
            <TableColumn>操作</TableColumn>
          </TableHeader>
          <TableBody items={rows} isLoading={loading} emptyContent="暂无媒体采集记录">
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
                <TableCell>{formatDateTime(row.capturedAt)}</TableCell>
                <TableCell>
                  <Button
                    size="sm"
                    color="primary"
                    variant="flat"
                    isDisabled={!canPlay(row)}
                    title={row.playbackMessage ?? undefined}
                    isLoading={ticketLoadingId === row.id}
                    onPress={() => void openPlayer(row)}
                  >
                    播放
                  </Button>
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </div>

      {totalPages > 1 ? (
        <div className="flex items-center justify-between gap-3">
          <span className="text-tiny text-default-400">共 {total} 条</span>
          <Pagination showControls page={page + 1} total={totalPages} onChange={(value) => setPage(value - 1)} />
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
    <Modal
      isOpen={capture != null && ticket != null}
      placement="center"
      scrollBehavior="inside"
      size="5xl"
      onOpenChange={(open) => {
        if (!open) {
          onClose();
        }
      }}
    >
      <ModalContent>
        {(close) => (
          <>
            <ModalHeader className="flex min-w-0 flex-col gap-0.5">
              <span>媒体回放</span>
              <span className="truncate text-tiny font-normal text-default-400" title={capture?.sourceUrl}>
                {capture?.sourceUrl}
              </span>
            </ModalHeader>
            <ModalBody>
              {ticket ? (
                <div className="flex min-h-8 items-center justify-end">
                  <Switch
                    size="sm"
                    color="primary"
                    aria-label="缺失片段补采"
                    isDisabled={ticketUpdating}
                    isSelected={ticket.backfillMissing}
                    onValueChange={onBackfillChange}
                  >
                    缺失片段补采
                  </Switch>
                </div>
              ) : null}
              {capture && ticket ? <MediaPlayer capture={capture} ticket={ticket} /> : null}
            </ModalBody>
            <ModalFooter>
              <span className="mr-auto text-tiny text-default-400">
                播放票据有效至 {formatDateTime(ticket?.expiresAt)}
              </span>
              <Button variant="flat" onPress={close}>关闭</Button>
            </ModalFooter>
          </>
        )}
      </ModalContent>
    </Modal>
  );
}

function MediaPlayer({
  capture,
  ticket,
}: {
  capture: HttpMediaCapture;
  ticket: HttpMediaPlaybackTicket;
}) {
  const mediaRef = useRef<HTMLMediaElement | null>(null);
  const [error, setError] = useState("");
  const audioOnly = capture.contentType?.toLowerCase().startsWith("audio/") ?? false;

  useEffect(() => {
    const element = mediaRef.current;
    if (!element) {
      return;
    }
    setError("");
    let hls: Hls | null = null;
    let dash: dashjs.MediaPlayerClass | null = null;

    if (capture.mediaKind === "HLS_MANIFEST") {
      if (element.canPlayType("application/vnd.apple.mpegurl")) {
        element.src = ticket.manifestUrl;
      } else if (Hls.isSupported()) {
        hls = new Hls({ enableWorker: true, lowLatencyMode: capture.liveStream });
        hls.on(Hls.Events.ERROR, (_event, data) => {
          if (data.fatal) {
            setError(data.details || "HLS 播放失败");
          }
        });
        hls.loadSource(ticket.manifestUrl);
        hls.attachMedia(element);
      } else {
        setError("当前浏览器不支持 HLS 播放");
      }
    } else if (capture.mediaKind === "DASH_MANIFEST") {
      dash = dashjs.MediaPlayer().create();
      dash.on(dashjs.MediaPlayer.events.ERROR, (event: { error?: { message?: string } }) => {
        setError(event?.error?.message || "DASH 播放失败");
      });
      dash.initialize(element, ticket.manifestUrl, true);
    } else {
      element.src = ticket.playUrl;
    }

    return () => {
      hls?.destroy();
      dash?.destroy();
      element.pause();
      element.removeAttribute("src");
      element.load();
    };
  }, [capture, ticket]);

  return (
    <div className={`flex flex-col items-center justify-center gap-3 bg-black ${audioOnly ? "min-h-40 px-5" : "min-h-[18rem]"}`}>
      {audioOnly ? (
        <audio
          ref={(element) => {
            mediaRef.current = element;
          }}
          className="w-full"
          controls
          onError={() => setError((current) => current || "媒体解码或网络请求失败")}
        />
      ) : (
        <video
          ref={(element) => {
            mediaRef.current = element;
          }}
          className="max-h-[70dvh] w-full bg-black object-contain"
          controls
          playsInline
          onError={() => setError((current) => current || "媒体解码或网络请求失败")}
        />
      )}
      {error ? <div className="w-full bg-danger-950/80 px-4 py-2 text-small text-danger-100">{error}</div> : null}
    </div>
  );
}

function MediaKindChip({ kind }: { kind: string }) {
  const label = kind === "HLS_MANIFEST" ? "HLS"
    : kind === "DASH_MANIFEST" ? "DASH"
      : kind === "MEDIA_SEGMENT" ? "分段" : "Range 媒体";
  return <Chip size="sm" variant="flat">{label}</Chip>;
}

function MediaStateChip({ row }: { row: HttpMediaCapture }) {
  const color = row.state === "COMPLETE" && row.offlineReady ? "success"
    : row.state === "COMPLETE" && row.playable ? "primary"
      : row.state === "COMPLETE" ? "default"
        : row.state === "FAILED" || row.state === "INCOMPLETE" ? "danger"
      : "warning";
  const label = row.state === "COMPLETE" && row.offlineReady ? "完整缓存"
    : row.state === "COMPLETE" && row.playable ? "缓存片段"
      : row.state === "COMPLETE" ? "已采集"
        : row.state === "CAPTURING" || row.state === "STARTING" ? "采集中"
          : row.state === "INCOMPLETE" ? "不完整" : "失败";
  return <Chip color={color} size="sm" variant="flat">{label}</Chip>;
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
