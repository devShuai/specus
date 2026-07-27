import type {
  ISOFile,
  Movie,
  MP4BoxBuffer,
  Sample,
  Track,
} from "mp4box";
import {
  buildIndexedMediaTimeWindows,
  type IndexedMediaTimeWindow,
  type MediaByteRange,
} from "./mediaPlaybackTimeline";

const INDEX_CHUNK_BYTES = 1024 * 1024;
const MAX_INDEX_BYTES = 32 * 1024 * 1024;
const MAX_INDEX_REQUESTS = 64;
const MAX_MOOV_BYTES = 24 * 1024 * 1024;
const MP4_EXTENDED_HEADER_BYTES = 16;
const STANDALONE_FTYP = new Uint8Array([
  0x00, 0x00, 0x00, 0x18,
  0x66, 0x74, 0x79, 0x70,
  0x69, 0x73, 0x6f, 0x6d,
  0x00, 0x00, 0x02, 0x00,
  0x69, 0x73, 0x6f, 0x6d,
  0x69, 0x73, 0x6f, 0x32,
]);

export interface Mp4PlaybackIndex {
  durationSeconds: number;
  windows: IndexedMediaTimeWindow[];
}

interface LoadMp4PlaybackIndexOptions {
  cachedRanges: MediaByteRange[];
  playUrl: string;
  signal?: AbortSignal;
}

export interface Mp4IndexChunk {
  data: ArrayBuffer;
  end: number;
  start: number;
}

export interface Mp4BoxLocation {
  headerBytes: number;
  size: number;
  start: number;
}

type Mp4IndexRangeReader = (
  start: number,
  end: number,
) => Promise<Mp4IndexChunk | null>;

export function supportsMp4Index(contentType: string | null, sourceUrl: string): boolean {
  const normalizedType = contentType?.toLowerCase() ?? "";
  if (
    normalizedType.includes("video/mp4")
    || normalizedType.includes("audio/mp4")
    || normalizedType.includes("application/mp4")
  ) {
    return true;
  }
  const path = sourceUrl.split(/[?#]/, 1)[0]?.toLowerCase() ?? "";
  return path.endsWith(".mp4") || path.endsWith(".m4v") || path.endsWith(".m4a");
}

export async function loadMp4PlaybackIndex({
  cachedRanges,
  playUrl,
  signal,
}: LoadMp4PlaybackIndexOptions): Promise<Mp4PlaybackIndex> {
  const ranges = normalizeMp4IndexRanges(cachedRanges);
  if (ranges.length === 0 || ranges[0].start !== 0) {
    throw new Error("缺少 MP4 文件头缓存");
  }

  const { MP4BoxBuffer, createFile } = await import("mp4box");
  const reader = createIndexRangeReader(playUrl, signal);
  let file = createFile();
  let movie: Movie | null = null;
  let parseError = "";
  file.onReady = (info) => {
    movie = info;
  };
  file.onError = (_module, message) => {
    parseError = message;
  };

  const parsedMovie = () => movie;
  await appendIndexRanges(
    file,
    MP4BoxBuffer,
    ranges,
    signal,
    reader.read,
    () => parsedMovie() != null,
  );
  let indexMovie = parsedMovie();
  if (!indexMovie) {
    const moov = await locateCachedMoovBox(
      ranges,
      reader.read,
      reader.loadedChunks,
      signal,
    );
    if (moov) {
      file = createFile();
      file.onReady = (info) => {
        movie = info;
      };
      file.onError = (_module, message) => {
        parseError = message;
      };
      try {
        file.appendBuffer(
          MP4BoxBuffer.fromArrayBuffer(buildStandaloneMp4Index(moov), 0),
          true,
        );
      } catch {
        parseError = "缓存中的 MP4 索引无法解析";
      }
      indexMovie = parsedMovie();
    }
  }
  if (!indexMovie) {
    const staleHint = reader.unavailableRequests() > 0
      ? "，部分缓存区间已失效"
      : "";
    throw new Error(parseError || `缓存中缺少完整 MP4 索引${staleHint}`);
  }

  const primaryTrack = selectPrimaryTrack(indexMovie);
  if (!primaryTrack) {
    throw new Error("MP4 中没有可播放的音视频轨道");
  }
  const durationSeconds = indexMovie.duration / indexMovie.timescale;
  const samples = file.getTrackSamplesInfo(primaryTrack.id);
  const windows = buildIndexedMediaTimeWindows(
    samples.map(toIndexedSample),
    ranges,
    durationSeconds,
    (timeSeconds) => file.seek(timeSeconds, true),
    primaryTrack.video != null,
  );
  if (windows.length === 0) {
    throw new Error("缓存块中没有可独立解码的关键帧");
  }

  return { durationSeconds, windows };
}

async function appendIndexRanges(
  file: ISOFile,
  BufferType: typeof MP4BoxBuffer,
  ranges: MediaByteRange[],
  signal: AbortSignal | undefined,
  read: Mp4IndexRangeReader,
  ready: () => boolean,
): Promise<void> {
  let nextOffset = 0;
  const fetched = new Set<string>();

  while (!ready()) {
    signal?.throwIfAborted();
    const range = ranges.find((candidate) =>
      nextOffset >= candidate.start && nextOffset <= candidate.end);
    if (!range) {
      break;
    }

    const requestStart = nextOffset;
    const requestEnd = Math.min(
      range.end,
      requestStart + INDEX_CHUNK_BYTES - 1,
    );
    const requestKey = `${requestStart}-${requestEnd}`;
    if (requestEnd < requestStart || fetched.has(requestKey)) {
      break;
    }
    fetched.add(requestKey);

    const chunk = await read(requestStart, requestEnd);
    if (!chunk || chunk.data.byteLength === 0) {
      break;
    }

    const buffer = BufferType.fromArrayBuffer(chunk.data, chunk.start);
    const expectedOffset = file.appendBuffer(buffer);
    if (ready()) {
      break;
    }

    nextOffset = expectedOffset > chunk.end
      ? expectedOffset
      : chunk.end + 1;
  }
}

function selectPrimaryTrack(movie: Movie): Track | null {
  return movie.videoTracks[0] ?? movie.audioTracks[0] ?? null;
}

function toIndexedSample(sample: Sample) {
  return {
    cts: sample.cts,
    duration: sample.duration,
    isSync: sample.is_sync,
    number: sample.number,
    offset: sample.offset,
    size: sample.size,
    timescale: sample.timescale,
  };
}

export function normalizeMp4IndexRanges(ranges: MediaByteRange[]): MediaByteRange[] {
  const sorted = ranges
    .filter((range) =>
      Number.isFinite(range.start)
      && Number.isFinite(range.end)
      && range.start >= 0
      && range.end >= range.start)
    .map((range) => ({
      end: Math.trunc(range.end),
      start: Math.trunc(range.start),
    }))
    .sort((left, right) => left.start - right.start);
  const merged: MediaByteRange[] = [];
  for (const range of sorted) {
    const previous = merged.at(-1);
    if (previous && range.start <= previous.end + 1) {
      previous.end = Math.max(previous.end, range.end);
    } else {
      merged.push({ ...range });
    }
  }
  return merged;
}

function parseContentRange(value: string | null): MediaByteRange | null {
  const match = value?.match(/^bytes\s+(\d+)-(\d+)\/(?:\d+|\*)$/i);
  if (!match) {
    return null;
  }
  return {
    end: Number(match[2]),
    start: Number(match[1]),
  };
}

function createIndexRangeReader(
  playUrl: string,
  signal: AbortSignal | undefined,
) {
  let loadedBytes = 0;
  let requests = 0;
  let unavailable = 0;
  const cache = new Map<string, Mp4IndexChunk | null>();
  const loadedChunks: Mp4IndexChunk[] = [];

  const read: Mp4IndexRangeReader = async (start, requestedEnd) => {
    signal?.throwIfAborted();
    const remainingBytes = MAX_INDEX_BYTES - loadedBytes;
    if (requests >= MAX_INDEX_REQUESTS || remainingBytes <= 0) {
      return null;
    }
    const end = Math.min(requestedEnd, start + remainingBytes - 1);
    const key = `${start}-${end}`;
    if (cache.has(key)) {
      return cache.get(key) ?? null;
    }

    requests += 1;
    const response = await fetch(playUrl, {
      headers: { Range: `bytes=${start}-${end}` },
      signal,
    });
    if (response.status === 416) {
      unavailable += 1;
      cache.set(key, null);
      return null;
    }
    if (response.status !== 206 && response.status !== 200) {
      throw new Error(`读取 MP4 索引失败 HTTP ${response.status}`);
    }

    const contentRange = parseContentRange(response.headers.get("Content-Range"));
    const fileStart = contentRange?.start ?? start;
    const declaredLength = Number(response.headers.get("Content-Length"));
    const requestedLength = end - start + 1;
    if (
      response.status === 200
      && (
        start !== 0
        || (Number.isFinite(declaredLength) && declaredLength > requestedLength)
      )
    ) {
      void response.body?.cancel();
      throw new Error("回放接口未按 Range 返回 MP4 索引");
    }

    const data = await response.arrayBuffer();
    if (data.byteLength === 0) {
      cache.set(key, null);
      return null;
    }
    loadedBytes += data.byteLength;
    const chunk = {
      data,
      end: fileStart + data.byteLength - 1,
      start: fileStart,
    };
    cache.set(key, chunk);
    loadedChunks.push(chunk);
    return chunk;
  };

  return {
    loadedChunks,
    read,
    unavailableRequests: () => unavailable,
  };
}

export async function locateCachedMoovBox(
  cachedRanges: MediaByteRange[],
  read: Mp4IndexRangeReader,
  existingChunks: Mp4IndexChunk[] = [],
  signal?: AbortSignal,
): Promise<ArrayBuffer | null> {
  const ranges = normalizeMp4IndexRanges(cachedRanges);
  const attempted = new Set<number>();
  let scanRequests = 0;

  const tryChunk = async (chunk: Mp4IndexChunk): Promise<ArrayBuffer | null> => {
    for (const location of findMp4MoovBoxes(chunk.data, chunk.start)) {
      if (attempted.has(location.start)) {
        continue;
      }
      attempted.add(location.start);
      const box = await readCompleteMoovBox(location, ranges, read, signal);
      if (box) {
        return box;
      }
    }
    return null;
  };

  for (const chunk of [...existingChunks]) {
    const box = await tryChunk(chunk);
    if (box) {
      return box;
    }
  }

  const scanRanges = ranges.length <= 1
    ? ranges
    : [...ranges.slice(1).reverse(), ranges[0]];
  for (const range of scanRanges) {
    let cursor = range.start;
    while (cursor <= range.end && scanRequests < MAX_INDEX_REQUESTS) {
      signal?.throwIfAborted();
      const requestStart = cursor === range.start
        ? cursor
        : Math.max(range.start, cursor - MP4_EXTENDED_HEADER_BYTES + 1);
      const requestEnd = Math.min(range.end, cursor + INDEX_CHUNK_BYTES - 1);
      scanRequests += 1;
      const chunk = await read(requestStart, requestEnd);
      if (chunk) {
        const box = await tryChunk(chunk);
        if (box) {
          return box;
        }
      }
      cursor = requestEnd + 1;
    }
  }
  return null;
}

export function findMp4MoovBox(
  data: ArrayBuffer,
  absoluteStart = 0,
): Mp4BoxLocation | null {
  return findMp4MoovBoxes(data, absoluteStart)[0] ?? null;
}

export function buildStandaloneMp4Index(moov: ArrayBuffer): ArrayBuffer {
  const output = new Uint8Array(STANDALONE_FTYP.byteLength + moov.byteLength);
  output.set(STANDALONE_FTYP);
  output.set(new Uint8Array(moov), STANDALONE_FTYP.byteLength);
  return output.buffer;
}

function findMp4MoovBoxes(
  data: ArrayBuffer,
  absoluteStart: number,
): Mp4BoxLocation[] {
  const bytes = new Uint8Array(data);
  const view = new DataView(data);
  const locations: Mp4BoxLocation[] = [];
  for (let typeOffset = 4; typeOffset <= bytes.length - 4; typeOffset += 1) {
    if (
      bytes[typeOffset] !== 0x6d
      || bytes[typeOffset + 1] !== 0x6f
      || bytes[typeOffset + 2] !== 0x6f
      || bytes[typeOffset + 3] !== 0x76
    ) {
      continue;
    }

    const headerOffset = typeOffset - 4;
    const shortSize = view.getUint32(headerOffset, false);
    let headerBytes = 8;
    let size = shortSize;
    if (shortSize === 1) {
      if (headerOffset + MP4_EXTENDED_HEADER_BYTES > bytes.length) {
        continue;
      }
      const high = view.getUint32(headerOffset + 8, false);
      const low = view.getUint32(headerOffset + 12, false);
      size = high * 2 ** 32 + low;
      headerBytes = MP4_EXTENDED_HEADER_BYTES;
    }
    if (
      !Number.isSafeInteger(size)
      || size < headerBytes
      || size > MAX_MOOV_BYTES
    ) {
      continue;
    }
    locations.push({
      headerBytes,
      size,
      start: absoluteStart + headerOffset,
    });
  }
  return locations;
}

async function readCompleteMoovBox(
  location: Mp4BoxLocation,
  ranges: MediaByteRange[],
  read: Mp4IndexRangeReader,
  signal?: AbortSignal,
): Promise<ArrayBuffer | null> {
  const boxEnd = location.start + location.size - 1;
  const coveringRange = ranges.find((range) =>
    location.start >= range.start && boxEnd <= range.end);
  if (!coveringRange) {
    return null;
  }

  const output = new Uint8Array(location.size);
  let cursor = location.start;
  while (cursor <= boxEnd) {
    signal?.throwIfAborted();
    const requestEnd = Math.min(boxEnd, cursor + INDEX_CHUNK_BYTES - 1);
    const chunk = await read(cursor, requestEnd);
    if (!chunk || chunk.start > cursor || chunk.end < cursor) {
      return null;
    }
    const sourceStart = cursor - chunk.start;
    const copyBytes = Math.min(
      chunk.data.byteLength - sourceStart,
      boxEnd - cursor + 1,
    );
    if (copyBytes <= 0) {
      return null;
    }
    output.set(
      new Uint8Array(chunk.data, sourceStart, copyBytes),
      cursor - location.start,
    );
    cursor += copyBytes;
  }
  return output.buffer;
}
