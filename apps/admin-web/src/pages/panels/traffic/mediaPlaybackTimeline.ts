export interface MediaTimeWindow {
  startSeconds: number;
  endSeconds: number;
  startPercent: number;
  endPercent: number;
}

export interface IndexedMediaTimeWindow extends MediaTimeWindow {
  byteEnd: number;
  byteStart: number;
  exact: true;
  seekOffset: number;
}

export interface MediaByteRange {
  end: number;
  start: number;
}

export interface IndexedMediaSample {
  cts: number;
  duration: number;
  isSync: boolean;
  number: number;
  offset: number;
  size: number;
  timescale: number;
}

export interface MediaSeekPoint {
  offset: number;
  time: number;
}

interface MediaByteWindow {
  capturedBytes: number;
  durationSeconds: number;
  rangeEnd: number | null;
  rangeStart: number | null;
  totalBytes: number | null;
}

export function estimateMediaTimeWindow({
  capturedBytes,
  durationSeconds,
  rangeEnd,
  rangeStart,
  totalBytes,
}: MediaByteWindow): MediaTimeWindow | null {
  if (
    totalBytes == null
    || !Number.isFinite(totalBytes)
    || totalBytes <= 0
    || !Number.isFinite(durationSeconds)
    || durationSeconds <= 0
  ) {
    return null;
  }

  const normalizedStart = clampInteger(rangeStart ?? 0, 0, totalBytes - 1);
  const inferredEnd = capturedBytes > 0
    ? normalizedStart + capturedBytes - 1
    : normalizedStart;
  const normalizedEnd = clampInteger(
    rangeEnd ?? inferredEnd,
    normalizedStart,
    totalBytes - 1,
  );
  const startPercent = (normalizedStart / totalBytes) * 100;
  const endPercent = ((normalizedEnd + 1) / totalBytes) * 100;

  return {
    startSeconds: durationSeconds * (startPercent / 100),
    endSeconds: durationSeconds * (endPercent / 100),
    startPercent,
    endPercent,
  };
}

export function estimateMediaTimeWindows(
  ranges: MediaByteRange[],
  totalBytes: number | null,
  durationSeconds: number,
): MediaTimeWindow[] {
  return ranges
    .map((range) => estimateMediaTimeWindow({
      capturedBytes: range.end - range.start + 1,
      durationSeconds,
      rangeEnd: range.end,
      rangeStart: range.start,
      totalBytes,
    }))
    .filter((window): window is MediaTimeWindow => window != null)
    .sort((left, right) => left.startSeconds - right.startSeconds);
}

export function buildIndexedMediaTimeWindows(
  samples: IndexedMediaSample[],
  ranges: MediaByteRange[],
  durationSeconds: number,
  seek: (timeSeconds: number) => MediaSeekPoint,
  requireSyncSample: boolean,
): IndexedMediaTimeWindow[] {
  if (!Number.isFinite(durationSeconds) || durationSeconds <= 0) {
    return [];
  }

  const orderedSamples = samples
    .filter((sample) =>
      Number.isFinite(sample.offset)
      && Number.isFinite(sample.size)
      && sample.size > 0
      && Number.isFinite(sample.timescale)
      && sample.timescale > 0)
    .slice()
    .sort((left, right) => left.number - right.number);
  const windows: IndexedMediaTimeWindow[] = [];

  for (const range of ranges) {
    let run: IndexedMediaSample[] = [];
    const flushRun = () => {
      if (run.length === 0) {
        return;
      }

      const candidates = requireSyncSample
        ? run.filter((sample) => sample.isSync)
        : run;
      let selected: {
        point: MediaSeekPoint;
        sample: IndexedMediaSample;
      } | null = null;
      for (const sample of candidates) {
        const point = seek(sample.cts / sample.timescale);
        if (
          Number.isFinite(point.offset)
          && Number.isFinite(point.time)
          && point.offset >= range.start
          && point.offset <= range.end
        ) {
          selected = { point, sample };
          break;
        }
      }
      if (!selected) {
        run = [];
        return;
      }

      const selectedIndex = run.indexOf(selected.sample);
      const playableSamples = run.slice(selectedIndex);
      const startSeconds = clampNumber(selected.point.time, 0, durationSeconds);
      const endSeconds = clampNumber(
        playableSamples.reduce((latest, sample) => Math.max(
          latest,
          (sample.cts + sample.duration) / sample.timescale,
        ), startSeconds),
        startSeconds,
        durationSeconds,
      );
      if (endSeconds > startSeconds) {
        windows.push({
          byteEnd: range.end,
          byteStart: range.start,
          endPercent: (endSeconds / durationSeconds) * 100,
          endSeconds,
          exact: true,
          seekOffset: selected.point.offset,
          startPercent: (startSeconds / durationSeconds) * 100,
          startSeconds,
        });
      }
      run = [];
    };

    for (const sample of orderedSamples) {
      const sampleEnd = sample.offset + sample.size - 1;
      const contained = sample.offset >= range.start && sampleEnd <= range.end;
      if (!contained) {
        flushRun();
        continue;
      }
      const previous = run.at(-1);
      if (previous && sample.number !== previous.number + 1) {
        flushRun();
      }
      run.push(sample);
    }
    flushRun();
  }

  return windows.sort((left, right) => left.startSeconds - right.startSeconds);
}

export function snapMediaTimeToWindow(
  requestedSeconds: number,
  windows: MediaTimeWindow[],
  direction = 0,
): number {
  if (!Number.isFinite(requestedSeconds) || windows.length === 0) {
    return Math.max(0, Number.isFinite(requestedSeconds) ? requestedSeconds : 0);
  }
  const requested = Math.max(0, requestedSeconds);
  const containing = windows.find((window) =>
    requested >= window.startSeconds && requested <= window.endSeconds);
  if (containing) {
    return requested;
  }
  if (direction > 0) {
    return windowStart(
      windows.find((window) => window.startSeconds > requested)
        ?? windows.at(-1)!,
    );
  }
  if (direction < 0) {
    const previous = windows
      .slice()
      .reverse()
      .find((window) => window.endSeconds < requested)
      ?? windows[0];
    return windowEnd(previous);
  }
  const candidates = windows.flatMap((window) => [
    windowStart(window),
    windowEnd(window),
  ]);
  return candidates.reduce((nearest, candidate) =>
    Math.abs(candidate - requested) < Math.abs(nearest - requested)
      ? candidate : nearest);
}

export function windowStart(window: MediaTimeWindow): number {
  if ("exact" in window && window.exact) {
    return window.startSeconds;
  }
  if (window.startSeconds === 0) {
    return 0;
  }
  return Math.min(
    window.endSeconds,
    window.startSeconds + Math.min(0.08, (window.endSeconds - window.startSeconds) / 4),
  );
}

export function windowEnd(window: MediaTimeWindow): number {
  return Math.max(
    window.startSeconds,
    window.endSeconds - Math.min(0.08, (window.endSeconds - window.startSeconds) / 4),
  );
}

function clampInteger(value: number, min: number, max: number): number {
  if (!Number.isFinite(value)) {
    return min;
  }
  return Math.min(max, Math.max(min, Math.trunc(value)));
}

function clampNumber(value: number, min: number, max: number): number {
  if (!Number.isFinite(value)) {
    return min;
  }
  return Math.min(max, Math.max(min, value));
}
