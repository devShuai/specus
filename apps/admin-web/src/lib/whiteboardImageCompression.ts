export const MAX_WHITEBOARD_IMAGE_DATA_URL_LENGTH = 48 * 1024;

const JPEG_DATA_URL_PREFIX = "data:image/jpeg;base64,";
const MAX_IMAGE_DIMENSION = 1200;
const MAX_RESIZE_PASSES = 12;
const QUALITY_STEPS = [0.82, 0.66, 0.5, 0.34, 0.22] as const;

export interface CompressedWhiteboardImage {
  dataUrl: string;
  width: number;
  height: number;
  quality: number;
}

export function fitWhiteboardImageDataUrl(
  sourceWidth: number,
  sourceHeight: number,
  encode: (width: number, height: number, quality: number) => string,
  maxDataUrlLength = MAX_WHITEBOARD_IMAGE_DATA_URL_LENGTH,
): CompressedWhiteboardImage {
  if (!Number.isFinite(sourceWidth) || sourceWidth <= 0 || !Number.isFinite(sourceHeight) || sourceHeight <= 0) {
    throw new Error("无法读取图片尺寸");
  }
  if (!Number.isFinite(maxDataUrlLength) || maxDataUrlLength <= JPEG_DATA_URL_PREFIX.length) {
    throw new Error("白板图片同步上限无效");
  }

  const sourceMaxDimension = Math.max(sourceWidth, sourceHeight);
  let targetMaxDimension = Math.min(sourceMaxDimension, MAX_IMAGE_DIMENSION);

  for (let resizePass = 0; resizePass < MAX_RESIZE_PASSES; resizePass += 1) {
    const scale = Math.min(1, targetMaxDimension / sourceMaxDimension);
    const width = Math.max(1, Math.round(sourceWidth * scale));
    const height = Math.max(1, Math.round(sourceHeight * scale));
    let lastEncodedLength = Number.POSITIVE_INFINITY;

    for (const quality of QUALITY_STEPS) {
      const dataUrl = encode(width, height, quality);
      if (!dataUrl.startsWith(JPEG_DATA_URL_PREFIX)) {
        throw new Error("当前浏览器无法生成白板所需的 JPEG 图片");
      }
      lastEncodedLength = dataUrl.length;
      if (lastEncodedLength <= maxDataUrlLength) {
        return { dataUrl, width, height, quality };
      }
    }

    if (width === 1 && height === 1) {
      break;
    }
    const estimatedFit = Math.sqrt(maxDataUrlLength / lastEncodedLength) * 0.9;
    const shrinkFactor = clamp(estimatedFit, 0.42, 0.76);
    targetMaxDimension = Math.max(1, Math.floor(Math.max(width, height) * shrinkFactor));
  }

  throw new Error("图片内容过于复杂，压缩后仍无法通过白板同步通道");
}

function clamp(value: number, min: number, max: number) {
  return Math.max(min, Math.min(max, value));
}
