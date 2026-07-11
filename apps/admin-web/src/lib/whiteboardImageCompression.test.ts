import { describe, expect, it } from "vitest";
import {
  fitWhiteboardImageDataUrl,
  MAX_WHITEBOARD_IMAGE_DATA_URL_LENGTH,
} from "./whiteboardImageCompression";

const JPEG_PREFIX = "data:image/jpeg;base64,";

function jpegDataUrlOfLength(length: number) {
  return JPEG_PREFIX + "A".repeat(Math.max(4, length - JPEG_PREFIX.length));
}

describe("fitWhiteboardImageDataUrl", () => {
  it("keeps the initial resolution when the encoded image already fits", () => {
    const result = fitWhiteboardImageDataUrl(2400, 1600, (width, height, quality) => (
      jpegDataUrlOfLength(JPEG_PREFIX.length + Math.ceil(width * height * quality * 0.02))
    ));

    expect(result.width).toBe(1200);
    expect(result.height).toBe(800);
    expect(result.quality).toBe(0.82);
    expect(result.dataUrl.length).toBeLessThanOrEqual(MAX_WHITEBOARD_IMAGE_DATA_URL_LENGTH);
  });

  it("continues shrinking highly detailed images until they fit", () => {
    const attemptedDimensions: string[] = [];
    const result = fitWhiteboardImageDataUrl(6000, 4000, (width, height, quality) => {
      attemptedDimensions.push(width + "x" + height);
      const simulatedLength = JPEG_PREFIX.length + Math.ceil(width * height * (0.65 + quality));
      return jpegDataUrlOfLength(simulatedLength);
    });

    expect(new Set(attemptedDimensions).size).toBeGreaterThan(2);
    expect(result.width).toBeLessThan(1200);
    expect(result.height).toBeLessThan(800);
    expect(result.dataUrl.length).toBeLessThanOrEqual(MAX_WHITEBOARD_IMAGE_DATA_URL_LENGTH);
  });

  it("still rejects an encoder whose output never becomes smaller", () => {
    expect(() => fitWhiteboardImageDataUrl(4000, 3000, () => (
      jpegDataUrlOfLength(MAX_WHITEBOARD_IMAGE_DATA_URL_LENGTH + 1)
    ))).toThrow("图片内容过于复杂");
  });
});
