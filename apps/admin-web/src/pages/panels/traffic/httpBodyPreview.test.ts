import { describe, expect, it } from "vitest";
import { isHttpImageBody, resolveHttpImageDataUrl } from "./httpBodyPreview";

const WEBP_BASE64 = "UklGRiIAAABXRUJQVlA4IBYAAAAwAQCdASoBAAEALmk0mk0iIiIiIgBoSygABc6zbAAA";

describe("HTTP body image preview", () => {
  it("detects WebP bytes stored with a generic media type", () => {
    const content = `data:application/octet-stream;base64,${WEBP_BASE64}`;

    expect(isHttpImageBody(content, "application/octet-stream")).toBe(true);
    expect(resolveHttpImageDataUrl(content, "application/octet-stream"))
      .toBe(`data:image/webp;base64,${WEBP_BASE64}`);
  });

  it("uses a declared image media type for generic data URLs", () => {
    const content = "data:application/octet-stream;base64,AAAA";

    expect(resolveHttpImageDataUrl(content, "image/webp; charset=binary"))
      .toBe("data:image/webp;base64,AAAA");
  });

  it("does not reinterpret arbitrary binary bodies as images", () => {
    const content = "data:application/octet-stream;base64,SGVsbG8=";

    expect(isHttpImageBody(content, "application/octet-stream")).toBe(false);
    expect(resolveHttpImageDataUrl(content, "application/octet-stream")).toBeNull();
  });
});
