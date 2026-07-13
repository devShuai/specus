import { describe, expect, it } from "vitest";
import { sha256Blob } from "./sha256";

describe("sha256Blob", () => {
  it("hashes empty content", async () => {
    await expect(sha256Blob(new Blob([]))).resolves.toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
  });

  it("hashes streamed text content", async () => {
    await expect(sha256Blob(new Blob(["abc"]))).resolves.toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });

  it("stops hashing when the operation is cancelled", async () => {
    const controller = new AbortController();
    controller.abort();

    await expect(sha256Blob(new Blob(["cancelled"]), controller.signal)).rejects.toMatchObject({
      name: "AbortError",
    });
  });
});
