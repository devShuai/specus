import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const moduleDir = dirname(fileURLToPath(import.meta.url));
const publicDir = resolve(moduleDir, "..", "public");
const target = resolve(publicDir, "favicon.ico");

function putUint16(buffer, offset, value) {
  buffer.writeUInt16LE(value, offset);
}

function putUint32(buffer, offset, value) {
  buffer.writeUInt32LE(value, offset);
}

function blend(base, overlay, alpha) {
  return Math.round(base * (1 - alpha) + overlay * alpha);
}

function distanceToSegment(px, py, ax, ay, bx, by) {
  const dx = bx - ax;
  const dy = by - ay;
  const lengthSq = dx * dx + dy * dy;
  const t = lengthSq === 0 ? 0 : Math.max(0, Math.min(1, ((px - ax) * dx + (py - ay) * dy) / lengthSq));
  const x = ax + t * dx;
  const y = ay + t * dy;
  return Math.sqrt((px - x) ** 2 + (py - y) ** 2);
}

function colorAt(size, x, y) {
  const radius = size * 0.22;
  const inside =
    (x >= radius || y >= radius || (x - radius) ** 2 + (y - radius) ** 2 <= radius ** 2) &&
    (x <= size - radius || y >= radius || (x - (size - radius)) ** 2 + (y - radius) ** 2 <= radius ** 2) &&
    (x >= radius || y <= size - radius || (x - radius) ** 2 + (y - (size - radius)) ** 2 <= radius ** 2) &&
    (x <= size - radius || y <= size - radius || (x - (size - radius)) ** 2 + (y - (size - radius)) ** 2 <= radius ** 2);

  if (!inside) {
    return [0, 0, 0, 0];
  }

  const t = (x + y) / (size * 2);
  let r = blend(7, 5, t);
  let g = blend(17, 7, t);
  let b = blend(31, 12, t);
  let a = 255;

  const px = x / size;
  const py = y / size;
  const lineWidth = size <= 16 ? 0.07 : 0.048;
  const ringWidth = size <= 16 ? 0.16 : 0.11;
  const ellipse = Math.sqrt(((px - 0.5) / 0.18) ** 2 + ((py - 0.5) / 0.27) ** 2);
  const portalFill = ellipse < 0.92;
  const tunnelRing = Math.abs(ellipse - 1) < ringWidth;
  const innerRing = Math.abs(ellipse - 0.52) < ringWidth * 0.65;
  const ingress = distanceToSegment(px, py, 0.16, 0.5, 0.38, 0.5) < lineWidth;
  const httpRoute =
    Math.min(
      distanceToSegment(px, py, 0.58, 0.43, 0.72, 0.32),
      distanceToSegment(px, py, 0.72, 0.32, 0.84, 0.31),
    ) < lineWidth;
  const tcpRoute =
    Math.min(
      distanceToSegment(px, py, 0.58, 0.57, 0.72, 0.68),
      distanceToSegment(px, py, 0.72, 0.68, 0.84, 0.69),
    ) < lineWidth;
  const ingressNode = (px - 0.16) ** 2 + (py - 0.5) ** 2 < 0.0044;
  const httpNode = (px - 0.84) ** 2 + (py - 0.31) ** 2 < 0.0044;
  const tcpNode = (px - 0.84) ** 2 + (py - 0.69) ** 2 < 0.0044;

  if (portalFill) {
    r = 8;
    g = 47;
    b = 73;
  }
  if (ingress) {
    r = 240;
    g = 253;
    b = 255;
  }
  if (httpRoute) {
    r = 34;
    g = 211;
    b = 238;
  }
  if (tcpRoute) {
    r = 251;
    g = 191;
    b = 36;
  }
  if (tunnelRing) {
    r = 103;
    g = 232;
    b = 249;
  }
  if (innerRing) {
    r = 186;
    g = 230;
    b = 253;
  }
  if (ingressNode) {
    r = 248;
    g = 250;
    b = 252;
  }
  if (httpNode) {
    r = 103;
    g = 232;
    b = 249;
  }
  if (tcpNode) {
    r = 251;
    g = 191;
    b = 36;
  }

  return [r, g, b, a];
}

function createDib(size) {
  const rowBytes = size * 4;
  const maskRowBytes = Math.ceil(size / 32) * 4;
  const headerSize = 40;
  const xorSize = rowBytes * size;
  const maskSize = maskRowBytes * size;
  const buffer = Buffer.alloc(headerSize + xorSize + maskSize);

  putUint32(buffer, 0, headerSize);
  putUint32(buffer, 4, size);
  putUint32(buffer, 8, size * 2);
  putUint16(buffer, 12, 1);
  putUint16(buffer, 14, 32);
  putUint32(buffer, 16, 0);
  putUint32(buffer, 20, xorSize);
  putUint32(buffer, 24, 2835);
  putUint32(buffer, 28, 2835);
  putUint32(buffer, 32, 0);
  putUint32(buffer, 36, 0);

  for (let y = 0; y < size; y += 1) {
    for (let x = 0; x < size; x += 1) {
      const [r, g, b, a] = colorAt(size, x + 0.5, y + 0.5);
      const offset = headerSize + (size - 1 - y) * rowBytes + x * 4;
      buffer[offset] = b;
      buffer[offset + 1] = g;
      buffer[offset + 2] = r;
      buffer[offset + 3] = a;
    }
  }

  return buffer;
}

const sizes = [16, 32, 48];
const images = sizes.map((size) => ({ size, data: createDib(size) }));
const headerSize = 6 + images.length * 16;
const totalSize = headerSize + images.reduce((sum, image) => sum + image.data.length, 0);
const ico = Buffer.alloc(totalSize);

putUint16(ico, 0, 0);
putUint16(ico, 2, 1);
putUint16(ico, 4, images.length);

let imageOffset = headerSize;
images.forEach((image, index) => {
  const entryOffset = 6 + index * 16;
  ico[entryOffset] = image.size;
  ico[entryOffset + 1] = image.size;
  ico[entryOffset + 2] = 0;
  ico[entryOffset + 3] = 0;
  putUint16(ico, entryOffset + 4, 1);
  putUint16(ico, entryOffset + 6, 32);
  putUint32(ico, entryOffset + 8, image.data.length);
  putUint32(ico, entryOffset + 12, imageOffset);
  image.data.copy(ico, imageOffset);
  imageOffset += image.data.length;
});

await mkdir(publicDir, { recursive: true });
await writeFile(target, ico);
console.log(`generated ${target}`);
