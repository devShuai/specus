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

function clamp01(value) {
  return Math.max(0, Math.min(1, value));
}

function roundedRectDistance(px, py, x, y, width, height, radius) {
  const qx = Math.abs(px - (x + width / 2)) - (width / 2 - radius);
  const qy = Math.abs(py - (y + height / 2)) - (height / 2 - radius);
  return Math.hypot(Math.max(qx, 0), Math.max(qy, 0)) + Math.min(Math.max(qx, qy), 0) - radius;
}

function fillCoverage(size, px, py, x, y, width, height, radius) {
  const antialias = 64 / size;
  return clamp01(0.5 - roundedRectDistance(px, py, x, y, width, height, radius) / antialias);
}

function segmentDistance(px, py, startX, startY, endX, endY) {
  const dx = endX - startX;
  const dy = endY - startY;
  const lengthSquared = dx * dx + dy * dy;

  if (lengthSquared === 0) {
    return Math.hypot(px - startX, py - startY);
  }

  const progress = clamp01(((px - startX) * dx + (py - startY) * dy) / lengthSquared);
  return Math.hypot(px - (startX + progress * dx), py - (startY + progress * dy));
}

function strokePolylineCoverage(size, px, py, points, strokeWidth) {
  const antialias = 64 / size;
  let distance = Number.POSITIVE_INFINITY;

  for (let index = 1; index < points.length; index += 1) {
    distance = Math.min(
      distance,
      segmentDistance(px, py, points[index - 1][0], points[index - 1][1], points[index][0], points[index][1]),
    );
  }

  distance -= strokeWidth / 2;
  return clamp01(0.5 - distance / antialias);
}

function circleCoverage(size, px, py, centerX, centerY, radius) {
  const antialias = 64 / size;
  return clamp01(0.5 - (Math.hypot(px - centerX, py - centerY) - radius) / antialias);
}

function archPoints(left, right, baseline, bottom) {
  const center = (left + right) / 2;
  const radius = (right - left) / 2;
  const points = [
    [left, bottom],
    [left, baseline],
  ];

  for (let step = 1; step <= 32; step += 1) {
    const angle = Math.PI - (Math.PI * step) / 32;
    points.push([center + Math.cos(angle) * radius, baseline - Math.sin(angle) * radius]);
  }

  points.push([right, bottom]);
  return points;
}

function paint(pixel, color, coverage) {
  const sourceAlpha = (color[3] / 255) * coverage;
  const targetAlpha = pixel[3] / 255;
  const outputAlpha = sourceAlpha + targetAlpha * (1 - sourceAlpha);

  if (outputAlpha <= 0) {
    return;
  }

  pixel[0] = Math.round((color[0] * sourceAlpha + pixel[0] * targetAlpha * (1 - sourceAlpha)) / outputAlpha);
  pixel[1] = Math.round((color[1] * sourceAlpha + pixel[1] * targetAlpha * (1 - sourceAlpha)) / outputAlpha);
  pixel[2] = Math.round((color[2] * sourceAlpha + pixel[2] * targetAlpha * (1 - sourceAlpha)) / outputAlpha);
  pixel[3] = Math.round(outputAlpha * 255);
}

function colorAt(size, x, y) {
  const px = (x / size) * 64;
  const py = (y / size) * 64;
  const pixel = [0, 0, 0, 0];
  const white = [242, 243, 247, 255];
  const accent = [41, 151, 255, 255];

  paint(pixel, [20, 22, 31, 255], fillCoverage(size, px, py, 0, 0, 64, 64, size === 16 ? 12 : 14));

  if (size === 16) {
    paint(pixel, white, strokePolylineCoverage(size, px, py, [[6, 12], [58, 12]], 9));
    paint(pixel, accent, strokePolylineCoverage(size, px, py, archPoints(17, 47, 46, 57), 9));
    return pixel;
  }

  if (size === 32) {
    paint(pixel, white, strokePolylineCoverage(size, px, py, [[6, 13], [58, 13]], 6));
    paint(pixel, white, strokePolylineCoverage(size, px, py, archPoints(16, 48, 42, 54), 6));
    paint(pixel, accent, circleCoverage(size, px, py, 32, 44, 5.5));
    return pixel;
  }

  paint(pixel, white, strokePolylineCoverage(size, px, py, [[7, 14], [57, 14]], 4.5));
  paint(pixel, [242, 243, 247, 128], strokePolylineCoverage(size, px, py, archPoints(8, 20, 36, 52), 4.5));
  paint(pixel, white, strokePolylineCoverage(size, px, py, archPoints(20, 44, 36, 52), 4.5));
  paint(pixel, [242, 243, 247, 128], strokePolylineCoverage(size, px, py, archPoints(44, 56, 36, 52), 4.5));
  paint(pixel, accent, circleCoverage(size, px, py, 32, 42, 4));

  return pixel;
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
