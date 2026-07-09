interface QrVersionSpec {
  version: number;
  dataCodewords: number;
  ecCodewords: number;
}

const QR_VERSION_SPECS: QrVersionSpec[] = [
  { version: 1, dataCodewords: 19, ecCodewords: 7 },
  { version: 2, dataCodewords: 34, ecCodewords: 10 },
  { version: 3, dataCodewords: 55, ecCodewords: 15 },
  { version: 4, dataCodewords: 80, ecCodewords: 20 },
  { version: 5, dataCodewords: 108, ecCodewords: 26 },
];

const QR_ALIGNMENT_PATTERN_POSITIONS: Record<number, number[]> = {
  1: [],
  2: [6, 18],
  3: [6, 22],
  4: [6, 26],
  5: [6, 30],
};

const GF_EXP = (() => {
  const exp = new Array<number>(255);
  let value = 1;
  for (let i = 0; i < 255; i += 1) {
    exp[i] = value;
    value <<= 1;
    if (value >= 0x100) {
      value ^= 0x11d;
    }
  }
  return exp;
})();

const GF_LOG = (() => {
  const log = new Array<number>(256).fill(0);
  for (let i = 0; i < 255; i += 1) {
    log[GF_EXP[i]] = i;
  }
  return log;
})();

export function createQrMatrix(value: string): boolean[][] {
  const data = Array.from(new TextEncoder().encode(value));
  const spec = QR_VERSION_SPECS.find((item) => data.length <= qrByteCapacity(item));
  if (!spec) {
    throw new Error("链接太长，请复制链接打开");
  }

  const dataCodewords = encodeQrDataCodewords(data, spec);
  const generator = reedSolomonGenerator(spec.ecCodewords);
  const ecCodewords = reedSolomonRemainder(dataCodewords, generator);
  const codewords = [...dataCodewords, ...ecCodewords];
  const base = drawQrFunctionPatterns(spec.version);
  placeQrDataBits(base.modules, base.isFunction, codewords);

  let bestMatrix: Array<Array<boolean | null>> | null = null;
  let bestPenalty = Number.POSITIVE_INFINITY;
  for (let mask = 0; mask < 8; mask += 1) {
    const candidate = cloneQrMatrix(base.modules);
    applyQrMask(candidate, base.isFunction, mask);
    drawQrFormatBits(candidate, base.isFunction, mask);
    const penalty = qrPenaltyScore(candidate);
    if (penalty < bestPenalty) {
      bestPenalty = penalty;
      bestMatrix = candidate;
    }
  }
  if (!bestMatrix) {
    throw new Error("二维码生成失败");
  }
  return bestMatrix.map((row) => row.map(Boolean));
}

function qrByteCapacity(spec: QrVersionSpec) {
  return Math.floor((spec.dataCodewords * 8 - 12) / 8);
}

function encodeQrDataCodewords(data: number[], spec: QrVersionSpec) {
  const bits: number[] = [];
  appendQrBits(bits, 0b0100, 4);
  appendQrBits(bits, data.length, 8);
  for (const byte of data) {
    appendQrBits(bits, byte, 8);
  }

  const capacityBits = spec.dataCodewords * 8;
  if (bits.length > capacityBits) {
    throw new Error("链接太长，请复制链接打开");
  }
  for (let i = 0, length = Math.min(4, capacityBits - bits.length); i < length; i += 1) {
    bits.push(0);
  }
  while (bits.length % 8 !== 0) {
    bits.push(0);
  }

  const result: number[] = [];
  for (let i = 0; i < bits.length; i += 8) {
    let value = 0;
    for (let j = 0; j < 8; j += 1) {
      value = (value << 1) | bits[i + j];
    }
    result.push(value);
  }
  for (let padIndex = 0; result.length < spec.dataCodewords; padIndex += 1) {
    result.push(padIndex % 2 === 0 ? 0xec : 0x11);
  }
  return result;
}

function appendQrBits(bits: number[], value: number, length: number) {
  for (let i = length - 1; i >= 0; i -= 1) {
    bits.push((value >>> i) & 1);
  }
}

function reedSolomonGenerator(degree: number) {
  const result = new Array<number>(degree).fill(0);
  result[degree - 1] = 1;
  let root = 1;
  for (let i = 0; i < degree; i += 1) {
    for (let j = 0; j < result.length; j += 1) {
      result[j] = gfMultiply(result[j], root);
      if (j + 1 < result.length) {
        result[j] ^= result[j + 1];
      }
    }
    root = gfMultiply(root, 0x02);
  }
  return result;
}

function reedSolomonRemainder(data: number[], generator: number[]) {
  const result = new Array<number>(generator.length).fill(0);
  for (const byte of data) {
    const factor = byte ^ (result.shift() ?? 0);
    result.push(0);
    for (let i = 0; i < generator.length; i += 1) {
      result[i] ^= gfMultiply(generator[i], factor);
    }
  }
  return result;
}

function gfMultiply(x: number, y: number) {
  if (x === 0 || y === 0) {
    return 0;
  }
  return GF_EXP[(GF_LOG[x] + GF_LOG[y]) % 255];
}

function drawQrFunctionPatterns(version: number) {
  const size = qrSize(version);
  const modules = Array.from({ length: size }, () => new Array<boolean | null>(size).fill(null));
  const isFunction = Array.from({ length: size }, () => new Array<boolean>(size).fill(false));
  const setFunction = (x: number, y: number, dark: boolean) => {
    modules[y][x] = dark;
    isFunction[y][x] = true;
  };

  drawQrFinderPattern(modules, isFunction, 3, 3);
  drawQrFinderPattern(modules, isFunction, size - 4, 3);
  drawQrFinderPattern(modules, isFunction, 3, size - 4);

  for (let i = 0; i < size; i += 1) {
    if (!isFunction[6][i]) {
      setFunction(i, 6, i % 2 === 0);
    }
    if (!isFunction[i][6]) {
      setFunction(6, i, i % 2 === 0);
    }
  }

  for (const y of QR_ALIGNMENT_PATTERN_POSITIONS[version] ?? []) {
    for (const x of QR_ALIGNMENT_PATTERN_POSITIONS[version] ?? []) {
      if (!isFunction[y][x]) {
        drawQrAlignmentPattern(modules, isFunction, x, y);
      }
    }
  }

  drawQrFormatBits(modules, isFunction, 0);
  setFunction(8, size - 8, true);
  return { modules, isFunction };
}

function drawQrFinderPattern(
  modules: Array<Array<boolean | null>>,
  isFunction: boolean[][],
  centerX: number,
  centerY: number,
) {
  for (let dy = -4; dy <= 4; dy += 1) {
    for (let dx = -4; dx <= 4; dx += 1) {
      const x = centerX + dx;
      const y = centerY + dy;
      if (x < 0 || y < 0 || y >= modules.length || x >= modules.length) {
        continue;
      }
      const distance = Math.max(Math.abs(dx), Math.abs(dy));
      modules[y][x] = distance !== 2 && distance !== 4;
      isFunction[y][x] = true;
    }
  }
}

function drawQrAlignmentPattern(
  modules: Array<Array<boolean | null>>,
  isFunction: boolean[][],
  centerX: number,
  centerY: number,
) {
  for (let dy = -2; dy <= 2; dy += 1) {
    for (let dx = -2; dx <= 2; dx += 1) {
      const x = centerX + dx;
      const y = centerY + dy;
      const distance = Math.max(Math.abs(dx), Math.abs(dy));
      modules[y][x] = distance !== 1;
      isFunction[y][x] = true;
    }
  }
}

function drawQrFormatBits(
  modules: Array<Array<boolean | null>>,
  isFunction: boolean[][],
  mask: number,
) {
  const size = modules.length;
  const bits = qrFormatBits(mask);
  const setFunction = (x: number, y: number, dark: boolean) => {
    modules[y][x] = dark;
    isFunction[y][x] = true;
  };

  for (let i = 0; i <= 5; i += 1) {
    setFunction(8, i, qrBit(bits, i));
  }
  setFunction(8, 7, qrBit(bits, 6));
  setFunction(8, 8, qrBit(bits, 7));
  setFunction(7, 8, qrBit(bits, 8));
  for (let i = 9; i < 15; i += 1) {
    setFunction(14 - i, 8, qrBit(bits, i));
  }
  for (let i = 0; i < 8; i += 1) {
    setFunction(size - 1 - i, 8, qrBit(bits, i));
  }
  for (let i = 8; i < 15; i += 1) {
    setFunction(8, size - 15 + i, qrBit(bits, i));
  }
  setFunction(8, size - 8, true);
}

function qrFormatBits(mask: number) {
  const errorCorrectionLevelL = 0b01;
  const data = (errorCorrectionLevelL << 3) | mask;
  let bits = data << 10;
  const generator = 0x537;
  for (let i = 14; i >= 10; i -= 1) {
    if (((bits >>> i) & 1) !== 0) {
      bits ^= generator << (i - 10);
    }
  }
  return ((data << 10) | bits) ^ 0x5412;
}

function qrBit(value: number, index: number) {
  return ((value >>> index) & 1) !== 0;
}

function placeQrDataBits(
  modules: Array<Array<boolean | null>>,
  isFunction: boolean[][],
  codewords: number[],
) {
  const size = modules.length;
  const bits = codewords.flatMap((word) => Array.from({ length: 8 }, (_, index) => ((word >>> (7 - index)) & 1) !== 0));
  let bitIndex = 0;
  let upward = true;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) {
      right = 5;
    }
    for (let vertical = 0; vertical < size; vertical += 1) {
      const y = upward ? size - 1 - vertical : vertical;
      for (let dx = 0; dx < 2; dx += 1) {
        const x = right - dx;
        if (!isFunction[y][x]) {
          modules[y][x] = bits[bitIndex] ?? false;
          bitIndex += 1;
        }
      }
    }
    upward = !upward;
  }
}

function applyQrMask(
  modules: Array<Array<boolean | null>>,
  isFunction: boolean[][],
  mask: number,
) {
  for (let y = 0; y < modules.length; y += 1) {
    for (let x = 0; x < modules.length; x += 1) {
      if (!isFunction[y][x] && qrMaskBit(mask, x, y)) {
        modules[y][x] = !modules[y][x];
      }
    }
  }
}

function qrMaskBit(mask: number, x: number, y: number) {
  switch (mask) {
    case 0:
      return (x + y) % 2 === 0;
    case 1:
      return y % 2 === 0;
    case 2:
      return x % 3 === 0;
    case 3:
      return (x + y) % 3 === 0;
    case 4:
      return (Math.floor(y / 2) + Math.floor(x / 3)) % 2 === 0;
    case 5:
      return ((x * y) % 2) + ((x * y) % 3) === 0;
    case 6:
      return (((x * y) % 2) + ((x * y) % 3)) % 2 === 0;
    case 7:
      return (((x + y) % 2) + ((x * y) % 3)) % 2 === 0;
    default:
      return false;
  }
}

function qrPenaltyScore(modules: Array<Array<boolean | null>>) {
  const matrix = modules.map((row) => row.map(Boolean));
  const size = matrix.length;
  let penalty = 0;

  for (let y = 0; y < size; y += 1) {
    penalty += qrLinePenalty(matrix[y]);
  }
  for (let x = 0; x < size; x += 1) {
    penalty += qrLinePenalty(matrix.map((row) => row[x]));
  }

  for (let y = 0; y < size - 1; y += 1) {
    for (let x = 0; x < size - 1; x += 1) {
      const color = matrix[y][x];
      if (matrix[y][x + 1] === color && matrix[y + 1][x] === color && matrix[y + 1][x + 1] === color) {
        penalty += 3;
      }
    }
  }

  for (let y = 0; y < size; y += 1) {
    for (let x = 0; x <= size - 7; x += 1) {
      if (qrFinderLikePattern(matrix[y].slice(x, x + 7))
        && (qrLightRun(matrix[y], x - 4, x) || qrLightRun(matrix[y], x + 7, x + 11))) {
        penalty += 40;
      }
    }
  }
  for (let x = 0; x < size; x += 1) {
    const column = matrix.map((row) => row[x]);
    for (let y = 0; y <= size - 7; y += 1) {
      if (qrFinderLikePattern(column.slice(y, y + 7))
        && (qrLightRun(column, y - 4, y) || qrLightRun(column, y + 7, y + 11))) {
        penalty += 40;
      }
    }
  }

  const dark = matrix.flat().filter(Boolean).length;
  penalty += Math.floor(Math.abs(dark * 20 - size * size * 10) / (size * size)) * 10;
  return penalty;
}

function qrLinePenalty(line: boolean[]) {
  let penalty = 0;
  let runColor = line[0];
  let runLength = 1;
  for (let i = 1; i < line.length; i += 1) {
    if (line[i] === runColor) {
      runLength += 1;
      if (runLength === 5) {
        penalty += 3;
      } else if (runLength > 5) {
        penalty += 1;
      }
    } else {
      runColor = line[i];
      runLength = 1;
    }
  }
  return penalty;
}

function qrFinderLikePattern(pattern: boolean[]) {
  return pattern.length === 7
    && pattern[0]
    && !pattern[1]
    && pattern[2]
    && pattern[3]
    && pattern[4]
    && !pattern[5]
    && pattern[6];
}

function qrLightRun(line: boolean[], start: number, end: number) {
  if (start < 0 || end > line.length) {
    return true;
  }
  return line.slice(start, end).every((value) => !value);
}

function qrSize(version: number) {
  return version * 4 + 17;
}

function cloneQrMatrix(modules: Array<Array<boolean | null>>) {
  return modules.map((row) => row.slice());
}


