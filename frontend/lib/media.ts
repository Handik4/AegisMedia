// In-browser media fingerprinting: SHA-256 over the exact bytes, plus a 64-bit
// DCT perceptual hash (pHash) over a 32x32 grayscale rendering.
//
// The pHash is the classic construction: downscale to 32x32 luminance, take the
// 2-D DCT-II, keep the 8x8 low-frequency block, and emit one bit per coefficient
// (1 when above the median of the AC terms). Two renderings of the same picture
// land within a few bits of each other; unrelated pictures sit near 32 bits apart.

export async function sha256Hex(data: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export async function sha256OfText(text: string): Promise<string> {
  return sha256Hex(new TextEncoder().encode(text).buffer as ArrayBuffer);
}

const N = 32;
const K = 8;

// Precomputed DCT-II basis: COS[u][x] = cos((2x+1) * u * pi / (2N)).
const COS: number[][] = Array.from({ length: K }, (_, u) =>
  Array.from({ length: N }, (_, x) => Math.cos(((2 * x + 1) * u * Math.PI) / (2 * N)))
);

/** 64-bit perceptual hash of a 32x32 grayscale grid (row-major, length 1024). */
export function phashFromGray(gray: ArrayLike<number>): string {
  // Row pass: for each row y and frequency u, sum over x.
  const rows: number[][] = Array.from({ length: N }, (_, y) =>
    Array.from({ length: K }, (_, u) => {
      let s = 0;
      for (let x = 0; x < N; x++) s += gray[y * N + x] * COS[u][x];
      return s;
    })
  );
  // Column pass over the K x K low-frequency block.
  const coeffs: number[] = [];
  for (let v = 0; v < K; v++) {
    for (let u = 0; u < K; u++) {
      let s = 0;
      for (let y = 0; y < N; y++) s += rows[y][u] * COS[v][y];
      coeffs.push(s);
    }
  }
  const ac = coeffs.slice(1).sort((a, b) => a - b);
  const median = ac[Math.floor(ac.length / 2)];
  let bits = 0n;
  for (let i = 0; i < 64; i++) {
    bits = (bits << 1n) | (coeffs[i] > median ? 1n : 0n);
  }
  return bits.toString(16).padStart(16, "0");
}

export function hammingDistanceHex(a: string, b: string): number {
  let x = BigInt("0x" + a) ^ BigInt("0x" + b);
  let n = 0;
  while (x > 0n) {
    n += Number(x & 1n);
    x >>= 1n;
  }
  return n;
}

function grayGridFromSource(source: CanvasImageSource): Uint8ClampedArray {
  const canvas = document.createElement("canvas");
  canvas.width = N;
  canvas.height = N;
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  if (!ctx) throw new Error("Canvas is unavailable in this browser.");
  ctx.imageSmoothingEnabled = true;
  ctx.imageSmoothingQuality = "high";
  ctx.drawImage(source, 0, 0, N, N);
  const { data } = ctx.getImageData(0, 0, N, N);
  const gray = new Uint8ClampedArray(N * N);
  for (let i = 0; i < N * N; i++) {
    gray[i] = 0.299 * data[i * 4] + 0.587 * data[i * 4 + 1] + 0.114 * data[i * 4 + 2];
  }
  return gray;
}

async function videoFrame(blob: Blob): Promise<HTMLVideoElement> {
  const url = URL.createObjectURL(blob);
  const video = document.createElement("video");
  video.muted = true;
  video.preload = "auto";
  video.src = url;
  await new Promise<void>((resolve, reject) => {
    video.onloadeddata = () => resolve();
    video.onerror = () => reject(new Error("The video could not be decoded."));
  });
  // Sample a stable frame: 10% in, capped at one second.
  video.currentTime = Math.min(1, (video.duration || 1) * 0.1);
  await new Promise<void>((resolve) => {
    video.onseeked = () => resolve();
  });
  return video;
}

export interface Fingerprint {
  sha256: string;
  phash: string | null; // null for audio / unsupported types
  bytes: number;
  mime: string;
  name: string;
  previewUrl: string | null;
}

/** Fingerprint a Blob: SHA-256 always; pHash for images and video. */
export async function fingerprintBlob(blob: Blob, name: string): Promise<Fingerprint> {
  const buf = await blob.arrayBuffer();
  const sha256 = await sha256Hex(buf);
  const mime = blob.type || "application/octet-stream";
  let phash: string | null = null;
  let previewUrl: string | null = null;
  if (mime.startsWith("image/")) {
    previewUrl = URL.createObjectURL(blob);
    // An <img> decodes every browser image format including SVG, which createImageBitmap rejects.
    const img = new Image();
    img.src = previewUrl;
    try {
      await img.decode();
    } catch {
      throw new Error("The image could not be decoded.");
    }
    phash = phashFromGray(grayGridFromSource(img));
  } else if (mime.startsWith("video/")) {
    const video = await videoFrame(blob);
    phash = phashFromGray(grayGridFromSource(video));
    previewUrl = video.src;
  }
  return { sha256, phash, bytes: blob.size, mime, name, previewUrl };
}

/** Fetch a remote asset in the browser. Fails with a clear message under CORS. */
export async function fingerprintUrl(url: string): Promise<Fingerprint> {
  let res: Response;
  try {
    res = await fetch(url, { mode: "cors" });
  } catch {
    throw new Error(
      "The browser could not fetch this URL (blocked by CORS or offline). Download the file and upload it instead."
    );
  }
  if (!res.ok) throw new Error(`The URL answered HTTP ${res.status}.`);
  const blob = await res.blob();
  const name = url.split("/").pop()?.split("?")[0] || "remote-asset";
  return fingerprintBlob(blob, name);
}
