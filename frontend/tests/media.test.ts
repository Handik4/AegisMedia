import { describe, expect, it } from "vitest";
import { hammingDistanceHex, phashFromGray, sha256Hex, sha256OfText } from "../lib/media";

const grid = (f: (x: number, y: number) => number) =>
  Uint8ClampedArray.from({ length: 1024 }, (_, i) => f(i % 32, Math.floor(i / 32)));

describe("SHA-256", () => {
  it("matches the known vector for 'abc'", async () => {
    expect(await sha256OfText("abc")).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    expect(await sha256Hex(new Uint8Array(0).buffer)).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  });
});

describe("64-bit perceptual hash", () => {
  const photo = grid((x, y) => 128 + 90 * Math.sin(x / 4) * Math.cos(y / 5));
  it("is 16 hex chars and deterministic", () => {
    const h = phashFromGray(photo);
    expect(h).toMatch(/^[0-9a-f]{16}$/);
    expect(phashFromGray(photo)).toBe(h);
  });
  it("survives mild noise and brightness shift (re-encoding) within the 10-bit threshold", () => {
    let seed = 7;
    const rnd = () => ((seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff - 0.5) * 6;
    const reencoded = Uint8ClampedArray.from(photo, (v) => v * 0.97 + 4 + rnd());
    expect(hammingDistanceHex(phashFromGray(photo), phashFromGray(reencoded))).toBeLessThanOrEqual(10);
  });
  it("separates unrelated pictures far beyond the threshold", () => {
    const other = grid((x, y) => (x * 7 + y * 13) % 256);
    const d = hammingDistanceHex(phashFromGray(photo), phashFromGray(other));
    expect(d).toBeGreaterThan(10);
  });
  it("computes exact Hamming distances", () => {
    expect(hammingDistanceHex("0000000000000000", "ffffffffffffffff")).toBe(64);
    expect(hammingDistanceHex("f0e1d2c3b4a59687", "f0e1d2c3b4a59687")).toBe(0);
    expect(hammingDistanceHex("0000000000000001", "8000000000000000")).toBe(2);
  });
});
