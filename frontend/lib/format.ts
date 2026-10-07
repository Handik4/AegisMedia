import { ATTO } from "./config";

export const shortAddr = (a: string) => (a ? `${a.slice(0, 6)}…${a.slice(-4)}` : "");
export const shortHash = (h: string, n = 10) => (h.length > n * 2 + 1 ? `${h.slice(0, n)}…${h.slice(-6)}` : h);

/** atto -> "1.2345" GEN (trimmed, at most 4 decimals). */
export function fmtGen(atto: bigint | number | string, decimals = 4): string {
  let v: bigint;
  try {
    v = BigInt(atto);
  } catch {
    return "0";
  }
  const neg = v < 0n;
  if (neg) v = -v;
  const whole = v / ATTO;
  const frac = (v % ATTO).toString().padStart(18, "0").slice(0, decimals).replace(/0+$/, "");
  return `${neg ? "-" : ""}${whole.toString()}${frac ? "." + frac : ""}`;
}

/** Exact decimal string -> atto bigint. Returns null on malformed input. */
export function toAtto(input: string): bigint | null {
  const t = input.trim();
  if (!/^\d+(\.\d{0,18})?$/.test(t)) return null;
  const [whole, frac = ""] = t.split(".");
  return BigInt(whole) * ATTO + BigInt((frac + "0".repeat(18)).slice(0, 18));
}

export function countdown(untilSec: number, nowSec = Math.floor(Date.now() / 1000)): string {
  const s = untilSec - nowSec;
  if (s <= 0) return "expired";
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  return d > 0 ? `${d}d ${h}h` : h > 0 ? `${h}h ${m}m` : `${m}m`;
}

export function timeAgo(sec: number, nowSec = Math.floor(Date.now() / 1000)): string {
  const s = Math.max(0, nowSec - sec);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export const isHex = (s: string, n: number) => new RegExp(`^(0x)?[0-9a-fA-F]{${n}}$`).test(s.trim());
