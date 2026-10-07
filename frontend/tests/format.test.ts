import { describe, expect, it } from "vitest";
import { countdown, fmtGen, isHex, toAtto } from "../lib/format";

describe("atto <-> GEN formatting", () => {
  it("round-trips exact decimals without float error", () => {
    expect(toAtto("0.515")).toBe(515_000_000_000_000_000n);
    expect(toAtto("5")).toBe(5_000_000_000_000_000_000n);
    expect(fmtGen(toAtto("2.5")!)).toBe("2.5");
    expect(fmtGen(5_000_000_000_000_000_000n)).toBe("5");
  });
  it("rejects malformed amounts", () => {
    for (const bad of ["", "-1", "1e3", "1.1234567890123456789", "abc", "1,5"]) expect(toAtto(bad)).toBeNull();
  });
  it("accepts bigint, number and string inputs", () => {
    expect(fmtGen("1750000000000000000")).toBe("1.75");
    expect(fmtGen(0n)).toBe("0");
  });
  it("bond plus 3% fee matches the contract's integer math", () => {
    const bond = toAtto("0.5")!;
    const fee = (bond * 300n) / 10000n;
    const value = bond + fee;
    expect(value).toBe(515_000_000_000_000_000n);
    expect((value * 10000n) / 10300n).toBe(bond); // the contract recovers the same bond
  });
  it("formats countdowns and validates hex", () => {
    expect(countdown(1000, 1000)).toBe("expired");
    expect(countdown(1000 + 90_000, 1000)).toBe("1d 1h");
    expect(isHex("ab".repeat(32), 64)).toBe(true);
    expect(isHex("0x" + "ab".repeat(20), 40)).toBe(true);
    expect(isHex("zz", 2)).toBe(false);
  });
});
