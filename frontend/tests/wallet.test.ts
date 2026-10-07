import { afterEach, describe, expect, it, vi } from "vitest";
import { connectAndSwitch, GENLAYER_CHAIN_PARAMS, switchToStudioNext, type Eip1193Provider } from "../lib/chain";

const rejections: unknown[] = [];
const onRejection = (r: unknown) => rejections.push(r);
process.on("unhandledRejection", onRejection);
afterEach(() => vi.restoreAllMocks());

function mockWallet(opts: { chain?: string; knowsChain?: boolean; rejectConnect?: boolean; switchError?: { code: number; message: string } } = {}) {
  let chain = opts.chain ?? "0x1";
  let known = opts.knowsChain ?? false;
  const calls: string[] = [];
  const provider: Eip1193Provider = {
    async request({ method, params }) {
      calls.push(method);
      switch (method) {
        case "eth_requestAccounts":
          if (opts.rejectConnect) throw Object.assign(new Error("User rejected the request."), { code: 4001 });
          return ["0x1111111111111111111111111111111111111111"];
        case "eth_chainId":
          return chain;
        case "wallet_switchEthereumChain":
          if (opts.switchError) throw Object.assign(new Error(opts.switchError.message), { code: opts.switchError.code });
          if (!known) throw Object.assign(new Error("Unrecognized chain ID"), { code: 4902 });
          chain = (params![0] as { chainId: string }).chainId;
          return null;
        case "wallet_addEthereumChain":
          known = true;
          chain = (params![0] as { chainId: string }).chainId;
          return null;
        default:
          throw new Error(`unsupported ${method}`);
      }
    },
  };
  return { provider, calls };
}

describe("Studio Next chain parameters", () => {
  it("uses chain id 61997 (0xf22d) and GEN as the native currency", () => {
    expect(parseInt(GENLAYER_CHAIN_PARAMS.chainId, 16)).toBe(61997);
    expect(GENLAYER_CHAIN_PARAMS.nativeCurrency).toEqual({ name: "GEN", symbol: "GEN", decimals: 18 });
    expect(GENLAYER_CHAIN_PARAMS.rpcUrls[0]).toMatch(/^https:\/\//);
  });
});

describe("wallet connection and automatic network switch", () => {
  it("adds then switches when the wallet has never seen Studio Next", async () => {
    const { provider, calls } = mockWallet();
    const r = await connectAndSwitch(provider);
    expect(r).toMatchObject({ error: null, chainId: 61997 });
    expect(r.account).toBe("0x1111111111111111111111111111111111111111");
    expect(calls).toEqual([
      "eth_requestAccounts", "eth_chainId", "wallet_switchEthereumChain", "wallet_addEthereumChain", "eth_chainId",
    ]);
  });

  it("switches directly when the network is already known", async () => {
    const { provider, calls } = mockWallet({ knowsChain: true });
    const r = await connectAndSwitch(provider);
    expect(r.chainId).toBe(61997);
    expect(calls).not.toContain("wallet_addEthereumChain");
  });

  it("does nothing extra when already on chain 61997", async () => {
    const { provider, calls } = mockWallet({ chain: "0xf22d" });
    expect((await connectAndSwitch(provider)).chainId).toBe(61997);
    expect(calls).toEqual(["eth_requestAccounts", "eth_chainId"]);
  });

  it("handles wallets that report an unknown chain as -32603", async () => {
    const { provider } = mockWallet({ switchError: { code: -32603, message: "Internal error" } });
    // the add call succeeds, so the flow completes
    const w = await switchToStudioNext(provider).then(() => "ok", (e) => e);
    expect(w).toBe("ok");
  });

  it("reports a rejected connection as a message, never as a rejection", async () => {
    const { provider } = mockWallet({ rejectConnect: true });
    const r = await connectAndSwitch(provider);
    expect(r.account).toBeNull();
    expect(r.error).toBe("Connection request was rejected.");
  });

  it("reports a user-rejected network switch without throwing", async () => {
    const { provider } = mockWallet({ switchError: { code: 4001, message: "User rejected the request." } });
    const r = await connectAndSwitch(provider);
    expect(r.error).toBe("Connection request was rejected.");
    expect(r.chainId).toBe(1);
  });

  it("has zero unhandled promise rejections across all flows", async () => {
    await new Promise((r) => setTimeout(r, 50));
    expect(rejections).toEqual([]);
  });
});
