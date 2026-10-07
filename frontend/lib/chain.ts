// Wallet / network helpers kept free of React so they can be unit-tested against a
// mock EIP-1193 provider.
import { CHAIN_ID, CHAIN_ID_HEX, EXPLORER_URL, NETWORK_LABEL, RPC_URL } from "./config";

export interface Eip1193Provider {
  request(args: { method: string; params?: unknown[] }): Promise<unknown>;
}

export const GENLAYER_CHAIN_PARAMS = {
  chainId: CHAIN_ID_HEX,
  chainName: NETWORK_LABEL,
  nativeCurrency: { name: "GEN", symbol: "GEN", decimals: 18 },
  rpcUrls: [RPC_URL],
  blockExplorerUrls: [EXPLORER_URL],
};

export async function readChainId(p: Eip1193Provider): Promise<number> {
  return parseInt((await p.request({ method: "eth_chainId" })) as string, 16);
}

/** Switch to Studio Next, adding the network first when the wallet does not know it. */
export async function switchToStudioNext(p: Eip1193Provider): Promise<void> {
  try {
    await p.request({ method: "wallet_switchEthereumChain", params: [{ chainId: CHAIN_ID_HEX }] });
  } catch (e) {
    const code = (e as { code?: number }).code;
    // 4902: unknown chain. Some wallets report it as -32603 (internal error).
    if (code === 4902 || code === -32603) {
      await p.request({ method: "wallet_addEthereumChain", params: [GENLAYER_CHAIN_PARAMS] });
    } else {
      throw e;
    }
  }
}

export interface ConnectResult {
  account: string | null;
  chainId: number;
  error: string | null;
}

/** Request accounts, then move the wallet onto chain 61997. Never rejects. */
export async function connectAndSwitch(p: Eip1193Provider): Promise<ConnectResult> {
  let account: string | null = null;
  let chainId = 0;
  try {
    const accounts = (await p.request({ method: "eth_requestAccounts" })) as string[];
    account = accounts[0] ?? null;
    chainId = await readChainId(p);
    if (chainId !== CHAIN_ID) {
      await switchToStudioNext(p);
      chainId = await readChainId(p);
    }
    return { account, chainId, error: null };
  } catch (e) {
    const err = e as { code?: number; message?: string };
    const error =
      err.code === 4001
        ? "Connection request was rejected."
        : err.message ?? "Wallet connection failed.";
    return { account, chainId, error };
  }
}
