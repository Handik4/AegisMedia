"use client";
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { CHAIN_ID } from "./config";
import { connectAndSwitch, readChainId, switchToStudioNext } from "./chain";

interface Eip1193Provider {
  request(args: { method: string; params?: unknown[] }): Promise<unknown>;
  on?(event: string, cb: (...a: any[]) => void): void;
  removeListener?(event: string, cb: (...a: any[]) => void): void;
}

interface WalletState {
  hasWallet: boolean;
  account: string | null;
  chainId: number | null;
  onCorrectChain: boolean;
  busy: boolean;
  error: string | null;
  connect(): Promise<void>;
  switchNetwork(): Promise<void>;
  disconnect(): void;
}

const Ctx = createContext<WalletState | null>(null);
const provider = () =>
  typeof window === "undefined" ? undefined : (window as unknown as { ethereum?: Eip1193Provider }).ethereum;

export function WalletProvider({ children }: { children: ReactNode }) {
  const [hasWallet, setHasWallet] = useState(false);
  const [account, setAccount] = useState<string | null>(null);
  const [chainId, setChainId] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const switchNetwork = useCallback(async () => {
    const p = provider();
    if (p) await switchToStudioNext(p);
  }, []);

  const readChain = useCallback(async () => {
    const p = provider();
    if (!p) return;
    setChainId(await readChainId(p));
  }, []);

  useEffect(() => {
    const p = provider();
    setHasWallet(Boolean(p));
    if (!p) return;
    void (async () => {
      try {
        const accounts = (await p.request({ method: "eth_accounts" })) as string[];
        setAccount(accounts[0] ?? null);
        await readChain();
      } catch {
        /* wallet locked or unavailable */
      }
    })();
    const onAccounts = (a: string[]) => setAccount(a[0] ?? null);
    const onChain = (c: string) => setChainId(parseInt(c, 16));
    p.on?.("accountsChanged", onAccounts);
    p.on?.("chainChanged", onChain);
    return () => {
      p.removeListener?.("accountsChanged", onAccounts);
      p.removeListener?.("chainChanged", onChain);
    };
  }, [readChain]);

  const connect = useCallback(async () => {
    const p = provider();
    if (!p) {
      setError("No injected wallet found. Install MetaMask or another EIP-1193 wallet.");
      return;
    }
    setBusy(true);
    setError(null);
    const r = await connectAndSwitch(p);
    if (r.account) setAccount(r.account);
    if (r.chainId) setChainId(r.chainId);
    setError(r.error);
    setBusy(false);
  }, []);

  const value = useMemo<WalletState>(
    () => ({
      hasWallet,
      account,
      chainId,
      onCorrectChain: chainId === CHAIN_ID,
      busy,
      error,
      connect,
      switchNetwork: async () => {
        setError(null);
        try {
          await switchNetwork();
        } catch (e) {
          setError((e as Error).message ?? "Could not switch network.");
        }
      },
      disconnect: () => setAccount(null),
    }),
    [hasWallet, account, chainId, busy, error, connect, switchNetwork]
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useWallet(): WalletState {
  const v = useContext(Ctx);
  if (!v) throw new Error("useWallet must be used inside WalletProvider");
  return v;
}
