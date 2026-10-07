"use client";
import { useCallback, useState } from "react";
import { submitWrite, type TxPhase, type WriteRequest } from "./contract";
import { txExplorerUrl } from "./config";
import { useToast } from "./toast";
import { useWallet } from "./wallet";

export interface TxState {
  phase: TxPhase | "idle" | "failed";
  hash: string | null;
  error: string | null;
}

function friendly(e: unknown): string {
  const msg = e instanceof Error ? e.message : String(e);
  const code = (e as { code?: number })?.code;
  if (code === 4001 || /user rejected|denied/i.test(msg)) return "Signature request was rejected in the wallet.";
  const known = msg.match(/ERR_[A-Z_]+[^\n"]*/);
  return known ? known[0] : msg.length > 280 ? msg.slice(0, 280) + "…" : msg;
}

/** Wallet-signed contract write with phase tracking and toasts. */
export function useTx() {
  const { account, onCorrectChain, switchNetwork } = useWallet();
  const notify = useToast();
  const [state, setState] = useState<TxState>({ phase: "idle", hash: null, error: null });

  const run = useCallback(
    async (req: WriteRequest, successText?: string): Promise<string | null> => {
      if (!account) {
        notify("error", "Connect a wallet first.");
        return null;
      }
      setState({ phase: "estimating", hash: null, error: null });
      try {
        if (!onCorrectChain) await switchNetwork();
        const hash = await submitWrite(account, req, (phase, h) =>
          setState((s) => ({ ...s, phase, hash: h ?? s.hash }))
        );
        if (successText) notify("ok", successText, txExplorerUrl(hash));
        return hash;
      } catch (e) {
        const error = friendly(e);
        setState({ phase: "failed", hash: null, error });
        notify("error", error);
        return null;
      }
    },
    [account, onCorrectChain, switchNetwork, notify]
  );

  const reset = useCallback(() => setState({ phase: "idle", hash: null, error: null }), []);
  return { ...state, run, reset, busy: state.phase === "estimating" || state.phase === "signing" };
}
