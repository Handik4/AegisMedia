"use client";
import { useEffect, useState } from "react";
import { Loader2, ShieldCheck, Wallet, TriangleAlert } from "lucide-react";
import { useWallet } from "@/lib/wallet";
import { api } from "@/lib/contract";
import { IS_CONFIGURED, NETWORK_LABEL } from "@/lib/config";
import { fmtGen, shortAddr } from "@/lib/format";
import { useTx } from "@/lib/useTx";
import { useData } from "@/lib/data";

export default function Header() {
  const w = useWallet();
  const tx = useTx();
  const { refresh } = useData();
  const [claimable, setClaimable] = useState<bigint>(0n);

  useEffect(() => {
    if (!w.account || !IS_CONFIGURED) {
      setClaimable(0n);
      return;
    }
    let live = true;
    const load = () => api.claimable(w.account!).then((v) => live && setClaimable(v)).catch(() => {});
    void load();
    const t = setInterval(load, 60000);
    return () => {
      live = false;
      clearInterval(t);
    };
  }, [w.account, tx.hash]);

  const claim = async () => {
    const hash = await tx.run({ method: "claim_payout", args: [] }, "Payout claimed");
    if (hash) {
      setClaimable(0n);
      void refresh();
    }
  };

  return (
    <header className="sticky top-0 z-40 border-b border-slate-200 bg-white/95 backdrop-blur">
      <div className="mx-auto flex max-w-7xl items-center justify-between gap-4 px-4 py-3 sm:px-6">
        <a href="#top" className="flex items-center gap-2.5" aria-label="AegisMedia home">
          <span className="grid h-8 w-8 place-items-center rounded-md border border-indigo-200 bg-indigo-50">
            <ShieldCheck className="h-4.5 w-4.5 text-indigo-600" aria-hidden />
          </span>
          <span className="font-display text-lg tracking-tight">
            Aegis<span className="text-indigo-600">Media</span>
          </span>
        </a>

        <nav className="hidden items-center gap-6 text-sm text-[color:var(--muted)] md:flex" aria-label="Sections">
          <a className="hover:text-[color:var(--paper)]" href="#registry">Registry</a>
          <a className="hover:text-[color:var(--paper)]" href="#verify">Verifier</a>
          <a className="hover:text-[color:var(--paper)]" href="#challenge">Challenge terminal</a>
        </nav>

        <div className="flex items-center gap-2">
          {w.account && claimable > 0n && (
            <button className="btn-ghost !py-2 text-xs" onClick={claim} disabled={tx.busy}>
              {tx.busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : null}
              Claim {fmtGen(claimable)} GEN
            </button>
          )}
          {w.account && !w.onCorrectChain && (
            <button className="btn !py-2 border border-amber-200 bg-amber-50 text-xs text-amber-700 hover:bg-amber-100" onClick={w.switchNetwork}>
              <TriangleAlert className="h-3.5 w-3.5" aria-hidden /> Switch to {NETWORK_LABEL}
            </button>
          )}
          {w.account ? (
            <button
              className="btn-ghost !py-2 font-mono text-xs"
              onClick={w.disconnect}
              title="Disconnect (this site only)"
            >
              <span className="h-2 w-2 rounded-full bg-[color:var(--seal)]" aria-hidden />
              {shortAddr(w.account)}
            </button>
          ) : (
            <button className="btn-primary !py-2 text-sm" onClick={w.connect} disabled={w.busy}>
              {w.busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Wallet className="h-4 w-4" aria-hidden />}
              Connect wallet
            </button>
          )}
        </div>
      </div>
      {w.error && (
        <p role="alert" className="border-t border-[color:var(--alarm)] bg-[color:var(--alarm-dim)] px-4 py-2 text-center text-xs">
          {w.error}
        </p>
      )}
    </header>
  );
}
