"use client";
import { ExternalLink, Github } from "lucide-react";
import { CHAIN_ID, CONTRACT_ADDRESS, GITHUB_URL, IS_CONFIGURED, NETWORK_LABEL, contractExplorerUrl } from "@/lib/config";
import { shortAddr } from "@/lib/format";
import { useData } from "@/lib/data";

export default function Footer() {
  const { overview, error, configured } = useData();
  const state = !configured ? "AWAITING DEPLOYMENT" : error && !overview ? "RPC UNREACHABLE" : overview?.solvent === false ? "SOLVENCY ALERT" : overview ? "OPERATIONAL" : "CONNECTING";
  const ok = state === "OPERATIONAL";
  return (
    <footer className="mt-24 border-t border-[color:var(--line)]">
      <div className="mx-auto grid max-w-7xl gap-8 px-4 py-10 text-sm sm:px-6 md:grid-cols-3">
        <div>
          <p className="font-display text-lg">Aegis<span className="text-indigo-600">Media</span></p>
          <p className="mt-2 max-w-xs text-[color:var(--muted)]">
            An on-chain media registry and impersonation circuit breaker. Official entities stake; validators adjudicate; forgers pay.
          </p>
        </div>
        <dl className="space-y-2 font-mono text-xs">
          <div className="flex justify-between gap-4"><dt className="text-[color:var(--muted)]">Network</dt><dd>{NETWORK_LABEL} · {CHAIN_ID}</dd></div>
          <div className="flex justify-between gap-4">
            <dt className="text-[color:var(--muted)]">Contract</dt>
            <dd>
              {IS_CONFIGURED ? (
                <a className="inline-flex items-center gap-1 underline underline-offset-2 hover:text-[color:var(--seal)]" href={contractExplorerUrl()} target="_blank" rel="noreferrer" title={CONTRACT_ADDRESS}>
                  {shortAddr(CONTRACT_ADDRESS)} <ExternalLink className="h-3 w-3" aria-hidden />
                </a>
              ) : "not deployed"}
            </dd>
          </div>
          <div className="flex justify-between gap-4">
            <dt className="text-[color:var(--muted)]">Protocol status</dt>
            <dd className={`inline-flex items-center gap-2 ${ok ? "text-[color:var(--seal)]" : "text-[color:var(--amber)]"}`}>
              <span className={`h-2 w-2 rounded-full ${ok ? "bg-[color:var(--seal)]" : "bg-[color:var(--amber)]"}`} aria-hidden />{state}
            </dd>
          </div>
        </dl>
        <div className="flex items-start gap-3 md:justify-end">
          <a className="btn-ghost" href={GITHUB_URL} target="_blank" rel="noreferrer"><Github className="h-4 w-4" aria-hidden /> GitHub</a>
          {IS_CONFIGURED && (
            <a className="btn-ghost" href={contractExplorerUrl()} target="_blank" rel="noreferrer"><ExternalLink className="h-4 w-4" aria-hidden /> Explorer</a>
          )}
        </div>
      </div>
    </footer>
  );
}
