"use client";
import { useEffect, useState } from "react";
import { Siren, ShieldCheck } from "lucide-react";
import { useData } from "@/lib/data";
import { countdown, fmtGen } from "@/lib/format";
import { IS_CONFIGURED } from "@/lib/config";

function Stat({ label, value, tone }: { label: string; value: string; tone?: "seal" | "alarm" }) {
  return (
    <div className="panel px-4 py-3.5">
      <p className="label">{label}</p>
      <p className={`mt-1 font-mono text-2xl tabular-nums ${tone === "seal" ? "text-[color:var(--seal)]" : tone === "alarm" ? "text-[color:var(--alarm)]" : ""}`}>
        {value}
      </p>
    </div>
  );
}

export default function Hero() {
  const { overview, entities, loading } = useData();
  const [now, setNow] = useState(() => Math.floor(Date.now() / 1000));
  useEffect(() => {
    const t = setInterval(() => setNow(Math.floor(Date.now() / 1000)), 30000);
    return () => clearInterval(t);
  }, []);
  const flagged = entities.filter((e) => e.flagged && e.flag_until > now);
  const dash = loading ? "…" : "—";

  return (
    <section id="top" className="mx-auto max-w-7xl px-4 pt-12 sm:px-6 sm:pt-16">
      {flagged.map((e) => (
        <div key={e.id} role="alert" className="pulse-alarm mb-4 flex flex-wrap items-center gap-3 rounded-xl border border-[color:var(--alarm)] bg-[color:var(--alarm-dim)] px-4 py-3">
          <Siren className="h-5 w-5 shrink-0 text-[color:var(--alarm)]" aria-hidden />
          <p className="text-sm">
            <span className="font-mono font-semibold tracking-wide text-[color:var(--alarm)]">IMPERSONATION_ALERT</span>{" "}
            <strong>{e.name}</strong> ({e.domain}) is being impersonated. Treat unsigned announcements as hostile. Circuit breaker clears in {countdown(e.flag_until, now)}.
          </p>
        </div>
      ))}

      <div className="grid items-end gap-8 lg:grid-cols-[1.3fr_1fr]">
        <div>
          <p className="label inline-flex items-center gap-2"><ShieldCheck className="h-3.5 w-3.5 text-indigo-600" aria-hidden /> Verifiable media registry</p>
          <h1 className="mt-4 font-display text-4xl leading-[1.05] tracking-tight sm:text-6xl">
            If it isn&rsquo;t <em className="text-indigo-600 not-italic">sealed</em> on-chain,<br className="hidden sm:block" /> it isn&rsquo;t official.
          </h1>
          <p className="mt-5 max-w-xl text-base text-[color:var(--muted)]">
            Founders, foundations and DAOs stake GEN to anchor announcements with a perceptual hash and an EIP-712 signature. Anyone can challenge a forgery; GenVM validators compare the evidence independently, slash the publisher and trip a circuit breaker that tokens and DeFi protocols can read.
          </p>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <Stat label="Entities" value={overview ? String(overview.entities) : dash} />
          <Stat label="Sealed broadcasts" value={overview ? String(overview.announcements) : dash} tone="seal" />
          <Stat label="Challenges" value={overview ? String(overview.challenges) : dash} />
          <Stat label="GEN locked" value={overview ? fmtGen(overview.total_locked, 2) : dash} />
        </div>
      </div>
      {!IS_CONFIGURED && (
        <p className="mt-8 rounded-xl border border-[color:var(--amber)] bg-[color:var(--ink-2)] px-4 py-3 text-sm text-[color:var(--amber)]">
          The AegisMedia contract is not deployed yet. This dashboard only runs in live mode against Studio Next: run <code className="font-mono">python scripts/deploy.py</code> to deploy and write the address to <code className="font-mono">frontend/lib/deployment.json</code>.
        </p>
      )}
    </section>
  );
}
