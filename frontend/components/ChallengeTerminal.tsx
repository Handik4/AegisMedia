"use client";
import { useEffect, useMemo, useRef, useState } from "react";
import { CheckCircle2, CircleDashed, Gavel, Loader2, ShieldAlert, ShieldCheck, ShieldQuestion, Swords } from "lucide-react";
import { useData } from "@/lib/data";
import { useWallet } from "@/lib/wallet";
import { useTx } from "@/lib/useTx";
import { api, snapshotTx, type TxSnapshot } from "@/lib/contract";
import { FEE_BPS, HAMMING_THRESHOLD, IS_CONFIGURED, MIN_BOND_GEN, txExplorerUrl } from "@/lib/config";
import { fmtGen, shortAddr, shortHash, timeAgo, toAtto } from "@/lib/format";
import type { Challenge, Verdict } from "@/lib/abi";
import BitMatrix from "./BitMatrix";

const STEPS = ["Fees estimated", "Wallet signature", "Submitted to consensus", "Validators fetch & compare", "Votes revealed", "Verdict settled"] as const;

/** Map the protocol status name onto how far along the telemetry timeline we are. */
function stepFor(phase: string, snap: TxSnapshot | null): number {
  if (!snap) return phase === "estimating" ? 0 : phase === "signing" ? 1 : phase === "submitted" ? 2 : -1;
  if (snap.decided) return 6;
  switch (snap.status) {
    case "REVEALING": return 4;
    case "PROPOSING":
    case "COMMITTING":
    case "ACTIVATED": return 3;
    default: return 2;
  }
}

const VERDICT_STYLE: Record<Verdict, { label: string; tone: string; icon: typeof ShieldAlert; blurb: string }> = {
  CONFIRMED_DEEPFAKE: { label: "CONFIRMED DEEPFAKE", tone: "var(--alarm)", icon: ShieldAlert, blurb: "Forgery evidence confirmed. A staked, domain-bound publisher is slashed and the circuit breaker is engaged; with no publisher the verdict is recorded but nothing is slashed." },
  LEGITIMATE_MEDIA: { label: "LEGITIMATE MEDIA", tone: "var(--seal)", icon: ShieldCheck, blurb: "The evidence holds up. The challenge bond is forfeited to the entity." },
  INCONCLUSIVE_DISMISSED: { label: "INCONCLUSIVE · DISMISSED", tone: "var(--amber)", icon: ShieldQuestion, blurb: "The URL could not be assessed. The bond is refunded; the arbitration fee is kept." },
};

function Telemetry({ phase, snap, hash }: { phase: string; snap: TxSnapshot | null; hash: string | null }) {
  const at = stepFor(phase, snap);
  return (
    <div>
      <ol className="space-y-2.5" aria-label="Consensus telemetry">
        {STEPS.map((label, i) => {
          const done = i < at, active = i === at;
          return (
            <li key={label} className="flex items-center gap-3 text-sm">
              {done ? <CheckCircle2 className="h-4 w-4 text-[color:var(--seal)]" aria-hidden /> : active ? <Loader2 className="h-4 w-4 animate-spin text-[color:var(--amber)]" aria-hidden /> : <CircleDashed className="h-4 w-4 text-[color:var(--line)]" aria-hidden />}
              <span className={done ? "text-[color:var(--paper)]" : active ? "text-[color:var(--amber)]" : "text-[color:var(--muted)]"}>{label}</span>
            </li>
          );
        })}
      </ol>
      {snap && (
        <dl className="mt-4 grid grid-cols-2 gap-x-4 gap-y-2 border-t border-[color:var(--line)] pt-3 font-mono text-[11px]">
          <div><dt className="label !text-[10px]">Status</dt><dd>{snap.status}</dd></div>
          <div><dt className="label !text-[10px]">Rounds</dt><dd>{snap.rounds}</dd></div>
          <div><dt className="label !text-[10px]">Validators</dt><dd>{snap.validators.length || "—"}</dd></div>
          <div><dt className="label !text-[10px]">Votes committed / revealed</dt><dd>{snap.votesCommitted} / {snap.votesRevealed}</dd></div>
          {snap.leader && <div className="col-span-2"><dt className="label !text-[10px]">Leader</dt><dd>{shortAddr(snap.leader)}</dd></div>}
          {snap.decided && <div className="col-span-2"><dt className="label !text-[10px]">Consensus / execution</dt><dd>{snap.consensusResult || "—"} · {snap.executionResult || "—"}</dd></div>}
        </dl>
      )}
      {hash && <a className="mt-3 inline-block font-mono text-[11px] underline underline-offset-2 hover:text-[color:var(--seal)]" href={txExplorerUrl(hash)} target="_blank" rel="noreferrer">tx {shortHash(hash, 8)}</a>}
    </div>
  );
}

function Outcome({ c, entityName, publisherName }: { c: Challenge; entityName: string; publisherName: string }) {
  const v = VERDICT_STYLE[c.verdict];
  const Icon = v.icon;
  const [baseline, setBaseline] = useState<string | null>(null);
  useEffect(() => {
    let live = true;
    if (c.baseline_id) void api.announcement(c.baseline_id).then((a) => live && setBaseline(a.phash)).catch(() => {});
    return () => { live = false; };
  }, [c.baseline_id]);
  const pct = c.distance < 0 ? 0 : Math.min(100, (c.distance / 64) * 100);
  return (
    <div className="seal-in" role="status">
      <div className="flex items-start gap-3 rounded-xl border p-4" style={{ borderColor: `color-mix(in srgb, ${v.tone} 55%, transparent)`, background: "var(--ink-3)" }}>
        <Icon className="mt-0.5 h-6 w-6 shrink-0" style={{ color: v.tone }} aria-hidden />
        <div>
          <p className="font-mono text-sm font-semibold tracking-widest" style={{ color: v.tone }}>{v.label}</p>
          <p className="mt-1 text-sm text-[color:var(--muted)]">{v.blurb}</p>
          <p className="mt-1 font-mono text-[11px] text-[color:var(--muted)]">reason: {c.reason} · signature: {c.sig_state}{c.http_status ? ` · HTTP ${c.http_status}` : ""}</p>
        </div>
      </div>

      <div className="mt-4">
        <div className="flex items-end justify-between">
          <p className="label">Hamming distance</p>
          <p className="font-mono text-2xl tabular-nums" style={{ color: c.distance > HAMMING_THRESHOLD ? "var(--alarm)" : "var(--seal)" }}>
            {c.distance < 0 ? "n/a" : `${c.distance}`}<span className="text-sm text-[color:var(--muted)]"> / 64 bits</span>
          </p>
        </div>
        <div className="relative mt-2 h-2.5 rounded-full bg-[color:var(--ink)]" role="meter" aria-valuemin={0} aria-valuemax={64} aria-valuenow={Math.max(c.distance, 0)} aria-label="Hamming distance">
          <div className="absolute inset-y-0 left-0 rounded-full" style={{ width: `${pct}%`, background: c.distance > HAMMING_THRESHOLD ? "var(--alarm)" : "var(--seal)" }} />
          <div className="absolute -top-1 bottom-[-4px] w-px bg-[color:var(--paper)]" style={{ left: `${(HAMMING_THRESHOLD / 64) * 100}%` }} title="Threshold" />
        </div>
        <p className="mt-1.5 text-[11px] text-[color:var(--muted)]">Threshold: more than {HAMMING_THRESHOLD} bits apart is a deepfake.</p>
      </div>

      {baseline && c.observed_phash && <div className="mt-4"><BitMatrix a={baseline} b={c.observed_phash} /></div>}

      <dl className="mt-4 grid grid-cols-3 gap-3 text-sm">
        <div><dt className="label">Slashed</dt><dd className="font-mono">{fmtGen(c.slashed)}</dd></div>
        <div><dt className="label">Burned</dt><dd className="font-mono">{fmtGen(c.burned)}</dd></div>
        <div><dt className="label">Bounty</dt><dd className="font-mono text-[color:var(--seal)]">{fmtGen(c.bounty)}</dd></div>
      </dl>
      <p className="mt-3 text-xs text-[color:var(--muted)]">Entity: {entityName}{c.publisher_id ? ` · publisher: ${publisherName}` : " · publisher: unknown / unstaked"}</p>
    </div>
  );
}

export default function ChallengeTerminal() {
  const { entities, challenges, refresh, configured } = useData();
  const w = useWallet();
  const tx = useTx();
  const [victim, setVictim] = useState<number | "">("");
  const [publisher, setPublisher] = useState<number>(0);
  const [uri, setUri] = useState("");
  const [bond, setBond] = useState(String(MIN_BOND_GEN));
  const [snap, setSnap] = useState<TxSnapshot | null>(null);
  const [outcome, setOutcome] = useState<Challenge | null>(null);
  const [lookupError, setLookupError] = useState<string | null>(null);
  const submittedUri = useRef("");

  const bondAtto = toAtto(bond);
  const fee = bondAtto === null ? 0n : (bondAtto * FEE_BPS) / 10000n;
  const total = bondAtto === null ? 0n : bondAtto + fee;
  const minBond = toAtto(String(MIN_BOND_GEN))!;
  const byId = useMemo(() => new Map(entities.map((e) => [e.id, e])), [entities]);
  const victimId = victim === "" ? entities[0]?.id : victim;

  const problems: string[] = [];
  if (!victimId) problems.push("Choose the entity being impersonated.");
  if (!/^https?:\/\/[^\s]+\.[^\s]+/i.test(uri.trim())) problems.push("Enter the full URL of the suspicious broadcast.");
  if (bondAtto === null || bondAtto < minBond) problems.push(`Minimum bond is ${MIN_BOND_GEN} GEN.`);
  if (publisher && publisher === victimId) problems.push("Choosing the victim as publisher slashes the victim's own stake. Only do this for a compromised key.");

  // Poll the transaction until consensus decides, then load the settled challenge record.
  useEffect(() => {
    if (!tx.hash) return;
    let live = true;
    const hash = tx.hash;
    const tick = async () => {
      try {
        const s = await snapshotTx(hash);
        if (!live) return;
        setSnap(s);
        if (s.decided) {
          clearInterval(timer);
          const recent = await api.challenges();
          const mine = recent.find((c) => c.contested_uri === submittedUri.current && c.challenger.toLowerCase() === (w.account ?? "").toLowerCase());
          if (live) {
            if (mine) setOutcome(mine);
            else setLookupError(`Consensus ended as ${s.consensusResult || s.status}. No settled challenge was recorded: the call may have reverted (for example a replay or an expired window).`);
            void refresh();
          }
        }
      } catch {
        /* transient RPC hiccup: keep polling */
      }
    };
    const timer = setInterval(tick, 3000);
    void tick();
    return () => { live = false; clearInterval(timer); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tx.hash]);

  const submit = async () => {
    if (problems.length > 0 && !(problems.length === 1 && problems[0].startsWith("Choosing the victim"))) return;
    if (!victimId || bondAtto === null) return;
    setSnap(null);
    setOutcome(null);
    setLookupError(null);
    submittedUri.current = uri.trim();
    await tx.run({ method: "challenge_broadcast", args: [BigInt(victimId), uri.trim(), BigInt(publisher)], value: bondAtto + fee });
  };

  const hardBlocked = problems.filter((p) => !p.startsWith("Choosing the victim")).length > 0;
  const running = tx.phase !== "idle" && tx.phase !== "failed" && !outcome && !lookupError;

  return (
    <section id="challenge" className="mx-auto mt-24 max-w-7xl scroll-mt-20 px-4 sm:px-6">
      <p className="label">03 · Challenge terminal</p>
      <h2 className="mt-2 font-display text-3xl sm:text-4xl">Report an impostor</h2>
      <p className="mt-2 max-w-2xl text-sm text-[color:var(--muted)]">
        Post a refundable bond plus a 3% arbitration fee. Validators fetch the link independently and look for explicit forgery evidence: a forged signature, or media whose independently computed perceptual hash diverges. Mentioning an entity is not evidence. A slashed publisher pays you a bounty; a false alarm forfeits your bond. A named publisher must host the URL on its registered domain.
      </p>

      <div className="mt-6 grid gap-5 lg:grid-cols-[1fr_1.1fr]">
        <div className="panel p-5">
          <div className="space-y-3">
            <label className="block"><span className="label">Impersonated entity</span>
              <select className="field mt-1" value={victimId ?? ""} onChange={(e) => setVictim(Number(e.target.value))} disabled={!configured}>
                {entities.length === 0 && <option value="">No entities registered</option>}
                {entities.map((e) => <option key={e.id} value={e.id}>{e.name} · {e.domain}</option>)}
              </select>
            </label>
            <label className="block"><span className="label">Impostor link</span>
              <input className="field mt-1" value={uri} onChange={(e) => setUri(e.target.value)} placeholder="https://fake-announce.example/merge.png" disabled={!configured} />
            </label>
            <label className="block"><span className="label">Publishing entity (staked channel that posted it)</span>
              <select className="field mt-1" value={publisher} onChange={(e) => setPublisher(Number(e.target.value))} disabled={!configured}>
                <option value={0}>Unknown publisher (no slash, no bounty, no alert)</option>
                {entities.map((e) => <option key={e.id} value={e.id}>{e.name} · {e.domain} · stake {fmtGen(e.stake, 2)} GEN</option>)}
              </select>
            </label>
            <label className="block"><span className="label">Challenge bond (GEN)</span>
              <input className="field mt-1 font-mono" inputMode="decimal" value={bond} onChange={(e) => setBond(e.target.value)} disabled={!configured} />
            </label>
          </div>
          <dl className="mt-4 space-y-1 rounded-lg bg-[color:var(--ink)] p-3 font-mono text-xs">
            <div className="flex justify-between"><dt className="text-[color:var(--muted)]">Refundable bond</dt><dd>{fmtGen(bondAtto ?? 0n)} GEN</dd></div>
            <div className="flex justify-between"><dt className="text-[color:var(--muted)]">Arbitration fee (3%, non-refundable)</dt><dd>{fmtGen(fee, 6)} GEN</dd></div>
            <div className="flex justify-between border-t border-[color:var(--line)] pt-1 text-sm"><dt>You send</dt><dd>{fmtGen(total, 6)} GEN</dd></div>
          </dl>
          {problems.length > 0 && uri !== "" && <ul className="mt-3 space-y-1 text-xs text-[color:var(--amber)]">{problems.map((p) => <li key={p}>• {p}</li>)}</ul>}
          <button className="btn-danger mt-4 w-full" disabled={!w.account || hardBlocked || tx.busy || running || !IS_CONFIGURED} onClick={submit}>
            {tx.busy || running ? <Loader2 className="h-4 w-4 animate-spin" /> : <Gavel className="h-4 w-4" aria-hidden />}
            {!w.account ? "Connect a wallet to challenge" : tx.phase === "signing" ? "Confirm in wallet…" : running ? "Validators deliberating…" : "Stake bond & submit challenge"}
          </button>
          <p className="mt-2 text-[11px] text-[color:var(--muted)]">Consensus can take a few minutes on Studio Next. This panel tracks it live.</p>
        </div>

        <div className="panel p-5" aria-live="polite">
          <p className="label inline-flex items-center gap-2"><Swords className="h-3.5 w-3.5" aria-hidden /> Validator consensus telemetry</p>
          <div className="mt-4">
            {tx.phase === "idle" && !outcome && <p className="text-sm text-[color:var(--muted)]">Submit a challenge to watch the validators work. You will see each stage, the Hamming distance score and the settlement.</p>}
            {tx.phase === "failed" && <p role="alert" className="text-sm text-[color:var(--alarm)]">{tx.error}</p>}
            {tx.phase !== "idle" && tx.phase !== "failed" && <Telemetry phase={tx.phase} snap={snap} hash={tx.hash} />}
            {lookupError && <p role="alert" className="mt-4 text-sm text-[color:var(--amber)]">{lookupError}</p>}
            {outcome && (
              <div className="mt-5 border-t border-[color:var(--line)] pt-5">
                <Outcome c={outcome} entityName={byId.get(outcome.victim_id)?.name ?? `#${outcome.victim_id}`} publisherName={byId.get(outcome.publisher_id)?.name ?? `#${outcome.publisher_id}`} />
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="mt-8">
        <h3 className="label">Recent adjudications</h3>
        <div className="panel mt-3 overflow-x-auto">
          <table className="w-full min-w-[40rem] text-left text-sm">
            <thead className="border-b border-[color:var(--line)] text-[color:var(--muted)]">
              <tr><th className="px-4 py-2.5 font-normal">#</th><th className="px-4 py-2.5 font-normal">Contested URL</th><th className="px-4 py-2.5 font-normal">Entity</th><th className="px-4 py-2.5 font-normal">Verdict</th><th className="px-4 py-2.5 font-normal">Bits</th><th className="px-4 py-2.5 font-normal">When</th></tr>
            </thead>
            <tbody>
              {challenges.length === 0 && <tr><td colSpan={6} className="px-4 py-6 text-center text-[color:var(--muted)]">No challenges yet.</td></tr>}
              {challenges.map((c) => (
                <tr key={c.id} className="border-b border-[color:var(--line)] last:border-0">
                  <td className="px-4 py-2.5 font-mono">{c.id}</td>
                  <td className="max-w-[18rem] truncate px-4 py-2.5 font-mono text-xs" title={c.contested_uri}>{c.contested_uri}</td>
                  <td className="px-4 py-2.5">{byId.get(c.victim_id)?.name ?? `#${c.victim_id}`}</td>
                  <td className="px-4 py-2.5 font-mono text-xs" style={{ color: VERDICT_STYLE[c.verdict]?.tone }}>{c.verdict}</td>
                  <td className="px-4 py-2.5 font-mono">{c.distance < 0 ? "—" : c.distance}</td>
                  <td className="px-4 py-2.5 text-[color:var(--muted)]">{timeAgo(c.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
}
