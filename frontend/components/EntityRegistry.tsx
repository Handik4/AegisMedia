"use client";
import { useState } from "react";
import { BadgeCheck, Globe, KeyRound, Loader2, Plus, X } from "lucide-react";
import { useData } from "@/lib/data";
import { useWallet } from "@/lib/wallet";
import { useTx } from "@/lib/useTx";
import { fmtGen, isHex, shortAddr, timeAgo, toAtto } from "@/lib/format";
import { MIN_STAKE_GEN } from "@/lib/config";
import { api } from "@/lib/contract";
import type { Announcement, Entity } from "@/lib/abi";
import { StatusPill } from "./Pills";
import { usePolling } from "@/lib/usePolling";

function RegisterModal({ onClose }: { onClose: () => void }) {
  const w = useWallet();
  const tx = useTx();
  const { refresh } = useData();
  const [f, setF] = useState({ name: "", domain: "", handle: "", signer: w.account ?? "", stake: String(MIN_STAKE_GEN) });
  const stake = toAtto(f.stake);
  const problems: string[] = [];
  if (f.name.trim().length < 3) problems.push("Name needs at least 3 characters.");
  if (!/^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(f.domain.trim())) problems.push("Enter a bare domain such as ethereum.org.");
  if (f.handle.trim().length < 2) problems.push("Enter the canonical X / YouTube handle.");
  if (!isHex(f.signer.replace(/^0x/i, ""), 40)) problems.push("Signer must be a 20-byte address.");
  if (stake === null || stake < toAtto(String(MIN_STAKE_GEN))!) problems.push(`Minimum stake is ${MIN_STAKE_GEN} GEN.`);

  const submit = async () => {
    if (problems.length || stake === null) return;
    const hash = await tx.run(
      { method: "register_entity", args: [f.name.trim(), f.domain.trim().toLowerCase(), f.handle.trim(), f.signer.trim()], value: stake },
      `${f.name.trim()} registered`
    );
    if (hash) {
      void refresh();
      onClose();
    }
  };
  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement>) => setF({ ...f, [k]: e.target.value });

  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-black/70 p-4" role="dialog" aria-modal="true" aria-labelledby="reg-title">
      <div className="panel w-full max-w-lg p-6">
        <div className="flex items-start justify-between">
          <h3 id="reg-title" className="font-display text-2xl">Register an official entity</h3>
          <button aria-label="Close" onClick={onClose} className="text-[color:var(--muted)] hover:text-[color:var(--paper)]"><X className="h-5 w-5" /></button>
        </div>
        <p className="mt-1 text-sm text-[color:var(--muted)]">Stake GEN to gain broadcast authority. The stake is slashable if your channel publishes a confirmed forgery.</p>
        <div className="mt-5 space-y-3">
          <label className="block"><span className="label">Name</span><input className="field mt-1" value={f.name} onChange={set("name")} placeholder="Ethereum Foundation" /></label>
          <div className="grid gap-3 sm:grid-cols-2">
            <label className="block"><span className="label">Domain</span><input className="field mt-1" value={f.domain} onChange={set("domain")} placeholder="ethereum.org" /></label>
            <label className="block"><span className="label">X / YouTube handle</span><input className="field mt-1" value={f.handle} onChange={set("handle")} placeholder="@ethereum" /></label>
          </div>
          <label className="block"><span className="label">Signing key address (EIP-712)</span><input className="field mt-1 font-mono" value={f.signer} onChange={set("signer")} placeholder="0x…" /></label>
          <label className="block"><span className="label">Security stake (GEN)</span><input className="field mt-1 font-mono" inputMode="decimal" value={f.stake} onChange={set("stake")} /></label>
        </div>
        {problems.length > 0 && <ul className="mt-4 space-y-1 text-xs text-[color:var(--amber)]">{problems.map((p) => <li key={p}>• {p}</li>)}</ul>}
        <div className="mt-6 flex justify-end gap-2">
          <button className="btn-ghost" onClick={onClose}>Cancel</button>
          <button className="btn-primary" disabled={!w.account || problems.length > 0 || tx.busy} onClick={submit}>
            {tx.busy && <Loader2 className="h-4 w-4 animate-spin" />}
            {w.account ? (tx.phase === "signing" ? "Confirm in wallet…" : "Stake & register") : "Connect a wallet first"}
          </button>
        </div>
      </div>
    </div>
  );
}

function EntityDrawer({ entity, onClose }: { entity: Entity; onClose: () => void }) {
  const { data, loading } = usePolling<Announcement[]>(() => api.entityAnnouncements(entity.id), 20000);
  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/60" role="dialog" aria-modal="true" aria-label={`${entity.name} details`}>
      <div className="h-full w-full max-w-md overflow-y-auto border-l border-[color:var(--line)] bg-white p-6">
        <div className="flex items-start justify-between gap-3">
          <div>
            <h3 className="font-display text-2xl">{entity.name}</h3>
            <div className="mt-2"><StatusPill entity={entity} /></div>
          </div>
          <button aria-label="Close" onClick={onClose} className="text-[color:var(--muted)] hover:text-[color:var(--paper)]"><X className="h-5 w-5" /></button>
        </div>
        <dl className="mt-5 grid grid-cols-2 gap-x-4 gap-y-3 text-sm">
          <div><dt className="label">Stake</dt><dd className="font-mono">{fmtGen(entity.stake)} GEN</dd></div>
          <div><dt className="label">Registered</dt><dd>{timeAgo(entity.registered_at)}</dd></div>
          <div><dt className="label">Challenges received</dt><dd className="font-mono">{entity.challenges_received}</dd></div>
          <div><dt className="label">Defended</dt><dd className="font-mono">{entity.challenges_defended}</dd></div>
          <div><dt className="label">Times slashed</dt><dd className="font-mono">{entity.times_slashed}</dd></div>
          <div><dt className="label">Total slashed</dt><dd className="font-mono">{fmtGen(entity.total_slashed)} GEN</dd></div>
          <div className="col-span-2"><dt className="label">Owner</dt><dd className="break-all font-mono text-xs">{entity.owner}</dd></div>
          <div className="col-span-2"><dt className="label">Signing key</dt><dd className="break-all font-mono text-xs">{entity.signer}</dd></div>
        </dl>
        <h4 className="label mt-7">Sealed broadcasts</h4>
        <ul className="mt-3 space-y-2">
          {loading && <li className="text-sm text-[color:var(--muted)]">Loading…</li>}
          {data?.length === 0 && <li className="text-sm text-[color:var(--muted)]">No broadcasts anchored yet.</li>}
          {data?.map((a) => (
            <li key={a.id} className="rounded-lg border border-[color:var(--line)] p-3 text-xs">
              <a className="break-all underline underline-offset-2 hover:text-[color:var(--seal)]" href={a.content_uri} target="_blank" rel="noreferrer">{a.content_uri}</a>
              <p className="mt-1.5 font-mono text-[color:var(--muted)]">sha256 {a.sha256_hash.slice(0, 16)}… · pHash {a.phash}</p>
              <p className="mt-1 font-mono text-[color:var(--muted)]">{a.status} · {timeAgo(a.attested_at)}</p>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

export default function EntityRegistry() {
  const { entities, loading, configured, error } = useData();
  const [registering, setRegistering] = useState(false);
  const [open, setOpen] = useState<Entity | null>(null);

  return (
    <section id="registry" className="mx-auto mt-20 max-w-7xl scroll-mt-20 px-4 sm:px-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="label">01 · Registry</p>
          <h2 className="mt-2 font-display text-3xl sm:text-4xl">Official entities</h2>
          <p className="mt-2 max-w-xl text-sm text-[color:var(--muted)]">Every card is backed by a locked stake. Flagged entities are under an active impersonation attack.</p>
        </div>
        <button className="btn-primary" onClick={() => setRegistering(true)} disabled={!configured}><Plus className="h-4 w-4" aria-hidden /> Register entity</button>
      </div>

      <div className="mt-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {entities.map((e) => (
          <button key={e.id} onClick={() => setOpen(e)} className={`panel group p-5 text-left transition hover:border-[color:var(--muted)] ${e.flagged ? "!border-[color:var(--alarm)]" : ""}`}>
            <div className="flex items-start justify-between gap-3">
              <h3 className="font-display text-xl leading-tight">
                {e.name}{e.verified && <BadgeCheck className="ml-1.5 inline h-4 w-4 text-[color:var(--seal)]" aria-label="Curator verified" />}
              </h3>
              <span className="label shrink-0">#{e.id}</span>
            </div>
            <div className="mt-3"><StatusPill entity={e} /></div>
            <dl className="mt-4 space-y-1.5 text-sm text-[color:var(--muted)]">
              <div className="flex items-center gap-2"><Globe className="h-3.5 w-3.5" aria-hidden /> {e.domain} · {e.handle}</div>
              <div className="flex items-center gap-2"><KeyRound className="h-3.5 w-3.5" aria-hidden /> <span className="font-mono text-xs">{shortAddr(e.signer)}</span></div>
            </dl>
            <div className="mt-4 flex items-end justify-between border-t border-[color:var(--line)] pt-3">
              <div><p className="label">Stake</p><p className="font-mono text-lg">{fmtGen(e.stake)} <span className="text-xs text-[color:var(--muted)]">GEN</span></p></div>
              <div className="text-right"><p className="label">Sealed</p><p className="font-mono text-lg">{e.announcement_count}</p></div>
            </div>
          </button>
        ))}
        {configured && !loading && entities.length === 0 && !error && (
          <p className="panel col-span-full p-8 text-center text-sm text-[color:var(--muted)]">No entities are registered on this contract yet.</p>
        )}
        {loading && Array.from({ length: 3 }).map((_, i) => <div key={i} className="panel h-44 animate-pulse" />)}
        {error && <p role="alert" className="panel col-span-full p-5 text-sm text-[color:var(--alarm)]">Could not read the registry: {error}</p>}
      </div>

      {registering && <RegisterModal onClose={() => setRegistering(false)} />}
      {open && <EntityDrawer entity={open} onClose={() => setOpen(null)} />}
    </section>
  );
}
