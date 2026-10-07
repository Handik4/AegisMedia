"use client";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { BadgeCheck, FileUp, Link2, Loader2, ScanSearch, ShieldQuestion, Siren, Stamp } from "lucide-react";
import { api } from "@/lib/contract";
import { fingerprintBlob, fingerprintUrl, sha256OfText, type Fingerprint } from "@/lib/media";
import type { MediaVerification } from "@/lib/abi";
import { useData } from "@/lib/data";
import { useWallet } from "@/lib/wallet";
import { useTx } from "@/lib/useTx";
import { signAnnouncement } from "@/lib/eip712";
import { CONTRACT_ADDRESS, HAMMING_THRESHOLD, IS_CONFIGURED } from "@/lib/config";
import { shortAddr } from "@/lib/format";
import BitMatrix from "./BitMatrix";

function Seal({ result }: { result: MediaVerification }) {
  if (result.status === "AUTHENTICATED")
    return (
      <div className="seal-in flex items-center gap-4 rounded-xl border border-[color:var(--seal)] bg-[color:var(--seal-dim)] p-4" role="status">
        <span className="grid h-14 w-14 shrink-0 place-items-center rounded-full border-2 border-[color:var(--seal)]">
          <BadgeCheck className="h-7 w-7 text-[color:var(--seal)]" aria-hidden />
        </span>
        <div>
          <p className="font-mono text-sm font-semibold tracking-widest text-[color:var(--seal)]">AUTHENTICATED SEAL</p>
          <p className="mt-0.5 text-sm">
            Anchored by <strong>{result.entity_name}</strong> · {result.match === "EXACT" ? "exact byte match" : `perceptual match (${result.distance}/64 bits apart, threshold ${HAMMING_THRESHOLD})`}
          </p>
        </div>
      </div>
    );
  return (
    <div className="flex items-center gap-4 rounded-xl border border-[color:var(--amber)] bg-[color:var(--ink-3)] p-4" role="status">
      <span className="grid h-14 w-14 shrink-0 place-items-center rounded-full border-2 border-dashed border-[color:var(--amber)]">
        <ShieldQuestion className="h-7 w-7 text-[color:var(--amber)]" aria-hidden />
      </span>
      <div>
        <p className="font-mono text-sm font-semibold tracking-widest text-[color:var(--amber)]">{result.status === "REVOKED" ? "REVOKED" : "UNVERIFIED"}</p>
        <p className="mt-0.5 text-sm text-[color:var(--muted)]">
          {result.status === "REVOKED" ? "The entity revoked the matching announcement." : "No sealed announcement matches this file. That is not proof of forgery. It is proof that nobody staked their name on it."}
        </p>
      </div>
    </div>
  );
}

function AnchorForm({ fp }: { fp: Fingerprint }) {
  const { entities, refresh } = useData();
  const w = useWallet();
  const tx = useTx();
  const mine = useMemo(() => entities.filter((e) => w.account && e.owner.toLowerCase() === w.account.toLowerCase()), [entities, w.account]);
  const [entityId, setEntityId] = useState<number | "">("");
  const [uri, setUri] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const selected = mine.find((e) => e.id === (entityId || mine[0]?.id));

  if (!w.account || mine.length === 0 || !fp.phash) return null;

  const anchor = async () => {
    setErr(null);
    if (!selected) return;
    if (!/^https?:\/\//i.test(uri)) return setErr("Enter the public https:// URL where this broadcast is published.");
    if (w.account!.toLowerCase() !== selected.signer.toLowerCase())
      return setErr(`The connected wallet (${shortAddr(w.account!)}) is not this entity's registered signing key (${shortAddr(selected.signer)}). Connect the signing key to anchor.`);
    try {
      const domain = await api.domain();
      const metadata = await sha256OfText(JSON.stringify({ name: fp.name, mime: fp.mime, bytes: fp.bytes }));
      const timestamp = BigInt(Math.floor(Date.now() / 1000));
      const signature = await signAnnouncement(w.account!, domain.verifyingContract || CONTRACT_ADDRESS, {
        entityId: BigInt(selected.id), contentUri: uri.trim(), sha256: fp.sha256, phash: fp.phash!, metadataDigest: metadata, timestamp,
      });
      const hash = await tx.run(
        { method: "attest_announcement", args: [BigInt(selected.id), uri.trim(), fp.sha256, fp.phash, metadata, timestamp, signature] },
        "Broadcast sealed on-chain"
      );
      if (hash) void refresh();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <div className="mt-5 rounded-xl border border-[color:var(--line)] bg-[color:var(--ink)] p-4">
      <p className="label inline-flex items-center gap-2"><Stamp className="h-3.5 w-3.5" aria-hidden /> Anchor as an official broadcast</p>
      <div className="mt-3 grid gap-3 sm:grid-cols-[1fr_2fr]">
        <select className="field" value={selected?.id ?? ""} onChange={(e) => setEntityId(Number(e.target.value))} aria-label="Entity">
          {mine.map((e) => <option key={e.id} value={e.id}>{e.name}</option>)}
        </select>
        <input className="field" value={uri} onChange={(e) => setUri(e.target.value)} placeholder="https://your-domain.org/announcement.png" aria-label="Published URL" />
      </div>
      <p className="mt-2 text-xs text-[color:var(--muted)]">Your wallet signs an EIP-712 message over the URL, SHA-256, pHash, metadata digest and timestamp.</p>
      {err && <p role="alert" className="mt-2 text-xs text-[color:var(--alarm)]">{err}</p>}
      <button className="btn-primary mt-3" disabled={tx.busy} onClick={anchor}>
        {tx.busy && <Loader2 className="h-4 w-4 animate-spin" />}
        {tx.phase === "signing" ? "Confirm in wallet…" : "Sign & anchor"}
      </button>
    </div>
  );
}

export default function VerifierPanel() {
  const [fp, setFp] = useState<Fingerprint | null>(null);
  const [result, setResult] = useState<MediaVerification | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [url, setUrl] = useState("");
  const [drag, setDrag] = useState(false);
  const input = useRef<HTMLInputElement>(null);

  const check = useCallback(async (job: () => Promise<Fingerprint>) => {
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      const f = await job();
      setFp(f);
      // An exact digest lookup always works; the pHash is only sent when one exists.
      setResult(await api.verify(f.sha256, f.phash ?? ""));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }, []);

  const onFile = (file?: File | null) => file && check(() => fingerprintBlob(file, file.name));

  return (
    <section id="verify" className="mx-auto mt-24 max-w-7xl scroll-mt-20 px-4 sm:px-6">
      <p className="label">02 · Verifier</p>
      <h2 className="mt-2 font-display text-3xl sm:text-4xl">Is this file sealed?</h2>
      <p className="mt-2 max-w-2xl text-sm text-[color:var(--muted)]">
        Hashing happens in your browser. Nothing is uploaded. Only the SHA-256 and the 64-bit perceptual hash go to the chain, where they are matched against sealed announcements.
      </p>

      <div className="mt-6 grid gap-5 lg:grid-cols-2">
        <div className="panel p-5">
          <div
            onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
            onDragLeave={() => setDrag(false)}
            onDrop={(e) => { e.preventDefault(); setDrag(false); onFile(e.dataTransfer.files[0]); }}
            className={`grid place-items-center rounded-xl border-2 border-dashed px-4 py-10 text-center transition ${drag ? "border-[color:var(--seal)] bg-[color:var(--seal-dim)]" : "border-[color:var(--line)]"}`}
          >
            <FileUp className="h-8 w-8 text-[color:var(--muted)]" aria-hidden />
            <p className="mt-3 text-sm">Drop an image or video here</p>
            <button className="btn-ghost mt-3" onClick={() => input.current?.click()} disabled={busy || !IS_CONFIGURED}>Choose a file</button>
            <input ref={input} type="file" accept="image/*,video/*,audio/*" className="sr-only" aria-label="Upload media" onChange={(e) => onFile(e.target.files?.[0])} />
          </div>
          <form className="mt-4 flex gap-2" onSubmit={(e) => { e.preventDefault(); if (url.trim()) void check(() => fingerprintUrl(url.trim())); }}>
            <div className="relative flex-1">
              <Link2 className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[color:var(--muted)]" aria-hidden />
              <input className="field !pl-9" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://…/announcement.png" aria-label="Media URL" />
            </div>
            <button className="btn-primary" disabled={busy || !url.trim() || !IS_CONFIGURED}><ScanSearch className="h-4 w-4" aria-hidden /> Check</button>
          </form>
          {!IS_CONFIGURED && <p className="mt-3 text-xs text-[color:var(--amber)]">Deploy the contract to enable verification.</p>}
        </div>

        <div className="panel min-h-[18rem] p-5" aria-live="polite">
          {busy && <p className="flex items-center gap-2 text-sm text-[color:var(--muted)]"><Loader2 className="h-4 w-4 animate-spin" /> Fingerprinting and querying the registry…</p>}
          {error && <p role="alert" className="text-sm text-[color:var(--alarm)]">{error}</p>}
          {!busy && !error && !fp && <p className="text-sm text-[color:var(--muted)]">Results appear here. A match returns the sealing entity; no match returns UNVERIFIED.</p>}
          {!busy && fp && (
            <div>
              {result && <Seal result={result} />}
              {result?.flagged && (
                <p className="mt-3 flex items-center gap-2 rounded-lg border border-[color:var(--alarm)] bg-[color:var(--alarm-dim)] px-3 py-2 text-xs"><Siren className="h-4 w-4 text-[color:var(--alarm)]" aria-hidden /> This entity is under an active impersonation alert. Prefer the sealed original over any re-post.</p>
              )}
              <div className="mt-4 flex gap-4">
                {fp.previewUrl && fp.mime.startsWith("image/") && (
                  // eslint-disable-next-line @next/next/no-img-element
                  <img src={fp.previewUrl} alt="Preview of the checked file" className="h-24 w-24 shrink-0 rounded-lg border border-[color:var(--line)] object-cover" />
                )}
                <dl className="min-w-0 flex-1 space-y-2 text-xs">
                  <div><dt className="label">File</dt><dd className="truncate">{fp.name} · {fp.mime} · {(fp.bytes / 1024).toFixed(1)} KB</dd></div>
                  <div><dt className="label">SHA-256</dt><dd className="break-all font-mono">{fp.sha256}</dd></div>
                  <div><dt className="label">pHash (64-bit)</dt><dd className="font-mono">{fp.phash ?? "not computable for this media type"}</dd></div>
                </dl>
              </div>
              {fp.phash && result?.match !== "NONE" && result?.announcement_id && <MatchBits announcementId={result.announcement_id} phash={fp.phash} />}
              <AnchorForm fp={fp} />
            </div>
          )}
        </div>
      </div>
    </section>
  );
}

function MatchBits({ announcementId, phash }: { announcementId: string; phash: string }) {
  const [base, setBase] = useState<string | null>(null);
  useEffect(() => {
    let live = true;
    void api.announcement(announcementId).then((a) => live && setBase(a.phash)).catch(() => live && setBase(null));
    return () => { live = false; };
  }, [announcementId]);
  if (!base) return null;
  return <div className="mt-4"><p className="label mb-2">Perceptual distance to the sealed original</p><BitMatrix a={base} b={phash} /></div>;
}
