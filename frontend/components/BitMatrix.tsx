// 64-cell comparison of two perceptual hashes: matching bits dim, differing bits lit.
export default function BitMatrix({ a, b, label }: { a: string; b: string; label?: string }) {
  const x = BigInt("0x" + a) ^ BigInt("0x" + b);
  const cells = Array.from({ length: 64 }, (_, i) => ((x >> BigInt(63 - i)) & 1n) === 1n);
  const diff = cells.filter(Boolean).length;
  return (
    <figure aria-label={label ?? `Perceptual hash comparison: ${diff} of 64 bits differ`}>
      <div className="grid grid-cols-16 gap-[3px]" style={{ gridTemplateColumns: "repeat(16, minmax(0, 1fr))" }}>
        {cells.map((d, i) => (
          <span
            key={i}
            className={`aspect-square rounded-[3px] ${d ? "bg-rose-500" : "bg-emerald-200"}`}
          />
        ))}
      </div>
      <figcaption className="mt-2 font-mono text-[11px] text-[color:var(--muted)]">
        {diff}/64 bits differ · <span className="text-[color:var(--seal)]">■</span> match <span className="text-[color:var(--alarm)]">■</span> differ
      </figcaption>
    </figure>
  );
}
