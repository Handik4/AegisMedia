import { BadgeCheck, Siren, Hourglass, ShieldAlert } from "lucide-react";
import type { Entity } from "@/lib/abi";

export function StatusPill({ entity }: { entity: Entity }) {
  if (entity.flagged)
    return (
      <span className="inline-flex items-center gap-1.5 rounded-full border border-[color:var(--alarm)] bg-[color:var(--alarm-dim)] px-2.5 py-1 font-mono text-[10px] tracking-wider text-[color:var(--alarm)]">
        <Siren className="h-3 w-3" aria-hidden /> FLAGGED_IMPERSONATION
      </span>
    );
  if (entity.status === "WITHDRAWING")
    return (
      <span className="inline-flex items-center gap-1.5 rounded-full border border-[color:var(--amber)] px-2.5 py-1 font-mono text-[10px] tracking-wider text-[color:var(--amber)]">
        <Hourglass className="h-3 w-3" aria-hidden /> EXITING
      </span>
    );
  if (entity.status === "UNDERCOLLATERALIZED")
    return (
      <span className="inline-flex items-center gap-1.5 rounded-full border border-[color:var(--amber)] px-2.5 py-1 font-mono text-[10px] tracking-wider text-[color:var(--amber)]">
        <ShieldAlert className="h-3 w-3" aria-hidden /> UNDERCOLLATERALIZED
      </span>
    );
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full border border-[color:var(--seal)] bg-[color:var(--seal-dim)] px-2.5 py-1 font-mono text-[10px] tracking-wider text-[color:var(--seal)]">
      <BadgeCheck className="h-3 w-3" aria-hidden /> STAKE ACTIVE
    </span>
  );
}
