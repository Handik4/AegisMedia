"use client";
import { createContext, useContext, type ReactNode } from "react";
import { api } from "./contract";
import { IS_CONFIGURED } from "./config";
import type { Challenge, Entity, ProtocolOverview } from "./abi";
import { usePolling } from "./usePolling";

interface Data {
  configured: boolean;
  overview: ProtocolOverview | null;
  entities: Entity[];
  challenges: Challenge[];
  error: string | null;
  loading: boolean;
  refresh(): Promise<void>;
}

const Ctx = createContext<Data | null>(null);

interface Snapshot {
  overview: ProtocolOverview;
  entities: Entity[];
  challenges: Challenge[];
}

// One sequential loader instead of three parallel pollers: Studio Next rate-limits the
// RPC to 30 requests per minute, so a burst on page load would trip it.
async function loadSnapshot(): Promise<Snapshot> {
  const overview = await api.overview();
  const entities = await api.entities();
  const challenges = await api.challenges();
  return { overview, entities, challenges };
}

export function DataProvider({ children }: { children: ReactNode }) {
  const s = usePolling(loadSnapshot, 45000, IS_CONFIGURED);
  const value: Data = {
    configured: IS_CONFIGURED,
    overview: s.data?.overview ?? null,
    entities: s.data?.entities ?? [],
    challenges: s.data?.challenges ?? [],
    error: s.error,
    loading: IS_CONFIGURED && s.loading,
    refresh: s.refresh,
  };
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useData(): Data {
  const v = useContext(Ctx);
  if (!v) throw new Error("useData must be used inside DataProvider");
  return v;
}
