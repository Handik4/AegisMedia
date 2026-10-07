// Live GenLayer bindings for AegisMedia. Everything here talks to Studio Next:
// there is no mock layer. genlayer-js is imported lazily so server rendering and the
// build never touch browser-only wallet code.
import "./bigintPolyfill";
import { CHAIN_ID, CONTRACT_ADDRESS, IS_CONFIGURED, RPC_URL } from "./config";
import type {
  Announcement,
  Challenge,
  Entity,
  MediaVerification,
  ProtocolOverview,
  Solvency,
} from "./abi";

interface Eip1193Provider {
  request(args: { method: string; params?: unknown[] }): Promise<unknown>;
}
type AnyClient = Record<string, (...a: any[]) => any>;

const ADDRESS = CONTRACT_ADDRESS as `0x${string}`;

async function buildClient(account?: string): Promise<AnyClient> {
  const sdk = (await import("genlayer-js")) as unknown as Record<string, any>;
  const shipped = sdk.chains?.studioDevnet;
  if (!shipped) throw new Error("genlayer-js ships no chain definition for Studio Next (61997).");
  const chain = { ...shipped, rpcUrls: { default: { http: [RPC_URL] } } };
  if (chain.id !== CHAIN_ID) throw new Error(`Unexpected chain id ${chain.id}.`);
  if (account) {
    const provider = (window as unknown as { ethereum?: Eip1193Provider }).ethereum;
    if (!provider) throw new Error("No injected wallet detected.");
    return sdk.createClient({ chain, account, provider });
  }
  return sdk.createClient({ chain });
}

let reader: Promise<AnyClient> | null = null;
const readerClient = () => (reader ??= buildClient());
const writers = new Map<string, Promise<AnyClient>>();
const writerClient = (account: string) => {
  const key = account.toLowerCase();
  if (!writers.has(key)) writers.set(key, buildClient(account));
  return writers.get(key)!;
};

/** GenVM calldata may decode dicts as Map; flatten to plain JSON-like values. */
function plain(v: unknown): unknown {
  if (v instanceof Map) return Object.fromEntries([...v.entries()].map(([k, x]) => [String(k), plain(x)]));
  if (Array.isArray(v)) return v.map(plain);
  if (v && typeof v === "object" && !(v instanceof Uint8Array)) {
    return Object.fromEntries(Object.entries(v as object).map(([k, x]) => [k, plain(x)]));
  }
  return v;
}

export async function view<T = unknown>(functionName: string, args: unknown[] = []): Promise<T> {
  if (!IS_CONFIGURED) throw new Error("AegisMedia is not deployed yet.");
  const client = await readerClient();
  // Studio Next rate-limits the RPC (30 requests/minute). Back off and retry rather
  // than surfacing a transient limit as a failure.
  for (let attempt = 0; ; attempt++) {
    try {
      const raw = await client.readContract({ address: ADDRESS, functionName, args });
      return plain(raw) as T;
    } catch (e) {
      const limited = /rate limit|429|too many requests/i.test(e instanceof Error ? e.message : String(e));
      if (!limited || attempt >= 3) throw e;
      await new Promise((r) => setTimeout(r, 3000 * (attempt + 1)));
    }
  }
}

const n = (v: unknown) => Number(v ?? 0);
const b = (v: unknown) => BigInt((v as bigint | number | string) ?? 0);

export const toEntity = (r: any): Entity => ({
  ...r,
  id: n(r.id),
  stake: b(r.stake),
  total_slashed: b(r.total_slashed),
  flag_until: n(r.flag_until),
  flag_count: n(r.flag_count),
  registered_at: n(r.registered_at),
  withdraw_available_at: n(r.withdraw_available_at),
  announcement_count: n(r.announcement_count),
  challenges_received: n(r.challenges_received),
  challenges_defended: n(r.challenges_defended),
  times_slashed: n(r.times_slashed),
});
export const toAnnouncement = (r: any): Announcement => ({
  ...r,
  entity_id: n(r.entity_id),
  timestamp: n(r.timestamp),
  attested_at: n(r.attested_at),
});
export const toChallenge = (r: any): Challenge => ({
  ...r,
  id: n(r.id),
  victim_id: n(r.victim_id),
  publisher_id: n(r.publisher_id),
  bond: b(r.bond),
  fee: b(r.fee),
  distance: n(r.distance),
  http_status: n(r.http_status),
  slashed: b(r.slashed),
  burned: b(r.burned),
  bounty: b(r.bounty),
  created_at: n(r.created_at),
});

export const api = {
  overview: async (): Promise<ProtocolOverview> => {
    const r = await view<any>("get_protocol_overview");
    return {
      ...r,
      entities: n(r.entities),
      announcements: n(r.announcements),
      challenges: n(r.challenges),
      total_locked: b(r.total_locked),
    };
  },
  solvency: async (): Promise<Solvency> => {
    const r = await view<any>("get_solvency");
    return Object.fromEntries(
      Object.entries(r).map(([k, v]) => [k, typeof v === "boolean" ? v : b(v)])
    ) as unknown as Solvency;
  },
  entities: async (): Promise<Entity[]> =>
    (await view<unknown[]>("list_entities", [0n, 100n])).map(toEntity),
  entityAnnouncements: async (id: number): Promise<Announcement[]> =>
    (await view<unknown[]>("list_entity_announcements", [BigInt(id), 0n, 50n])).map(toAnnouncement),
  recentAnnouncements: async (): Promise<Announcement[]> =>
    (await view<unknown[]>("list_recent_announcements", [20n])).map(toAnnouncement),
  announcement: async (id: string) => toAnnouncement(await view("get_announcement", [id])),
  verify: async (sha: string, phash: string): Promise<MediaVerification> => {
    const r = await view<any>("verify_media", [sha, phash]);
    return { ...r, distance: n(r.distance), entity_id: n(r.entity_id) };
  },
  challenges: async (): Promise<Challenge[]> => {
    const count = n(await view("get_challenge_count"));
    const offset = Math.max(0, count - 20);
    return (await view<unknown[]>("list_challenges", [BigInt(offset), 20n])).map(toChallenge).reverse();
  },
  challenge: async (id: number) => toChallenge(await view("get_challenge", [BigInt(id)])),
  claimable: async (addr: string): Promise<bigint> => b(await view("get_claimable", [addr])),
  domain: () =>
    view<{ name: string; version: string; chainId: number; verifyingContract: string }>("get_eip712_domain"),
};

export interface WriteRequest {
  method: string;
  args: unknown[];
  value?: bigint;
}

export type TxPhase = "estimating" | "signing" | "submitted";

/** Estimate fees, have the wallet sign, and submit. Resolves with the tx hash. */
export async function submitWrite(
  account: string,
  req: WriteRequest,
  onPhase?: (p: TxPhase, hash?: string) => void
): Promise<string> {
  if (!IS_CONFIGURED) throw new Error("AegisMedia is not deployed yet.");
  const client = await writerClient(account);
  const value = req.value ?? 0n;
  onPhase?.("estimating");
  // Studio Next has no fee manager: a write without an explicit deposit is rejected
  // (FeeValueMustBeNonZero), so the deposit is derived from the live fee policy.
  const estimate = await client.estimateTransactionFeesForWrite({
    address: ADDRESS,
    functionName: req.method,
    args: req.args,
    value,
  });
  const fees: Record<string, unknown> = {
    distribution: estimate.distribution,
    feeValue: estimate.feeValue,
  };
  if (estimate.messageAllocations) fees.messageAllocations = estimate.messageAllocations;
  onPhase?.("signing");
  const hash = (await client.writeContract({
    address: ADDRESS,
    functionName: req.method,
    args: req.args,
    value,
    fees,
  })) as string;
  onPhase?.("submitted", hash);
  return hash;
}

export interface TxSnapshot {
  hash: string;
  status: string; // PENDING | PROPOSING | COMMITTING | REVEALING | ACCEPTED | FINALIZED | UNDETERMINED ...
  decided: boolean;
  rounds: number;
  validators: string[];
  leader: string;
  votesCommitted: number;
  votesRevealed: number;
  executionResult: string;
  consensusResult: string;
}

const DECIDED = new Set(["ACCEPTED", "FINALIZED", "UNDETERMINED", "CANCELED", "LEADER_TIMEOUT", "VALIDATORS_TIMEOUT"]);

export async function snapshotTx(hash: string): Promise<TxSnapshot> {
  const client = await readerClient();
  const tx = (await client.getTransaction({ hash })) as Record<string, any>;
  const status = String(tx.statusName ?? tx.status ?? "PENDING");
  return {
    hash,
    status,
    decided: DECIDED.has(status),
    rounds: n(tx.numOfRounds),
    validators: ((tx.consumedValidators ?? []) as string[]).map(String),
    leader: String(tx.lastLeader ?? ""),
    votesCommitted: n(tx.lastRound?.votesCommitted),
    votesRevealed: n(tx.lastRound?.votesRevealed),
    executionResult: String(tx.txExecutionResultName ?? ""),
    consensusResult: String(tx.resultName ?? ""),
  };
}

export async function accountBalance(addr: string): Promise<bigint> {
  const client = await readerClient();
  try {
    return BigInt(await client.getBalance({ address: addr }));
  } catch {
    return 0n;
  }
}
