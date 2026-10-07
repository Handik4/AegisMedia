// Decoded view shapes for contracts/aegis_media.py. genlayer-js addresses methods by
// name, so no ABI array is needed; these types describe what the views return.

// ---- decoded view shapes -------------------------------------------------
export interface Entity {
  id: number;
  owner: string;
  name: string;
  domain: string;
  handle: string;
  signer: string;
  stake: bigint;
  status: "ACTIVE" | "WITHDRAWING" | "UNDERCOLLATERALIZED";
  alert: "CLEAR" | "FLAGGED_IMPERSONATION";
  flagged: boolean;
  flag_until: number;
  flag_count: number;
  registered_at: number;
  withdraw_available_at: number;
  announcement_count: number;
  challenges_received: number;
  challenges_defended: number;
  times_slashed: number;
  total_slashed: bigint;
  verified: boolean;
}

export interface Announcement {
  id: string;
  entity_id: number;
  content_uri: string;
  sha256_hash: string;
  phash: string;
  metadata_digest: string;
  timestamp: number;
  signature: string;
  signer: string;
  attested_at: number;
  status: "AUTHENTICATED" | "REVOKED";
}

export type Verdict = "CONFIRMED_DEEPFAKE" | "LEGITIMATE_MEDIA" | "INCONCLUSIVE_DISMISSED";

export interface Challenge {
  id: number;
  challenger: string;
  victim_id: number;
  publisher_id: number;
  contested_uri: string;
  bond: bigint;
  fee: bigint;
  verdict: Verdict;
  reason: string;
  sig_state: "VALID" | "INVALID" | "MISSING";
  distance: number; // -1 when no perceptual comparison was possible
  observed_phash: string;
  baseline_id: string;
  http_status: number;
  slashed: bigint;
  burned: bigint;
  bounty: bigint;
  created_at: number;
}

export interface MediaVerification {
  status: "AUTHENTICATED" | "UNVERIFIED" | "REVOKED";
  match: "EXACT" | "PERCEPTUAL" | "NONE";
  distance: number;
  announcement_id: string;
  entity_id: number;
  entity_name: string;
  flagged: boolean;
}

export interface ProtocolOverview {
  entities: number;
  announcements: number;
  challenges: number;
  total_locked: bigint;
  solvent: boolean;
  status: string;
}

export interface Solvency {
  total_in: bigint;
  total_paid_out: bigint;
  total_burned: bigint;
  entity_stakes: bigint;
  challenger_bonds: bigint;
  claimable: bigint;
  protocol_fees: bigint;
  total_locked: bigint;
  solvent: boolean;
}
