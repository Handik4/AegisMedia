// Integration tests against the contract deployed on Studio Next (chain 61997).
// They run the frontend's own read layer (lib/contract.ts) so any BigInt / Map /
// number decoding problem surfaces here rather than in the browser.
import { describe, expect, it } from "vitest";
import { createClient, chains } from "genlayer-js";
import { hashTypedData } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { api, view } from "../lib/contract";
import { CONTRACT_ADDRESS, CHAIN_ID, RPC_URL, IS_CONFIGURED } from "../lib/config";
import { announcementTypedData } from "../lib/eip712";
import { FEE_BPS } from "../lib/config";
import { toAtto } from "../lib/format";

describe.runIf(IS_CONFIGURED)("live contract reads and decoding", () => {
  it("is configured with a checksummed address on chain 61997", () => {
    expect(CONTRACT_ADDRESS).toMatch(/^0x[0-9a-fA-F]{40}$/);
    expect(CHAIN_ID).toBe(61997);
  });

  it("decodes the registered entities (seed entities first) with bigint stakes", async () => {
    const entities = await api.entities();
    expect(entities.length).toBeGreaterThanOrEqual(2);
    const [ef, guard] = entities;
    expect(ef).toMatchObject({ id: 1, name: "Ethereum Foundation", domain: "ethereum.org", handle: "@ethereum" });
    expect(guard).toMatchObject({ id: 2, name: "Vitalik Impersonation Guard", handle: "@VitalikGuard" });
    for (const e of entities) {
      expect(typeof e.stake).toBe("bigint");
      expect(typeof e.total_slashed).toBe("bigint");
      expect(typeof e.id).toBe("number");
      expect(e.stake).toBeGreaterThan(0n);
      expect(e.signer).toMatch(/^0x[0-9a-f]{40}$/);
      expect(["ACTIVE", "WITHDRAWING", "UNDERCOLLATERALIZED"]).toContain(e.status);
      expect(["CLEAR", "FLAGGED_IMPERSONATION"]).toContain(e.alert);
    }
    expect(ef.stake).toBe(5_000_000_000_000_000_000n);
  });

  it("circuit-breaker status agrees across entity view, alert view and the DeFi hook", async () => {
    for (const e of await api.entities()) {
      const hook = await view<boolean>("is_impersonation_active", [BigInt(e.id)]);
      const alert = await view<{ active: boolean; status: string }>("get_alert", [BigInt(e.id)]);
      expect(hook).toBe(e.flagged);
      expect(alert.active).toBe(e.flagged);
      expect(alert.status).toBe(e.flagged ? "FLAGGED_IMPERSONATION" : "CLEAR");
      expect(e.alert).toBe(alert.status);
    }
  });

  it("decodes the overview and solvency report; the invariant holds", async () => {
    const o = await api.overview();
    const entities = await api.entities();
    expect(o.entities).toBe(entities.length);
    expect(typeof o.total_locked).toBe("bigint");
    const s = await api.solvency();
    expect(s.solvent).toBe(true);
    expect(s.total_in).toBe(s.total_paid_out + s.entity_stakes + s.challenger_bonds + s.claimable + s.protocol_fees);
    expect(s.total_locked).toBe(s.entity_stakes + s.challenger_bonds + s.claimable + s.protocol_fees);
  });

  it("decodes settled challenges and their announcements", async () => {
    const challenges = await api.challenges();
    expect(challenges.length).toBeGreaterThanOrEqual(1);
    const c = challenges[0];
    expect(["CONFIRMED_DEEPFAKE", "LEGITIMATE_MEDIA", "INCONCLUSIVE_DISMISSED"]).toContain(c.verdict);
    for (const f of [c.bond, c.fee, c.slashed, c.burned, c.bounty]) expect(typeof f).toBe("bigint");
    expect(c.fee).toBe((c.bond * FEE_BPS) / 10000n);
    expect(typeof c.distance).toBe("number");
    const anns = await api.entityAnnouncements(1);
    expect(anns.length).toBeGreaterThanOrEqual(1);
    expect(anns[0].sha256_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(anns[0].phash).toMatch(/^[0-9a-f]{16}$/);
    expect(anns[0].status).toBe("AUTHENTICATED");
  });

  it("verifier lookup: exact match is AUTHENTICATED, unknown media is UNVERIFIED", async () => {
    const [a] = await api.entityAnnouncements(1);
    const hit = await api.verify(a.sha256_hash, a.phash);
    expect(hit).toMatchObject({ status: "AUTHENTICATED", match: "EXACT", entity_id: 1, distance: 0 });
    const miss = await api.verify("00".repeat(32), "ffffffffffffffff");
    expect(miss.status).toBe("UNVERIFIED");
  });

  it("frontend EIP-712 typed data hashes to exactly the digest the contract expects", async () => {
    const domain = await api.domain();
    expect(domain.chainId).toBe(61997);
    const payload = {
      entityId: 1n,
      contentUri: "https://ethereum.org/frontend-parity.png",
      sha256: "ab".repeat(32),
      phash: "f0e1d2c3b4a59687",
      metadataDigest: "cd".repeat(32),
      timestamp: 1_800_000_000n,
    };
    const td = announcementTypedData(domain.verifyingContract, payload);
    const local = hashTypedData({
      domain: { ...td.domain, chainId: BigInt(td.domain.chainId), verifyingContract: td.domain.verifyingContract as `0x${string}` },
      types: { Announcement: td.types.Announcement },
      primaryType: "Announcement",
      message: {
        entityId: payload.entityId,
        contentUriHash: td.message.contentUriHash,
        sha256Hash: td.message.sha256Hash as `0x${string}`,
        phash: BigInt(`0x${payload.phash}`),
        metadataDigest: td.message.metadataDigest as `0x${string}`,
        timestamp: payload.timestamp,
      },
    });
    const onChain = await view<string>("announcement_digest", [
      payload.entityId, payload.contentUri, payload.sha256, payload.phash, payload.metadataDigest, payload.timestamp,
    ]);
    expect(local.toLowerCase()).toBe(onChain.toLowerCase());
  });

  it("challenge_broadcast builds a valid transaction with bigint bond + fee parameters", async () => {
    const sdkChain = { ...chains.studioDevnet, rpcUrls: { default: { http: [RPC_URL] } } };
    const account = privateKeyToAccount(("0x" + "7".repeat(64)) as `0x${string}`);
    const client = createClient({ chain: sdkChain, account }) as any; // eslint-disable-line
    const bond = toAtto("0.5")!;
    const value = bond + (bond * FEE_BPS) / 10000n;
    expect(value).toBe(515_000_000_000_000_000n);
    const estimate = await client.estimateTransactionFeesForWrite({
      address: CONTRACT_ADDRESS as `0x${string}`,
      functionName: "challenge_broadcast",
      args: [1n, "https://impostor.example/merge.png", 0n],
      value,
    });
    expect(typeof estimate.feeValue).toBe("bigint");
    expect(estimate.feeValue).toBeGreaterThan(0n);
    expect(estimate.distribution).toBeTruthy();
  });
});
