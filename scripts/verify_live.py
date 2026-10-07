#!/usr/bin/env python3
"""End-to-end verification against the deployed contract on Studio Next.

Checks, in order:
  1. the seed entities are registered with their stakes,
  2. an authentic media announcement is anchored with a valid EIP-712 signature,
  3. a deepfake challenge is adjudicated by validator consensus, slashes the
     publisher, pays the challenger a bounty and trips the circuit breaker,
  4. the solvency invariant holds.

    .venv/bin/python scripts/verify_live.py

The contested URL must be reachable by the validators; the default is an httpbin echo
page that mentions the entity and carries no signature. Override with AEGIS_CONTESTED_URL.
"""

import hashlib
import os
import sys
import time
import urllib.parse

from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_utils import keccak

from aegis_chain import ATTO, Chain, get_or_create_key, load_deployment

PASS, FAIL = "PASS", "FAIL"
results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, ok, detail))
    print(f"[{PASS if ok else FAIL}] {name}{(' — ' + detail) if detail else ''}")


def sign_announcement(domain: dict, key: str, entity_id: int, uri: str, sha: str, phash: str, md: str, ts: int) -> str:
    full = {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"}, {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"}, {"name": "verifyingContract", "type": "address"}],
            "Announcement": [
                {"name": "entityId", "type": "uint256"}, {"name": "contentUriHash", "type": "bytes32"},
                {"name": "sha256Hash", "type": "bytes32"}, {"name": "phash", "type": "uint64"},
                {"name": "metadataDigest", "type": "bytes32"}, {"name": "timestamp", "type": "uint256"}]},
        "primaryType": "Announcement",
        "domain": {k: domain[k] for k in ("name", "version", "chainId", "verifyingContract")},
        "message": {"entityId": entity_id, "contentUriHash": keccak(text=uri), "sha256Hash": bytes.fromhex(sha),
                    "phash": int(phash, 16), "metadataDigest": bytes.fromhex(md), "timestamp": ts},
    }
    signed = Account.sign_message(encode_typed_data(full_message=full), key)
    return "0x" + signed.signature.hex().removeprefix("0x")


def main() -> int:
    dep = load_deployment()
    if not dep.get("address"):
        print("No deployment found. Run scripts/deploy.py first.")
        return 2
    address = dep["address"]
    owner = Chain(get_or_create_key("AEGIS_DEPLOYER_KEY"), address)
    rogue = Chain(get_or_create_key("AEGIS_ROGUE_KEY"), address)
    hunter = Chain(get_or_create_key("AEGIS_HUNTER_KEY"), address)
    for c in (owner, rogue, hunter):
        c.ensure_funds(15 * ATTO)

    # 1. seed entities ------------------------------------------------------
    ef_id = int(owner.read("find_entity_by_domain", ["ethereum.org"]))
    guard_id = int(owner.read("find_entity_by_domain", ["vitalik-guard.org"]))
    check("seed entity Ethereum Foundation registered", ef_id > 0, f"id {ef_id}")
    check("seed entity Vitalik Impersonation Guard registered", guard_id > 0, f"id {guard_id}")
    if ef_id == 0:
        return 1
    ef = owner.read("get_entity", [ef_id])
    check("entity stake meets the 5 GEN minimum", int(ef["stake"]) >= 5 * ATTO, f"{int(ef['stake']) / ATTO} GEN")

    # 2. authentic anchor ---------------------------------------------------
    domain = owner.read("get_eip712_domain")
    media = f"aegis-demo-authentic-media-{int(time.time())}".encode()
    sha = hashlib.sha256(media).hexdigest()
    phash = f"{int.from_bytes(hashlib.sha256(media).digest()[:8], 'big'):016x}"
    md = hashlib.sha256(b"demo-metadata").hexdigest()
    uri = f"https://ethereum.org/aegis-demo/{sha[:12]}.png"
    ts = int(time.time())
    seed_key = get_or_create_key("AEGIS_SEED_KEY_EF")
    sig = sign_announcement(domain, seed_key, ef_id, uri, sha, phash, md, ts)
    owner.write("attest_announcement", [ef_id, uri, sha, phash, md, ts, sig])
    seal = owner.read("verify_media", [sha, phash])
    check("authentic media anchored (AUTHENTICATED, exact match)",
          seal["status"] == "AUTHENTICATED" and seal["match"] == "EXACT" and int(seal["entity_id"]) == ef_id,
          str(seal["status"]))
    near = owner.read("verify_media", [hashlib.sha256(b"re-encoded").hexdigest(), f"{int(phash, 16) ^ 0b111:016x}"])
    check("perceptual near-match within 10 bits is AUTHENTICATED", near["status"] == "AUTHENTICATED" and int(near["distance"]) == 3)
    unknown = owner.read("verify_media", [hashlib.sha256(b"never anchored").hexdigest(), f"{int(phash, 16) ^ (2**20 - 1):016x}"])
    check("unrelated media is UNVERIFIED", unknown["status"] == "UNVERIFIED")

    # 3. deepfake challenge -------------------------------------------------
    rogue.client  # noqa: B018
    rogue.write("register_entity",
                [f"Rogue Newswire {ts}", f"rogue-{ts}.example", f"@rogue{ts}", rogue.address.lower()],
                value=5 * ATTO)
    rogue_id = int(owner.read("find_entity_by_domain", [f"rogue-{ts}.example"]))
    stake_before = int(owner.read("get_entity", [rogue_id])["stake"])

    contested = os.environ.get("AEGIS_CONTESTED_URL") or (
        "https://httpbin.org/anything?" + urllib.parse.urlencode(
            {"msg": f"Ethereum Foundation (ethereum.org) announces a surprise airdrop {ts}"}))
    bond = ATTO // 2
    print(f"challenging {contested}")
    hunter.write("challenge_broadcast", [ef_id, contested, rogue_id], value=bond + bond * 300 // 10000)
    count = int(owner.read("get_challenge_count"))
    ch = owner.read("get_challenge", [count])
    check("validators confirm the deepfake", ch["verdict"] == "CONFIRMED_DEEPFAKE", f"{ch['verdict']} ({ch['reason']})")
    stake_after = int(owner.read("get_entity", [rogue_id])["stake"])
    check("publisher stake slashed by 50%", stake_before - stake_after == stake_before // 2, f"{stake_before / ATTO} -> {stake_after / ATTO} GEN")
    check("50% of the slash burned, 50% paid as bounty",
          int(ch["burned"]) + int(ch["bounty"]) == int(ch["slashed"]) and int(ch["bounty"]) > 0)
    check("circuit breaker engaged for the impersonated entity", bool(owner.read("is_impersonation_active", [ef_id])))
    claimable = int(owner.read("get_claimable", [hunter.address]))
    check("challenger can claim bond + bounty", claimable == int(ch["bond"]) + int(ch["bounty"]), f"{claimable / ATTO} GEN")
    hunter.write("claim_payout")
    check("claim pays out", int(owner.read("get_claimable", [hunter.address])) == 0)

    # 4. solvency -----------------------------------------------------------
    s = owner.read("get_solvency")
    locked = int(s["entity_stakes"]) + int(s["challenger_bonds"]) + int(s["claimable"]) + int(s["protocol_fees"])
    check("solvency: total_in == total_paid_out + liabilities",
          bool(s["solvent"]) and int(s["total_in"]) == int(s["total_paid_out"]) + locked)

    failed = [r for r in results if not r[1]]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
