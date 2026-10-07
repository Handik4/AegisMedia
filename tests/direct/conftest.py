"""Shared helpers for AegisMedia direct-mode tests (pure ASCII, English only)."""

import hashlib
import json
import time
from datetime import datetime, timezone

import pytest
from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_utils import keccak

CONTRACT = "contracts/aegis_media.py"
ATTO = 10**18
MIN_STAKE = 5 * ATTO
CHAIN_ID = 61997

# Deterministic signing keys (test-only, never funded anywhere).
KEY_FOUNDATION = "0x" + "11" * 32
KEY_GUARD = "0x" + "22" * 32
KEY_ATTACKER = "0x" + "33" * 32

# Base perceptual hash and helpers to craft hashes at an exact Hamming distance.
PHASH_BASE = "f0e1d2c3b4a59687"


def phash_at_distance(base: str, bits: int) -> str:
    """Flip the lowest `bits` bits of a 64-bit hash (exact Hamming distance)."""
    return f"{int(base, 16) ^ ((1 << bits) - 1):016x}"


def sha_of(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def acct(key: str):
    return Account.from_key(key)


def signer_of(key: str) -> str:
    return acct(key).address.lower()


def now_ts() -> int:
    return int(time.time())


def sign_announcement(domain: dict, key: str, entity_id: int, uri: str, sha: str,
                      phash: str, metadata: str, timestamp: int) -> str:
    full = {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "Announcement": [
                {"name": "entityId", "type": "uint256"},
                {"name": "contentUriHash", "type": "bytes32"},
                {"name": "sha256Hash", "type": "bytes32"},
                {"name": "phash", "type": "uint64"},
                {"name": "metadataDigest", "type": "bytes32"},
                {"name": "timestamp", "type": "uint256"},
            ],
        },
        "primaryType": "Announcement",
        "domain": {
            "name": domain["name"],
            "version": domain["version"],
            "chainId": domain["chainId"],
            "verifyingContract": domain["verifyingContract"],
        },
        "message": {
            "entityId": entity_id,
            "contentUriHash": keccak(text=uri),
            "sha256Hash": bytes.fromhex(sha),
            "phash": int(phash, 16),
            "metadataDigest": bytes.fromhex(metadata),
            "timestamp": timestamp,
        },
    }
    signed = Account.sign_message(encode_typed_data(full_message=full), key)
    return "0x" + signed.signature.hex().removeprefix("0x")


@pytest.fixture
def world(direct_vm, direct_deploy, direct_alice, direct_bob, direct_charlie, direct_owner):
    """Deployed contract plus named actors."""
    contract = direct_deploy(CONTRACT)
    for who in (direct_alice, direct_bob, direct_charlie):
        direct_vm.deal(who, 10_000 * ATTO)
    w = type("World", (), {})()
    w.vm, w.c = direct_vm, contract
    w.alice, w.bob, w.charlie = direct_alice, direct_bob, direct_charlie
    w.owner = direct_owner
    w.domain = contract.get_eip712_domain()
    return w


def register(w, who, name, domain, handle, key, stake=MIN_STAKE):
    w.vm.sender = who
    w.vm.value = stake
    eid = w.c.register_entity(name, domain, handle, signer_of(key))
    w.vm.value = 0
    return eid


def attest(w, who, entity_id, key, uri, sha, phash, metadata=None, ts=None):
    metadata = metadata or sha_of("meta:" + sha)
    ts = ts or now_ts()
    sig = sign_announcement(w.domain, key, entity_id, uri, sha, phash, metadata, ts)
    w.vm.sender = who
    return w.c.attest_announcement(entity_id, uri, sha, phash, metadata, ts, sig)


def challenge(w, who, victim_id, uri, publisher_id=0, bond=ATTO // 2):
    fee = bond * 300 // 10000
    w.vm.sender = who
    w.vm.value = bond + fee
    try:
        return w.c.challenge_broadcast(victim_id, uri, publisher_id)
    finally:
        w.vm.value = 0


def mock_page(w, pattern, status=200, body=b"", headers=None):
    # Real GenVM responses carry headers as dict[str, bytes].
    hdrs = {k: v.encode() if isinstance(v, str) else v for k, v in (headers or {}).items()}
    w.vm.mock_web(pattern, {"response": {"status": status, "headers": hdrs, "body": body},
                            "method": "GET"})


def descriptor_headers(w, key, entity_id, uri, sha, phash, metadata, ts):
    sig = sign_announcement(w.domain, key, entity_id, uri, sha, phash, metadata, ts)
    return {
        "x-aegis-entity": str(entity_id),
        "x-aegis-content-uri": uri,
        "x-aegis-sha256": sha,
        "x-aegis-phash": phash,
        "x-aegis-metadata-digest": metadata,
        "x-aegis-timestamp": str(ts),
        "x-aegis-signature": sig,
    }


def warp(w, seconds_from_now: int):
    later = datetime.fromtimestamp(time.time() + seconds_from_now, tz=timezone.utc)
    w.vm.warp(later.strftime("%Y-%m-%dT%H:%M:%SZ"))


# --------------------------------------------------------------------------
# Challenge scenario fixture: a victim entity with an attested baseline, and a
# separate staked publisher entity.
# --------------------------------------------------------------------------
AUTH_BYTES = b"authentic-merge-announcement-image-bytes"
AUTH_SHA = hashlib.sha256(AUTH_BYTES).hexdigest()
AUTH_URI = "https://ethereum.org/blog/merge-announcement.png"
CONTESTED = "https://impostor.example/merge-announcement.png"
GATEWAY = "https://gateway.aegis-oracle.example/phash"


@pytest.fixture
def scenario(world):
    w = world
    w.victim = register(w, w.alice, "Ethereum Foundation", "ethereum.org", "@ethereum", KEY_FOUNDATION)
    w.publisher = register(w, w.bob, "Impostor Media", "impostor.example", "@impostor", KEY_ATTACKER,
                           stake=20 * ATTO)
    w.meta = sha_of("meta-merge")
    w.ts = now_ts()
    w.ann = attest(w, w.alice, w.victim, KEY_FOUNDATION, AUTH_URI, AUTH_SHA, PHASH_BASE, w.meta, w.ts)
    w.auth_headers = descriptor_headers(w, KEY_FOUNDATION, w.victim, AUTH_URI, AUTH_SHA, PHASH_BASE,
                                        w.meta, w.ts)
    return w


def solvent(w) -> dict:
    s = w.c.get_solvency()
    assert s["solvent"], s
    assert s["total_in"] == s["total_paid_out"] + s["entity_stakes"] + s["challenger_bonds"] \
        + s["claimable"] + s["protocol_fees"]
    return s


def forged_headers(w, victim_id=None):
    """An x-aegis descriptor claiming the victim entity, signed by the attacker's key."""
    return descriptor_headers(w, KEY_ATTACKER, victim_id or w.victim, AUTH_URI, AUTH_SHA, PHASH_BASE,
                              w.meta, w.ts)
