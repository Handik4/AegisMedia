"""EIP-712 digest, signature recovery and perceptual-hash math."""
import pytest
from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_utils import keccak

from conftest import *


@pytest.mark.parametrize("n", [1, 55, 135, 136, 137, 271, 272, 273, 400, 500])
def test_digest_matches_eth_account_across_keccak_block_boundaries(world, n):
    """Pure-Python keccak256 must agree with eth_utils for every padding case."""
    w = world
    uri = "https://ethereum.org/" + "a" * max(0, n - 21) if n > 21 else "u" * n
    sha, md, ts = sha_of("x"), sha_of("y"), 1_700_000_000
    on_chain = w.c.announcement_digest(3, uri, sha, PHASH_BASE, md, ts)
    sig = sign_announcement(w.domain, KEY_FOUNDATION, 3, uri, sha, PHASH_BASE, md, ts)
    recovered_ref = Account.recover_message(
        encode_typed_data(full_message=_full(w, 3, uri, sha, md, ts)), signature=sig)
    # the digest the contract builds must be the digest eth_account signed
    sm = encode_typed_data(full_message=_full(w, 3, uri, sha, md, ts))
    assert on_chain == "0x" + keccak(b"\x19" + sm.version + sm.header + sm.body).hex()
    assert recovered_ref.lower() == signer_of(KEY_FOUNDATION)


def _full(w, eid, uri, sha, md, ts):
    return {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"}, {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"}, {"name": "verifyingContract", "type": "address"}],
            "Announcement": [
                {"name": "entityId", "type": "uint256"}, {"name": "contentUriHash", "type": "bytes32"},
                {"name": "sha256Hash", "type": "bytes32"}, {"name": "phash", "type": "uint64"},
                {"name": "metadataDigest", "type": "bytes32"}, {"name": "timestamp", "type": "uint256"}]},
        "primaryType": "Announcement",
        "domain": {k: w.domain[k] for k in ("name", "version", "chainId", "verifyingContract")},
        "message": {"entityId": eid, "contentUriHash": keccak(text=uri), "sha256Hash": bytes.fromhex(sha),
                    "phash": int(PHASH_BASE, 16), "metadataDigest": bytes.fromhex(md), "timestamp": ts},
    }


def test_domain_binds_chain_and_contract(world):
    d = world.domain
    assert d["chainId"] == 61997 and d["name"] == "AegisMedia" and d["version"] == "1"
    assert d["verifyingContract"].startswith("0x") and len(d["verifyingContract"]) == 42


def test_digest_changes_with_every_field(world):
    c = world.c
    base = ("https://ethereum.org/a", sha_of("a"), PHASH_BASE, sha_of("m"), 100)
    ref = c.announcement_digest(1, *base)
    variants = [
        c.announcement_digest(2, *base),
        c.announcement_digest(1, "https://ethereum.org/b", *base[1:]),
        c.announcement_digest(1, base[0], sha_of("b"), *base[2:]),
        c.announcement_digest(1, base[0], base[1], phash_at_distance(PHASH_BASE, 1), *base[3:]),
        c.announcement_digest(1, *base[:3], sha_of("n"), base[4]),
        c.announcement_digest(1, *base[:4], 101),
    ]
    assert len({ref, *variants}) == 7


@pytest.mark.parametrize("a,b,expected", [
    ("0000000000000000", "0000000000000000", 0),
    ("0000000000000000", "ffffffffffffffff", 64),
    ("0000000000000000", "0000000000000001", 1),
    ("8000000000000000", "0000000000000001", 2),
    ("ffffffffffffffff", "fffffffffffffffe", 1),
    ("f0f0f0f0f0f0f0f0", "0f0f0f0f0f0f0f0f", 64),
    ("0xAAAAAAAAAAAAAAAA", "5555555555555555", 64),
    ("aaaaaaaaaaaaaaaa", "AAAAAAAAAAAAAAAA", 0),
])
def test_hamming_known_vectors(world, a, b, expected):
    assert world.c.compute_hamming(a, b) == expected


def test_hamming_is_symmetric_and_satisfies_triangle_inequality(world):
    c = world.c
    xs = [PHASH_BASE, phash_at_distance(PHASH_BASE, 5), phash_at_distance(PHASH_BASE, 17), "0123456789abcdef"]
    for a in xs:
        for b in xs:
            assert c.compute_hamming(a, b) == c.compute_hamming(b, a)
            for m in xs:
                assert c.compute_hamming(a, b) <= c.compute_hamming(a, m) + c.compute_hamming(m, b)


@pytest.mark.parametrize("bits", [0, 1, 10, 11, 32, 64])
def test_hamming_exact_bit_counts(world, bits):
    assert world.c.compute_hamming(PHASH_BASE, phash_at_distance(PHASH_BASE, bits)) == bits


@pytest.mark.parametrize("bad", ["", "abc", "g" * 16, "f" * 15, "f" * 17])
def test_hamming_rejects_malformed_hashes(world, bad):
    with world.vm.expect_revert("ERR_INVALID_INPUT"):
        world.c.compute_hamming(bad, PHASH_BASE)
