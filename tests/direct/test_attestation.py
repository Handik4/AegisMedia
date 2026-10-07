"""Announcement attestation with EIP-712 signature verification."""
import pytest
from conftest import *

URI = "https://ethereum.org/blog/post.png"


@pytest.fixture
def ent(world):
    world.eid = register(world, world.alice, "Ethereum Foundation", "ethereum.org", "@ethereum", KEY_FOUNDATION)
    return world


def test_authentic_attestation_is_recorded_as_authenticated(ent):
    w = ent
    sha, md = sha_of("post"), sha_of("meta")
    ann_id = attest(w, w.alice, w.eid, KEY_FOUNDATION, URI, sha, PHASH_BASE, md)
    a = w.c.get_announcement(ann_id)
    assert a["status"] == "AUTHENTICATED" and a["entity_id"] == w.eid
    assert a["sha256_hash"] == sha and a["phash"] == PHASH_BASE and a["metadata_digest"] == md
    assert a["signer"] == signer_of(KEY_FOUNDATION)
    assert w.c.get_entity(w.eid)["announcement_count"] == 1
    assert ann_id == w.c.announcement_digest(w.eid, URI, sha, PHASH_BASE, md, a["timestamp"])


def test_signature_from_wrong_key_is_rejected(ent):
    w = ent
    with w.vm.expect_revert("ERR_INVALID_SIGNATURE"):
        attest(w, w.alice, w.eid, KEY_ATTACKER, URI, sha_of("p"), PHASH_BASE)


def test_signature_over_different_payload_is_rejected(ent):
    w = ent
    ts, sha, md = now_ts(), sha_of("p"), sha_of("m")
    sig = sign_announcement(w.domain, KEY_FOUNDATION, w.eid, URI, sha, PHASH_BASE, md, ts)
    w.vm.sender = w.alice
    with w.vm.expect_revert("ERR_INVALID_SIGNATURE"):  # altered pHash
        w.c.attest_announcement(w.eid, URI, sha, phash_at_distance(PHASH_BASE, 3), md, ts, sig)
    with w.vm.expect_revert("ERR_INVALID_SIGNATURE"):  # altered URI
        w.c.attest_announcement(w.eid, "https://ethereum.org/other", sha, PHASH_BASE, md, ts, sig)
    with w.vm.expect_revert("ERR_INVALID_SIGNATURE"):  # altered timestamp
        w.c.attest_announcement(w.eid, URI, sha, PHASH_BASE, md, ts + 1, sig)


def test_signature_for_another_entity_cannot_be_replayed_cross_entity(ent):
    w = ent
    other = register(w, w.bob, "Guard", "guard.org", "@guard", KEY_FOUNDATION)  # same signer key
    ts, sha, md = now_ts(), sha_of("p"), sha_of("m")
    sig = sign_announcement(w.domain, KEY_FOUNDATION, w.eid, URI, sha, PHASH_BASE, md, ts)
    w.vm.sender = w.bob
    with w.vm.expect_revert("ERR_INVALID_SIGNATURE"):
        w.c.attest_announcement(other, URI, sha, PHASH_BASE, md, ts, sig)


def test_signature_for_other_contract_domain_is_rejected(ent):
    w = ent
    ts, sha, md = now_ts(), sha_of("p"), sha_of("m")
    foreign = dict(w.domain, verifyingContract="0x" + "ab" * 20)
    sig = sign_announcement(foreign, KEY_FOUNDATION, w.eid, URI, sha, PHASH_BASE, md, ts)
    w.vm.sender = w.alice
    with w.vm.expect_revert("ERR_INVALID_SIGNATURE"):
        w.c.attest_announcement(w.eid, URI, sha, PHASH_BASE, md, ts, sig)


def test_signature_for_other_chain_is_rejected(ent):
    w = ent
    ts, sha, md = now_ts(), sha_of("p"), sha_of("m")
    sig = sign_announcement(dict(w.domain, chainId=1), KEY_FOUNDATION, w.eid, URI, sha, PHASH_BASE, md, ts)
    w.vm.sender = w.alice
    with w.vm.expect_revert("ERR_INVALID_SIGNATURE"):
        w.c.attest_announcement(w.eid, URI, sha, PHASH_BASE, md, ts, sig)


def test_high_s_malleated_signature_is_rejected(ent):
    w = ent
    ts, sha, md = now_ts(), sha_of("p"), sha_of("m")
    sig = sign_announcement(w.domain, KEY_FOUNDATION, w.eid, URI, sha, PHASH_BASE, md, ts)
    raw = bytes.fromhex(sig[2:])
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    s_hi = n - int.from_bytes(raw[32:64], "big")
    flipped = raw[:32] + s_hi.to_bytes(32, "big") + bytes([raw[64] ^ 1])
    w.vm.sender = w.alice
    with w.vm.expect_revert("ERR_INVALID_SIGNATURE"):
        w.c.attest_announcement(w.eid, URI, sha, PHASH_BASE, md, ts, "0x" + flipped.hex())


@pytest.mark.parametrize("bad_sig", ["", "0x", "0x1234", "0x" + "00" * 65, "0x" + "zz" * 65])
def test_malformed_signatures_are_rejected(ent, bad_sig):
    w = ent
    w.vm.sender = w.alice
    with w.vm.expect_revert("ERR_INVALID_SIGNATURE"):
        w.c.attest_announcement(w.eid, URI, sha_of("p"), PHASH_BASE, sha_of("m"), now_ts(), bad_sig)


def test_recovery_id_zero_one_form_is_accepted(ent):
    w = ent
    ts, sha, md = now_ts(), sha_of("p"), sha_of("m")
    sig = bytearray(bytes.fromhex(sign_announcement(w.domain, KEY_FOUNDATION, w.eid, URI, sha, PHASH_BASE, md, ts)[2:]))
    sig[64] -= 27
    w.vm.sender = w.alice
    assert w.c.attest_announcement(w.eid, URI, sha, PHASH_BASE, md, ts, "0x" + sig.hex())


def test_only_owner_can_attest(ent):
    w = ent
    with w.vm.expect_revert("ERR_UNAUTHORIZED"):
        attest(w, w.bob, w.eid, KEY_FOUNDATION, URI, sha_of("p"), PHASH_BASE)


def test_exact_replay_is_rejected(ent):
    w = ent
    sha, md, ts = sha_of("p"), sha_of("m"), now_ts()
    attest(w, w.alice, w.eid, KEY_FOUNDATION, URI, sha, PHASH_BASE, md, ts)
    with w.vm.expect_revert("ERR_REPLAY"):
        attest(w, w.alice, w.eid, KEY_FOUNDATION, URI, sha, PHASH_BASE, md, ts)


def test_same_content_with_fresh_timestamp_is_rejected(ent):
    w = ent
    sha = sha_of("p")
    attest(w, w.alice, w.eid, KEY_FOUNDATION, URI, sha, PHASH_BASE, ts=now_ts() - 10)
    with w.vm.expect_revert("already attested for this entity"):
        attest(w, w.alice, w.eid, KEY_FOUNDATION, URI, sha, PHASH_BASE, ts=now_ts())


def test_stale_timestamp_is_rejected_as_replay(ent):
    w = ent
    with w.vm.expect_revert("ERR_REPLAY"):
        attest(w, w.alice, w.eid, KEY_FOUNDATION, URI, sha_of("p"), PHASH_BASE, ts=now_ts() - 2 * 86400)


def test_future_timestamp_is_rejected(ent):
    w = ent
    with w.vm.expect_revert("ERR_REPLAY"):
        attest(w, w.alice, w.eid, KEY_FOUNDATION, URI, sha_of("p"), PHASH_BASE, ts=now_ts() + 3600)


@pytest.mark.parametrize("uri", ["file:///etc/passwd", "http://localhost/x", "http://10.0.0.5/x",
                                 "http://192.168.1.1/x", "http://127.0.0.1/x", "http://2130706433/x",
                                 "http://[::1]/x", "https://user:pw@ethereum.org/x", "ftp://ethereum.org/x",
                                 "https://x.nip.io/x", "https://metadata.google.internal/x", "not a url"])
def test_unsafe_content_uris_are_rejected(ent, uri):
    w = ent
    with w.vm.expect_revert("ERR_UNSAFE_URL"):
        attest(w, w.alice, w.eid, KEY_FOUNDATION, uri, sha_of("p"), PHASH_BASE)


@pytest.mark.parametrize("field,bad", [("sha", "ab" * 31), ("sha", "zz" * 32), ("phash", "f" * 15), ("md", "00")])
def test_malformed_digest_fields_are_rejected(ent, field, bad):
    w = ent
    sha, ph, md = sha_of("p"), PHASH_BASE, sha_of("m")
    args = {"sha": sha, "phash": ph, "md": md}
    args[field] = bad
    w.vm.sender = w.alice
    with w.vm.expect_revert("ERR_INVALID_INPUT"):
        w.c.attest_announcement(w.eid, URI, args["sha"], args["phash"], args["md"], now_ts(), "0x" + "11" * 65)


def test_entity_without_active_authority_cannot_attest(ent):
    w = ent
    w.vm.sender = w.alice
    w.c.request_withdrawal(w.eid)
    with w.vm.expect_revert("ERR_INSUFFICIENT_STAKE"):
        attest(w, w.alice, w.eid, KEY_FOUNDATION, URI, sha_of("p"), PHASH_BASE)


def test_revoked_announcement_is_no_longer_authenticated(ent):
    w = ent
    sha = sha_of("p")
    ann = attest(w, w.alice, w.eid, KEY_FOUNDATION, URI, sha, PHASH_BASE)
    w.vm.sender = w.bob
    with w.vm.expect_revert("ERR_UNAUTHORIZED"):
        w.c.revoke_announcement(ann)
    w.vm.sender = w.alice
    w.c.revoke_announcement(ann)
    assert w.c.get_announcement(ann)["status"] == "REVOKED"
    assert w.c.verify_media(sha, PHASH_BASE)["status"] == "REVOKED"


def test_listing_announcements(ent):
    w = ent
    ids = [attest(w, w.alice, w.eid, KEY_FOUNDATION, URI, sha_of(f"p{i}"), PHASH_BASE) for i in range(3)]
    listed = w.c.list_entity_announcements(w.eid, 0, 10)
    assert [a["id"] for a in listed] == ids
    assert [a["id"] for a in w.c.list_recent_announcements(2)] == [ids[2], ids[1]]
    with w.vm.expect_revert("unknown announcement"):
        w.c.get_announcement("0xdead")
