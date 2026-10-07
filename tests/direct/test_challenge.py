"""Deepfake / impersonation challenge engine: verdicts, slashing, bounties."""
import pytest
from conftest import *

FEE_BPS = 300


def gateway(w, phash, status=200):
    w.vm.sender = w.owner
    w.c.set_phash_gateway(GATEWAY)
    w.vm.mock_web(r"gateway\.aegis-oracle\.example",
                  {"response": {"status": status, "headers": {}, "body": f'{{"phash": "{phash}"}}'.encode()},
                   "method": "GET"})


def serve_forged(w, headers=None, body=b"Ethereum Foundation announces the Merge airdrop!"):
    mock_page(w, r"impostor\.example", body=body, headers=headers or {})


def verdict_of(result):
    return result["verdict"], result["reason"]


# ------------------------------------------------------------ deepfake paths
def test_missing_signature_claiming_identity_is_a_confirmed_deepfake(scenario):
    w = scenario
    serve_forged(w)
    r = challenge(w, w.charlie, w.victim, CONTESTED, w.publisher)
    assert verdict_of(r) == ("CONFIRMED_DEEPFAKE", "missing_signature")
    assert r["sig_state"] == "MISSING"


def test_forged_signature_is_a_confirmed_deepfake(scenario):
    w = scenario
    forged = descriptor_headers(w, KEY_ATTACKER, w.victim, AUTH_URI, AUTH_SHA, PHASH_BASE, w.meta, w.ts)
    serve_forged(w, forged, b"fake-bytes")
    r = challenge(w, w.charlie, w.victim, CONTESTED, w.publisher)
    assert verdict_of(r) == ("CONFIRMED_DEEPFAKE", "forged_signature")
    assert r["sig_state"] == "INVALID"


def test_copied_valid_signature_over_altered_bytes_is_a_deepfake(scenario):
    """Attacker re-serves the authentic descriptor and signature with different media."""
    w = scenario
    serve_forged(w, w.auth_headers, b"deepfake-video-bytes")
    r = challenge(w, w.charlie, w.victim, CONTESTED, w.publisher)
    assert verdict_of(r) == ("CONFIRMED_DEEPFAKE", "signature_payload_mismatch")
    assert r["sig_state"] == "VALID"


def test_altered_phash_beyond_threshold_is_a_deepfake(scenario):
    w = scenario
    gateway(w, phash_at_distance(PHASH_BASE, 11))
    serve_forged(w, w.auth_headers, b"re-encoded-but-different-content")
    r = challenge(w, w.charlie, w.victim, CONTESTED, w.publisher)
    assert verdict_of(r) == ("CONFIRMED_DEEPFAKE", "phash_divergence")
    assert r["distance"] == 11 and r["observed_phash"] == phash_at_distance(PHASH_BASE, 11)


def test_forged_signature_and_diverged_phash_reports_both(scenario):
    w = scenario
    gateway(w, phash_at_distance(PHASH_BASE, 30))
    forged = descriptor_headers(w, KEY_ATTACKER, w.victim, AUTH_URI, AUTH_SHA, PHASH_BASE, w.meta, w.ts)
    serve_forged(w, forged, b"other")
    r = challenge(w, w.charlie, w.victim, CONTESTED, w.publisher)
    assert verdict_of(r) == ("CONFIRMED_DEEPFAKE", "forged_signature_and_phash_divergence")
    assert r["distance"] == 30


def test_json_sidecar_descriptor_with_forged_signature_is_a_deepfake(scenario):
    w = scenario
    import json
    forged = descriptor_headers(w, KEY_ATTACKER, w.victim, AUTH_URI, AUTH_SHA, PHASH_BASE, w.meta, w.ts)
    body = json.dumps({"aegis": {k[len("x-aegis-"):].replace("-", "_"): v for k, v in forged.items()}}).encode()
    serve_forged(w, {}, body)
    r = challenge(w, w.charlie, w.victim, CONTESTED, w.publisher)
    assert r["verdict"] == "CONFIRMED_DEEPFAKE" and r["sig_state"] == "INVALID"


def test_identity_claim_by_domain_mention_alone_is_enough(scenario):
    w = scenario
    serve_forged(w, body=b"official notice from ethereum.org: send ETH to claim")
    assert challenge(w, w.charlie, w.victim, CONTESTED, w.publisher)["verdict"] == "CONFIRMED_DEEPFAKE"


# ------------------------------------------------------------ legitimate paths
@pytest.mark.parametrize("bits", [0, 3, 10])
def test_valid_signature_and_phash_within_threshold_is_legitimate(scenario, bits):
    w = scenario
    gateway(w, phash_at_distance(PHASH_BASE, bits))
    serve_forged(w, w.auth_headers, b"re-encoded-authentic-mirror")
    r = challenge(w, w.charlie, w.victim, CONTESTED, w.publisher)
    assert verdict_of(r) == ("LEGITIMATE_MEDIA", "valid_signature_and_phash_match")
    assert r["distance"] == bits


def test_hamming_threshold_boundary_is_ten_bits_inclusive(scenario):
    w = scenario
    gateway(w, phash_at_distance(PHASH_BASE, 10))
    serve_forged(w, w.auth_headers, b"mirror")
    assert challenge(w, w.charlie, w.victim, CONTESTED, w.publisher)["verdict"] == "LEGITIMATE_MEDIA"
    other = "https://impostor.example/second.png"
    w.vm.clear_mocks()  # the harness matches the first registered mock, so replace both
    serve_forged(w, w.auth_headers, b"mirror")
    gateway(w, phash_at_distance(PHASH_BASE, 11))
    assert challenge(w, w.charlie, w.victim, other, w.publisher)["verdict"] == "CONFIRMED_DEEPFAKE"


def test_exact_authentic_bytes_are_legitimate_even_unsigned(scenario):
    w = scenario
    serve_forged(w, {}, AUTH_BYTES)
    r = challenge(w, w.charlie, w.victim, CONTESTED, w.publisher)
    assert verdict_of(r) == ("LEGITIMATE_MEDIA", "exact_authentic_bytes")
    assert r["baseline_id"] == w.ann


def test_unsigned_page_on_the_entitys_own_domain_is_legitimate(scenario):
    w = scenario
    mock_page(w, r"ethereum\.org/blog", body=b"Ethereum Foundation blog post")
    r = challenge(w, w.charlie, w.victim, "https://blog.ethereum.org/blog/post")
    assert verdict_of(r) == ("LEGITIMATE_MEDIA", "official_channel_origin")


def test_page_that_makes_no_identity_claim_is_legitimate(scenario):
    w = scenario
    serve_forged(w, body=b"a video about cats")
    r = challenge(w, w.charlie, w.victim, CONTESTED, w.publisher)
    assert verdict_of(r) == ("LEGITIMATE_MEDIA", "no_identity_claim")


# ------------------------------------------------------------ inconclusive
@pytest.mark.parametrize("status", [404, 403, 429, 500, 503])
def test_unreachable_or_rate_limited_url_is_inconclusive(scenario, status):
    w = scenario
    mock_page(w, r"impostor\.example", status=status)
    r = challenge(w, w.charlie, w.victim, CONTESTED, w.publisher)
    assert verdict_of(r) == ("INCONCLUSIVE_DISMISSED", "unreachable")
    assert r["http_status"] == status


def test_network_failure_is_inconclusive(scenario):
    w = scenario  # no web mock registered: the fetch raises inside the VM
    r = challenge(w, w.charlie, w.victim, CONTESTED, w.publisher)
    assert r["verdict"] == "INCONCLUSIVE_DISMISSED"


def test_incomplete_descriptor_cannot_prove_a_signature(scenario):
    """The signature covers the pHash, so a descriptor without one verifies nothing."""
    w = scenario
    import json
    body = json.dumps({"aegis": {"entity_id": str(w.victim), "signature": w.auth_headers["x-aegis-signature"],
                                 "content_uri": AUTH_URI, "sha256": AUTH_SHA, "metadata_digest": w.meta,
                                 "timestamp": str(w.ts)}}).encode()
    serve_forged(w, {}, body)
    r = challenge(w, w.charlie, w.victim, CONTESTED, w.publisher)
    assert (r["verdict"], r["sig_state"]) == ("CONFIRMED_DEEPFAKE", "INVALID")


# ------------------------------------------------------------ economics
def test_deepfake_slashes_publisher_burns_half_and_pays_challenger_bounty(scenario):
    w = scenario
    serve_forged(w)
    bond = ATTO // 2
    r = challenge(w, w.charlie, w.victim, CONTESTED, w.publisher, bond)
    stake_before = 20 * ATTO
    slashed = stake_before * 5000 // 10000
    assert (r["slashed"], r["burned"], r["bounty"]) == (slashed, slashed // 2, slashed - slashed // 2)
    assert w.c.get_entity(w.publisher)["stake"] == stake_before - slashed
    assert w.c.get_entity(w.publisher)["times_slashed"] == 1
    # challenger gets the bond back plus the bounty; the 3% fee is retained
    assert w.c.get_claimable(w.charlie) == bond + r["bounty"]
    s = solvent(w)
    assert s["protocol_fees"] == bond * FEE_BPS // 10000
    assert s["total_burned"] == r["burned"] and s["total_paid_out"] == r["burned"]


def test_deepfake_flags_the_victim_for_seven_days_and_circuit_breaker_trips(scenario):
    w = scenario
    assert w.c.is_impersonation_active(w.victim) is False
    serve_forged(w)
    challenge(w, w.charlie, w.victim, CONTESTED, w.publisher)
    assert w.c.is_impersonation_active(w.victim) is True
    assert w.c.is_impersonation_active(w.publisher) is False
    alert = w.c.get_alert(w.victim)
    assert alert["status"] == "FLAGGED_IMPERSONATION" and alert["active"]
    assert 7 * 86400 - 60 <= alert["seconds_remaining"] <= 7 * 86400
    assert w.c.get_entity(w.victim)["alert"] == "FLAGGED_IMPERSONATION"
    warp(w, 7 * 86400 - 120)
    assert w.c.is_impersonation_active(w.victim) is True
    warp(w, 7 * 86400 + 120)
    assert w.c.is_impersonation_active(w.victim) is False
    assert w.c.get_alert(w.victim)["status"] == "CLEAR"


def test_second_confirmation_extends_the_flag_and_counts(scenario):
    w = scenario
    serve_forged(w)
    challenge(w, w.charlie, w.victim, CONTESTED, w.publisher)
    warp(w, 5 * 86400)
    challenge(w, w.charlie, w.victim, "https://impostor.example/second", w.publisher)
    warp(w, 10 * 86400)  # past the first flag, inside the second
    assert w.c.is_impersonation_active(w.victim) is True
    assert w.c.get_entity(w.victim)["flag_count"] == 2


def test_false_challenge_forfeits_bond_to_the_entity(scenario):
    w = scenario
    gateway(w, PHASH_BASE)
    serve_forged(w, w.auth_headers, b"authentic-mirror")
    r = challenge(w, w.charlie, w.victim, CONTESTED, w.publisher, ATTO)
    assert r["verdict"] == "LEGITIMATE_MEDIA"
    assert w.c.get_claimable(w.charlie) == 0
    assert w.c.get_claimable(w.alice) == ATTO  # entity owner receives the forfeited bond
    assert w.c.is_impersonation_active(w.victim) is False
    assert w.c.get_entity(w.victim)["challenges_defended"] == 1
    assert w.c.get_entity(w.publisher)["stake"] == 20 * ATTO  # untouched
    assert solvent(w)["protocol_fees"] == ATTO * FEE_BPS // 10000


def test_inconclusive_refunds_the_bond_but_keeps_the_fee(scenario):
    w = scenario
    mock_page(w, r"impostor\.example", status=503)
    challenge(w, w.charlie, w.victim, CONTESTED, w.publisher)
    assert w.c.get_claimable(w.charlie) == ATTO // 2
    assert solvent(w)["protocol_fees"] == (ATTO // 2) * FEE_BPS // 10000
    assert w.c.is_impersonation_active(w.victim) is False


def test_unstaked_publisher_bounty_comes_from_the_fee_pool(scenario):
    w = scenario
    # build a fee pool first with one inconclusive challenge of 10 GEN
    mock_page(w, r"outage\.example", status=503)
    challenge(w, w.charlie, w.victim, "https://outage.example/a", 0, 10 * ATTO)
    pool = w.c.get_solvency()["protocol_fees"]
    serve_forged(w)
    r = challenge(w, w.charlie, w.victim, CONTESTED, 0, ATTO // 2)
    fee = (ATTO // 2) * FEE_BPS // 10000
    expected = min((pool + fee) * 5000 // 10000, ATTO // 2)
    assert r["verdict"] == "CONFIRMED_DEEPFAKE" and r["slashed"] == 0 and r["bounty"] == expected
    solvent(w)


def test_publisher_slash_of_the_victim_itself_is_consistent(scenario):
    w = scenario
    serve_forged(w)
    r = challenge(w, w.charlie, w.victim, CONTESTED, w.victim)  # compromised-key case
    assert r["slashed"] == 5 * ATTO * 5000 // 10000
    e = w.c.get_entity(w.victim)
    assert e["stake"] == 5 * ATTO - r["slashed"] and e["flagged"] and e["times_slashed"] == 1
    solvent(w)


def test_slash_below_minimum_stake_revokes_broadcast_authority(scenario):
    w = scenario
    serve_forged(w)
    challenge(w, w.charlie, w.victim, CONTESTED, w.victim)
    assert w.c.get_entity(w.victim)["status"] == "UNDERCOLLATERALIZED"
    with w.vm.expect_revert("ERR_INSUFFICIENT_STAKE"):
        attest(w, w.alice, w.victim, KEY_FOUNDATION, AUTH_URI + "2", sha_of("new"), PHASH_BASE)
    w.vm.sender, w.vm.value = w.alice, 5 * ATTO
    w.c.top_up_stake(w.victim)  # recapitalise
    assert w.c.get_entity(w.victim)["status"] == "ACTIVE"


def test_arbitration_fee_math_and_overpayment_raises_the_bond(scenario):
    w = scenario
    mock_page(w, r"impostor\.example", status=503)
    w.vm.sender, w.vm.value = w.charlie, 1_030_000_000_000_000_000  # 1.03 GEN -> 1.0 bond + 0.03 fee
    r = w.c.challenge_broadcast(w.victim, CONTESTED, 0)
    w.vm.value = 0
    assert r["bond"] == ATTO and r["fee"] == 30_000_000_000_000_000


def test_bond_below_half_gen_is_rejected(scenario):
    w = scenario
    w.vm.sender = w.charlie
    w.vm.value = 514_000_000_000_000_000  # bond rounds below 0.5 GEN
    with w.vm.expect_revert("ERR_INSUFFICIENT_BOND"):
        w.c.challenge_broadcast(w.victim, CONTESTED, 0)
    w.vm.value = 0


def test_challenge_without_value_is_rejected(scenario):
    w = scenario
    w.vm.sender = w.charlie
    with w.vm.expect_revert("ERR_INSUFFICIENT_BOND"):
        w.c.challenge_broadcast(w.victim, CONTESTED, 0)


# ------------------------------------------------------------ guards
def test_replayed_challenge_on_an_adjudicated_url_is_rejected(scenario):
    w = scenario
    serve_forged(w)
    challenge(w, w.charlie, w.victim, CONTESTED, w.publisher)
    with w.vm.expect_revert("ERR_REPLAY"):
        challenge(w, w.bob, w.victim, CONTESTED, w.publisher)
    with w.vm.expect_revert("ERR_REPLAY"):  # canonicalisation: scheme/host case + fragment
        challenge(w, w.bob, w.victim, "HTTPS://Impostor.EXAMPLE/merge-announcement.png#frag", w.publisher)


def test_inconclusive_challenge_can_be_retried_only_after_the_cooldown(scenario):
    w = scenario
    mock_page(w, r"impostor\.example", status=503)
    challenge(w, w.charlie, w.victim, CONTESTED, w.publisher)
    with w.vm.expect_revert("ERR_COOLDOWN"):
        challenge(w, w.charlie, w.victim, CONTESTED, w.publisher)
    warp(w, 3700)
    w.vm.clear_mocks()
    serve_forged(w)
    assert challenge(w, w.charlie, w.victim, CONTESTED, w.publisher)["verdict"] == "CONFIRMED_DEEPFAKE"


def test_challenge_outside_the_baseline_window_is_expired(scenario):
    w = scenario
    serve_forged(w)
    warp(w, 31 * 86400)
    with w.vm.expect_revert("ERR_CHALLENGE_EXPIRED"):
        challenge(w, w.charlie, w.victim, CONTESTED, w.publisher)


def test_challenge_inside_the_window_edge_is_accepted(scenario):
    w = scenario
    serve_forged(w)
    warp(w, 29 * 86400)
    assert challenge(w, w.charlie, w.victim, CONTESTED, w.publisher)["verdict"] == "CONFIRMED_DEEPFAKE"


def test_challenge_against_entity_without_baseline_is_expired(world):
    w = world
    eid = register(w, w.alice, "Fresh", "fresh.org", "@fresh", KEY_FOUNDATION)
    with w.vm.expect_revert("ERR_CHALLENGE_EXPIRED"):
        challenge(w, w.charlie, eid, CONTESTED)


def test_revoked_baselines_do_not_keep_a_challenge_alive(scenario):
    w = scenario
    w.vm.sender = w.alice
    w.c.revoke_announcement(w.ann)
    with w.vm.expect_revert("ERR_CHALLENGE_EXPIRED"):
        challenge(w, w.charlie, w.victim, CONTESTED)


@pytest.mark.parametrize("uri", ["http://localhost/x", "http://169.254.169.254/latest", "file:///x",
                                 "http://0x7f.0.0.1/x", "http://[::1]/x", "javascript:alert(1)"])
def test_unsafe_contested_urls_are_rejected(scenario, uri):
    w = scenario
    with w.vm.expect_revert("ERR_UNSAFE_URL"):
        challenge(w, w.charlie, w.victim, uri)


def test_unknown_victim_or_publisher_is_rejected(scenario):
    w = scenario
    with w.vm.expect_revert("unknown entity"):
        challenge(w, w.charlie, 99, CONTESTED)
    with w.vm.expect_revert("unknown publisher"):
        challenge(w, w.charlie, w.victim, CONTESTED, 99)


def test_challenge_records_are_queryable(scenario):
    w = scenario
    serve_forged(w)
    r = challenge(w, w.charlie, w.victim, CONTESTED, w.publisher)
    assert w.c.get_challenge_count() == 1
    assert w.c.get_challenge(r["id"]) == r
    assert w.c.list_challenges(0, 10) == [r]
    assert r["challenger"].lower() == w.c.get_challenge(1)["challenger"].lower()
    with w.vm.expect_revert("unknown challenge"):
        w.c.get_challenge(5)
