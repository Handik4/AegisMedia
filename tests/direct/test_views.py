"""Media verifier lookups and the DeFi-facing circuit breaker."""
from conftest import *


def test_verify_media_exact_match_is_authenticated(scenario):
    w = scenario
    r = w.c.verify_media(AUTH_SHA, PHASH_BASE)
    assert r["status"] == "AUTHENTICATED" and r["match"] == "EXACT" and r["distance"] == 0
    assert r["entity_id"] == w.victim and r["entity_name"] == "Ethereum Foundation"
    assert r["announcement_id"] == w.ann and r["flagged"] is False


def test_verify_media_perceptual_match_within_threshold(scenario):
    w = scenario
    r = w.c.verify_media(sha_of("re-encoded"), phash_at_distance(PHASH_BASE, 8))
    assert (r["status"], r["match"], r["distance"]) == ("AUTHENTICATED", "PERCEPTUAL", 8)


def test_verify_media_just_beyond_threshold_is_unverified(scenario):
    w = scenario
    r = w.c.verify_media(sha_of("edited"), phash_at_distance(PHASH_BASE, 11))
    assert (r["status"], r["match"], r["entity_id"]) == ("UNVERIFIED", "NONE", 0)


def test_verify_media_unknown_digest_without_phash_is_unverified(scenario):
    assert scenario.c.verify_media(sha_of("never seen"), "")["status"] == "UNVERIFIED"


def test_verify_media_picks_the_closest_baseline(scenario):
    w = scenario
    far = phash_at_distance(PHASH_BASE, 9)
    attest(w, w.alice, w.victim, KEY_FOUNDATION, AUTH_URI + "b", sha_of("other"), far)
    r = w.c.verify_media(sha_of("probe"), phash_at_distance(far, 2))
    assert r["distance"] == 2


def test_verify_media_reports_flagged_entity(scenario):
    w = scenario
    mock_page(w, r"impostor\.example", body=b"Ethereum Foundation giveaway", headers=forged_headers(w))
    challenge(w, w.charlie, w.victim, CONTESTED, w.publisher)
    assert w.c.verify_media(AUTH_SHA, PHASH_BASE)["flagged"] is True


def test_circuit_breaker_is_false_for_clean_and_unknown_entities(scenario):
    w = scenario
    assert not w.c.is_impersonation_active(w.victim)
    assert not w.c.is_impersonation_active(w.publisher)
    assert not w.c.is_impersonation_active(0)
    assert w.c.get_alert(w.victim)["seconds_remaining"] == 0


def test_get_config_exposes_protocol_constants(world):
    cfg = world.c.get_config()
    assert cfg["min_stake"] == 5 * ATTO and cfg["min_challenge_bond"] == ATTO // 2
    assert cfg["arbitration_fee_bps"] == 300 and cfg["hamming_threshold"] == 10
    assert cfg["withdraw_cooldown"] == 7 * 86400 and cfg["flag_duration"] == 7 * 86400
