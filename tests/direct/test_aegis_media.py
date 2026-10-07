"""Regression PoCs for the four audit findings (publisher slashing, news-article
circuit-breaker DDoS, JSON sidecar bypass, fee-pool drain). Each test is written as
the attacker's move and asserts that it now fails."""
import json

import pytest
from conftest import *


def gateway(w, phash):
    """Configure the trusted pHash gateway. Registered first: its URL embeds the contested URL."""
    w.vm.sender = w.owner
    w.c.set_phash_gateway(GATEWAY)
    w.vm.mock_web(r"gateway\.aegis-oracle\.example",
                  {"response": {"status": 200, "headers": {}, "body": f'{{"phash": "{phash}"}}'.encode()},
                   "method": "GET"})


def sidecar_body(w, headers, media_uri=None):
    """A JSON sidecar carrying the descriptor fields from `headers` (and an optional media_uri)."""
    doc = {k[len("x-aegis-"):].replace("-", "_"): v for k, v in headers.items()}
    if media_uri:
        doc["media_uri"] = media_uri
    return json.dumps({"aegis": doc}).encode()


# ---------------------------------------------------------------- finding 1
def test_poc_arbitrary_publisher_slash(scenario):
    """Attacker names an innocent entity as publisher of a URL it has nothing to do with."""
    w = scenario
    innocent = register(w, w.charlie, "Innocent Co", "innocent.example", "@innocent", KEY_GUARD, stake=20 * ATTO)
    mock_page(w, r"impostor\.example", body=b"x", headers=forged_headers(w))
    before = (w.c.get_entity(innocent), w.c.get_solvency(), w.c.get_challenge_count())
    with w.vm.expect_revert("ERR_PUBLISHER_MISMATCH"):
        challenge(w, w.bob, w.victim, CONTESTED, innocent)
    assert (w.c.get_entity(innocent), w.c.get_solvency(), w.c.get_challenge_count()) == before
    assert w.c.get_entity(innocent)["stake"] == 20 * ATTO and w.c.get_entity(innocent)["times_slashed"] == 0
    assert not w.c.is_impersonation_active(w.victim)


@pytest.mark.parametrize("uri", [
    "https://notimpostor.example/x.png",          # lookalike sharing a suffix
    "https://impostor.example.evil.test/x.png",   # registered domain only as a prefix label
    "https://evil.test/impostor.example/x.png",   # domain in the path
    "https://evil.test/x.png?host=impostor.example",
])
def test_publisher_binding_rejects_lookalike_hosts(scenario, uri):
    w = scenario
    with w.vm.expect_revert("ERR_PUBLISHER_MISMATCH"):
        challenge(w, w.charlie, w.victim, uri, w.publisher)
    assert w.c.get_entity(w.publisher)["stake"] == 20 * ATTO


def test_publisher_binding_accepts_the_domain_and_its_subdomains(scenario):
    w = scenario
    mock_page(w, r"media\.impostor\.example", body=b"x", headers=forged_headers(w))
    r = challenge(w, w.charlie, w.victim, "https://media.impostor.example/x.png", w.publisher)
    assert r["verdict"] == "CONFIRMED_DEEPFAKE" and r["slashed"] == 10 * ATTO


def test_the_victim_cannot_be_slashed_for_a_third_party_url(scenario):
    w = scenario
    with w.vm.expect_revert("ERR_PUBLISHER_MISMATCH"):
        challenge(w, w.charlie, w.victim, CONTESTED, w.victim)
    assert w.c.get_entity(w.victim)["stake"] == 5 * ATTO


# ---------------------------------------------------------------- finding 2
NEWS = b"""<html><title>Ethereum Foundation (ethereum.org, @ethereum) announces roadmap</title>
<p>The Ethereum Foundation said on Tuesday...</p></html>"""


def test_poc_news_article_false_positive(scenario):
    """A genuine news story mentioning the entity must not flag it or trip the breaker."""
    w = scenario
    mock_page(w, r"news\.example", body=NEWS, headers={"content-type": "text/html"})
    r = challenge(w, w.charlie, w.victim, "https://news.example/ethereum-foundation-roadmap")
    assert r["verdict"] in ("LEGITIMATE_MEDIA", "INCONCLUSIVE_DISMISSED")
    assert r["verdict"] != "CONFIRMED_DEEPFAKE"
    assert not w.c.is_impersonation_active(w.victim)
    assert w.c.get_entity(w.victim)["flag_count"] == 0
    assert w.c.get_alert(w.victim)["status"] == "CLEAR"


def test_news_article_stays_clean_even_with_a_publisher_named(scenario):
    w = scenario
    mock_page(w, r"impostor\.example", body=NEWS, headers={"content-type": "text/html"})
    r = challenge(w, w.charlie, w.victim, CONTESTED, w.publisher)
    assert r["verdict"] == "LEGITIMATE_MEDIA" and r["slashed"] == 0
    assert w.c.get_entity(w.publisher)["stake"] == 20 * ATTO and not w.c.is_impersonation_active(w.victim)


def test_news_article_stays_clean_when_a_gateway_is_configured(scenario):
    w = scenario
    gateway(w, phash_at_distance(PHASH_BASE, 40))  # nothing resembling official media
    mock_page(w, r"news\.example", body=NEWS, headers={"content-type": "text/html"})
    r = challenge(w, w.charlie, w.victim, "https://news.example/story")
    assert r["verdict"] == "LEGITIMATE_MEDIA" and not w.c.is_impersonation_active(w.victim)


def test_news_page_embedding_official_image_does_not_flag_without_a_slash(scenario):
    """Even a page that reproduces official media cannot trip the breaker unless a
    staked, domain-bound publisher pays for it."""
    w = scenario
    gateway(w, phash_at_distance(PHASH_BASE, 2))
    mock_page(w, r"news\.example", body=NEWS, headers={"content-type": "text/html"})
    r = challenge(w, w.charlie, w.victim, "https://news.example/story-with-photo")
    assert r["slashed"] == 0 and r["bounty"] == 0
    assert not w.c.is_impersonation_active(w.victim)


def test_junk_signature_on_an_unstaked_host_cannot_trip_the_breaker(scenario):
    """The cheap DDoS: plant a forged signature on a page you control, challenge it, flag the victim."""
    w = scenario
    mock_page(w, r"attacker\.example", body=b"x", headers=forged_headers(w))
    r = challenge(w, w.bob, w.victim, "https://attacker.example/x.png")
    assert r["verdict"] == "CONFIRMED_DEEPFAKE" and r["reason"] == "forged_signature"
    assert r["slashed"] == 0 and r["bounty"] == 0
    assert not w.c.is_impersonation_active(w.victim) and w.c.get_entity(w.victim)["flag_count"] == 0


def test_circuit_breaker_costs_the_publishers_stake(scenario):
    w = scenario
    mock_page(w, r"impostor\.example", body=b"x", headers=forged_headers(w))
    stake = w.c.get_entity(w.publisher)["stake"]
    r = challenge(w, w.charlie, w.victim, CONTESTED, w.publisher)
    assert r["slashed"] > 0 and w.c.get_entity(w.publisher)["stake"] == stake - r["slashed"]
    assert w.c.is_impersonation_active(w.victim)


# ---------------------------------------------------------------- finding 3
def test_poc_json_sidecar_bypass(scenario):
    """A sidecar with a genuine signature and an authentic-looking pHash, wrapping fake media."""
    w = scenario
    body = sidecar_body(w, w.auth_headers, media_uri="https://impostor.example/fake.mp4")
    mock_page(w, r"impostor\.example", body=body, headers={"content-type": "application/json"})
    r = challenge(w, w.charlie, w.victim, CONTESTED, w.publisher)
    # The asserted pHash is never trusted: with no gateway the contract cannot measure the media.
    assert r["verdict"] == "INCONCLUSIVE_DISMISSED" and r["reason"] == "unverifiable_signed_media"
    assert r["verdict"] != "LEGITIMATE_MEDIA"
    assert r["slashed"] == 0 and not w.c.is_impersonation_active(w.victim)


def test_sidecar_without_a_media_reference_is_inconclusive_even_with_a_gateway(scenario):
    w = scenario
    gateway(w, PHASH_BASE)
    mock_page(w, r"impostor\.example", body=sidecar_body(w, w.auth_headers), headers={})
    r = challenge(w, w.charlie, w.victim, CONTESTED, w.publisher)
    assert r["verdict"] == "INCONCLUSIVE_DISMISSED"


def test_sidecar_with_gateway_hashes_the_referenced_media_and_catches_the_fake(scenario):
    w = scenario
    gateway(w, phash_at_distance(PHASH_BASE, 25))  # the referenced media is not the signed one
    mock_page(w, r"impostor\.example", body=sidecar_body(w, w.auth_headers, "https://impostor.example/fake.mp4"),
              headers={"x-aegis-entity": str(w.victim)})  # the host itself claims the entity
    r = challenge(w, w.charlie, w.victim, CONTESTED, w.publisher)
    assert (r["verdict"], r["reason"]) == ("CONFIRMED_DEEPFAKE", "phash_divergence")
    assert r["distance"] == 25 and r["slashed"] == 10 * ATTO


def test_sidecar_with_gateway_accepts_genuinely_signed_media(scenario):
    w = scenario
    gateway(w, phash_at_distance(PHASH_BASE, 2))
    mock_page(w, r"impostor\.example", body=sidecar_body(w, w.auth_headers, "https://impostor.example/real.mp4"), headers={})
    r = challenge(w, w.charlie, w.victim, CONTESTED, w.publisher)
    assert (r["verdict"], r["reason"]) == ("LEGITIMATE_MEDIA", "valid_signature_and_phash_match")


def test_sidecar_media_reference_must_be_a_safe_url(scenario):
    w = scenario
    gateway(w, PHASH_BASE)
    mock_page(w, r"impostor\.example",
              body=sidecar_body(w, w.auth_headers, "http://169.254.169.254/latest/meta-data"), headers={})
    assert challenge(w, w.charlie, w.victim, CONTESTED, w.publisher)["verdict"] == "INCONCLUSIVE_DISMISSED"


def test_origin_asserted_phash_header_is_never_trusted(scenario):
    """Valid descriptor, different bytes, perfect-looking pHash header, no gateway: no slash, no LEGIT."""
    w = scenario
    mock_page(w, r"impostor\.example", body=b"completely different bytes", headers=w.auth_headers)
    r = challenge(w, w.charlie, w.victim, CONTESTED, w.publisher)
    assert r["verdict"] == "INCONCLUSIVE_DISMISSED"


# ---------------------------------------------------------------- finding 4
def test_poc_fee_pool_drain(scenario):
    """publisher = 0 used to pay the challenger out of the shared fee pool."""
    w = scenario
    mock_page(w, r"down\.example", status=503)
    challenge(w, w.charlie, w.victim, "https://down.example/a", 0, 10 * ATTO)  # seed a fee pool
    pool = w.c.get_solvency()["protocol_fees"]
    assert pool == 10 * ATTO * 300 // 10000

    mock_page(w, r"attacker\.example", body=b"x", headers=forged_headers(w))
    bond = ATTO // 2
    r = challenge(w, w.bob, w.victim, "https://attacker.example/x.png", 0, bond)
    assert r["verdict"] == "CONFIRMED_DEEPFAKE"
    assert r["bounty"] == 0 and r["slashed"] == 0
    assert w.c.get_claimable(w.bob) == bond                      # bond refund only
    after = solvent(w)
    assert after["protocol_fees"] == pool + bond * 300 // 10000  # the pool only ever grows


def test_unregistered_publisher_id_reverts(scenario):
    w = scenario
    before = w.c.get_solvency()
    with w.vm.expect_revert("unknown publisher"):
        challenge(w, w.charlie, w.victim, CONTESTED, 99)
    assert w.c.get_solvency() == before


def test_fee_pool_never_decreases_across_every_verdict_path(scenario):
    w = scenario
    mock_page(w, r"impostor\.example", body=b"x", headers=forged_headers(w))
    pools = [w.c.get_solvency()["protocol_fees"]]
    challenge(w, w.charlie, w.victim, CONTESTED, w.publisher)                  # deepfake, slashed
    pools.append(w.c.get_solvency()["protocol_fees"])
    mock_page(w, r"news\.example", body=NEWS, headers={"content-type": "text/html"})
    challenge(w, w.charlie, w.victim, "https://news.example/a")                # legitimate
    pools.append(w.c.get_solvency()["protocol_fees"])
    mock_page(w, r"down\.example", status=500)
    challenge(w, w.charlie, w.victim, "https://down.example/a")                # inconclusive
    pools.append(w.c.get_solvency()["protocol_fees"])
    assert pools == sorted(pools) and pools[-1] > pools[0]
    solvent(w)


# ------------------------------------------------- reviewer: UGC / unclaimed signatures
def test_poc_signed_json_on_a_ugc_host_does_not_slash_the_host(scenario):
    """Someone uploads a signed JSON to a forum or IPFS gateway on an entity's domain.
    The host never claimed the identity (no x-aegis-entity header), so it is not slashed."""
    w = scenario
    forged = forged_headers(w)
    body = sidecar_body(w, forged, media_uri="https://impostor.example/fake.mp4")
    mock_page(w, r"impostor\.example", body=body, headers={"content-type": "application/json"})
    r = challenge(w, w.charlie, w.victim, CONTESTED, w.publisher)
    assert (r["verdict"], r["reason"]) == ("INCONCLUSIVE_DISMISSED", "unclaimed_signature")
    assert r["slashed"] == 0 and w.c.get_entity(w.publisher)["stake"] == 20 * ATTO
    assert not w.c.is_impersonation_active(w.victim)


def test_valid_signature_with_diverging_media_but_no_header_claim_is_inconclusive(scenario):
    w = scenario
    gateway(w, phash_at_distance(PHASH_BASE, 30))
    no_claim = {k: v for k, v in w.auth_headers.items() if k != "x-aegis-entity"}
    mock_page(w, r"impostor\.example", body=b"other media", headers=no_claim)
    r = challenge(w, w.charlie, w.victim, CONTESTED, w.publisher)
    assert (r["verdict"], r["reason"]) == ("INCONCLUSIVE_DISMISSED", "unclaimed_signature")
    assert r["slashed"] == 0


def test_forged_signature_without_a_header_claim_is_inconclusive(scenario):
    w = scenario
    no_claim = {k: v for k, v in forged_headers(w).items() if k != "x-aegis-entity"}
    mock_page(w, r"impostor\.example", body=b"x", headers=no_claim)
    r = challenge(w, w.charlie, w.victim, CONTESTED, w.publisher)
    assert (r["verdict"], r["reason"]) == ("INCONCLUSIVE_DISMISSED", "unclaimed_signature")
    assert r["sig_state"] == "INVALID" and r["slashed"] == 0


def test_header_naming_a_different_entity_is_not_a_claim_on_the_victim(scenario):
    w = scenario
    other = dict(forged_headers(w), **{"x-aegis-entity": str(w.publisher)})
    mock_page(w, r"impostor\.example", body=b"x", headers=other)
    r = challenge(w, w.charlie, w.victim, CONTESTED, w.publisher)
    assert r["verdict"] == "INCONCLUSIVE_DISMISSED" and r["slashed"] == 0


def test_explicit_header_claim_with_forged_signature_still_slashes(scenario):
    """The legitimate case keeps working: the host's own server asserts the identity."""
    w = scenario
    mock_page(w, r"impostor\.example", body=b"x", headers=forged_headers(w))
    r = challenge(w, w.charlie, w.victim, CONTESTED, w.publisher)
    assert (r["verdict"], r["reason"]) == ("CONFIRMED_DEEPFAKE", "forged_signature")
    assert r["slashed"] == 10 * ATTO
