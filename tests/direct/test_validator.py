"""Validator-side equivalence: leaders and validators must agree on evidence, not on bytes."""
from conftest import *


def serve(w, body=b"Ethereum Foundation announces a giveaway", headers=None, status=200):
    """Default page carries a forged descriptor (a deepfake); headers={} serves a plain page."""
    w.vm.clear_mocks()
    mock_page(w, r"impostor\.example", status=status, body=body,
              headers=forged_headers(w) if headers is None else headers)


def set_gateway(w, phash):
    """(Re)point the gateway mock. The harness matches the first registered mock and
    the gateway URL embeds the contested URL, so the gateway mock must come first and
    the mocks are rebuilt from scratch on every call."""
    w.vm.clear_mocks()
    w.vm.mock_web(r"gateway\.aegis-oracle\.example",
                  {"response": {"status": 200, "headers": {}, "body": f'{{"phash": "{phash}"}}'.encode()},
                   "method": "GET"})
    mock_page(w, r"impostor\.example", body=b"mirror", headers=w.auth_headers)
    w.vm.sender = w.owner
    w.c.set_phash_gateway(GATEWAY)


def test_validator_agrees_when_it_sees_the_same_evidence(scenario):
    w = scenario
    serve(w)
    challenge(w, w.charlie, w.victim, CONTESTED, w.publisher)
    assert w.vm.run_validator() is True


def test_validator_disagrees_when_it_sees_a_legitimate_page(scenario):
    w = scenario
    serve(w)
    challenge(w, w.charlie, w.victim, CONTESTED, w.publisher)
    serve(w, body=b"a video about cats", headers={})
    assert w.vm.run_validator() is False


def test_validator_disagrees_if_the_origin_is_unreachable_for_it(scenario):
    w = scenario
    serve(w)
    challenge(w, w.charlie, w.victim, CONTESTED, w.publisher)
    serve(w, status=503)
    assert w.vm.run_validator() is False


def test_validators_agree_on_unreachable_regardless_of_status_code(scenario):
    w = scenario
    serve(w, status=503)
    challenge(w, w.charlie, w.victim, CONTESTED, w.publisher)
    serve(w, status=429)
    assert w.vm.run_validator() is True


def test_validator_tolerates_small_phash_drift(scenario):
    w = scenario
    serve(w, headers=w.auth_headers, body=b"mirror")
    set_gateway(w, phash_at_distance(PHASH_BASE, 3))
    challenge(w, w.charlie, w.victim, CONTESTED, w.publisher)
    set_gateway(w, phash_at_distance(PHASH_BASE, 5))  # 2 bits of drift
    assert w.vm.run_validator() is True


def test_validator_rejects_phash_drift_beyond_tolerance(scenario):
    w = scenario
    serve(w, headers=w.auth_headers, body=b"mirror")
    set_gateway(w, phash_at_distance(PHASH_BASE, 3))
    challenge(w, w.charlie, w.victim, CONTESTED, w.publisher)
    set_gateway(w, phash_at_distance(PHASH_BASE, 7))  # 4 bits of drift
    assert w.vm.run_validator() is False


def test_validator_rejects_a_verdict_flip_across_the_threshold(scenario):
    w = scenario
    serve(w, headers=w.auth_headers, body=b"mirror")
    set_gateway(w, phash_at_distance(PHASH_BASE, 10))
    r = challenge(w, w.charlie, w.victim, CONTESTED, w.publisher)
    assert r["verdict"] == "LEGITIMATE_MEDIA"
    set_gateway(w, phash_at_distance(PHASH_BASE, 11))
    assert w.vm.run_validator() is False


def test_validator_rejects_a_forged_leader_verdict(scenario):
    w = scenario
    serve(w)  # honest evidence: unsigned page claiming identity -> deepfake
    challenge(w, w.charlie, w.victim, CONTESTED, w.publisher)
    lie = {"reachable": True, "status": 200, "verdict": "LEGITIMATE_MEDIA", "sig": "INVALID", "exact": False, "trusted": False,
           "d_base": -1, "d_signed": -1}
    assert w.vm.run_validator(leader_result=lie) is False


def test_validator_rejects_a_leader_that_errored(scenario):
    w = scenario
    serve(w)
    challenge(w, w.charlie, w.victim, CONTESTED, w.publisher)
    assert w.vm.run_validator(leader_error=Exception("[LLM_ERROR] boom")) is False


def test_validator_rejects_a_malformed_leader_payload(scenario):
    w = scenario
    serve(w)
    challenge(w, w.charlie, w.victim, CONTESTED, w.publisher)
    assert w.vm.run_validator(leader_result={"verdict": "CONFIRMED_DEEPFAKE"}) is False
