"""Solvency: total_in == total_paid_out + liabilities, pull payouts, fee governance."""
import pytest
from conftest import *


def serve_forged(w, body=b"Ethereum Foundation announces the Merge airdrop!"):
    mock_page(w, r"impostor\.example", body=body)


def test_solvency_holds_through_a_full_lifecycle(scenario):
    w = scenario
    solvent(w)
    serve_forged(w)
    challenge(w, w.charlie, w.victim, CONTESTED, w.publisher)
    solvent(w)
    mock_page(w, r"cats\.example", body=b"cats")
    challenge(w, w.bob, w.victim, "https://cats.example/v", 0, ATTO)
    solvent(w)
    mock_page(w, r"down\.example", status=503)
    challenge(w, w.charlie, w.victim, "https://down.example/v", 0)
    s = solvent(w)
    assert s["total_in"] == 5 * ATTO + 20 * ATTO + (ATTO // 2 * 10300 // 10000) + ATTO * 10300 // 10000 \
        + (ATTO // 2 * 10300 // 10000)
    for who in (w.charlie, w.alice):
        w.vm.sender = who
        if w.c.get_claimable(who):
            w.c.claim_payout()
        solvent(w)


def test_claim_payout_pays_once_and_updates_totals(scenario):
    w = scenario
    serve_forged(w)
    r = challenge(w, w.charlie, w.victim, CONTESTED, w.publisher)
    owed = w.c.get_claimable(w.charlie)
    assert owed == r["bond"] + r["bounty"]
    w.vm.sender = w.charlie
    assert w.c.claim_payout() == owed
    assert w.c.get_claimable(w.charlie) == 0
    with w.vm.expect_revert("ERR_NO_CLAIMABLE_BALANCE"):
        w.c.claim_payout()
    s = solvent(w)
    assert s["total_paid_out"] == r["burned"] + owed


def test_claim_without_balance_is_rejected(world):
    world.vm.sender = world.bob
    with world.vm.expect_revert("ERR_NO_CLAIMABLE_BALANCE"):
        world.c.claim_payout()


def test_fee_withdrawal_moves_fees_to_governor_claimable(scenario):
    w = scenario
    mock_page(w, r"down\.example", status=503)
    challenge(w, w.charlie, w.victim, "https://down.example/v", 0, 10 * ATTO)
    fees = w.c.get_solvency()["protocol_fees"]
    assert fees == 10 * ATTO * 300 // 10000
    w.vm.sender = w.owner
    with w.vm.expect_revert("invalid fee amount"):
        w.c.withdraw_fees(fees + 1)
    with w.vm.expect_revert("invalid fee amount"):
        w.c.withdraw_fees(0)
    w.c.withdraw_fees(fees)
    s = solvent(w)
    assert s["protocol_fees"] == 0 and w.c.get_claimable(w.owner) == fees
    assert w.c.claim_payout() == fees
    solvent(w)


def test_stake_returns_and_slashes_stay_conserved(scenario):
    w = scenario
    serve_forged(w)
    challenge(w, w.charlie, w.victim, CONTESTED, w.publisher)
    w.vm.sender = w.bob
    w.c.request_withdrawal(w.publisher)
    warp(w, 7 * 86400 + 60)
    remaining = w.c.get_entity(w.publisher)["stake"]
    assert remaining == 10 * ATTO
    assert w.c.execute_withdrawal(w.publisher) == remaining
    assert w.c.claim_payout() == remaining
    solvent(w)


def test_slash_hits_a_stake_pending_withdrawal(scenario):
    """An exit request must not shield the stake from a challenge."""
    w = scenario
    w.vm.sender = w.bob
    w.c.request_withdrawal(w.publisher)
    serve_forged(w)
    r = challenge(w, w.charlie, w.victim, CONTESTED, w.publisher)
    assert r["slashed"] == 10 * ATTO
    assert w.c.get_entity(w.publisher)["stake"] == 10 * ATTO


def test_burn_plus_bounty_equals_slashed(scenario):
    w = scenario
    serve_forged(w)
    r = challenge(w, w.charlie, w.victim, CONTESTED, w.publisher)
    assert r["burned"] + r["bounty"] == r["slashed"]


def test_liabilities_never_exceed_inflow_and_nothing_is_minted(scenario):
    w = scenario
    serve_forged(w)
    challenge(w, w.charlie, w.victim, CONTESTED, w.publisher)
    s = w.c.get_solvency()
    assert s["total_locked"] + s["total_paid_out"] == s["total_in"]
    assert s["total_locked"] <= s["total_in"]


def test_protocol_overview_reports_counts_and_solvency(scenario):
    w = scenario
    ov = w.c.get_protocol_overview()
    assert ov["entities"] == 2 and ov["announcements"] == 1 and ov["challenges"] == 0
    assert ov["solvent"] is True and ov["status"] == "OPERATIONAL"
