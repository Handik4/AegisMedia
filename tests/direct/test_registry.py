"""Entity registration, stake accounting and withdrawal cooldowns."""
import pytest
from conftest import *

DAY = 86400


def test_register_entity_records_identity_and_stake(world):
    w = world
    eid = register(w, w.alice, "Ethereum Foundation", "Ethereum.ORG", "@ethereum", KEY_FOUNDATION, 7 * ATTO)
    e = w.c.get_entity(eid)
    assert eid == 1 and e["name"] == "Ethereum Foundation"
    assert e["domain"] == "ethereum.org"  # normalised to lowercase
    assert e["handle"] == "@ethereum" and e["signer"] == signer_of(KEY_FOUNDATION)
    assert e["stake"] == 7 * ATTO and e["status"] == "ACTIVE" and e["alert"] == "CLEAR"
    assert w.c.get_entity_count() == 1
    assert solvent(w)["entity_stakes"] == 7 * ATTO


def test_stake_below_minimum_is_rejected(world):
    w = world
    w.vm.sender, w.vm.value = w.alice, MIN_STAKE - 1
    with w.vm.expect_revert("ERR_INSUFFICIENT_STAKE"):
        w.c.register_entity("Foundation", "ethereum.org", "@eth", signer_of(KEY_FOUNDATION))


def test_exact_minimum_stake_is_accepted(world):
    assert register(world, world.alice, "Foundation", "ethereum.org", "@eth", KEY_FOUNDATION, MIN_STAKE) == 1


def test_duplicate_domain_is_rejected_case_insensitively(world):
    w = world
    register(w, w.alice, "A One", "ethereum.org", "@a", KEY_FOUNDATION)
    w.vm.sender, w.vm.value = w.bob, MIN_STAKE
    with w.vm.expect_revert("domain already registered"):
        w.c.register_entity("A Two", "ETHEREUM.org", "@b", signer_of(KEY_GUARD))


def test_duplicate_handle_is_rejected_case_insensitively(world):
    w = world
    register(w, w.alice, "A One", "one.org", "@Ethereum", KEY_FOUNDATION)
    w.vm.sender, w.vm.value = w.bob, MIN_STAKE
    with w.vm.expect_revert("handle already registered"):
        w.c.register_entity("A Two", "two.org", "@ETHEREUM", signer_of(KEY_GUARD))


@pytest.mark.parametrize("domain", ["", "nodot", "-bad.org", "bad-.org", "sp ace.org", "a..b.org", "x" * 130 + ".org"])
def test_invalid_domains_are_rejected(world, domain):
    w = world
    w.vm.sender, w.vm.value = w.alice, MIN_STAKE
    with w.vm.expect_revert("ERR_INVALID_INPUT"):
        w.c.register_entity("Valid Name", domain, "@h", signer_of(KEY_FOUNDATION))


@pytest.mark.parametrize("signer", ["", "0x1234", "zz" * 20, "0x" + "ab" * 21])
def test_invalid_signer_is_rejected(world, signer):
    w = world
    w.vm.sender, w.vm.value = w.alice, MIN_STAKE
    with w.vm.expect_revert("ERR_INVALID_INPUT"):
        w.c.register_entity("Valid Name", "valid.org", "@h", signer)


@pytest.mark.parametrize("name", ["", "x" * 65, "bad\nname"])
def test_invalid_names_are_rejected(world, name):
    w = world
    w.vm.sender, w.vm.value = w.alice, MIN_STAKE
    with w.vm.expect_revert("ERR_INVALID_INPUT"):
        w.c.register_entity(name, "valid.org", "@h", signer_of(KEY_FOUNDATION))


def test_registration_ids_and_pagination(world):
    w = world
    for i in range(5):
        register(w, w.alice, f"Entity {i}", f"entity{i}.org", f"@e{i}", KEY_FOUNDATION)
    page = w.c.list_entities(1, 2)
    assert [e["id"] for e in page] == [2, 3]
    assert len(w.c.list_entities(0, 100)) == 5
    assert w.c.list_entities(5, 10) == []
    assert w.c.find_entity_by_domain("ENTITY3.org") == 4
    assert w.c.find_entity_by_domain("missing.org") == 0


def test_top_up_increases_stake_and_liabilities(world):
    w = world
    eid = register(w, w.alice, "Foundation", "ethereum.org", "@eth", KEY_FOUNDATION)
    w.vm.sender, w.vm.value = w.alice, 3 * ATTO
    w.c.top_up_stake(eid)
    assert w.c.get_entity(eid)["stake"] == 8 * ATTO
    assert solvent(w)["total_in"] == 8 * ATTO


def test_top_up_by_non_owner_is_rejected(world):
    w = world
    eid = register(w, w.alice, "Foundation", "ethereum.org", "@eth", KEY_FOUNDATION)
    w.vm.sender, w.vm.value = w.bob, ATTO
    with w.vm.expect_revert("ERR_UNAUTHORIZED"):
        w.c.top_up_stake(eid)


def test_withdrawal_cooldown_blocks_early_exit(world):
    w = world
    eid = register(w, w.alice, "Foundation", "ethereum.org", "@eth", KEY_FOUNDATION)
    w.vm.sender = w.alice
    available = w.c.request_withdrawal(eid)
    assert available >= now_ts() + 7 * DAY - 5
    assert w.c.get_entity(eid)["status"] == "WITHDRAWING"
    with w.vm.expect_revert("ERR_COOLDOWN"):
        w.c.execute_withdrawal(eid)
    warp(w, 7 * DAY - 60)
    with w.vm.expect_revert("ERR_COOLDOWN"):
        w.c.execute_withdrawal(eid)


def test_withdrawal_after_cooldown_pays_through_claimable(world):
    w = world
    eid = register(w, w.alice, "Foundation", "ethereum.org", "@eth", KEY_FOUNDATION, 9 * ATTO)
    w.vm.sender = w.alice
    w.c.request_withdrawal(eid)
    warp(w, 7 * DAY + 60)
    assert w.c.execute_withdrawal(eid) == 9 * ATTO
    s = solvent(w)
    assert s["entity_stakes"] == 0 and s["claimable"] == 9 * ATTO
    assert w.c.claim_payout() == 9 * ATTO
    s = solvent(w)
    assert s["total_paid_out"] == 9 * ATTO and s["total_locked"] == 0


def test_withdrawal_can_be_cancelled_and_restores_authority(world):
    w = world
    eid = register(w, w.alice, "Foundation", "ethereum.org", "@eth", KEY_FOUNDATION)
    w.vm.sender = w.alice
    w.c.request_withdrawal(eid)
    w.c.cancel_withdrawal(eid)
    assert w.c.get_entity(eid)["status"] == "ACTIVE"
    with w.vm.expect_revert("no withdrawal pending"):
        w.c.cancel_withdrawal(eid)


def test_withdrawal_requires_owner_and_state(world):
    w = world
    eid = register(w, w.alice, "Foundation", "ethereum.org", "@eth", KEY_FOUNDATION)
    w.vm.sender = w.bob
    with w.vm.expect_revert("ERR_UNAUTHORIZED"):
        w.c.request_withdrawal(eid)
    w.vm.sender = w.alice
    with w.vm.expect_revert("no withdrawal pending"):
        w.c.execute_withdrawal(eid)
    w.c.request_withdrawal(eid)
    with w.vm.expect_revert("already requested"):
        w.c.request_withdrawal(eid)


def test_top_up_blocked_while_withdrawing(world):
    w = world
    eid = register(w, w.alice, "Foundation", "ethereum.org", "@eth", KEY_FOUNDATION)
    w.vm.sender = w.alice
    w.c.request_withdrawal(eid)
    w.vm.value = ATTO
    with w.vm.expect_revert("withdrawal pending"):
        w.c.top_up_stake(eid)


def test_unknown_entity_queries(world):
    with world.vm.expect_revert("unknown entity"):
        world.c.get_entity(99)
    assert world.c.is_impersonation_active(99) is False


def test_governor_is_deployer_and_gated(world):
    w = world
    eid = register(w, w.alice, "Foundation", "ethereum.org", "@eth", KEY_FOUNDATION)
    w.vm.sender = w.bob
    with w.vm.expect_revert("governor only"):
        w.c.set_verified(eid, True)
    with w.vm.expect_revert("governor only"):
        w.c.set_phash_gateway("https://gw.example.org/p")
    with w.vm.expect_revert("governor only"):
        w.c.withdraw_fees(1)
    with w.vm.expect_revert("governor only"):
        w.c.transfer_governor("0x" + "ab" * 20)
    w.vm.sender = w.owner
    w.c.set_verified(eid, True)
    assert w.c.get_entity(eid)["verified"] is True
    w.c.set_phash_gateway("https://gw.example.org/p")
    assert w.c.get_config()["phash_gateway"] == "https://gw.example.org/p"
    with w.vm.expect_revert("ERR_UNSAFE_URL"):
        w.c.set_phash_gateway("http://127.0.0.1/p")
    with w.vm.expect_revert("zero address"):
        w.c.transfer_governor("0x" + "00" * 20)
