#!/usr/bin/env python3
"""Deploy AegisMedia to GenLayer Studio Next, seed two demo entities and sync the frontend.

    .venv/bin/python scripts/deploy.py

Keys: a throwaway deployer key and two seed signing keys are generated into `.env`
on first run (gitignored) and funded from the Studio faucet. Override with
AEGIS_DEPLOYER_KEY / AEGIS_SEED_KEY_EF / AEGIS_SEED_KEY_GUARD in the environment.
"""

import sys

from eth_account import Account

from aegis_chain import ATTO, CONTRACT_FILE, Chain, get_or_create_key, save_deployment

SEED_STAKE = 5 * ATTO
SEEDS = [
    {"key": "AEGIS_SEED_KEY_EF", "name": "Ethereum Foundation", "domain": "ethereum.org", "handle": "@ethereum"},
    {"key": "AEGIS_SEED_KEY_GUARD", "name": "Vitalik Impersonation Guard", "domain": "vitalik-guard.org", "handle": "@VitalikGuard"},
]


def main() -> int:
    deployer = Chain(get_or_create_key("AEGIS_DEPLOYER_KEY"))
    print(f"deployer {deployer.address}")
    deployer.ensure_funds(40 * ATTO)  # seed stakes + fees

    print("deploying contracts/aegis_media.py to Studio Next (chain 61997)…")
    address = deployer.deploy(CONTRACT_FILE.read_bytes())
    print(f"deployed at {address}")
    save_deployment(address, None)

    for seed in SEEDS:
        signer = Account.from_key(get_or_create_key(seed["key"])).address.lower()
        print(f"registering {seed['name']} (signer {signer})")
        deployer.write(
            "register_entity",
            [seed["name"], seed["domain"], seed["handle"], signer],
            value=SEED_STAKE,
        )

    overview = deployer.read("get_protocol_overview")
    print(f"protocol overview: {overview}")
    print("frontend/lib/deployment.json updated; the dashboard now reads this contract live.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
