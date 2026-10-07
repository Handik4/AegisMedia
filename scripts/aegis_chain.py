"""Shared GenLayer Studio Next client helpers for the deploy / verify scripts.

All amounts are atto-scale wei. Keys live in `.env` (gitignored): the script
generates throwaway keys on first use and funds them from the Studio faucet, so
no real credentials are ever required.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

from eth_account import Account
from genlayer_py import create_client
from genlayer_py.chains import studio_devnet  # type: ignore[reportAttributeAccessIssue]

ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = ROOT / ".env"
DEPLOYMENT_JSON = ROOT / "frontend" / "lib" / "deployment.json"
CONTRACT_FILE = ROOT / "contracts" / "aegis_media.py"
ATTO = 10**18
CHAIN_ID = 61997

OK_EXEC = "FINISHED_WITH_RETURN"
OK_CONSENSUS = "MAJORITY_AGREE"


class ChainError(Exception):
    pass


# --------------------------------------------------------------------- env
def _read_env() -> dict[str, str]:
    out: dict[str, str] = {}
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip()
    return out


def get_or_create_key(name: str) -> str:
    """A hex private key stored under `name` in .env, generated on first use."""
    env = _read_env()
    if name in os.environ:
        return os.environ[name]
    if name not in env:
        env[name] = Account.create().key.hex().removeprefix("0x")
        ENV_FILE.write_text("\n".join(f"{k}={v}" for k, v in env.items()) + "\n")
        ENV_FILE.chmod(0o600)
    key = env[name]
    return key if key.startswith("0x") else "0x" + key


# ------------------------------------------------------------------- retry
def retry(fn, attempts: int = 4, wait_s: float = 5.0):
    last: Exception | None = None
    for i in range(attempts):
        try:
            return fn()
        except ChainError:
            raise
        except Exception as exc:  # noqa: BLE001 - transient transport failures
            last = exc
            if i + 1 < attempts:
                time.sleep(wait_s * (i + 1))
    raise ChainError(f"transient RPC failure after {attempts} attempts: {last}")


def _fees_from(estimate: dict) -> dict:
    fees: dict = {
        "distribution": estimate["distribution"],
        "feeValue": estimate.get("feeValue") or estimate.get("fee_value") or 0,
    }
    if estimate.get("messageAllocations") is not None:
        fees["messageAllocations"] = estimate["messageAllocations"]
    return fees


def _policy_fee_estimate(client) -> dict:
    from genlayer_py.contracts.actions import (  # noqa: PLC0415
        _estimate_transaction_fees_with_policy,
        get_current_fee_policy,
    )

    return _estimate_transaction_fees_with_policy(client, None, get_current_fee_policy(client))


# ------------------------------------------------------------------- chain
class Chain:
    """A client bound to one account (and, once known, one contract)."""

    def __init__(self, private_key: str, contract: str | None = None):
        self.account = Account.from_key(private_key)
        self.client = create_client(chain=studio_devnet, account=self.account)
        self.contract = contract

    @property
    def address(self) -> str:
        return self.account.address

    def balance(self) -> int:
        def call():
            resp = self.client.provider.make_request("eth_getBalance", [self.address, "latest"])
            return int(resp.get("result", "0x0"), 16)

        return retry(call)

    def ensure_funds(self, target_wei: int) -> None:
        """Top up from the Studio faucet until the account holds `target_wei`."""
        current = self.balance()
        if current < target_wei:
            retry(lambda: self.client.fund_account(self.address, target_wei - current + 1))

    def read(self, method: str, args: list | None = None) -> Any:
        return retry(lambda: self.client.read_contract(self.contract, method, args=args or []))

    def _fees(self, method: str, args: list, value: int) -> dict:
        try:
            est = self.client.estimate_transaction_fees_for_write(self.contract, method, args=args, value=value)
        except Exception:  # noqa: BLE001 - simulation clock differs from the block clock
            est = _policy_fee_estimate(self.client)
        return _fees_from(est)

    def _wait(self, tx_hash, label: str) -> dict:
        receipt = retry(
            lambda: self.client.wait_for_transaction_receipt(
                tx_hash, wait_until="decided", interval=4, retries=150  # type: ignore[reportCallIssue]
            ),
            attempts=3,
        )
        exec_name = receipt.get("txExecutionResultName") or receipt.get("tx_execution_result_name")
        consensus = receipt.get("result_name")
        if exec_name is not None and exec_name != OK_EXEC:
            raise ChainError(f"{label}: execution failed ({exec_name})")
        if consensus is not None and consensus != OK_CONSENSUS:
            raise ChainError(f"{label}: consensus {consensus}")
        receipt["_tx_hash"] = tx_hash
        return receipt

    def write(self, method: str, args: list | None = None, value: int = 0) -> dict:
        args = args or []
        fees = self._fees(method, args, value)
        # Submissions are never retried: a duplicate write would duplicate state.
        tx_hash = self.client.write_contract(self.contract, method, args=args, value=value, fees=fees)
        print(f"  tx {method}: {str(tx_hash)[:18]}… waiting for consensus")
        return self._wait(tx_hash, method)

    def deploy(self, code: bytes) -> str:
        fees = _fees_from(_policy_fee_estimate(self.client))
        tx_hash = self.client.deploy_contract(code=code, args=[], fees=fees)
        print(f"  deploy tx {str(tx_hash)[:18]}… waiting for consensus")
        receipt = self._wait(tx_hash, "deploy")
        data = receipt.get("data") or {}
        decoded = receipt.get("txDataDecoded") or receipt.get("tx_data_decoded") or {}
        addr = (
            data.get("contract_address")
            or decoded.get("contractAddress")
            or receipt.get("contract_address")
            or receipt.get("contractAddress")
        )
        if not addr:
            raise ChainError(f"deploy receipt carried no contract address: {json.dumps(receipt, default=str)[:400]}")
        self.contract = addr
        return addr

    def tx_result(self, receipt: dict) -> Any:
        """Decoded transaction (for return values)."""
        return self.client.get_transaction(receipt["_tx_hash"])


def load_deployment() -> dict:
    return json.loads(DEPLOYMENT_JSON.read_text())


def save_deployment(address: str, tx: str | None) -> None:
    DEPLOYMENT_JSON.write_text(
        json.dumps(
            {
                "address": address,
                "network": "studio-next",
                "chainId": CHAIN_ID,
                "deployedAt": int(time.time()),
                "deployTx": tx,
            },
            indent=2,
        )
        + "\n"
    )
