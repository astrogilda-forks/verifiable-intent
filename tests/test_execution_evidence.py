"""Execution evidence: the checkout that runs is the checkout the chain committed to.

An L3 checkout mandate commits to a checkout by hash (``checkout_hash``, also the
``transaction_id`` of the L3 payment mandate). Whatever executes later has to be
those same bytes. These tests express that rule as an approval-binding record and
run it through the reference reader of the pinned ``agent-evidence-vectors``
package (see ``[project.optional-dependencies] dev`` in ``pyproject.toml``).

The package needs Python 3.11 or newer, so the module is skipped on 3.10.
"""

from __future__ import annotations

import base64
import hashlib
import json

import pytest

from helpers import checkout_hash_from_jwt, create_checkout_jwt, get_merchant_keys

approvalbinding = pytest.importorskip("agent_evidence_vectors.approvalbinding")

NOW = "2026-10-29T12:00:00Z"
TARGET = "https://tennis-warehouse.com"
PRINCIPAL = "user:user-alice-001"
KEY_ID = "user-device-key-1"


def _record(checkout_jwt: str, consumed: tuple[str, ...] = ()) -> dict:
    """An approval-binding record whose approval is the chain's checkout commitment."""
    committed_hash = checkout_hash_from_jwt(checkout_jwt)
    digest = base64.urlsafe_b64decode(committed_hash + "=" * (-len(committed_hash) % 4))
    approval = {
        "approvalId": committed_hash,
        "approver": PRINCIPAL,
        "clientId": "agent-key-1",
        "event": "checkout",
        "expiresAt": "2026-10-29T12:05:00Z",
        "issuedAt": "2026-10-29T11:55:00Z",
        "keyId": KEY_ID,
        "payloadSha256": digest.hex(),
        "phase": "pre-execution",
        "principal": PRINCIPAL,
        "target": TARGET,
        "tool": "checkout.complete",
    }
    return {
        "approval": approval,
        "consumedApprovalIds": list(consumed),
        "contractId": approvalbinding.CONTRACT_ID,
        "decisionTime": NOW,
        "policyRelease": {
            "firstServedAt": "2026-10-29T09:00:00Z",
            "graceSeconds": 300,
            "lastServedAt": "2026-10-29T12:30:00Z",
            "lookup": "ok",
            "releaseId": "policy-release-1",
        },
        "presentedApprovals": [approval],
        "trustedKeys": {PRINCIPAL: KEY_ID},
        "use": {
            "approvalId": committed_hash,
            "clientId": "agent-key-1",
            "event": "checkout",
            "payloadFile": "payload.bin",
            "phase": "pre-execution",
            "principal": PRINCIPAL,
            "target": TARGET,
            "tool": "checkout.complete",
            "usedAt": NOW,
        },
    }


def _verify(tmp_path, record: dict, executed_jwt: str) -> dict:
    (tmp_path / "payload.bin").write_bytes(executed_jwt.encode("utf-8"))
    path = tmp_path / "record.json"
    path.write_text(json.dumps(record), encoding="utf-8")
    return approvalbinding.verify(path)


def test_committed_checkout_hash_is_sha256_of_the_jwt():
    jwt = create_checkout_jwt([{"sku": "BAB86345", "quantity": 1}], get_merchant_keys())
    digest = hashlib.sha256(jwt.encode("utf-8")).digest()
    assert checkout_hash_from_jwt(jwt) == base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def test_executed_checkout_matching_the_commitment_is_allowed(tmp_path):
    jwt = create_checkout_jwt([{"sku": "BAB86345", "quantity": 1}], get_merchant_keys())
    assert _verify(tmp_path, _record(jwt), jwt) == {"decision": "allow", "reason": "bound"}


def test_a_different_cart_under_the_same_commitment_is_denied(tmp_path):
    keys = get_merchant_keys()
    committed = create_checkout_jwt([{"sku": "BAB86345", "quantity": 1}], keys)
    swapped = create_checkout_jwt([{"sku": "HEA23102", "quantity": 1}], keys)
    assert _verify(tmp_path, _record(committed), swapped) == {"decision": "deny", "reason": "payload_mismatch"}


def test_a_checkout_that_already_ran_cannot_run_again(tmp_path):
    jwt = create_checkout_jwt([{"sku": "BAB86345", "quantity": 1}], get_merchant_keys())
    record = _record(jwt, consumed=(checkout_hash_from_jwt(jwt),))
    assert _verify(tmp_path, record, jwt) == {"decision": "deny", "reason": "approval_replayed"}
