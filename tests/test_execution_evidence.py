"""Judge a VI purchase at the moment it is dispatched.

A VI chain proves what the user authorized. It does not say whether that
authority still held, and whether the bytes sent to the merchant were the
bytes approved, when the agent acted. These tests project an Immediate-mode
chain into an authority-at-dispatch record and give it to the reference reader
of the pinned ``agent-evidence-vectors`` package, so the dispatch-time
decision (allow or deny, and the first check that fails) is reproducible
from the credentials alone. See docs/execution-evidence.md.

The package needs Python 3.11 or later. Where it is not installed the module
is skipped, unless ``VI_REQUIRE_EXECUTION_EVIDENCE`` is set, as it is in the
``execution-evidence`` CI job, where an import error fails the run.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest
from helpers import (
    MERCHANTS,
    PAYMENT_INSTRUMENT,
    checkout_hash_from_jwt,
    create_checkout_jwt,
    get_issuer_keys,
    get_merchant_keys,
    get_user_keys,
)

from verifiable_intent import (
    CheckoutMandate,
    IssuerCredential,
    MandateMode,
    PaymentMandate,
    UserMandate,
    create_layer1,
    create_layer2_immediate,
    verify_chain,
)
from verifiable_intent.crypto.disclosure import hash_bytes

try:
    from agent_evidence_vectors import authoritydispatch
except ImportError:
    if os.environ.get("VI_REQUIRE_EXECUTION_EVIDENCE"):
        raise
    pytest.skip(
        "agent-evidence-vectors is not installed; use pip install -e '.[evidence]'",
        allow_module_level=True,
    )

CHECKOUT_TOOL = "checkout.complete"
PAYMENT_TOOL = "payment.authorize"
L2_LIFETIME_SECONDS = 900


def _iso(timestamp: int) -> str:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class ImmediatePurchase:
    """An Immediate-mode L1 + L2 chain whose checkout the user confirmed."""

    def __init__(self) -> None:
        issuer, user, merchant = get_issuer_keys(), get_user_keys(), get_merchant_keys()
        self.merchant = merchant
        self.now = int(time.time())
        credential = IssuerCredential(
            iss="https://www.mastercard.com",
            sub="user-alice-001",
            iat=self.now,
            exp=self.now + 365 * 24 * 3600,
            pan_last_four="1234",
            scheme="Mastercard",
            cnf_jwk=user.public_jwk,
        )
        self.l1 = create_layer1(credential, issuer.private_key)
        l1_serialized = self.l1.serialize()

        self.checkout_jwt = create_checkout_jwt([{"sku": "BAB86345", "quantity": 1}], merchant)
        self.checkout_hash = checkout_hash_from_jwt(self.checkout_jwt)
        mandate = UserMandate(
            nonce="exec-evidence-1",
            aud="https://www.agent.com",
            iat=self.now,
            exp=self.now + L2_LIFETIME_SECONDS,
            mode=MandateMode.IMMEDIATE,
            sd_hash=hash_bytes(l1_serialized.encode("ascii")),
            checkout_mandate=CheckoutMandate(
                vct="mandate.checkout.1",
                checkout_jwt=self.checkout_jwt,
                checkout_hash=self.checkout_hash,
            ),
            payment_mandate=PaymentMandate(
                vct="mandate.payment.1",
                currency="USD",
                amount=27999,
                payee=MERCHANTS[0],
                payment_instrument=PAYMENT_INSTRUMENT,
                transaction_id=self.checkout_hash,
            ),
        )
        self.l2 = create_layer2_immediate(mandate, user.private_key).sd_jwt
        result = verify_chain(self.l1, self.l2, issuer_public_key=issuer.public_key, l1_serialized=l1_serialized)
        assert result.valid, result.errors

    def record(
        self,
        *,
        dispatched: bytes,
        decision_time: int | None = None,
        tool: str = CHECKOUT_TOOL,
        evidence_observed_at: int | None = None,
        max_evidence_age_seconds: int = 300,
        revoked_grants: tuple[dict[str, str], ...] = (),
    ) -> dict:
        """Project the chain into an authority-at-dispatch record.

        Hop 1 is the issuer's grant to the user (L1) and hop 2 the user's grant
        to the agent (L2), narrowed to the checkout. The approved bytes are the
        checkout JWT the user confirmed in L2.
        """
        decided = self.now + 60 if decision_time is None else decision_time
        observed = decided if evidence_observed_at is None else evidence_observed_at
        l1, l2 = self.l1.payload, self.l2.payload
        approved_sha256 = hashlib.sha256(self.checkout_jwt.encode("utf-8")).hexdigest()
        return {
            "contractId": authoritydispatch.CONTRACT_ID,
            "attempt": {"attemptId": "vi-immediate", "runId": "vi-example"},
            "decisionTime": _iso(decided),
            "approvedAction": {
                "tool": tool,
                "target": MERCHANTS[0]["id"],
                "payloadSha256": approved_sha256,
                "approvedAt": _iso(l2["iat"]),
            },
            "dispatch": {"tool": tool, "target": MERCHANTS[0]["id"], "payloadFile": "dispatched.bin"},
            "delegation": [
                {
                    "grantId": "vi-l1",
                    "grantor": l1["iss"],
                    "grantee": f"user:{l1['sub']}",
                    "notBefore": _iso(l1["iat"]),
                    "expiresAt": _iso(l1["exp"]),
                    "scope": [CHECKOUT_TOOL, PAYMENT_TOOL],
                },
                {
                    "grantId": "vi-l2",
                    "grantor": f"user:{l1['sub']}",
                    "grantee": l2["aud"],
                    "notBefore": _iso(l2["iat"]),
                    "expiresAt": _iso(l2["exp"]),
                    "scope": [CHECKOUT_TOOL, PAYMENT_TOOL] if tool == PAYMENT_TOOL else [CHECKOUT_TOOL],
                },
            ],
            "authorityEvidence": {
                "source": "vi-credential-validity-windows",
                "revision": "none",
                "observedAt": _iso(observed),
                "evidenceAgeSeconds": decided - observed,
                "maxAgeSeconds": max_evidence_age_seconds,
                "revokedGrants": list(revoked_grants),
            },
        }


@pytest.fixture(scope="module")
def purchase() -> ImmediatePurchase:
    return ImmediatePurchase()


def _judge(tmp_path: Path, record: dict, dispatched: bytes) -> dict[str, str]:
    (tmp_path / "dispatched.bin").write_bytes(dispatched)
    path = tmp_path / "record.json"
    path.write_text(json.dumps(record, indent=2, sort_keys=True), encoding="utf-8")
    return authoritydispatch.verify(path)


def test_approved_hash_is_the_checkout_hash_the_chain_carries(purchase: ImmediatePurchase):
    """The record's approved digest and VI's checkout_hash are one SHA-256 of the same bytes."""
    digest = hashlib.sha256(purchase.checkout_jwt.encode("utf-8")).digest()
    assert base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii") == purchase.checkout_hash


def test_dispatching_the_confirmed_checkout_is_authorized(tmp_path: Path, purchase: ImmediatePurchase):
    dispatched = purchase.checkout_jwt.encode("utf-8")
    verdict = _judge(tmp_path, purchase.record(dispatched=dispatched), dispatched)
    assert verdict == {"decision": "allow", "reason": "authorized"}


def test_checkout_changed_after_confirmation_is_refused(tmp_path: Path, purchase: ImmediatePurchase):
    """A merchant-signed checkout for two rackets is a different byte string than the one approved."""
    changed = create_checkout_jwt([{"sku": "BAB86345", "quantity": 2}], purchase.merchant).encode("utf-8")
    verdict = _judge(tmp_path, purchase.record(dispatched=changed), changed)
    assert verdict == {"decision": "deny", "reason": "dispatch_not_approved"}


def test_dispatch_after_the_l2_mandate_expires_is_refused(tmp_path: Path, purchase: ImmediatePurchase):
    dispatched = purchase.checkout_jwt.encode("utf-8")
    late = purchase.now + L2_LIFETIME_SECONDS + 1
    verdict = _judge(tmp_path, purchase.record(dispatched=dispatched, decision_time=late), dispatched)
    assert verdict == {"decision": "deny", "reason": "grant_expired"}


def test_tool_outside_the_narrowed_scope_is_refused(tmp_path: Path, purchase: ImmediatePurchase):
    """A record whose last hop does not list the tool being dispatched is refused."""
    dispatched = purchase.checkout_jwt.encode("utf-8")
    record = purchase.record(dispatched=dispatched, tool=PAYMENT_TOOL)
    record["delegation"][-1]["scope"] = [CHECKOUT_TOOL]
    verdict = _judge(tmp_path, record, dispatched)
    assert verdict == {"decision": "deny", "reason": "dispatch_not_approved"}


def test_revocation_reported_before_dispatch_is_refused(tmp_path: Path, purchase: ImmediatePurchase):
    """VI carries no revocation channel; a status source outside it can report one."""
    dispatched = purchase.checkout_jwt.encode("utf-8")
    revoked = ({"grantId": "vi-l1", "revokedAt": _iso(purchase.now + 30)},)
    verdict = _judge(tmp_path, purchase.record(dispatched=dispatched, revoked_grants=revoked), dispatched)
    assert verdict == {"decision": "deny", "reason": "grant_revoked"}


def test_stale_authority_evidence_is_refused(tmp_path: Path, purchase: ImmediatePurchase):
    dispatched = purchase.checkout_jwt.encode("utf-8")
    record = purchase.record(
        dispatched=dispatched,
        decision_time=purchase.now + 600,
        evidence_observed_at=purchase.now + 60,
        max_evidence_age_seconds=300,
    )
    verdict = _judge(tmp_path, record, dispatched)
    assert verdict == {"decision": "deny", "reason": "authority_evidence_stale"}
