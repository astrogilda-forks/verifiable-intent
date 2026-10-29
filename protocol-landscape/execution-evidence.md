# Execution Evidence

What a verifier can check after a VI chain has been used: that what executed is what the chain committed to.

> **Status**: Informative. Nothing on this page changes the core specification. The mapping is based on `agent-evidence-vectors` 0.30.0 and its approval-binding contract.

---

## The Gap

A VI chain proves what the user authorized and what the agent committed to. The L3b checkout mandate carries `checkout_hash`, and the L3a payment mandate carries the same value as `transaction_id`. After that, a merchant or network executes something. The chain on its own does not say whether the executed checkout is byte-identical to the committed one, or whether the same commitment was used twice.

Both questions are answered by comparing the executed bytes with the digest the chain already holds, and by keeping a record of commitments already consumed. An approval-binding record expresses exactly that comparison.

## Mapping

| VI field | Approval-binding field |
|---|---|
| L3b `checkout_hash` (SHA-256 of the checkout JWT, base64url) | `approval.payloadSha256` (the same digest, hex) and `approval.approvalId` |
| The executed checkout JWT | the bytes of `use.payloadFile` |
| L1 `sub` and the user key `kid` | `approval.principal` and `approval.keyId` |
| The merchant in the L3 fulfillment | `approval.target` |
| Commitments already honoured | `consumedApprovalIds` |

The reference reader checks, in order, the contract identifier, an ambiguous identifier, replay, the approver's key, the principal, the event and phase, the payload bytes, the validity window, and whether the policy release was served at decision time. It returns `allow` with reason `bound`, or `deny` with the first check that failed. `payload_mismatch` is the case of a different cart executed under an unchanged commitment, and `approval_replayed` is a second use of the same one.

## Running It

`tests/test_execution_evidence.py` builds the record from a real checkout JWT produced by the example helpers and runs four cases through the reader: bound, swapped cart, replayed commitment, and the hash definition itself. The package is pinned in the `dev` extra of `pyproject.toml`, so the existing CI job installs it, and the Dependabot entry added with it opens a pull request for each new release. The package needs Python 3.11 or newer, so the module is skipped on 3.10.

To run the wider corpus against your own verifier:

```bash
uvx agent-evidence-vectors==0.30.0 --list-corpora
```

## Open Questions This Does Not Settle

The mapping binds the executed checkout to the commitment. It does not say where the consumed-commitment set lives, who may write to it, or which party anchors the `iat` of each layer in a dispute. Those are questions for the specification, and this page leaves them there.
