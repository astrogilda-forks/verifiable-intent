# Protocol Landscape

The Verifiable Intent (VI) core specification (`spec/`) is intentionally
protocol-agnostic. It defines credential formats, delegation chains, and
verification procedures without referencing any particular payment protocol or
agent framework.

> **Protocol versions**: The pages in this section are based on the Universal
> Commerce Protocol (UCP) specification as of 23 January 2026, the Agent Payments
> Protocol (AP2) specification as of 16 September 2025, and the Agentic Commerce
> Protocol (ACP) specification as of 30 January 2026.

The [Protocol Ecosystem](protocols.md) page explains VI's relationship to
existing agentic commerce protocols. UCP and ACP handle payment transport; VI
handles authorization proof. The page covers specific integration points for each
protocol (UCP's AP2 Mandates Extension and ACP's extension mechanism) and why VI
credentials ride alongside either without transport-layer changes.

The [Cross-Protocol Glossary](glossary.md) provides detailed term-by-term
mappings across VI, UCP/AP2, and ACP. Tables cover roles, credential layers,
execution flows, integrity mechanisms, and all five registered VI constraint
types. Recurrence mapping is documented separately as a top-level payment mandate
field (not a constraint). Reverse
mappings list UCP/AP2 and ACP terms that have no VI equivalent, with explanations
of why.

The [Execution Evidence](execution-evidence.md) page maps the L3 checkout commitment
onto an approval-binding record, so a verifier can check that the checkout that ran
is the checkout the chain committed to. A test in `tests/` runs that check through
a pinned third-party reader.

## Contributing

To propose an integration mapping for a new protocol:

1. Open an issue describing the target protocol, its relevance to agentic
   commerce, and the expected audience.
2. Reference the glossary for shared terminology and add new columns for your
   protocol where applicable.
