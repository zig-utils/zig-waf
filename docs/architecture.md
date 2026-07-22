# Engine architecture contracts

The core API separates immutable, shareable policy from isolated request state:

- `Waf.Builder` validates configuration before allocating a published `Waf`.
- A `Waf` has a stable address and may be shared by worker threads. Its only
  mutable field is an atomic live-transaction count used to prevent premature
  destruction.
- Each `Transaction` belongs to one request and one worker at a time. It is not
  shared between threads.
- Connector calls have strict lifecycle ordering. Invalid transitions fail
  explicitly; reduced or unavailable features will follow the same rule.
- Header and body byte limits are checked before counters are incremented.
  Body writes count inspected bytes but do not imply in-memory buffering.
- Detection-only mode retains interventions and marks them non-enforcing so
  audit and diagnostics do not diverge from enabled mode.

`Runtime` publishes a fully validated replacement generation in one critical
operation. Existing transactions remain pinned to the retired generation and
new transactions use the replacement. A retired generation cannot be reclaimed
until its live transaction count reaches zero.

The normative ownership, allocator, error, feature-discovery, connector, and
reclamation rules are recorded in
[ADR 0001](adr/0001-ownership-concurrency-hot-reload.md).
