# Engine architecture contracts

The core API separates immutable, shareable policy from isolated request state:

- `Waf.Builder` validates configuration before allocating a published `Waf`.
- A `Waf` has a stable address and may be shared by worker threads. Its mutable
  state is limited to atomic live-transaction and unique-sequence counters.
- Each `Transaction` belongs to one request and one worker at a time. It is not
  shared between threads.
- Connector calls have strict lifecycle ordering. Invalid transitions fail
  explicitly; reduced or unavailable features will follow the same rule.
- Header and body byte limits are checked before counters are incremented.
  Body writes count inspected bytes but do not imply in-memory buffering.
- Detection-only mode retains interventions and marks them non-enforcing so
  audit and diagnostics do not diverge from enabled mode.
- Scalar values have explicit origins and minimum phase availability. Common
  values use a 64-byte allocation-free fast path; larger values are copied into
  bounded transaction-owned storage.
- Timing combines a wall clock captured at transaction creation with a
  monotonic clock for `DURATION`. Applications may provide their Zig 0.17
  `std.Io` backend or a nonblocking, thread-safe clock callback.

Connection setup precedes SecLang evaluation and therefore has no public phase
number. The stable five rule phases are request headers (1), request body (2),
response headers (3), response body (4), and logging (5). Enforced disruptive
interventions mark the current phase interrupted; `drop` additionally terminates
inspection. Detection-only interventions preserve the same evidence without
interrupting execution. Logging remains available after a terminal intervention
and may be finalized exactly once.

`Runtime` publishes a fully validated replacement generation in one critical
operation. Existing transactions remain pinned to the retired generation and
new transactions use the replacement. A retired generation cannot be reclaimed
until its live transaction count reaches zero.

The normative ownership, allocator, error, feature-discovery, connector, and
reclamation rules are recorded in
[ADR 0001](adr/0001-ownership-concurrency-hot-reload.md).

The scalar compatibility and producer contract is documented in
[Scalar transaction variables](scalar-variables.md).
The keyed namespace, target, selector, and macro contract is documented in
[Collection variables](collections.md).
Cross-request collection storage, mutation, expiry, failure policy, and the
Pantry-linked LMDB backend are documented in
[Persistent collections](persistence.md).
The stable transformation union, ownership, bounded pipelines, caching, and
ModSecurity/Coraza profile byte semantics are documented in
[Transformation contracts](transformations.md).
The stable scalar and regex operator union, numeric parsing profiles, captures,
memoization, and bounded regex errors are documented in
[Operator contracts](operators.md).
The phrase (Aho-Corasick) and IP CIDR matcher operators, file loading, and
compatibility parsing are documented in
[Phrase and IP matcher contracts](matchers.md).
Query-string argument and cookie parsing, decoding, and separator configuration
are documented in
[Request-target parsing contracts](request-parsing.md).
