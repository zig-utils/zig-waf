# Metadata and non-disruptive actions

WAF-14 compiles rule metadata and non-disruptive actions into immutable typed
plan ranges. Request processing never reparses action text. A transaction
preflights macro expansion, arithmetic, persistent mutations, scalar updates,
collection replacements, captures, and owned event evidence before publishing
any local state.

## Application API

`Transaction.applyMatchedRule` accepts a standalone compiled rule and borrowed
`MatchContext`. `Transaction.applyMatchedChain` requires the exact compiled
head-to-tail sequence; partial, missing, duplicated, or reordered members are
rejected before effects. Local-only variants stage persistent actions as
explicit pending work and are intended for connectors that own persistence
coordination.

Successful application returns `LocalEffectOutcome` with a stable
`MatchIntentId`. `matchIntent` exposes transaction-owned, immutable evidence:
the selected/head identity, severity, post-action expanded message, log data,
ordered tags, matched name/value/source, log and audit choices, capture count,
effect count, and pending-persistence count. It performs no audit, telemetry,
network, filesystem, UI, or database output.

## Ordering and atomicity

Effective WAF-13 action ranges execute in source order. RULE metadata is staged
first. Later actions see earlier TX, ENV, persistent-collection, and identity
scalar writes. Message, log data, and tags expand after all members complete.
`capture` replaces TX.0 through TX.9 as a set, clearing stale optional groups.

Collection and scalar storage use allocation-complete commit primitives.
Persistent sessions take a checkpoint before a rule or chain. Any syntax,
macro, capacity, arithmetic, timestamp, allocation, or backend-policy error
leaves local state, event intent, bindings, mutation logs, and decay clocks at
the preflight boundary.

## Persistent behavior

`initcol`, `setsid`, `setuid`, and `setrsc` bind the five supported persistent
namespaces. Assignment, deletion, and checked signed addition/subtraction are
revisioned mutations. `expirevar` stores an absolute deadline derived from the
injected clock. `deprecatevar` records amount, period, and observation time;
the backend recomputes whole-period decay against its authoritative revision,
including after conflicts. Values clamp at zero, partial periods are retained,
and remove/recreate resets the decay clock.

Production never substitutes an in-memory backend. Missing, unavailable,
timed-out, corrupt, exhausted, or conflicting persistence follows the builder's
explicit fail-open/fail-closed policy and remains observable through
`lastPersistentFailure`.

## Limits and qualification

Independent limits cover match names/values, captures, macro output, scalar and
collection storage, persistent records/mutations, intent count, and aggregate
intent bytes. The executable qualification commands are:

```sh
zig build test --summary all
zig build fuzz-actions -Daction-fuzz-iterations=10000
zig build bench-actions -Doptimize=ReleaseFast
zig build test-plan-corpus -Dplan-corpus=<repeatable-path>
```

Pinned upstream paths, revisions, fixture mappings, fuzz parameters, corpus
counts, and measured benchmark values are embedded in
`src/compatibility/evidence/non-disruptive-actions.json`.
