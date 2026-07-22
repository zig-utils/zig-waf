# Disruptive, flow, and runtime control actions

WAF-15 compiles disruptive decisions, flow metadata, and runtime controls into
immutable plan ABI 6. A matched standalone rule or complete chain stages these
decisions together with WAF-14 metadata, captures, TX/ENV writes, persistent
mutations, and owned event evidence. Expansion, lifecycle, capability,
persistence, allocation, or intervention errors publish none of that state.

The runtime supports `allow` (transaction, request, and phase scope), `block`,
`deny`, `drop`, `pass`, capability-gated `proxy`, `redirect`, and `status`.
`block` resolves its phase default during compilation. Redirect status falls
back to 302 unless it is 301, 302, 303, or 307. Detection-only decisions retain
the same owned evidence but do not interrupt a phase or terminate inspection.

`PhaseCursor` traverses immutable same-phase chain heads without steady-state
allocation. Numeric `skip` counts only executable heads. Static and dynamic
`skipAfter` values resolve to the first later same-name marker; dynamic values
see effects staged by the matching rule. All allow scopes leave phase-5 logging
reachable.

Transaction-local controls cover rule engine, audit engine and parts, request
body access/limit/processor, force-request-body, response-body access, rule ID
and tag exclusions, and exact or regex-delimited target exclusions by ID or
tag. Body controls reject changes after their consumption boundary. Exclusions
are bounded by count and owned bytes and affect only subsequent evaluation.
Regex target selectors compile through the pinned `zig-regex` dependency and
use pointer-stable compiled programs with isolated per-transaction workers;
matcher limits surface as explicit transaction errors.

The connector ABI reserves explicit pause capability/intervention tags so a
connector cannot silently treat pause as pass. Parsing a duration, enforcing a
configured duration bound, and scheduling nonblocking pause execution are
owned by WAF-21; WAF-15 does not publish a partially functional pause action.

Executable evidence is recorded in
`src/compatibility/evidence/disruptive-flow-controls.json`. CI runs unit and
integration tests, the pinned five-root plan corpus, 10,000 deterministic action
fuzz cases, and ReleaseFast action benchmarks.

The closing ReleaseFast run on the development host (5,000 iterations per
scenario) measured the no-op cursor at p99 250 ns with zero operation
allocations, dynamic `skipAfter` at p99 42 ns with zero operation allocations,
and exclusion-heavy traversal plus a regex target probe at p99 292 ns. The last
scenario records four bounded first-use matcher-cache allocations (142 bytes)
per transaction; cursor traversal itself only advances immutable plan slices
and transaction-local counters.

The implementation gate passed the complete hosted workflow on commit
`0b803704e22b8c5b86c4f4927fe555d3542fb83f`, including dependency-lock and
no-submodule checks, 219 tests, the pinned CRS/ModSecurity/Coraza corpora,
10,000-case fuzz steps, and all ReleaseFast benchmarks.
