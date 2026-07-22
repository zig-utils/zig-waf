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

Executable evidence is recorded in
`src/compatibility/evidence/disruptive-flow-controls.json`. CI runs unit and
integration tests, the pinned five-root plan corpus, 10,000 deterministic action
fuzz cases, and ReleaseFast action benchmarks.
