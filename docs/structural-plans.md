# Immutable structural execution plans

WAF-11 turns one or more owned SecLang documents into a bounded, immutable
execution plan. Parsing remains the WAF-10 syntax boundary; WAF-12 and later
issues validate and execute the complete directive/action/operator registry.
Unknown directives and actions remain addressable metadata and never become an
implicit claim of support.

## Compilation and ownership

`plan.compile` returns one owned `*Plan` or a typed error. `compileOutcome`
returns either a complete plan or a stable `WAF-PLAN-*` diagnostic with a
primary and optional related source span. No partially built plan can be
published. The plan owns its source bytes, line indexes, strings, rule graph,
indexes, prefilters, and macro programs, so parser documents and their source
registry may be destroyed immediately after compilation.

Every mutable compiler collection is temporary. Published data is stored in
compact contiguous slices addressed by typed 32-bit IDs. A plan handle owns one
reference to an immutable payload. `Plan.retain` creates another handle;
`compileWithPrevious` shares the prior payload only after a BLAKE3 fast reject
and field-wise equality over every owned source, string, descriptor, graph, and
index. The payload reference count is atomic, and equivalent generations may be
destroyed in either order while other threads read them.

`Waf.Builder.setRetainedPlan` retains a caller-owned plan on successful build.
`buildTransferringPlan` transfers the supplied handle only on success. A WAF
releases its plan after its final transaction drains. Runtime reload publishes
only an already-built WAF; old transactions continue to expose their original
plan and new transactions see the replacement.

## Structural representation

The plan preserves directive, argument, target, operator, action, and rule
source order. It exposes:

- five phase indexes containing only chain heads;
- explicit chain head, next, and position fields for every member;
- phase-scoped `SecDefaultAction` snapshot identity, with unphased rules
  remaining in phase 2;
- ordered effective transformation pipelines with `t:none` reset behavior;
- strict unsigned 64-bit external IDs and duplicate-definition diagnostics;
- target collection, selector, and modifier descriptors;
- action-family tags for transformations, metadata, non-disruptive,
  disruptive, flow, and unknown actions;
- addressable marker and generic-directive indexes;
- conservative exact, prefix, suffix, contains, phrase-any, and literal-regex
  prefilters; and
- deduplicated runtime macro programs for operator parameters and action
  values.

Prefilters are rejection-only hints. `prefilterMayMatch` returning `true` still
requires normal operator execution. Negated operators, dynamic macro-bearing
parameters, quoted/escaped phrase lists, and non-literal regexes deliberately
receive no prefilter. This makes absence conservative and prevents an
optimization from changing matching behavior.

Macro programs split literals from `%{SCALAR}` and `%{COLLECTION.key}` tokens at
configuration time. Token ranges, names, and keys are owned by the plan;
requests never parse macro syntax. Unknown names remain structural so WAF-12
can apply the complete compatibility registry. Unterminated and empty
expressions are source-anchored configuration diagnostics.

## Identity and diagnostics

The public 32-byte fingerprint is BLAKE3 over typed semantic values and
resolved string bytes. It is domain-separated by compiler ABI version 2 and
does not include allocator addresses, native struct padding, filesystem paths,
or source offsets. Identical ordered configuration at unrelated paths therefore
has the same public identity. The compiler ABI must change whenever the
canonical structural interpretation changes.

Semantic failures use stable codes:

| Code | Meaning |
| --- | --- |
| `WAF-PLAN-0101` | Invalid or overflowing rule ID |
| `WAF-PLAN-0102` | Duplicate rule ID; related span is the first definition |
| `WAF-PLAN-0103` | Invalid phase |
| `WAF-PLAN-0104` | Dangling or cross-boundary chain |
| `WAF-PLAN-0105` | Chain phase disagreement |
| `WAF-PLAN-0106` | Transformation without a name |
| `WAF-PLAN-0107` | Unterminated macro |
| `WAF-PLAN-0108` | Empty macro expression |
| `WAF-PLAN-0109` | Action is not permitted in `SecDefaultAction` |
| `WAF-PLAN-0110` | Duplicate default for a phase; related span is the first definition |
| `WAF-PLAN-0111` | Default is missing a disruptive action |

Default actions require an explicit phase and a disruptive action. A phase may
be defined once per compiled configuration context. Metadata and flow actions,
duplicate phase actions, and `t:none` are rejected before publication. Rules
inherit only the snapshot for their effective phase; explicit per-rule
transformations retain the ModSecurity-compatible `t:none` reset behavior.

Allocation and configured capacity failures remain distinct typed errors.

## Resource limits and verification

`plan.Limits` independently bounds documents, source references, directives,
rules, rules per phase, chain members, graph edges, targets, actions,
transformations, defaults, markers, generic directives, prefilters and their
literals/bytes, macro programs/tokens, arguments, strings, individual string
bytes, aggregate interned bytes, and aggregate owned bytes. Numeric and typed-ID
arithmetic is checked and compilation uses no recursion proportional to rule or
chain count.

Unit tests inject failure at every observed allocation point, repeat 250
compile/deinit cycles, exercise real-thread sharing and retirement, and verify
failed builder validation preserves caller ownership. The deterministic fuzz
oracle checks source spans, typed ranges, phase ordering, chains, prefilters,
macros, fingerprints, and diagnostics over a pinned 10,000-case mutation run.

Hosted CI structurally compiles the same 58 pinned ModSecurity 3.0.16, Coraza
3.7.0, and deployable CRS 4.28.0 configuration files used by WAF-10, with no
unexplained exclusions. The boundary contains 925 directives, 761 rules, and
2,419,595 bytes of reported plan-owned storage. The complete evidence is embedded from
`src/compatibility/evidence/structural-plan.json` as `plan.evidence_json`.

On the hosted pinned CRS SQLi fixture (98,977 input bytes, 74 directives, 73
rules), ReleaseFast measured 88,518 compiled rules/s, 286,761 owned bytes,
68,092 deduplicated string bytes, 2.784 billion indexed rules/s traversal,
873,188 ns equivalent-generation reuse compilation, and a 4 ns average
publication swap. These values are observations from Actions run 29945716010,
not hard-coded performance gates.

## Reproduction

```sh
zig build test
zig build check
zig build test-plan-corpus \
  -Dplan-corpus=../owasp-crs/crs-setup.conf.example \
  -Dplan-corpus=../owasp-crs/plugins \
  -Dplan-corpus=../owasp-crs/rules \
  -Dplan-corpus=../modsecurity \
  -Dplan-corpus=../coraza
zig build fuzz-plan -Dplan-fuzz-iterations=10000
zig build bench-plan -Doptimize=ReleaseFast \
  -Dplan-benchmark=../owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf
```

The ReleaseFast benchmark reports compilation throughput, rules and directives
per second, owned bytes, bytes per rule, string deduplication, phase-index
traversal throughput, equivalent-generation reuse time, and isolated runtime
publication pause. These are compiler baselines; WAF request-path release gates
remain owned by WAF-39.
