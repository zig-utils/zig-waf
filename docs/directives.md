# Stable directive configuration

WAF-12 defines the configuration boundary between the lossless SecLang parser,
the immutable structural plan, and downstream directive implementations. The
registry is the exact case-insensitive union derived from ModSecurity 3.0.16
and Coraza 3.7.0: 82 ModSecurity names plus four Coraza-only names produce 86
canonical entries.

`SecConnReadStateLimit` and `SecConnWriteStateLimit` are part of the union even
though ModSecurity recognizes and rejects them as not yet supported. Conversely,
`SecUnicodeCodePage` is not a directive; it is the optional second argument to
`SecUnicodeMapFile`. Coraza's distinct compatibility spelling is
`SecUnicodeMap`.

## Public model

`directives.registry` exposes the canonical name, typed schema, repeatability,
build capability, upstream presence and support state, local implementation
state, secret classification, and owning GitHub issue for every row. Lookup is
ASCII case-insensitive and unknown `Sec*` names are rejected.

`directives.validatePlan` validates a complete immutable plan without
allocation. `validatePlanWithLimits` additionally accepts explicit resource
limits. `directives.Configuration.init` returns a zero-allocation typed view
that borrows the plan, preserves every source span, exposes source-ordered
occurrences, resolves the last occurrence of replacement directives, and
computes a semantic BLAKE3 fingerprint.

The fingerprint hashes effective singular settings and all append/operation
directives in global source order. Sensitive values use a fixed redaction
marker, so API keys and remote-rule credentials do not affect or appear in the
fingerprint. `Waf.Builder` validates before retaining or transferring a plan,
and every published `Waf` exposes the typed view through
`directiveConfiguration()`.

## Compatibility states

- `implemented`: the pinned upstream accepts and applies the directive.
- `recognized_limited`: the pinned upstream recognizes the name but rejects or
  limits at least one documented form.
- `absent`: the name is not present in that upstream inventory.
- Local `schema_only`: zig-waf recognizes and validates the directive, while
  runtime semantics remain owned by the linked downstream issue.
- Local `accepted_no_effect`: reserved for explicitly documented compatibility
  no-ops; WAF-12 currently declares none.

Reduced builds pass an explicit `CapabilitySet` and fail with
`WAF-DIRECTIVE-0102` when a used directive is unavailable. They never warn and
ignore.

## Diagnostics and safety

Stable diagnostics currently cover unknown directives, unavailable
capabilities, arity/schema errors, bounded-resource failures, unsafe paths,
non-HTTPS or credential-bearing remote URLs, and malformed MIME/ID lists.
Diagnostics carry source spans and static messages; secret values are never
interpolated.

Validation uses checked arithmetic and independent limits for directive and
argument counts, per-value and aggregate bytes, MIME entries, remote-rule
declarations, paths, URLs, and keys. Paths reject control bytes and `..`
components. Remote rule sources require a nonempty key and credential-free
HTTPS URL. Numeric, octal, Unicode code-page, separator, MIME, and ID-range
parsing is strict and overflow-safe.

## Reproducing evidence

Use the exact Pantry-pinned Zig compiler and locked upstream commits:

```sh
zig build test-directive-inventory \
  -Dmodsecurity-scanner=../modsecurity/src/parser/seclang-scanner.ll \
  -Dmodsecurity-parser=../modsecurity/src/parser/seclang-parser.yy \
  -Dcoraza-directives=../coraza/internal/seclang/directivesmap.gen.go

zig build test-directive-corpus \
  -Ddirective-corpus=../owasp-crs/crs-setup.conf.example \
  -Ddirective-corpus=../owasp-crs/plugins \
  -Ddirective-corpus=../owasp-crs/rules \
  -Ddirective-corpus=../modsecurity \
  -Ddirective-corpus=../coraza

zig build test-crs-configuration \
  -Dcrs-configuration=../owasp-crs/crs-setup.conf.example \
  -Dcrs-configuration=../owasp-crs/rules

zig build fuzz-directives -Ddirective-fuzz-iterations=10000
zig build bench-directives -Doptimize=ReleaseFast \
  -Ddirective-benchmark=../owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf
```

Machine-readable results live in
`src/compatibility/evidence/directive-union.json`. Runtime behavior is added by
WAF-13 through WAF-31; recognition in this registry is not a claim that those
issues are complete.
