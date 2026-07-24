# Transformation contracts

The stable built-in transformation registry is a closed, typed union matching
ModSecurity 3.0.16 and Coraza 3.7.0. Names resolve case-insensitively while a
ruleset is compiled. Published plans retain only canonical names and typed
`TransformationKind` values; request execution performs no string lookup.

`normalizePath` and `normalizePathWin` are accepted aliases for the canonical
`normalisePath` and `normalisePathWin` names. `none` is not a runtime
transformation. It resets the inherited transformation pipeline during plan
compilation.

## Stable inventory

- Encoding and representation: `base64Decode`, `base64DecodeExt`,
  `base64Encode`, `hexDecode`, `hexEncode`, `sqlHexDecode`, `urlDecode`,
  `urlDecodeUni`, `urlEncode`, `htmlEntityDecode`, `cssDecode`, `jsDecode`,
  `escapeSeqDecode`, `utf8toUnicode`, and `length`.
- Canonicalization and filtering: `lowercase`, `uppercase`, `trim`,
  `trimLeft`, `trimRight`, `compressWhitespace`, `removeWhitespace`,
  `removeNulls`, `replaceNulls`, `removeComments`, `removeCommentsChar`,
  `replaceComments`, `cmdLine`, `normalisePath`, `normalisePathWin`,
  `parityEven7bit`, `parityOdd7bit`, and `parityZero7bit`.
- Compatibility digests: `md5` and `sha1`.

## Bytes, ownership, and limits

Inputs and outputs are arbitrary byte strings. Embedded NUL bytes are not
terminators, and UTF-8 is assumed only by `utf8toUnicode` and Coraza-profile
HTML5 entity decoding. An unchanged result may borrow the input. Generated
bytes occupy one of two reusable executor scratch buffers and remain valid
until that slot is reused. The result reports storage provenance and the
upstream `changed` flag separately because that flag is not always equivalent
to byte inequality.

The `Limits` contract defines input, output, pipeline-step, cumulative-output,
cache-entry, and cache-storage bounds. Ordered execution enforces the step and
cumulative bounds before returning checkpoints or an operator-visible value.
The output limit applies to generated storage; unchanged and sliced results may
borrow their already input-bounded bytes. Expansions use exact preflight sizing
and checked arithmetic before scratch capacity is acquired. Allocation failure,
invalid strict input, input/output/work limit exhaustion, and plugin failure are
distinct errors with a stable `FailureKind` policy class. Tolerant compatibility
decoders preserve their specified malformed bytes instead of turning malformed
input into an engine error.

The optional Unicode map used by `urlDecodeUni` is immutable borrowed storage.
It must outlive every executor that references it and can therefore be shared
by request workers without mutation or locking.

`SecCacheTransformations On` enables a transaction-local exact-key LRU. Keys
include the typed pipeline, exact input bytes, and `multiMatch` mode. Hash
matches are confirmed with complete kind and byte comparisons. Cached values
and checkpoints are never shared between transactions. If one entry cannot fit
the configured cache bound, or a cache-only allocation fails, caching enters an
explicit `limit_exhausted` or `allocation_failed` state for that transaction;
the requested transformations still execute normally. Cache hit, miss,
eviction, byte, entry, and status counters are available to evidence and
benchmark tooling.

## Compatibility profiles

The executor selects an explicit ModSecurity or Coraza profile. Profiles keep
observable differences in malformed Base64/hex/URL input, HTML entity sets,
UTF-8 error handling, path cleanup, empty input, and `changed` reporting. They
do not use the host locale or platform path library at request time.

Coraza-profile HTML entity decoding uses the complete Go 1.25 HTML5 inventory,
including legacy names without semicolons and paired code points. The generated
table is SHA-256 pinned and retains the Go Authors' BSD notice. ModSecurity
mode preserves its smaller byte-oriented named and numeric entity behavior.

## Plugin boundary

WAF-16 publishes only the closed built-in `Kind` union above. Unknown names
remain plan-publication errors; neither the compiler nor executor performs a
plugin lookup or runtime string fallback. The native Zig and versioned C
registration APIs and actual callback dispatch are scoped to
[WAF-22](https://github.com/zig-utils/zig-waf/issues/23), with these fixed
ownership rules:

- Registration is builder-only and finishes before rule parsing. Publishing a
  `Waf` freezes copied descriptors into an immutable registry snapshot and
  gives accepted plugins dense typed slots. In-flight transactions retain the
  old snapshot across hot reload.
- Native Zig and C descriptors normalize into the same internal slot contract.
  Compiled plans retain a slot plus registry generation/fingerprint, never an
  arbitrary callback pointer or request-time name.
- A callback borrows its input only for the call and cannot retain executor
  scratch, transaction, or builder addresses. Callback output is copied into
  the transaction executor's bounded storage before it becomes operator-visible.
- Plugin state owned by the immutable `Waf` must be thread-safe. Mutable
  per-request state belongs to the `Transaction`; registration and ruleset
  mutation are forbidden on the request path.
- Callback allocation, output/work-limit, and plugin failures stay distinct.
  `PluginFailure` is reserved now so WAF-22 cannot collapse a plugin defect into
  tolerant malformed-input behavior or silently bypass a rule.
- A missing, ABI-incompatible, duplicate, or unavailable plugin rejects the
  ruleset before publication. Reduced builds never convert plugin steps into
  no-ops.

## Qualification evidence

Transformation behavior is qualified by executable evidence that runs in hosted
CI on the exact closing SHA:

- The retained Coraza 3.7.0 corpus (`tests/transformation_evidence.zig`) pins
  all 35 upstream fixture files by SHA-256 and replays their 355 cases under the
  Coraza profile.
- Per-kind differential vectors (`tests/transformation_differential.zig`) assert
  byte output and `changed` semantics across empty, unchanged, malformed,
  binary, and expansion categories, require every stable kind and both aliases
  to be exercised, and prove maximum-bound input stays deterministic and
  allocation-bounded for every kind under both profiles.
- Upstream inventory drift (`tools/transformation_inventory.zig`) compares the
  typed registry against the pinned ModSecurity scanner/parser spellings and the
  Coraza registration list; CI fails if the stable union drifts.
- Deterministic fuzzing (`tools/transformation_fuzz.zig`) exercises every
  decoder and random ordered pipelines under output and work limits.
- ReleaseFast benchmarks (`benchmarks/transformations.zig`, `zig build
  bench-transformations`) record borrowed no-op, decoder-heavy, path
  normalization, digest, CRS-pipeline, `multiMatch`, and cache hit/miss timings
  alongside allocation counts, output sizes, and p50/p95/p99 per-operation
  latency for the CRS pipeline and cache-miss paths. Borrowed no-op steps and the
  warmed steady-state CRS pipeline both report zero per-operation allocations,
  and the bounded cache demonstrates measured LRU eviction. Request-path
  throughput and percentile release gates belong to
  [WAF-39](https://github.com/zig-utils/zig-waf/issues/40).

## Cryptographic warning

`md5` and `sha1` return the raw 16-byte and 20-byte digest values required by
SecLang compatibility. MD5 and SHA-1 are cryptographically broken. These
transformations are not approved for passwords, signatures, API tokens,
certificate operations, policy-bundle integrity, or any new security design.
Use a modern purpose-specific primitive for those jobs.

Implementation and qualification are tracked by
[WAF-16](https://github.com/zig-utils/zig-waf/issues/17).
