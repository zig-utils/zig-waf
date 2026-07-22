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
Expansion sizes use checked arithmetic. Allocation failure, invalid strict
input, and limit exhaustion are distinct errors. Tolerant compatibility
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

## Cryptographic warning

`md5` and `sha1` return the raw 16-byte and 20-byte digest values required by
SecLang compatibility. MD5 and SHA-1 are cryptographically broken. These
transformations are not approved for passwords, signatures, API tokens,
certificate operations, policy-bundle integrity, or any new security design.
Use a modern purpose-specific primitive for those jobs.

Implementation and qualification are tracked by
[WAF-16](https://github.com/zig-utils/zig-waf/issues/17).
