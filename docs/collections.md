# Collection variables, targets, and macros

Issue [WAF-08](https://github.com/zig-utils/zig-waf/issues/9) defines the
transaction-facing collection model used by SecLang targets and runtime macro
expansion. `collections.Name` is the executable registry for 37 canonical
namespaces, including transient request/response data, TX, and the persistent
namespace interfaces consumed by WAF-09.

## Storage and ownership

Collection keys and values are copied into a transaction-local arena. Repeated
values retain insertion order and source origin/offset/length. Entry count,
individual key/value size, and physical allocated bytes are independently
bounded. Replacement and deletion use tombstones: superseded arena bytes remain
charged to the physical limit, so hostile update churn cannot hide memory growth
behind a smaller live-byte count.

Headers, ENV, GEO, RULE, TX, and persistent map keys compare ASCII
case-insensitively. Argument, cookie, file, multipart, JSON, and XML keys retain
case. Map-style `set`, repeated `add`, selector-based removal, and paired atomic
insertion cover both SecLang actions and parser producers.

## Targets and selectors

A target combines a collection, an all/exact/compiled-regex key selector, and
the SecLang count marker. Exclusion targets are applied while iterating without
allocating a result list. Exact header and map selectors honor the namespace key
policy. Regex targets use a ruleset-owned Pantry-pinned `zig-regex` plus one
reusable matcher per worker, so DFA state is amortized without sharing mutable
matching state. Runtime exhaustion or an input limit is returned as
`MatcherLimitExceeded`, never converted into a false non-match.

The transaction API phase-gates collections before returning iterators or
counts. Request-body, response-header, and response-body namespaces therefore
cannot leak future-phase values even if a producer publishes data early.

## Runtime macros

Runtime strings compile once into immutable literal, scalar, and collection
tokens. Compilation rejects empty, unknown, malformed, unterminated, oversized,
and over-tokenized input. Expansion has an independent output bound and reads
the current transaction state. It is single-pass, matching the upstream model;
expanded bytes are not reparsed as nested macros.

ModSecurity expands a missing value to empty while Coraza preserves the
expression text without delimiters. `Builder.setMacroMissingPolicy` makes this
baseline difference explicit; the stable default is ModSecurity-compatible
empty expansion.

## Downstream producers

This issue owns namespaces, storage, mutation, origins, targets, selectors,
counts, exclusions, and macro resolution. Parsing remains deliberately located
with the subsystem that can provide correct offsets and diagnostics:

- WAF-23: URL arguments, headers, and cookies.
- WAF-25: files and multipart collections.
- WAF-26: URL-encoded and JSON body collections.
- WAF-27: XML/XPath collections.
- WAF-09: persistence, expiry, and cross-request synchronization for IP,
  SESSION, USER, GLOBAL, and RESOURCE.

Those producers use the same bounded publication APIs; unavailable data is
absent rather than fabricated. Run `zig build bench-collections
-Doptimize=ReleaseFast` for the reusable regex-target plus macro-expansion hot
path.
