# Phrase and IP matcher contracts

The `@pm` phrase family and the `@ipMatch` IP family compile their arguments into
immutable, shareable matchers. Compilation is a ruleset-load concern; request-
time evaluation performs no allocation for `@ipMatch` and no string dispatch.

## Phrase matching (`@pm`, `@pmFromFile`, `@pmFromDataset`)

Space-separated keywords compile into an ASCII case-insensitive Aho-Corasick
automaton. `contains` answers the boolean `@pm` result — whether any keyword
occurs in the input — in O(1) work per input byte through a precomputed
failure-chain terminal flag. An empty keyword (from repeated spaces) makes the
automaton always match, mirroring the pinned engines.

- `@pmFromFile` reads one keyword per line, trimming each line and ignoring
  blank lines and `#` comments.
- `@pmFromDataset` compiles the keyword list the engine's dataset registry
  supplies (`compilePatterns`).
- Shorthand aliases `pmf` (for `pmFromFile`) resolve case-insensitively.

A non-overlapping match iterator reports, at each successive terminal position,
the longest keyword ending there, then resumes after the match. It backs `@pm`
capture extraction; the boolean result uses `contains`. Capture position
semantics are not corpus-pinned.

Pattern count, per-pattern length, and total automaton state count are bounded;
exceeding a bound is a distinguishable build error, so a pathological ruleset is
rejected before publication rather than exhausting memory at load.

## IP matching (`@ipMatch`, `@ipMatchFromFile`, `@ipMatchFromDataset`)

A comma-separated list of IPv4/IPv6 addresses and CIDR subnets compiles into a
subnet set. Parsing follows the pinned Go `net.ParseIP`/`net.ParseCIDR`
behavior Coraza uses:

- A bare IPv6 address is treated as `/128`; a bare IPv4 address as `/32`.
- An unparseable subnet token is skipped rather than failing the ruleset.
- An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) is normalized to IPv4, matching
  Go `net.IP.To4`, so it compares as IPv4 and never matches a genuine IPv6
  subnet — and an IPv4-mapped subnet keeps only the low 32 mask bits.

Membership parses the input address and tests it against each subnet;
cross-family comparisons never match. `@ipMatchFromFile` reads one subnet per
line, trimming and ignoring blank and `#`-comment lines; `ipMatchF` is its
shorthand alias.

## Qualification evidence

- The retained Coraza corpora (`tests/operator_evidence.zig`) replay the pinned
  `pm` (15 cases) and `ipMatch` (3623 cases) fixtures under this implementation,
  including the IPv4-mapped normalization edge cases.
- Focused unit tests in `src/phrase.zig`, `src/ip_match.zig`, and
  `src/operators.zig` cover case-insensitive membership, empty patterns, bounds,
  zero-compressed IPv6, cross-family safety, and file parsing.
- Deterministic fuzzing (`zig build fuzz-operators`) asserts the phrase and IP
  matchers never crash, stay deterministic, and produce in-bounds monotonic
  match iterators over random inputs.
- ReleaseFast benchmarks (`zig build bench-operators`) record `@pm` and
  `@ipMatch` latency.

Implementation and qualification are tracked by
[WAF-18](https://github.com/zig-utils/zig-waf/issues/19). Dataset registry
loading and reload wiring land with the engine's dataset subsystem; regex
operators are [WAF-17](https://github.com/zig-utils/zig-waf/issues/18).
