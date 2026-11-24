# Operator contracts

The stable scalar operator registry is a closed, typed union matching
ModSecurity 3.0.16 and Coraza 3.7.0. Names resolve case-insensitively while a
ruleset is compiled. Request-time evaluation performs no string dispatch, and
scalar comparison is allocation-free.

## Scalar operators

| Operator | Semantics |
| --- | --- |
| `eq`, `ge`, `gt`, `le`, `lt` | Numeric comparison of the input and argument. |
| `beginsWith`, `endsWith` | ASCII byte prefix and suffix tests. |
| `contains`, `strmatch` | Substring containment of the argument within the input. |
| `within` | Substring containment of the input within the argument. |
| `streq` | Exact byte equality. |
| `containsWord` | Argument present with non-letter word boundaries. |

Inputs and arguments are arbitrary byte strings; neither is retained by
`evaluate`. The argument is the already macro-expanded operator parameter and
the input is the transformed variable value. `evaluateNegated` applies SecLang
`!@op` negation to the raw outcome.

### Numeric parsing profiles

Numeric parsing is the clearest observable divergence between the two engines
and is selected by `Profile`:

- **Coraza** uses Go `strconv.Atoi`: the entire string must be an optional sign
  followed by decimal digits. Leading whitespace, trailing bytes, empty input,
  or 64-bit overflow parse to `0`.
- **ModSecurity** uses C++ `std::stoi`: it skips leading whitespace, reads an
  optional sign and a leading digit run, and stops at the first non-digit. No
  digits or a value outside the 32-bit range parses to `0`.

So `@eq 5` against `" 5"` matches under ModSecurity but not Coraza, and `@eq 5`
against `"5abc"` matches under ModSecurity only.

### `containsWord`

`containsWord` matches when the argument appears delimited by non-letter
boundaries (string start, string end, or any byte outside `A-Za-z`, which
notably treats digits and punctuation as boundaries). An empty argument always
matches; a non-empty argument never matches an empty input. Coraza registers it
as a ModSecurity-compatible operator only, so zig-waf implements the identical
word-boundary semantics for both profiles.

## Regex operators

`@rx`, `@rxGlobal`, and `@rsub` are compiled through zig-regex. A `RegexOperator`
is a ruleset-owned compiled program; it is immutable and may be shared by
request workers. Create one reusable `Worker` per worker thread so the mutable
lazy-DFA and NFA caches — which already memoize automaton construction across
evaluations — are never shared across threads.

Every pattern is compiled with ModSecurity 3.0.16's semantics, which CRS is
written against (#90): ModSecurity passes `PCRE2_DOTALL | PCRE2_MULTILINE` and
no `PCRE2_UTF`, and Coraza prepends `(?sm)`. So `.` matches a newline, `^` and
`$` match at line breaks, and the pattern and input are bytes: `\x{ff}` is the
byte `0xff`, and `(?i)` folds ASCII letters only (`RegexOperator.default_flags`).

A pattern is compiled with capture groups. When zig-regex refuses that compile
as too complex, it is compiled again for spans only (#89), and
`RegexOperator.spans_only` is set. zig-regex refuses a capturing compile when
the pattern needs its backtracking engine and could backtrack exponentially
there; without captures, the same pattern runs on its linear engine, which finds
a match for exactly the same inputs, starting at the same position. Only capture
field `0`, the whole match, is filled then, and its end can be longer than
PCRE's, because the linear engine reports the longest match from that start.
Thirteen CRS 4.28 patterns take this path, most of them Unix command-injection
rules, and every one of them reads only `TX:0`, in its log message.

Most values match no rule, so `@rx` first asks only whether a value matches,
and looks for captures only when it does (#87). Each capturing pattern is also
compiled for spans only, as `RegexOperator.tester`, and every worker asks that
one shared regex through zig-regex's `isMatch`. Since zig-regex 0.5.2 that call
keeps its lazy DFAs warm across calls and threads, where a `Worker`'s own
matcher builds them again for each value it is created for. When the tester
says no, the capturing engine never runs. When it says yes and the capturing
engine finds nothing, the value still matches, with field `0` only: zig-regex's
backtracker misses some matches PCRE2 finds, such as
`^(?:[^']*?'[^']*?'[^']*?)*?'` on `a'b'c'`, and the linear engine agrees with
PCRE2 there. The cost is memory: the spans-only compiles of CRS 4.28's patterns
take about 60 MB, against 15 MB for the capturing ones, so a WAF with CRS loaded
holds about 90 MiB resident instead of 35 MiB (see the
[benchmark lab](benchmark-lab.md)).

- **`@rx`** returns the leftmost match with capture fields `0..9`. Field `0` is
  the full match; fields `1..9` are the first nine parenthesized groups. A
  non-participating optional group is reported as present `false`, distinct from
  a group that matched the empty string. Capture fields borrow the evaluated
  input and are valid only while it is.
- **`@rxGlobal`** returns every non-overlapping match and keeps the first value
  per capture field index, matching ModSecurity `storeOrUpdateFirst`.
- **`@rsub`** preserves the pinned ModSecurity 3.0.16 behavior exactly:
  `Rsub::evaluate` is an unimplemented stub that returns true. zig-waf does not
  invent substitution semantics the baseline lacks; actual regex substitution
  is out of scope until upstream implements it.
- An empty pattern always matches, mirroring both engines.

### Bounded errors

Invalid or over-complex patterns are rejected before publication with a
distinguishable `RegexCompileError` (`InvalidRegexPattern`,
`RegexProgramTooComplex`, `OutOfMemory`), so a ruleset never publishes a pattern
that fails at request time. `Builder.build` refuses the whole rule set with
`error.InvalidOperatorParameter` (`ZIG_WAF_ERROR_INVALID_CONFIG` through the C
ABI) and names the rule in the debug log at level `err`, as ModSecurity and
Coraza refuse to load it. Before #89 such a rule loaded switched off. `zig-waf
validate` and `zig build test-crs-configuration` build the engine, so they
report it too. A bounded runtime error — match limit, step limit,
or oversized input — is not a match: `RegexOutcome` reports it through
`runtime_error` and `limit_exceeded`, exactly as ModSecurity sets
`TX.MSC_PCRE_ERROR` and `TX.MSC_PCRE_LIMITS_EXCEEDED` and does not match.

### Ownership and allocation

`RegexOperator` uses its compile allocator for transient per-evaluation capture
storage, freed before `evaluate` returns; callers see only borrowed offsets into
the input. Supply a fast, thread-safe general-purpose allocator (not
`page_allocator`) so concurrent workers do not serialize on a system-call-per
allocation. The optional per-worker memo (`workerWithMemo`) keeps a bounded LRU
of recent `@rx` outcomes keyed by exact input bytes and rebuilds capture fields
against the live input from stored offsets, with least-recently-used eviction
and hit/miss statistics.

## Validation operators

Three validation operators check the encoding or byte composition of a value and
match when it is invalid, matching the pinned Coraza semantics:

- **`@validateByteRange`** compiles a comma-separated allowed-byte set of
  `start-end` ranges and single values, and matches when the input contains any
  byte outside the set. An empty argument matches unconditionally, and an empty
  input never matches. An out-of-range or non-numeric byte specification is a
  distinguishable compile error.
- **`@validateUtf8Encoding`** matches when the input is not valid UTF-8.
- **`@validateUrlEncoding`** matches when the input contains a `%` not followed
  by two hexadecimal digits, or a truncated `%`. An empty input never matches.

## Qualification evidence

- The retained Coraza operator corpus (`tests/operator_evidence.zig`) pins the
  scalar operator fixture files by SHA-256 and replays their 118 cases under the
  Coraza profile, plus the 53-case `validateByteRange`/`validateUtf8Encoding`/
  `validateUrlEncoding` corpus.
- Focused unit tests in `src/operators.zig` cover both numeric profiles, string
  and word-boundary semantics, negation, regex captures, empty patterns, invalid
  patterns, `rxGlobal` match counting, `rsub`, and memoization with LRU eviction.
- ReleaseFast benchmarks (`benchmarks/operators.zig`, `zig build
  bench-operators`) record scalar, regex match/miss, `rxGlobal`, and memoized
  latencies; memoization serves repeat inputs roughly two orders of magnitude
  faster than a fresh match.

Implementation and qualification are tracked by
[WAF-17](https://github.com/zig-utils/zig-waf/issues/18). SQLi/XSS detectors are
[WAF-19](https://github.com/zig-utils/zig-waf/issues/20), and phrase, dataset,
and IP operators are [WAF-18](https://github.com/zig-utils/zig-waf/issues/19).
