# SecLang frontend

The WAF-10 frontend is a bounded, source-preserving syntax layer for the stable
SecLang accepted by ModSecurity 3.0.16, Coraza 3.7.0, and OWASP CRS 4.28.0. It
does not decide whether a directive, action, transformation, or operator is
available in a particular build. Immutable semantic compilation and complete
directive validation belong to WAF-11 and WAF-12; configuration publication
must wait for those stages.

## Ownership and entry points

`seclang.parser.parseBytes` returns an `OwnedDocument`. The value owns both its
source registry and AST, so no token or span borrows the caller's byte buffer.
`parseBytesOutcome` returns the same ownership context with either a document
or a structured diagnostic. `seclang.include.parseFile` parses a file and its
relative includes, while `parseTree` requires an explicit configuration root
and entry path.

All returned owned values have one `deinit` operation. A successful `Document`
contains original directive spelling, half-open physical byte spans, raw
argument spelling and quote kind, and structured target/operator/action nodes.
Unknown directives remain lossless generic nodes for later semantic handling.

## Lexical and syntax contract

- UTF-8 sources are owned before parsing. LF and CRLF are accepted, including a
  final physical line without a newline.
- Backslash continuations retain a logical-to-physical segment map. Baseline
  whitespace removal is quote-aware and cannot accidentally merge operands.
- Comments begin only outside a token. Hashes in regexes, macro text, quoted
  values, and unquoted operator tokens remain data.
- Single, double, unquoted, and mixed arguments retain raw escapes. Unterminated
  quotes, dangling escapes or continuations, trailing operands, and malformed
  rule shapes fail rather than publishing a partial document.
- `SecRule` targets preserve negation/count modifiers and selectors. Operators
  preserve negation, explicit names and parameters; an omitted operator name is
  represented as the compatible implicit `rx`. Action commas are split only
  outside nested quotes and escapes.

## Diagnostics

Every syntax failure has a stable `WAF-SECLANG-*` code, severity, primary span,
optional secondary span, and static message. Human rendering includes exact
path, line, byte column, a bounded source excerpt, and the include ancestry.
Rendering has explicit byte, excerpt, and ancestry limits and never needs an
unbounded error string. Allocation failure and invalid source identity remain
typed infrastructure errors rather than being mislabeled as syntax.

## Include security model

The include resolver canonicalizes its root and every existing candidate.
Absolute includes are denied by default. Lexical traversal and canonical or
symlink escape are rejected; only regular files are loaded. Active canonical
paths detect cycles and loaded canonical paths deduplicate repeated inclusion.
Globs support `*`, `?`, and bracket classes, never let `*` cross a separator,
and are sorted lexically before parsing.

Depth, pattern length, glob matches, source count, bytes per source, aggregate
bytes, physical lines, logical-line bytes, segments, tokens, token bytes,
directives, arguments, targets, and actions all have explicit limits. Required
empty matches fail; optional empty matches do not hide permission, malformed
pattern, escape, cycle, or resource errors.

Canonicalization followed by path-based I/O prevents ordinary traversal and
symlink escapes. A deployment that permits untrusted local users to mutate the
configuration tree concurrently must additionally provide an immutable mount
or equivalent OS-level directory ownership; path canonicalization alone is not
a replacement for filesystem access control.

## Pinned evidence

Hosted CI checks out exact commits recorded in `dependencies.lock.json` and
parses the deployable configuration corpus from all three baselines:

| Baseline | Commit | Files |
| --- | --- | ---: |
| ModSecurity 3.0.16 | `7ea9fefbe0ba409d8733b4d682c8c4c059cd028d` | 12 |
| Coraza 3.7.0 | `27069d06c896be74b77b9a6c0b539a0cbfaca360` | 13 |
| OWASP CRS 4.28.0 | `55b09f5acfd16413e7b31041100711ceb7adc89c` | 33 |

The combined gate covers 58 files, 803,184 bytes, and 925 directives with no
unexplained exclusions. CRS's 13 `util/crs-rules-check/examples` files are
deliberately malformed upstream validator inputs; the frontend rejects them as
expected and does not count them as deployable CRS configuration.

The same evidence is available to tooling at
`src/compatibility/evidence/seclang-parser.json` and is embedded as
`seclang.evidence.json`.

## Reproduction

```sh
zig build test
zig build check
zig build test-parser-corpus \
  -Dparser-corpus=../owasp-crs/crs-setup.conf.example \
  -Dparser-corpus=../owasp-crs/plugins \
  -Dparser-corpus=../owasp-crs/rules \
  -Dparser-corpus=../modsecurity \
  -Dparser-corpus=../coraza
zig build fuzz-parser -Dparser-fuzz-iterations=10000
zig build bench-parser -Doptimize=ReleaseFast \
  -Dparser-benchmark=../owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf
```

The benchmark reports bytes and directives per second, allocations per parse,
and peak owned bytes. It asserts that tracked live ownership returns to zero
after every parse/deinit cycle. Performance results establish a comparable
baseline; WAF request-path release gates are owned by WAF-39.
