# Coraza operator fixtures

These 12 JSON files are copied without modification from
`internal/operators/testdata` in Coraza 3.7.0 at commit
`27069d06c896be74b77b9a6c0b539a0cbfaca360`.

The fixtures are licensed under Apache-2.0. The upstream `LICENSE` is retained
in this directory. `SHA256SUMS` records every imported JSON file so accidental
fixture edits and upstream drift are executable review failures.

Each case is `{ "name", "type": "op", "param", "input", "ret" }`, where `param`
is the operator argument, `input` is the value under test, and `ret` is `1` for
a match or `0` otherwise. The zig-waf harness selects the operator by the
canonical filename and evaluates it under the Coraza profile.

`containsWord` is retained from this corpus even though Coraza registers it as a
ModSecurity-compatible operator only; its cases encode the pinned non-letter
word-boundary semantics that zig-waf implements identically for both profiles.
