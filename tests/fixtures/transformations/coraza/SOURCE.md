# Coraza transformation fixtures

These 35 JSON files are copied without modification from
`internal/transformations/testdata` in Coraza 3.7.0 at commit
`27069d06c896be74b77b9a6c0b539a0cbfaca360`.

The fixtures are licensed under Apache-2.0. The upstream `LICENSE` is retained
in this directory. `SHA256SUMS` records every imported JSON file so accidental
fixture edits and upstream drift are executable review failures.

The zig-waf harness selects the transformation by the canonical filename. This
is necessary because several upstream digest cases use descriptive case names
such as `md5-test1`, while Coraza's generic fixture runner ignores the `ret`
field and validates transformed bytes only.
