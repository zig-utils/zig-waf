# STX operations console workspace

Console source will be developed with the local `~/Code/Tools/stx` checkout.
CI uses the exact STX commit in `dependencies.lock.json`. Production binaries
embed fingerprinted static output from `console/dist`; Bun and STX are never
runtime dependencies.

The asset pipeline and typed `/api/v1` client are tracked by
[WAF-60](https://github.com/zig-utils/zig-waf/issues/61).

