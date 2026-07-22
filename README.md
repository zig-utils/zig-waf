# zig-waf

`zig-waf` is a high-performance, embeddable web application firewall and fleet
platform written in Zig. It targets the stable feature union of ModSecurity
3.0.16 and Coraza 3.7.0, with complete OWASP CRS 4.28.0 compatibility as a v1
release gate.

This repository is pre-alpha. Current builds establish API and compatibility
foundations; they are not yet suitable as a production security boundary.

## Development

Zig 0.17-dev, PostgreSQL 18, and libpq are installed and locked through Pantry:

```sh
pantry install
zig build test
zig build check
zig build bench-scalars -Doptimize=ReleaseFast
zig build fuzz-parser -Dparser-fuzz-iterations=10000
```

Production fleet mode requires PostgreSQL. SQLite will only support isolated
tests and single-node demonstrations. Core request inspection never depends on
database availability.

Local development uses sibling checkouts of `zig-injection`, `zig-regex`, and
`zig-tls`, plus `~/Code/Tools/stx`. CI checks out the exact commits recorded in
`dependencies.lock.json`; no repository uses Git submodules.

## Components

- Immutable compiled `Waf` and isolated per-request `Transaction`
- `zig-wafd` HTTP/1.1 and HTTP/2 reverse proxy
- C connector ABI and Nginx, Caddy, Envoy, and HAProxy integrations
- PostgreSQL-backed fleet controller and durable event ingestion
- STX operations console embedded as fingerprinted static assets

The complete implementation graph is tracked by the
[WAF roadmap](https://github.com/zig-utils/zig-waf/issues/1).
The bounded syntax and include contracts are documented in
[`docs/seclang-parser.md`](docs/seclang-parser.md).

## License

MIT. Imported compatibility fixtures retain their upstream licenses and
notices.
