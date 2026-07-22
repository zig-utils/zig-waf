# Scalar transaction variables

Issue [WAF-07](https://github.com/zig-utils/zig-waf/issues/8) establishes the
bounded scalar registry and the transaction producers needed by later rule,
body, and collection work. `variables.Name` is the executable source of truth:
all 77 canonical names round-trip case-insensitively and have a minimum phase
and default origin. `MULTIPART_SEMICOLON_MISSING` is accepted as the historical
alias for `MULTIPART_MISSING_SEMICOLON`.

## Ownership and bounds

Every published value is copied into transaction-owned storage. Values of 64
bytes or less stay inline; larger values use the WAF allocator. Both individual
values and aggregate live scalar bytes are bounded by `Limits`. Failed updates
leave their prior value owned and valid. Callers may retain a `View` only until
the next update of that variable or transaction destruction.

Origins distinguish connection data, request targets and headers, body and
response processing, timing, parsers, compatibility state, rule matches,
engine-generated values, and connector identity. A stored value is invisible
before its minimum availability point even when a connector supplies it early.

## Producer behavior

- Connection setup publishes remote/server addresses and ports. `REMOTE_HOST`
  follows ModSecurity compatibility behavior and initially mirrors the remote
  address; no blocking reverse DNS lookup occurs on the request path.
- URI setup publishes raw/canonical URI foundations, path, basename, query,
  method, protocol, and request line. Strict decoding and complete origin
  offsets are owned by WAF-23.
- Request headers derive `SERVER_NAME`, `AUTH_TYPE`, and the standard request
  body processor names without retaining header buffers.
- Request and response body writes publish inspected byte counts. Parser
  integrations report request and response body errors through explicit hooks;
  successful phase completion fills absent error flags with `0`.
- Response processing publishes content type, protocol, status, legacy status
  forms, actual inspected `RESPONSE_CONTENT_LENGTH`, outbound-limit state, and
  response-parser diagnostics. The nonstandard `RESPONSE_BODY_LENGTH` spelling
  is rejected.
- Identity hooks publish `REMOTE_USER`, `USERID`, `SESSIONID`, and `WEBAPPID`.
  The engine generates a bounded per-generation `UNIQUE_ID` from transaction
  time and an atomic sequence.
- Rule matches replace `MATCHED_VAR` and `MATCHED_VAR_NAME` with the latest
  match. `HIGHEST_SEVERITY` begins at `255` and retains the lowest numeric
  severity seen.
- Regex integrations can distinguish a general compatibility error from an
  execution-limit error without pretending PCRE2 is the production engine.

## Time semantics

Creation captures Unix wall time and an awake/monotonic timestamp. Calendar
variables are rendered in UTC for reproducibility; `TIME_WDAY` uses the
POSIX/Go convention (`Sunday=0`). `DURATION` is elapsed monotonic milliseconds,
so wall-clock corrections cannot make it go backward.

`Builder.setIo` accepts the application-owned Zig 0.17 `std.Io` backend. Tests
and specialized embedders may instead use `setClockSource`; that callback must
be nonblocking and thread-safe and its context must outlive the WAF. A timestamp
before the Unix epoch fails explicitly during connection initialization.

## Deliberate downstream ownership

The registry includes scalar names whose bytes can only be produced by later
subsystems. WAF-08 owns collection-derived aggregates such as argument and file
sizes. WAF-24 and WAF-28 own opt-in bounded materialization of full request and
response bodies. Those variables are absent until their producer publishes a
real value; the engine never substitutes an empty value or silently buffers an
unbounded body.

Run `zig build bench-scalars -Doptimize=ReleaseFast` to measure transaction size
and a complete populated scalar lifecycle. This benchmark performs no logging,
database, telemetry, or UI work.
