# Audit logging

A finished transaction serializes into an audit-log record via
`Transaction.serializeAuditLog(allocator, format)`. The call snapshots the
audit-relevant facts into an `audit.AuditRecord` and renders them in the
requested format, honoring the active `SecAuditLogParts` selection. All
intermediate state lives in a temporary arena; the returned bytes are owned by
the caller.

## The snapshot

`buildAuditRecord` gathers, borrowing bytes that are stable for the
transaction's lifetime:

- Identity and connection: `unique_id`, client/server address and port.
- Request line: `REQUEST_METHOD`, `REQUEST_URI`, and the HTTP version (the
  `REQUEST_PROTOCOL` value without its `HTTP/` prefix).
- Request and response headers, iterated from `REQUEST_HEADERS` /
  `RESPONSE_HEADERS` with the casing the connector supplied.
- Request and response bodies (`REQUEST_BODY` / `RESPONSE_BODY`) and the
  response status.
- The wall-clock timestamp from the configured clock source.
- `is_interrupted` — whether an intervention is pending.
- Part-H messages: one per matched rule flagged `auditlog`, formatted from the
  accumulated match intents in ModSecurity's `RuleMessage::log` layout
  (`ModSecurity: Warning.`/`Access denied with code N.` followed by
  `[id "…"] [msg "…"] [data "…"] [severity "…"] [tag "…"] … [unique_id "…"]`).

## Parts

Sections are gated by `SecAuditLogParts` (`ctl:auditLogParts` at runtime). `A`
(header) and `Z` (terminator) are always present; `B` request headers, `C`
request body, `E` response body, `F` response headers, and `H` trailer are
selectable, and the reserved `D`/`G`/`I`/`J`/`K` markers emit empty when chosen.

## Formats

- **Native serial** — ModSecurity's legacy dashed-boundary format
  (`--<boundary>-A--` … `--<boundary>-Z--`), pinned to `toOldAuditLogFormat`,
  including the blank-line record terminator after `Z`.
- **JSON** — Coraza's structured schema (`{"transaction":{…},"messages":[…]}`)
  with header objects whose repeated names group into arrays.
- **Legacy JSON** — Coraza's flatter schema with
  `remote_address`/`local_address` naming and header maps whose repeated values
  join with `, ` into a single string.
- **OCSF** — an OCSF v1.2.0 "Web Resources Activity" event (class 6004),
  allowed/denied by interruption, with HTTP request/response objects, endpoints,
  per-message enrichments, and observables, matching Coraza's OCSF formatter.

Header-map key order is nondeterministic in Go's `encoding/json`, so the JSON
family is schema-compatible with Coraza rather than byte-identical.

## Delivery

Formatted records are delivered across an I/O-free `Sink` boundary the
connector owns (`src/audit_writer.zig`): `SerialWriter` appends each record and
a newline (serial file, stdout/stderr, or a syslog/HTTPS sink), `CallbackWriter`
hands each record to a callback, and `concurrentEntry` produces the ModSecurity
concurrent-layout per-record path (`YYYYMMDD/YYYYMMDD-HHMM/YYYYMMDD-HHMMSS-<id>`)
and combined-log index line. The core never blocks on I/O.

## Redaction

The ModSecurity `sanitise*` actions mask sensitive data before serialization:

- `sanitizeRequestHeader:<name>` / `sanitizeResponseHeader:<name>` replace the
  named header's value with a same-length run of `*`.
- `sanitizeArg:<name>` masks the value of a request-body argument in place
  (the bytes after the first `=` in the argument's raw `key=value` segment).
- `sanitizeMatched` masks whichever variable the rule matched, dispatching to
  header or argument masking by the matched variable's collection.

Masking is fail-safe — it only ever masks more, never leaks — so it applies
directly rather than through the staged rollback batch. `sanitizeMatchedBytes`
(masking only the operator-matched byte sub-range) is not yet implemented.

## Qualification evidence

- Unit tests in `src/audit.zig` cover each format (serial byte-exactly; the JSON
  family by round-tripping through `std.json`), the UTC timestamp layout, part
  gating, and body suppression.
- An engine test in `src/engine.zig` drives a disruptive `auditlog` rule and
  asserts the serial and JSON serializations of the live transaction.

Implementation is tracked by
[WAF-29](https://github.com/zig-utils/zig-waf/issues/30). Audit writers
(serial/concurrent/syslog/HTTPS) and redaction, debug logs, and telemetry land
in later issues.
