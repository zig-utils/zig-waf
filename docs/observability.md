# Observability

What the engine will tell you about itself, and the shape of each answer. Four
things, with different costs and different consumers: metrics for whether it is
healthy, a debug log for why it did something, timings for what is slow, and a trace
identifier so any of it can be joined to the request it belongs to.

One rule runs through all of them: **the request path does no blocking I/O for a
diagnostic.** Every sink here is a bounded in-memory structure the host drains. A WAF
that stalls a request to describe what it is doing has made the diagnostic cost more
than the check it was describing.

## Metrics

`metrics.zig` renders a Prometheus exposition from the engine's own counters, and
`fleet_metrics.zig` does the same for control-plane state (nodes, drift, events,
alerts). Both render into a caller-provided buffer with a fixed ceiling, so scraping
cannot allocate without bound.

Two properties are worth knowing:

- **Every series is always present**, including at zero. A counter that appears only
  once it is non-zero makes a dashboard look broken on a healthy system, and makes an
  absent metric indistinguishable from a metric nobody is producing.
- **A metric that cannot be collected is omitted, not reported as zero.** For
  control-plane metrics that means a database read that failed leaves the series out
  rather than publishing a zero an alert would read as "no attacks".

Label values are escaped, so a value carrying a quote or newline cannot forge a
neighbouring series.

## Debug log

`SecDebugLog` and `SecDebugLogLevel` are honoured through `debug_log.zig`. Levels
match ModSecurity's 0-9, so a configuration means here what it means there:

| Level | What it adds |
| --- | --- |
| 0 | nothing at all, including errors |
| 1-2 | what the engine could not do, and what it degraded |
| 3 | decisions: interventions, a phase interrupted |
| 4 | how the transaction was handled — phases, body processing |
| 5 | per-rule outcomes, with the rule's configured `id:` |
| 6-9 | per-target and finer detail |

Read the configured values from a compiled plan with
`debug_log.settingsFromPlan(plan)`, and attach a `Recorder` with
`builder.setDebugLog(&recorder)`. Both halves matter: without the recorder nothing is
collected, and `Settings.active()` reports the half-configured cases — a path with
level 0, or a level with no path — rather than logging somewhere nobody chose.

An out-of-range level is an error, not a clamp. Reading `SecDebugLogLevel 12` as 9
would flood the log and as 0 would silence it, both without telling anyone the
configuration was wrong.

**The buffer is bounded and admits it.** Level 9 emits a record per rule per target,
which is unbounded in the size of the request, so there is a ceiling on records, on
total bytes, and on any single message. Drops and truncations are counted and the
rendered output ends with a line naming them. This is not decoration: a reader who
cannot tell a clipped log from a complete one will read a gap as an absence.

The recorder is not thread-safe. One per transaction is the simple arrangement; a
shared one needs the host's lock.

## Rule timing

Off by default, enabled with `builder.setRuleTiming(true)`, read with
`transaction.ruleTiming()`. Reading the clock twice per rule is a real cost across a
full CRS run, and it is not worth paying to compute a number nobody consumes.

`measured` says whether timing was on, which is the field that keeps the rest honest:
an unmeasured zero reported as a measurement is how a dashboard comes to show a WAF
that costs nothing. When it is on, the slowest rule is attributed by its configured
id — a total says something is slow, an attribution says what to look at.

The release gate in `benchmarks/request_path.zig` measures the same path from the
outside and fails a build on a tail-latency or memory regression.

## Trace correlation

Every transaction has a `UNIQUE_ID`, and `transaction.traceContext()` resolves the W3C
trace context: the incoming `traceparent` continued with a span of the WAF's own, or a
fresh trace when the request carries no usable one.

The header comes from the client, so:

- **Parsing is strict** — 55 bytes, version `00`, lowercase hex, correct separators,
  non-zero identifiers. Anything else is rejected rather than repaired, because a
  lenient parser turns attacker input into identifiers a tracing backend will index.
- **A malformed header starts a new trace** rather than failing the request or
  forwarding the value. Failing would turn observability into an outage; forwarding
  would let a client choose the trace id its records land under.
- **`inherited` says which happened**, because a span whose parent was discarded is a
  root span and must not reference a parent that will never arrive.
- **Sampling is inherited, not re-decided.** A WAF sampling independently emits spans
  whose parents are missing, and a trace with holes reads as a system that lost the
  request.

Resolution is lazy and cached: a deployment that never traces generates no
identifiers, and one that does gets the same span each time it asks.

**Exporting is the host's job.** OTLP is a network protocol, and a blocking export in
the request path is exactly the cost this design refuses. The engine produces the
identifiers and the records; the host ships them.

## Redaction and sensitive data

`sanitiseArg`, `sanitiseRequestHeader`, and `sanitiseResponseHeader` mask values in
the audit log, and `sanitiseMatchedBytes` is rejected at compile time rather than
silently ignored — a redaction action that does nothing is worse than one that is
missing, because the configuration says the secret is masked.

Audit records escape ill-formed UTF-8 to U+FFFD when writing JSON, so a request body
carrying invalid bytes cannot break the log's structure or inject a field into it.
