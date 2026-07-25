# Fleet control-plane storage

The WAF engine has no database dependency. Everything described here lives
behind `src/pg.zig` (a libpq client) and `src/fleet.zig` (the schema and its
repositories), compiled only into the `pg-test` and `bench-ingestion` builds, so
the request path never links libpq and never blocks on a database.

`src/sqlite.zig` and `src/fleet_sqlite.zig` mirror the client and a subset of the
repositories on embedded SQLite, for single-node demos and for tests that need no
server. They carry no fleet guarantees — no concurrent writers, no partitioning,
no retention — and are not a deployment target.

## Client

`pg.Conn` wraps one connection; it is not thread-safe, and a pool hands out one
per task. Every value reaching SQL is bound as a parameter (`$1`, `$2`, …), so
node ids, labels, and event fields are never interpolated into a statement.

- `exec` runs a statement expecting no rows. `queryScalar`/`queryScalarParams`
  return the first column of the first row, distinguishing SQL NULL (null) from
  an empty string. `query` returns a forward `Rows` cursor over borrowed column
  text.
- `execParamsOpt` binds a null parameter as SQL NULL, for columns that are
  genuinely absent rather than empty. `execParamsOptCount` additionally reports
  how many rows the statement affected, which is how an idempotent insert says
  whether the row was new.
- `copyIn` streams a `COPY … FROM STDIN` payload in PostgreSQL's text format;
  `copyEscape` writes a field into it.
- `reset` reconnects with the same connection string after the server severs the
  connection. Session state does not survive it, so anything that must outlive a
  reset belongs in the connection string — `options=-csearch_path=…` rather than
  `SET search_path`.

`pg.Pool` is bounded and non-blocking: `acquire` returns an idle connection,
opens one while under `max`, or fails with `PoolExhausted` so a caller drops or
retries rather than stalling a worker. Connections are opened outside the lock,
so a slow connect never blocks other tasks.

## Schema and migrations

`fleet.migrations` is an append-only, version-ordered list. `pg.migrate` records
each in `schema_migrations` and applies each in its own transaction, so applying
twice is a no-op and a failure leaves the schema at the last fully applied
version. Existing migrations are never edited; a change is a new version.

| Table | Holds |
| --- | --- |
| `nodes` | Enrolled nodes: status, version, `labels` jsonb, heartbeat |
| `rulesets` | Immutable `(name, version)` rule-set bundles and signatures |
| `node_rulesets` | Which version each node is assigned to run |
| `security_events` | The event stream, range-partitioned on `occurred_at` |
| `alert_rules` | Alert definitions, webhook targets, per-rule secrets |
| `alert_deliveries` | Webhook delivery attempts and their outcomes |

## Nodes and rollout

`NodeRepository` enrolls (idempotently — re-enrollment refreshes hostname and
version), records heartbeats, and answers inventory questions: counts by status,
and how many active nodes have missed a heartbeat window. `setLabel`/`withLabel`
maintain the `labels` jsonb map that segments the fleet by region, tier, or
canary.

`RulesetRepository` publishes immutable versions: a published version is never
rewritten, so a rollback is a rollout of an earlier version rather than an edit.
`publishSigned` stores an Ed25519 signature over the content and `verify` fails
closed — a signature from another key, an absent signature, an unsigned bundle,
and content altered after publication are all false rather than an error a caller
might overlook. The signature is asymmetric because every node in the fleet
verifies bundles: a shared secret would have to reach all of them, after which one
compromised node could forge a policy the whole fleet accepts. Nodes hold only the
public key, and the signing key never leaves the control plane. Webhook payloads
keep HMAC-SHA256, where the secret is shared with exactly one receiver by design.

`RolloutRepository` assigns versions to one node (a canary), to a labeled cohort,
or fleet-wide, and reports how many nodes are on a version so convergence is
observable.

Nodes report the version they are actually running, so the control plane can name
the nodes that have *drifted* from their assignment — never reconciled, failed to
apply a bundle, or changed out of band. A node that has never reported counts as
drifted; silence is not compliance.

`advanceIfHealthy` is the gate between a canary and the fleet: it widens a rollout
only when every node already on the version is heartbeating within the window and
has confirmed the version it runs. An empty cohort fails the gate, because rolling
out on the strength of a canary that was never deployed is the mistake a gate
exists to prevent. A failed gate changes nothing.

## Event ingestion

A node buffers events in an `EventSpool` and a worker drains the queue to
PostgreSQL in one transaction. The path is built so that neither a database
outage nor a node crash loses events, and so that a retry cannot duplicate them.

- **Idempotency.** An event may carry a node-assigned key. A unique index on
  `(event_key, occurred_at)` — the identity of a replayed event, since the node
  stamps `occurred_at` before queuing — makes re-ingestion a no-op. Ingestion
  returns how many events were actually inserted, so the deduplicated count is
  visible. Keyless events carry no identity and always insert.
- **Batching.** `recordBatch` issues a statement per event; `recordBatchCopy`
  streams the batch as one COPY into a transaction-scoped staging table and
  inserts from there, which preserves the conflict handling COPY itself cannot
  express. `drain` picks by size at the measured crossover
  (`EventSpool.copy_threshold`); see `zig build bench-ingestion`.
- **Durability.** `persist` writes the queue to a single file: a plaintext
  header, then a Zstandard frame holding the events. `restore` bounds every read
  against the decoded body and rejects a truncated, corrupt, or oversized
  snapshot rather than trusting it. Older formats are still read, because a
  restart is exactly when a node is upgraded and a pending queue must survive it.
- **Reconnect.** `drainReconnecting` resets the connection and retries the batch
  once, which is safe precisely because ingestion is idempotent. Events stay
  queued if the retry also fails, so a database that is down is a delay.
- **Backpressure.** The queue is bounded. By default a full queue refuses new
  events (`SpoolFull`) and the node decides what to do; `drop_oldest` instead
  sheds the stale head to keep the recent tail, counting what it discards in
  `dropped` so the loss is never silent.

## Search, retention, and export

`security_events` is range-partitioned on `occurred_at`, so a time-bounded query
prunes to the partitions that can hold matches, and retention is an O(1)
partition drop instead of a bulk delete. `EventPartitions.ensureMonth` creates
the upcoming month ahead of time; `dropMonth` removes an aged one with its rows.
`pruneOlderThan` remains for a row-level policy inside a retained partition.

`recentForNode` serves event search and transaction detail. `exportCsv` renders a
node's events as RFC 4180 CSV, quoting fields and doubling embedded quotes so a
URI or message containing commas, quotes, or newlines round-trips intact.

## Alerts

`AlertRepository` resolves the enabled webhooks for an event action and holds an
optional per-rule secret. When one is set, the payload is delivered with a hex
HMAC-SHA256 signature (`fleet.signPayload`, checked against RFC 4231 vectors) so
a receiver can verify the request came from the control plane and was not
tampered with. `AlertDeliveryRepository` records every attempt with its outcome,
including an unreachable host, whose HTTP status is NULL rather than zero.

## Running the tests

The integration tests skip when `PG_TEST_DSN` is unset, so the default suite
needs no database. Each test runs in its own uniquely named schema, dropped
afterwards, so tests neither see each other's rows nor contend over DDL when the
build runner executes them in parallel.

```
initdb -D data -U waf --auth=trust
pg_ctl -D data -o "-p 5456 -k $PWD" -w start
PG_TEST_DSN="host=$PWD port=5456 user=waf dbname=postgres" zig build pg-test
```

`zig build sqlite-test` covers the embedded backend and needs no server.
