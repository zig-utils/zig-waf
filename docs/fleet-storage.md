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

`prepare`/`execPrepared`/`queryPrepared` parse a statement once per connection; a
prepared name outlives a pool checkout, so the handful of hot statement shapes are
planned once rather than on every call. `setStatementTimeout` bounds how long any
statement may run, and `sendQuery`/`cancel`/`discardResults` abandon one already in
flight — cancellation being a request, not a guarantee, since a statement that has
already finished completes.

Values are bound in text format throughout, and bytea columns go through
`decode(…, 'hex')`. Binary format would move type encoding onto the client — for
`timestamptz` that means reimplementing PostgreSQL's own encoding, where any drift
silently mis-dates events — and buys nothing measurable at these value sizes.

`pg.Pool` is bounded and non-blocking: `acquire` returns an idle connection,
opens one while under `max`, or fails with `PoolExhausted` so a caller drops or
retries rather than stalling a worker. Connections are opened outside the lock,
so a slow connect never blocks other tasks.

`pg.WorkloadPools` gives the API, rollout, and ingestion workloads separate bounded
pools. They fail differently and must not share a budget: a shared pool makes every
workload as available as the greediest one, and a bad afternoon of console traffic
should not stop the fleet from receiving a policy. `totalLimit` is what the
database's `max_connections` must accommodate for the process.

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
| `users` | Console identities: role, password hash or federated subject |
| `api_tokens`, `sessions` | Credentials, stored only as hashes |
| `saved_searches` | Named event queries per user |
| `settings` | Keyed control-plane configuration |
| `admin_log` | Every administrative change, with actor and target |

The schema constrains what can be stored rather than trusting writers: roles are a
fixed set, so an unrecognized value cannot be stored and later read as some default;
a user must have either a password hash or a federated subject, so no identity
exists that cannot authenticate; credentials are unique by hash and cascade with
their user; and secrets are stored only as hashes, so the table is not itself a
credential.

Index types match how each column is searched. BRIN covers the event stream's
timestamp — events arrive in time order, so the physical order already matches the
indexed order and a range query needs only a summary per block range, where the
B-tree it replaced cost far more space for the same question. GIN covers the jsonb
columns, so a label containment query is indexed rather than a scan. The composite
`(node_id, occurred_at)` B-tree remains for per-node lookups, which a summary cannot
serve.

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

## Node identity

`fleet_nodes.zig` answers the question every other operation depends on: *which
node is this, and may it still act*. Enrolling by asserting an id is fine for a
demo and is not an identity, so this layer covers the credential a node enrolls
with, the certificate it authenticates by, and the ways both can be taken away.

**Enrollment tokens** are single-use and expiring, and only their SHA-256 hash is
stored. A token that can be replayed is a permanent fleet credential sitting in
whatever provisioning system carried it, and a stolen database should not yield one
that still works.

`claim` is a single statement whose WHERE clause carries every condition —
matching hash, unclaimed, unwithdrawn, unexpired — so the row is consumed by the
same statement that qualifies it. This is the point: two nodes starting together in
an autoscaling group is the ordinary case, and a read followed by a write would let
both pass the read. There is no moment between the check and the consumption for a
second claim to land in.

Withdrawal is its own column rather than a backdated expiry. "Withdrawn" and "ran
out" are different facts to whoever reads the trail afterwards, and an expiry moved
below `created_at` would contradict the check that keeps the window coherent.
Claimed tokens survive `purgeExpired`, because they are the record of which token
enrolled which node.

**Certificates** authenticate a node only inside their validity window, only while
unrevoked, and only while the node itself is active — so retiring a node ends its
access without touching any certificate. `authenticate` returns the node id or
null, and null covers unknown, not-yet-valid, expired, and revoked without
distinguishing them: whoever is holding the certificate does not need to be told
which.

Fingerprints are accepted only as 64 lowercase hex characters. A value with an
uppercase digit or a stray colon would be stored happily and then never match what
a TLS terminator computes, and "a node cannot authenticate with a certificate the
console shows as valid" is a genuinely hard failure to read.

`rotate` records the replacement and leaves the outgoing certificate valid until it
expires on its own. Both authenticate during the changeover, so a rotation does not
depend on the node and the control plane agreeing on an instant — a cutover that is
instant is how a fleet goes silent mid-request. `needsRotation` asks about the
*node*, not about one certificate, because an expiring certificate is not a problem
when a newer one is already in place; asking the other way would issue a new
certificate on every check. `rotationDue` is the work list a rotation job walks.

`revoke` requires a reason, enforced by the schema. An unexplained revocation is
indistinguishable from a mistake, and the safe response to a mistake is to
re-issue — which is exactly wrong after a key compromise. `revokeAllFor` exists
because revoking the one certificate an operator knows about leaves any others
working.

Issuing the certificate is not here: signing a CSR needs an X.509 CA, which arrives
with the TLS work ([#43](https://github.com/zig-utils/zig-waf/issues/43)). What
this owns is the lifecycle state an mTLS terminator consults on every connection.

**Replay prevention.** `NonceLedger.accept` takes a nonce once per node. The
primary key enforces it, so two concurrent replays cannot both be accepted the way
they can between a check and an insert. Nonces are scoped per node — keyed on the
nonce alone, two nodes independently choosing the same value would lock each other
out — and they expire, because a table that must be kept forever is one someone
eventually truncates, silently removing the protection. A purged nonce may be
reused safely: the request carrying it is itself rejected as stale long before.

**Capabilities and version negotiation.** A node reports what it supports and what
protocol version it speaks. `negotiate` returns the older of the two versions, so a
fleet can be upgraded one node at a time, and refuses anything below the supported
minimum rather than serving it best-effort — a node that cannot be told what to
enforce is worse than one that knows it is unsupported, because it looks healthy.

An unreported capability counts as unsupported. That default matters: a node sent
rules it cannot evaluate does not fail loudly, it silently enforces less than the
operator believes it is enforcing. `lacking` names the nodes a policy needing a
capability cannot be rolled out to, which is the question worth asking before a
rollout rather than after.

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

`recentForNode` serves event search and transaction detail. `pageForNode` pages from
a `(occurred_at, id)` cursor rather than an OFFSET: a page is defined by where the
last one ended, so events arriving between requests neither shift rows into a page
already shown nor skip rows the reader never saw — which is precisely what OFFSET
does on a stream that is still growing.

`exportCsv` renders a node's events as RFC 4180 CSV, quoting fields and doubling
embedded quotes so a URI or message containing commas, quotes, or newlines
round-trips intact.

`SavedSearchRepository` stores named queries per user as jsonb, interpreted by the
console. The query is never spliced into SQL here: a saved search is user-authored,
and turning one into a statement is how a search feature becomes an injection
vector.

`EventPartitions.sizes` reports bytes and estimated rows per partition, and
`forecast` turns the measured size and the observed ingestion rate into days of
retention remaining within a byte budget. Every figure is measured rather than
configured — an event's size depends on its URIs and messages — and a stream with no
measurable growth, or a budget already exceeded, reports no forecast rather than a
fabricated number.

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

libpq is linked as a shared library, so on macOS the loader needs to be told where
it is: prefix the command with
`DYLD_LIBRARY_PATH=pantry/postgresql.org/libpq/v18.0.0/lib` (Linux uses
`LD_LIBRARY_PATH`, which is what the CI job sets).

CI runs this suite against a `postgres:18` service container, so these tests gate
merges rather than depending on someone remembering to run them.

**One caveat worth knowing.** `zig build pg-test` caches a successful run and
replays it, and `PG_TEST_DSN` is not part of the cache key. Pointing it at a
different database and re-running therefore reports `Build Summary: 7/7 steps
succeeded` with `run test cached` — without opening a connection to it. That is
indistinguishable from a passing run, which makes it dangerous whenever the *point*
of the run is which database it talks to, such as verifying a restored backup. Run
the test binary directly in that case and insist on the `All N tests passed` line;
[`docs/postgres-operations.md`](postgres-operations.md) records the procedure.

`zig build sqlite-test` covers the embedded backend and needs no server.

## Identity and authorization

`fleet_auth.zig` holds console identity: local password login, roles, API tokens,
and sessions. Two kinds of secret are protected differently on purpose. A password
is chosen by a person, so it is low-entropy and worth attacking offline: it is
stored as an argon2id hash, whose cost is the defence. A token or session id is
generated here with 256 bits of entropy, so guessing it is not a threat and only a
stolen database matters: those are stored as SHA-256 hashes. Using argon2 for them
would put a deliberately expensive hash on every API request — a denial-of-service
vector bought for no security.

A secret exists in recoverable form exactly once, when it is issued. Authentication
failure is uniform: an unknown email, a disabled account, a federated account with
no password, and a wrong password are all "no", because which one it was is what an
attacker probing for accounts wants to learn. Disabling a user immediately
invalidates its tokens and sessions without having to find them; expiry is checked
by authentication itself rather than trusting housekeeping to have run; and
revocation is recorded rather than deleted, so a credential that was used stays
accounted for.

Authorization is a total function from role to enumerated action, so a new action
must be classified to be permitted anywhere, and a role that does not parse grants
nothing rather than defaulting.

`oidc.zig` verifies ID tokens for federated login. The algorithm is a property of
the *key*, never of the token's header, so a token cannot nominate how it is
verified — which is what defeats `alg: none` and the algorithm-confusion attack that
turns a provider's public key into an HMAC secret. Issuer, audience, expiry, issued-
at, and nonce are all required to match, the nonce in constant time. Accounts link by
subject, not email: an email address can be reassigned, and a linkage by email would
hand the new holder the old account. Discovery and JWKS fetching stay with the
caller, which owns HTTP and its destination policy, so verification is a pure
function of its inputs.

## Alerts and telemetry

A rule fires when its threshold is met inside its window, and then stays quiet for
its dedupe interval. Alerting on every matching event is noise, and noise is how a
real alert gets missed. Firing is a single statement — the threshold check, the
dedupe check, and the stamp that starts the next quiet period cannot interleave — so
two dispatchers seeing the same burst deliver one alert rather than two.

A silence suppresses a rule for a stated reason, by a named actor, until a stated
time. It is preferred to disabling the rule: it expires by itself, so nobody has to
remember to switch an alert back on, and the reason survives the incident.

Delivery attempts are recorded with their outcome, including an unreachable host,
whose HTTP status is NULL rather than zero. `consecutiveFailures` counts only the run
since the last success, so it measures the channel's current state, and
`failingChannels` names every rule whose last attempt did not succeed. This is the
metric that matters most: an alert channel that is failing looks exactly like quiet.

`fleet_metrics.render` exposes the fleet in the Prometheus text format — nodes by
status, unresponsive nodes, ruleset drift, recent events by action, event-stream
bytes, delivery outcomes, failing channels, and active silences. These are
control-plane metrics; request-path metrics come from the engine and never depend on
a database being reachable. A metric that cannot be collected is omitted rather than
reported as zero, since zero would be a claim about the fleet rather than an absence
— and label values are escaped, so a hostname can never forge a second series.
