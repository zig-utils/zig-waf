# Running the control-plane PostgreSQL

Every command here was executed against the PostgreSQL 18.4 this repository pins,
and the outputs quoted are from those runs. A recovery procedure that has never been
run is a hypothesis, and the moment you need it is the worst time to discover which
step was wrong.

## Deployment profile

**Version.** PostgreSQL 18 and libpq 18, both pinned through Pantry (`deps.yaml`,
`pantry.lock`) and published in the SBOM. The client links libpq at build time, so
the server and client majors move together deliberately rather than by whatever the
host happens to have.

Both are declared in `deps.yaml` and resolved in `pantry.lock`:

```yaml
dependencies:
  postgres: ^18
  postgresql.org/libpq: ^18
services:
  autoStart:
    - postgres
```

```
pantry install                       # resolves the pinned server and libpq
pantry/postgresql.org/v18.4/bin/     # initdb, postgres, pg_ctl, psql, pg_basebackup
pantry/postgresql.org/libpq/v18.0.0/ # headers and library the engine links
```

Use the versioned `bin/` directory rather than `pantry/.bin`: the symlinks there
resolve `initdb` to the libpq-only package, which cannot find `postgres`.

**Service lifecycle.** `services.autoStart` brings the cluster up for development.
Production lifecycle is `pg_ctl` under whatever supervisor runs the host. The control
plane needs a cluster of its own — not a database inside a shared one — because
retention drops partitions, and a `DROP TABLE` in the wrong cluster is unrecoverable
without the procedure below.

```
initdb -D "$PGDATA" -U waf --auth=scram-sha-256 --data-checksums
pg_ctl -D "$PGDATA" -o "-p 5432 -k /run/postgresql" -w start
pg_ctl -D "$PGDATA" -m fast -w stop
```

`--data-checksums` is not optional here. Silent corruption in an audit store is
indistinguishable from an attacker having edited it, and checksums are what turn that
question into an answer.

**DSN.** The client takes a libpq conninfo string. Two settings belong in it rather
than in a session `SET`, because a session setting does not survive `Conn.reset`
after a failover:

```
host=/run/postgresql port=5432 user=waf dbname=fleet \
  sslmode=verify-full sslrootcert=/etc/waf/ca.pem \
  options='-cclient_min_messages=warning'
```

**TLS.** `sslmode=verify-full` — not `require`. `require` encrypts and authenticates
nothing: it accepts any certificate, so it stops passive capture and not the attacker
who can route your traffic. `verify-full` additionally checks the hostname, which is
what makes the CA check meaningful.

**Credentials.** `scram-sha-256`; never `trust` or `md5`. The control plane's role
needs `CONNECT`, `SELECT`/`INSERT`/`UPDATE`/`DELETE` on its own schema, and `CREATE`
only while migrations run. Nothing it does requires superuser.

**Pools.** `pg.WorkloadPools` budgets API, rollout, and ingestion separately so one
cannot starve another; `totalLimit()` is what the server's `max_connections` must
accommodate for the process. Size `max_connections` for the sum across every process
that connects, plus headroom for `pg_basebackup` and an operator's `psql` — a cluster
that refuses a superuser connection during an incident is a cluster you cannot fix.

**Health checks.** `SELECT 1` proves a connection. It does not prove the control
plane works, so the readiness probe should also confirm the schema is at the expected
version:

```sql
SELECT max(version) FROM schema_migrations;
```

## Backup

Physical base backup, streaming its own WAL so the copy is self-consistent:

```
pg_basebackup -h "$PGHOST" -p 5432 -U waf -D /backup/base-$(date +%F) -Fp -Xs -P
pg_verifybackup /backup/base-$(date +%F)
```

Verified run: 56,563 kB transferred, 71 MB on disk, `backup successfully verified`.

**Verify every backup before trusting it.** `pg_verifybackup` reads the manifest and
checksums the files; a backup that has never been verified is a file, not a backup.

## Point-in-time recovery

A base backup alone recovers to the moment the backup was taken. That is worth
stating plainly, because it is the assumption that fails during an incident: in the
drill below, restoring a base backup produced a database missing every row written
after it. Recovering to a chosen moment needs archived WAL.

On the primary:

```sql
ALTER SYSTEM SET wal_level = replica;
ALTER SYSTEM SET archive_mode = on;
ALTER SYSTEM SET archive_command = 'test ! -f /archive/%f && cp %p /archive/%f';
```

then restart (`archive_mode` is not reloadable). The `test ! -f` guard refuses to
overwrite an existing segment: an archive command that silently overwrites turns one
corrupt segment into an unrecoverable archive.

To recover to a moment:

```
cp -R /backup/base-2026-07-25 "$PGDATA"      # restore
chmod 700 "$PGDATA"
cat >> "$PGDATA/postgresql.auto.conf" <<EOF
restore_command = 'cp /archive/%f %p'
recovery_target_time = '2026-07-25 20:17:10.254336-07'
recovery_target_action = 'promote'
archive_mode = off
EOF
touch "$PGDATA/recovery.signal"
pg_ctl -D "$PGDATA" -o "-p 5432 -k /run/postgresql" -w start
```

`archive_mode = off` on the recovered copy matters: a recovering instance that
archives into the same directory as the primary corrupts the archive both depend on.

## Recovery drills

Run these on a schedule, against a copy. Each one is written as a question with an
answer you can check, because a drill that only confirms the server started has
verified nothing.

**Drill 1 — does the backup restore at all?** Restore a base backup to a spare port
and start it. Verified: started, and contained exactly the rows present when the
backup was taken and no others.

**Drill 2 — does PITR reach the moment you choose?** Take a backup, write a row, note
the time, write another row, then recover to the noted time. Verified: the first row
present, the second absent, with the server log naming the boundary:

```
LOG:  starting point-in-time recovery to 2026-07-25 20:17:10.254336-07
LOG:  consistent recovery state reached at 0/2B000120
LOG:  recovery stopping before commit of transaction 22875, time 2026-07-25 20:17:10.259568-07
```

**Drill 3 — is the recovered database usable by the application?** Not "does psql
connect" — run the application's own integration suite against the recovered
instance. Verified: all 54 integration tests passed against the PITR-recovered
database. This is the drill that catches a restore which technically succeeded and
left the schema at a version the application cannot use.

**`zig build pg-test` cannot perform this drill.** The build system caches a
successful run and replays it, so pointing `PG_TEST_DSN` at a different database and
re-running reports success without opening a connection to it:

```
$ PG_TEST_DSN="host=/tmp/pgw-pitr port=5458 user=waf dbname=drill" zig build pg-test --summary all
Build Summary: 7/7 steps succeeded
+- run test cached          <-- never ran
```

That output is indistinguishable from a passing drill, which makes it the most
dangerous thing in this document: it certifies a backup nobody tested. Run the test
binary directly instead, so the run cannot be cached away:

```
DYLD_LIBRARY_PATH=pantry/postgresql.org/libpq/v18.0.0/lib \
PG_TEST_DSN="host=/tmp/pgw-pitr port=5458 user=waf dbname=drill" \
  "$(ls -t .zig-cache/o/*/test | head -1)"
# 54/54 ... All 54 tests passed.
```

Insist on the `All N tests passed` line. A drill whose evidence is `7/7 steps
succeeded` has proved nothing.

The suite creates its own private schema and drops it on exit, so `schema_migrations`
is absent from the recovered database afterwards — that is the harness cleaning up,
not a failed restore.

**Drill 4 — does a failed migration leave the schema usable?** `pg.migrate` applies
each migration in its own transaction and records it only on success, so a failure
rolls that migration back and leaves the schema at the last fully applied version.
Covered by the integration suite, which asserts a deliberately failing migration
leaves its version unrecorded.

**Drill 5 — does the client survive losing its connection?** Sever it and watch:

```sql
SELECT pg_terminate_backend(pg_backend_pid());
```

Verified in the integration suite: the next statement fails, `Conn.reset` reconnects,
and `EventSpool.drainReconnecting` retries the batch — safely, because ingestion is
idempotent, so a batch that committed before its acknowledgement was lost is skipped
rather than duplicated.

## Failover

The client reconnects with the same conninfo string (`Conn.reset`), so a failover is
transparent to it exactly to the extent that the conninfo still resolves to a
writable server. Two consequences worth designing around:

- **Point the DSN at something that moves** — a virtual address, a proxy, or a
  multi-host conninfo with `target_session_attrs=read-write`. A DSN naming one host
  survives a restart of that host and nothing else.
- **Session state does not survive** a reconnect. Anything that must outlive one
  belongs in the conninfo `options` (this is why `search_path` and
  `client_min_messages` live there), not in a `SET`.

During a failover the ingestion queue is what stands between an outage and lost
events: it is bounded, it persists to disk, and it reports what it shed
(`EventSpool.dropped`). Size it for the longest failover you intend to survive —
`bench-ingestion` gives the per-event cost to work from.
