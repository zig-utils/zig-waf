# Persistent collections

`TX` is transaction-local. `IP`, `SESSION`, `USER`, `GLOBAL`, and `RESOURCE`
may be bound to cross-request storage through the versioned
`persistent.Backend` callback table. Merely constructing a transaction performs
no backend calls. A request pays persistence cost only after explicitly
initializing a persistent namespace.

## Ownership and lifecycle

The application owns the backend context and must keep it alive until the WAF
and all child transactions are destroyed. A load returns an allocator-owned
snapshot; the transaction copies visible values into its bounded collection
store and destroys the snapshot. Each namespace may be initialized once with
one collection key per transaction. Repeating the same binding is a no-op;
attempting to rebind it to another key is an error.

Transactions keep an ordered, bounded mutation log. `processLogging` flushes
only dirty bindings. Connector code must call `processLogging` before `deinit`;
destruction never performs hidden blocking I/O and therefore cannot flush a
skipped logging phase.

## Mutation compatibility

- Assignment creates or replaces the value while preserving an existing
  expiry, matching ModSecurity collection storage.
- Deletion removes the value and its expiry state.
- Addition and subtraction treat missing, expiry-only, and non-numeric values
  as zero. Leading ASCII whitespace and a sign are accepted and parsing stops
  after the decimal prefix, matching the pinned `std::stoi` behavior.
- Arithmetic uses checked signed 64-bit integers. Overflow is an explicit
  capacity error rather than native overflow.
- `expirevar` records an absolute nanosecond deadline. It may create
  expiry-only state before a value exists; expiry-only state is not visible to
  rule reads. A later assignment preserves that deadline.
- A value is expired when `deadline <= now`. Loads hide expired and expiry-only
  state. Maintenance cleanup removes no more than its record and variable
  budgets.

`setCollectionValue`, `addTransactionCollectionValue`, and exact removal cover
transaction-local `TX`. The persistent action surface consists of
`initializePersistentCollection`, `setPersistentCollectionValue`,
`addPersistentCollectionValue`, `removePersistentCollectionValue`, and
`expirePersistentCollectionValue`. WAF-15's SecLang action compiler will call
these same APIs for `initcol`, `setuid`, `setsid`, `setrsc`, `setvar`, and
`expirevar`.

## Concurrency and atomicity

Every stored record has a monotonic revision. A commit supplies its expected
revision and an ordered mutation batch. The backend publishes the entire batch
once or returns a conflict without partial state. A transaction reloads the
current revision and rebases its mutation log up to `max_retry_attempts`.
Numeric deltas are applied inside the backend commit, so concurrent increments
compose instead of becoming last-writer-wins.

The in-memory backend uses a short publication lock and constructs replacement
records before swapping them into view. The LMDB backend performs compare,
mutation, encoding, and publication in one LMDB write transaction. Allocation,
validation, map-full, stale-revision, and commit failures leave the prior
revision readable.

## Failure policy

The default is `fail_closed`. Backend unavailability, timeout, conflict
exhaustion, corruption, and capacity exhaustion return typed transaction
errors. With `fail_open`, those backend failures allow lifecycle processing to
continue and are retained in `lastPersistentFailure`; invalid caller input and
allocator failure are never converted into fail-open success. Rules and
connectors can therefore audit the exact failure instead of silently assuming
that persistence succeeded.

## LMDB deployment

LMDB 0.9.35 is installed and locked through Pantry as
`openldap.org/liblmdb`. Zig 0.17 translates the pinned header and statically
links the Pantry archive. There is no system-library fallback and no Git
submodule.

`persistent_lmdb.LmdbBackend.init` requires a caller-created directory and
accepts an explicit map size, reader count, permissions, directory mode, and
the same persistence limits used by the WAF builder. The on-disk record format
has a magic value, schema version, namespace, revision, bounded collection key,
bounded entry count, explicit value-presence flag, expiry, and length-delimited
name/value bytes. Decoding rejects truncation, trailing bytes, invalid enums,
invalid flags, oversized fields, and excessive aggregate size before
publication.

The current backend is single-environment and process-safe according to LMDB's
locking model. Operators must size the map deliberately and treat map-full as a
capacity alert. LMDB is for WAF persistent collections; PostgreSQL remains the
production fleet control-plane database.
