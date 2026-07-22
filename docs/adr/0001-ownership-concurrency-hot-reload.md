# ADR 0001: Ownership, concurrency, and hot reload

- Status: Accepted
- Date: 2026-07-22
- Issue: [WAF-03](https://github.com/zig-utils/zig-waf/issues/4)

## Context

The request path must share compiled policy across workers without sharing
mutable transaction state. Configuration reload must never expose a partially
validated policy or reclaim memory still referenced by an in-flight request.
Connectors also need precise byte-lifetime and error contracts.

## Decision

### Allocators and byte ownership

- `Waf.Builder` borrows its allocator and uses it to allocate the resulting
  `Waf`. The allocator must remain valid until that `Waf` is reclaimed.
- An allocator used by concurrently executing transactions must be safe for
  concurrent allocation and free calls.
- Configuration input is validated before publication. Future rule compiler
  inputs will be copied into immutable generation-owned storage; a published
  generation never borrows caller rule buffers.
- Connection, request-target, identity, and match scalar values are copied into
  transaction-owned bounded storage. Values up to 64 bytes use inline storage;
  larger values use the generation allocator and are freed by `Transaction.deinit`.
- Header and body slices passed by connectors are borrowed only for the duration
  of the call unless the API explicitly documents a copy. Streaming body calls
  currently retain only bounded counters.
- Every successful transaction creation requires exactly one `deinit`. Every
  successful build, runtime build, and retirement handle similarly has one
  explicit reclamation path.

### Mutability and concurrency

- A published `Waf` is immutable except for atomic live-transaction and
  unique-sequence counters. A configured clock callback is borrowed, immutable,
  nonblocking, and required to be thread-safe.
- A `Waf` may be shared by any number of worker threads.
- A `Transaction` is isolated to one request and must be used by one thread at a
  time. Moving it between threads is allowed only with external synchronization
  and while no call is active.
- Connector callbacks, blocking audit I/O, telemetry export, UI work, and
  database operations are not permitted on the inspection hot path.

### Runtime publication and reclamation

- `Runtime` exclusively owns one active `Waf` generation at a stable address.
- `Runtime.newTransaction` briefly serializes generation-pointer acquisition and
  increments that generation's live count before releasing the lock. All later
  transaction processing is independent of the runtime lock.
- `Runtime.reload` accepts only a fully built generation with zero active
  transactions. It publishes the replacement as one critical operation and
  returns the previous generation in a `RetiredGeneration` handle.
- Existing requests stay pinned to the retired generation. New requests use the
  replacement. `RetiredGeneration.tryReclaim` returns `TransactionsActive` until
  the last pinned request has deinitialized.
- Publishing the currently active pointer, publishing a generation already in
  use, and creating work after shutdown all fail explicitly.
- The administrative owner must stop new request creation before
  `Runtime.deinit`, reclaim every retirement handle, and then destroy the runtime.

### Errors and feature discovery

- Programmer/lifecycle violations, resource exhaustion, invalid untrusted
  inputs, unsupported configuration, and temporary ownership conflicts remain
  distinct error classes. They are never converted to silent success.
- Native callers use `FeatureSet`; C callers use the corresponding stable bit
  assignments in `zig_waf_feature_bit`.
- A reduced build must omit its feature bit and reject configuration that
  requires the missing feature. It may not silently ignore a directive.
- C structures are sized and versioned. New optional fields consume reserved
  space or require an ABI version change; callers must initialize `struct_size`
  and `abi_version`.

### Connector responsibilities

Connectors are responsible for lifecycle ordering, transport buffering,
backpressure, applying only enforced interventions, and calling logging and
deinitialization on every terminal path. The engine is responsible for phase
legality, bounded inspection state, decision evidence, and generation pinning.

## Consequences

The generation acquisition mutex adds a small fixed cost once per request. It
avoids unsafe lock-free pointer reclamation and does not cover rule execution or
body inspection. The `bench-ownership` build step measures direct creation and
runtime-pinned creation independently so this cost remains visible as the engine
evolves.

Compiled execution-plan layout is owned by WAF-11. That work must preserve this
publication and reclamation contract.
