# C connector ABI

`include/zig_waf.h` is the boundary a native data plane links against — the Nginx,
Caddy, Envoy, and HAProxy connectors, and anything else that wants to run traffic
through the engine without writing Zig. It is the supported cross-language surface;
there is no embedded script runtime (see [`docs/plugins.md`](plugins.md)).

## Linking

`zig build` installs the ABI twice, from the same code:

- `lib/libzig-waf.a`, a static archive for a connector that links the engine in
  (the Nginx, Caddy, Envoy and HAProxy connectors, rpx's dataplane);
- `lib/libzig-waf.dylib` (`.so` on Linux), a shared library for a host that
  loads it at runtime through a foreign-function interface, such as Bun's
  `bun:ffi` (`@stacksjs/waf`) or Python's `ctypes`. liblmdb is linked into it as
  an archive, so it needs nothing else on the loader path.

`zig build test` runs the C smoke test against both.

## What the version means

`ZIG_WAF_ABI_VERSION` is `0xMMMMmmmm` — major in the high 16 bits, minor in the low
16. A connector reads `zig_waf_abi_version()` at load time and compares:

| Comparison | Meaning |
| --- | --- |
| Same major, library minor ≥ connector minor | Compatible. Use it. |
| Same major, library minor < connector minor | The library predates the connector. Fields the connector expects may not exist; refuse to load. |
| Different major | Incompatible. Refuse to load. |

The library applies the same rule to the `abi_version` stamped in every struct it is
handed: a 1.0 connector is served by a 1.1 library, and a struct stamped with a minor
newer than the library's is refused with `ZIG_WAF_ERROR_UNSUPPORTED_ABI`.

| Version | Added |
| --- | --- |
| 1.0 | The transaction lifecycle, rule sets, interventions, audit serialization |
| 1.1 | Host operators: `zig_waf_plugins_t`, `zig_waf_register_operator`, `zig_waf_config_t.plugins`, `zig_waf_transaction_plugin_unavailable_count`, and the `PLUGIN_OPERATORS` feature bit |

The library never silently degrades. A call whose struct is too small for the fields
it names returns `ZIG_WAF_STATUS_INVALID_ARGUMENT` rather than reading past the end
or filling in defaults, because a connector that thinks it configured a limit and did
not is worse than one that failed to start.

## How the structs stay compatible

Every struct begins with `struct_size` and `abi_version`, and every one ends with a
`reserved` array. The caller sets both header fields; the library checks
`struct_size` against what it needs and reads only fields the caller's size covers.

That makes two directions safe:

- **A newer connector against an older library.** The connector's struct is larger.
  The library reads the prefix it knows, which is still laid out where it expects,
  and ignores the rest.
- **An older connector against a newer library.** The connector's struct is smaller.
  The library sees a `struct_size` that does not cover a field it would have read and
  refuses, rather than reading memory the connector never allocated.

Growth is therefore **additive only**: a new field takes space from `reserved`, never
from a new position, and never changes an existing field's offset. `src/c_api.zig`
pins the sizes and offsets in a test, so an accidental layout change fails the build
instead of being discovered by a connector in production.

A field taken from `reserved` leaves `struct_size` unchanged, so size alone cannot
say whether the caller knows the field exists. The caller's `abi_version` does: the
library reads such a field only from a struct stamped with the minor that introduced
it, because to an older connector the slot was reserved and may hold anything.
`zig_waf_config_t.plugins` (1.1) is read this way, and a test proves that a 1.0
config with a stray value in that slot is never dereferenced.

Removing or repurposing a field, changing an enum's numeric values, or changing a
function's signature is a **major** bump.

## Capability discovery

`zig_waf_query_features` reports `feature_bits` and `highest_phase`. A connector
asks rather than assumes: a build without a feature returns a clear bit rather than
a stub that silently does nothing.

| Bit | Name | Meaning |
| --- | --- | --- |
| 0 | `TRANSACTION_LIFECYCLE` | The five inspection phases plus logging |
| 1 | `BOUNDED_STREAMING_BODIES` | Request and response bodies may be streamed in chunks under a limit |
| 2 | `DETECTION_ONLY` | Interventions can be reported without being enforced |
| 3 | `NATIVE_SQLI` | libinjection-backed `@detectSQLi`/`@detectXSS` |
| 4 | `SCALAR_VARIABLES` | Bounded scalar transaction variables |
| 5 | `COLLECTION_VARIABLES` | Collection variables, with selectors |
| 6 | `RUNTIME_MACROS` | `%{...}` macro expansion at evaluation time |
| 7 | `PERSISTENT_COLLECTIONS` | `initcol` collections through a storage backend |
| 8 | `ATOMIC_HOT_RELOAD` | A rule set can be replaced while transactions are in flight |
| 9 | `COMPILED_EXECUTION_PLAN` | Rules run from a compiled, validated plan |
| 10 | `TRANSFORMATION_EXECUTION` | The pinned transformation set runs on rule inputs |
| 11 | `PLUGIN_OPERATORS` | Host operators can be registered with `zig_waf_register_operator` (1.1) |

`ZIG_WAF_FEATURE_KNOWN_BITS` is every bit the header names. A bit outside it is one
the header predates, and a connector ignores it rather than guessing what it means.

The numbers are fixed. The engine derives each one from the order of `waf.Feature`;
`src/c_api.zig` pins that order against this table, and the C smoke test checks that
the library reports exactly the bits the header names. Through 0.0.3 the header
published `ATOMIC_HOT_RELOAD` at bit 5, which the library has always used for
collection variables, so a connector built against that header was testing a
different feature than the one it named. Rebuild such a connector against the
corrected header.

## Host operators

Some operators cannot live inside the WAF: `@inspectFile` needs a scanner, `@geoLookup`
a database. A connector provides them the way a Zig host does through
`plugin.Registry` ([`docs/plugins.md`](plugins.md)), with a callback per operator:

```c
static zig_waf_operator_outcome_t inspect(void *scanner, const uint8_t *parameter,
                                          size_t parameter_len, const uint8_t *input,
                                          size_t input_len) {
    switch (scanner_lookup(scanner, input, input_len)) {
    case SCANNER_INFECTED: return ZIG_WAF_OPERATOR_MATCH;
    case SCANNER_CLEAN: return ZIG_WAF_OPERATOR_NO_MATCH;
    default: return ZIG_WAF_OPERATOR_UNAVAILABLE; /* not loaded, busy, too slow */
    }
}

zig_waf_plugins_t *plugins = NULL;
zig_waf_plugins_create(&plugins);
zig_waf_register_operator(plugins, (const uint8_t *)"inspectFile", 11, scanner, inspect);
config.plugins = plugins;                 /* config.abi_version = ZIG_WAF_ABI_VERSION */
zig_waf_create_with_rules(&config, rules, rules_len, &waf);
zig_waf_plugins_destroy(plugins);         /* the WAF kept its own copy */
```

The rules that make this safe to build a security control on are the plugin rules,
unchanged:

- **Registration happens before compilation.** The names in `config.plugins` go to the
  rule compiler, so a rule naming a registered operator compiles and a rule naming an
  operator nothing provides still fails with `ZIG_WAF_ERROR_INVALID_CONFIG`, rather
  than compiling into a rule that never matches.
- **The callback must not block.** It runs on the request path, possibly on several
  threads at once. A scanner or a lookup that needs I/O answers from state it maintains
  elsewhere, and says `UNAVAILABLE` when that state cannot answer.
- **Unavailable is not clean.** `UNAVAILABLE` does not match, but it is counted, and
  `zig_waf_transaction_plugin_unavailable_count` reports the count for the transaction.
  A return value other than the three outcomes is treated as `UNAVAILABLE`, because a
  callback that answered something the library does not understand did not say the
  input was clean.

A name is letters, digits and underscores, with or without the leading `@`, matched
case-insensitively as rule operators are. An empty or otherwise unspellable name, a
NULL callback, or a name already in the set returns `ZIG_WAF_ERROR_INVALID_ARGUMENT`.

## Ownership

- A `zig_waf_t` is created by the caller and destroyed with `zig_waf_destroy`. It
  outlives every transaction created from it; destroying it with transactions still
  alive is refused rather than accepted and then crashed on.
- A `zig_waf_transaction_t` is destroyed with `zig_waf_transaction_destroy`.
- Bytes the library returns (an audit record from
  `zig_waf_transaction_serialize_audit_log`) are freed with `zig_waf_free`. Bytes the
  caller passes in are borrowed for the duration of the call and never retained.
- A rule set compiled by `zig_waf_create_with_rules` is retained by the WAF, so the
  caller keeps no obligation after the call returns.
- A `zig_waf_plugins_t` is created with `zig_waf_plugins_create` and destroyed with
  `zig_waf_plugins_destroy`. A WAF copies the registrations it was created with, so the
  set may be destroyed, or extended for the next WAF, once that call returns. What the
  WAF cannot copy is the host's side: each `context` and `callback` must stay valid
  until every WAF created with them is destroyed. A set is not thread-safe; build it
  before handing the config to other threads.
- The `parameter` and `input` a host operator receives are borrowed for that call
  only. A pointer whose length is 0 must not be read.

## Errors

Every function returns a `zig_waf_status_t`. There are no out-of-band error codes and
nothing is reported by a null return alone, so a connector can handle failure in one
place. A status is never `OK` on a path that did not do what was asked.

## What is not in the ABI

Anything that would put blocking work on the request path: no file opening, no
sockets, no process execution, no script interpreter. A connector that needs those
supplies them itself — the WAF asks through a callback the connector controls, which
is the same boundary `plugin.Registry` provides to Zig hosts.
