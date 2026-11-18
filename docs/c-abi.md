# C connector ABI

`include/zig_waf.h` is the boundary a native data plane links against — the Nginx,
Caddy, Envoy, and HAProxy connectors, and anything else that wants to run traffic
through the engine without writing Zig. It is the supported cross-language surface;
there is no embedded script runtime (see [`docs/plugins.md`](plugins.md)).

## What the version means

`ZIG_WAF_ABI_VERSION` is `0xMMMMmmmm` — major in the high 16 bits, minor in the low
16. A connector reads `zig_waf_abi_version()` at load time and compares:

| Comparison | Meaning |
| --- | --- |
| Same major, library minor ≥ connector minor | Compatible. Use it. |
| Same major, library minor < connector minor | The library predates the connector. Fields the connector expects may not exist; refuse to load. |
| Different major | Incompatible. Refuse to load. |

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

`ZIG_WAF_FEATURE_KNOWN_BITS` is every bit the header names. A bit outside it is one
the header predates, and a connector ignores it rather than guessing what it means.

The numbers are fixed. The engine derives each one from the order of `waf.Feature`;
`src/c_api.zig` pins that order against this table, and the C smoke test checks that
the library reports exactly the bits the header names. Through 0.0.3 the header
published `ATOMIC_HOT_RELOAD` at bit 5, which the library has always used for
collection variables, so a connector built against that header was testing a
different feature than the one it named. Rebuild such a connector against the
corrected header.

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

## Errors

Every function returns a `zig_waf_status_t`. There are no out-of-band error codes and
nothing is reported by a null return alone, so a connector can handle failure in one
place. A status is never `OK` on a path that did not do what was asked.

## What is not in the ABI

Anything that would put blocking work on the request path: no file opening, no
sockets, no process execution, no script interpreter. A connector that needs those
supplies them itself — the WAF asks through a callback the connector controls, which
is the same boundary `plugin.Registry` provides to Zig hosts.
