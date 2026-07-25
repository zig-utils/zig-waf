# Host extensions

Some things a WAF is asked to do cannot live inside it. `@geoLookup` needs a
MaxMind database, `@rbl` a DNS query, `@inspectFile` an external scanner,
`@fuzzyHash` a corpus of hashes. Each is a file, a socket, or a process, and the
request path must not block on any of them; where that data lives, how long it may
take, and what happens when it is missing are deployment decisions the WAF has no
standing to make.

So zig-waf does not implement them. It lets a host register one, through
`plugin.Registry`, and calls it exactly where the configuration says.

## What can be registered

| Extension | Contract | Selected by |
| --- | --- | --- |
| Operator | `plugin.Operator` | the operator name in a rule (`@geoLookup`) |
| Body processor | `plugin.BodyProcessor` | `ctl:requestBodyProcessor=NAME` |
| Persistent collections | `persistent.Backend` | `SecCollectionEngine`, `initcol` |
| Audit delivery | `audit_writer.Sink` | `SecAuditLogType` |

The registry is borrowed for the WAF's lifetime, so the host owns the storage and
must outlive both the WAF and its transactions — the same ownership rule as the
persistent backend.

## Two properties worth relying on

**An extension nothing provides fails to compile.** A rule naming an unregistered
operator, or a `ctl` naming an unregistered processor, is a compile error rather
than a rule that never matches or a body nothing reads. That is the difference
between a ruleset that is missing coverage and one that only appears to have it, and
it is why the plugin names are passed to `plan.compileWithPlugins`: the compiler can
then tell "the host provides this" from "nobody does".

**Unable to answer is not the same as no match.** An operator plugin returns
`unavailable` when its data source is missing, unreachable, or too slow. The rule
does not match — there is nothing to match on — but the engine counts it, and
`Transaction.pluginUnavailableCount` reports it. A GeoIP database that failed to load
would otherwise show up as an unbroken stream of requests from nowhere in
particular, which is exactly the failure an operator needs to see. A body processor
says `malformed` for the same reason: a body it declined to read is a body no rule
inspected, and it raises `REQBODY_PROCESSOR_ERROR` rather than passing as empty.

## What is deliberately not extensible

**Transformations.** The transformation set is a closed, typed union pinned to the
ModSecurity and Coraza union and checked against both upstreams' sources by
`zig build test-transformation-inventory`. A host-supplied transformation would
break the property that makes that check meaningful — that every transformation a
rule can name behaves byte-for-byte as the baselines do.

**Actions and directives.** Both are closed sets for the same reason: their
semantics are the compatibility surface. An unrecognized action or directive is a
diagnostic, not an extension point.

**WASM.** There is no embedded runtime, and adding one would put an interpreter on
the request path. The supported way to write an extension in another language is the
versioned C ABI (`include/zig_waf.h`, #33), which a host can back with whatever it
likes — including a WASM runtime it manages itself.

## Writing a plugin

```zig
var lookup = MyGeoDatabase{ ... };
const operators = [_]plugin.Operator{.{
    .name = "geoLookup",
    .context = &lookup,
    .evaluateFn = MyGeoDatabase.evaluate,
}};
const registry = plugin.Registry{ .operators = &operators };
try registry.validate(); // distinct, non-empty names

var names: [8][]const u8 = undefined;
const plan = try waf.plan.compileWithPlugins(
    allocator, &sources, &documents, .{}, null,
    .{ .operators = registry.operatorNames(&names) },
);

var builder = waf.engine.Builder.init(allocator);
builder.setRetainedPlan(plan);
builder.setPluginRegistry(&registry);
```

`evaluateFn` runs on the request path, so it must not block. A plugin that needs a
network round trip is expected to answer from a cache it maintains elsewhere and
report `unavailable` on a miss — which is a truthful answer, where a guess would
not be.
