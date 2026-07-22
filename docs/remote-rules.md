# Remote rule source contract

`remote_rules.load` is a candidate-build facility. It is never called by a
transaction and is intentionally independent of the proxy, audit pipeline,
PostgreSQL, and UI.

The loader accepts an injected transport and a mandatory destination policy.
The transport receives the authentication key separately from the URL and
must apply the policy before every DNS result, connection, and redirect. Its
owned response includes the final URL, redirect count, body, status, and every
connected address so the loader can verify the evidence again before accepting
the source.

Only credential-free HTTPS URLs are accepted. Limits independently bound the
key, URL, timeout, redirects, response bytes, and connected-address evidence.
The loader rejects empty bodies, non-200 responses, unsafe final URLs, missing
address evidence, or any denied destination. Accepted sources expose a BLAKE3
content digest and retain owned final-URL/body provenance for parsing into the
ordered source registry.

`FailAction.abort` returns `error.RemoteRulesAborted`. `FailAction.warn`
returns a typed warning and no source; it never substitutes empty or stale
rules. Warning values deliberately contain neither the authentication key nor
response bytes. Allocation failures always propagate and are never converted
to warnings.

`seclang.assembly.assembleFile` resolves accepted bytes into a child source at
the owning `SecRemoteRules` span. `plan.compileTree` walks local and remote
children at their directive positions, so defaults, chains, updates, and
markers see true textual order. The immutable plan retains remote source IDs,
content digests, directive spans, and Warn records. Authentication and hashing
keys use fixed redaction markers in structural fingerprints.

The deterministic test transport proves the interface and hostile-response
handling. WAF-42 owns the concrete HTTP implementation over `zig-tls`,
including DNS resolution, ALPN, certificate validation, nonblocking I/O, and
redirect connection enforcement.
