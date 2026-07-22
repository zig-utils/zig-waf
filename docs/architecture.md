# Engine architecture contracts

The core API separates immutable, shareable policy from isolated request state:

- `Waf.Builder` validates configuration before allocating a published `Waf`.
- A `Waf` has a stable address and may be shared by worker threads. Its only
  mutable field is an atomic live-transaction count used to prevent premature
  destruction.
- Each `Transaction` belongs to one request and one worker at a time. It is not
  shared between threads.
- Connector calls have strict lifecycle ordering. Invalid transitions fail
  explicitly; reduced or unavailable features will follow the same rule.
- Header and body byte limits are checked before counters are incremented.
  Body writes count inspected bytes but do not imply in-memory buffering.
- Detection-only mode retains interventions and marks them non-enforcing so
  audit and diagnostics do not diverge from enabled mode.

Compiled rulesets will be immutable execution plans referenced by `Waf`.
Hot reload will publish a fully validated replacement and allow existing
transactions to finish against their original plan before reclamation.
