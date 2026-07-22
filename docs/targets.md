# Supported target matrix

| Target | Engine/library | `zig-wafd` | Fleet controller | Console |
| --- | --- | --- | --- | --- |
| Linux x86_64 | Required | Required | Required | Embedded |
| Linux aarch64 | Required | Required | Required | Embedded |
| macOS aarch64 | Development | Development | Development | Development |
| macOS x86_64 | Development | Development | Development | Development |
| Windows x86_64 | Library validation | Not in v1 | Not in v1 | Not in v1 |
| WASM/WASI | Connector subset | Not applicable | Not applicable | Not applicable |

Official GA artifacts target Linux x86_64 and aarch64. Other rows describe
build and test intent, not a production support promise. Apache and IIS
connectors are outside v1 scope.
