# Request-target parsing contracts

Request parsing populates the argument and cookie collections from the raw
request during target and header processing. Parsing borrows the request bytes;
decoding writes into a bounded scratch buffer, so the request path performs no
implicit allocation beyond the transaction-owned collection storage and no
blocking I/O.

## Query-string arguments

`processUri` splits the raw URI on the first `?`, publishes `QUERY_STRING`, and
parses the query into `ARGS_GET` (and the derived `ARGS`, `ARGS_NAMES`,
`ARGS_GET_NAMES`, `ARGS_COMBINED_SIZE`). Parsing follows the pinned Coraza
`doParseQuery`:

- Segments are split on the configured separator, defaulting to `&`.
  `SecArgumentSeparator` reconfigures it (for example to `;`).
- Empty segments (from repeated separators) are skipped.
- Each segment splits on its first `=`; a segment with no `=` has an empty
  value.
- Keys and values are decoded with the pinned `queryUnescape`
  (`application/x-www-form-urlencoded`): `+` becomes a space, `%XX` decodes a
  byte, and a malformed or truncated `%` is preserved literally.

Each argument's `Source` records the raw byte offset and length within the URI
so rule evidence and audit logging can quote the original bytes.

## Cookies

`addRequestHeader` parses a `Cookie` header into `REQUEST_COOKIES` and
`REQUEST_COOKIES_NAMES`. The Netscape-format split is byte-oriented: `name=value`
pairs separated by `;` with surrounding spaces trimmed; a pair with no `=` has an
empty value. Cookie names and values are stored as raw bytes.

## Request body

The request body is buffered in a transaction-owned buffer as chunks arrive,
bounded by the request-body limit, and published as `REQUEST_BODY` at
`processRequestBody` when `SecRequestBodyAccess` is on. The buffer keeps bytes in
memory up to an in-memory threshold and streams the overflow to a spool sink
(`src/request_buffer.zig`); a hard total limit caps the body, and the
reject/process-partial policy governs overflow. Disk-exhaustion is a distinct,
non-blocking error.

Body processors run against the buffered body based on the request-body
processor (from the `Content-Type` or `ctl:requestBodyProcessor`):

- **URLENCODED** parses `application/x-www-form-urlencoded` bodies into
  `ARGS_POST` with the same pinned decoding and separator as the query string.
- **JSON** flattens the body into dotted `ARGS_POST` keys rooted at `json`, with
  array indices (`json.items.0`) and a per-array length entry (`json.items`),
  matching the pinned Coraza flattening. Invalid JSON sets the request-body
  processor error flag.
- **MULTIPART** parses `multipart/form-data` (boundary from the `Content-Type`)
  with a reader pinned to Go's `mime/multipart` delimiter semantics. Fields
  populate `ARGS_POST`; file parts populate `FILES` (client filename),
  `FILES_NAMES` (field), `FILES_SIZES`, and `FILES_COMBINED_SIZE`; every part's
  raw header lines are recorded in `MULTIPART_PART_HEADERS`, and the
  Content-Disposition `name`/`filename` params mirror into `MULTIPART_NAME` and
  `MULTIPART_FILENAME`, matching ModSecurity. A missing boundary or an
  unterminated part raises `MULTIPART_STRICT_ERROR`.
- **RAW** exposes the body as `REQUEST_BODY` without argument extraction.

## Bounds and safety

- The raw request target is bounded by `max_request_target_bytes`; an oversized
  target is rejected before parsing.
- Argument key and value byte totals accumulate into `ARGS_COMBINED_SIZE` with
  overflow-checked arithmetic.
- The query decoder never expands its input, and the scratch buffer is bounded
  by the query length.

## Qualification evidence

- Focused unit tests in `src/request.zig` cover segment splitting, the
  first-equals rule, empty values, malformed and truncated percent escapes,
  custom separators, and cookie trimming.
- Engine tests in `src/engine.zig` prove `processUri` populates `ARGS_GET` from a
  decoded query, `addRequestHeader` populates `REQUEST_COOKIES` from a `Cookie`
  header, and `SecArgumentSeparator` reconfigures the split.
- A deterministic fuzz test asserts the parsers never crash, decoding stays
  within bounds and deterministic, and iterators yield only borrowed input
  slices.
- A ReleaseFast benchmark (`zig build bench-request`) records allocation-free
  query and cookie parsing throughput.

Implementation and qualification are tracked by
[WAF-23](https://github.com/zig-utils/zig-waf/issues/24). Body-argument
processors, cookie v0/v1 formats, path arguments, smuggling-safe host parsing,
and decoding-error variables land in later slices of this issue and the body
processor issues.
