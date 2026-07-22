# C connector ABI

The public `zig_waf.h` header and generated compatibility headers live here.
The ABI uses opaque handles, sized and versioned structs, explicit ownership,
feature discovery, callback tables, and stable error codes. Its implementation
is tracked by [WAF-32](https://github.com/zig-utils/zig-waf/issues/33).

