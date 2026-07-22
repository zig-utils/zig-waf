//! Stable SecLang transformation inventory and canonical name resolution.

const std = @import("std");

pub const Kind = enum(u8) {
    base64_decode,
    base64_decode_ext,
    base64_encode,
    cmd_line,
    compress_whitespace,
    css_decode,
    escape_seq_decode,
    hex_decode,
    hex_encode,
    html_entity_decode,
    js_decode,
    length,
    lowercase,
    md5,
    normalise_path,
    normalise_path_win,
    parity_even_7bit,
    parity_odd_7bit,
    parity_zero_7bit,
    remove_comments,
    remove_comments_char,
    remove_nulls,
    remove_whitespace,
    replace_comments,
    replace_nulls,
    sha1,
    sql_hex_decode,
    trim,
    trim_left,
    trim_right,
    uppercase,
    url_decode,
    url_decode_uni,
    url_encode,
    utf8_to_unicode,

    pub fn canonicalName(self: Kind) []const u8 {
        return specs[@backingInt(self)].name;
    }
};

pub const Resolution = union(enum) {
    reset,
    builtin: Kind,

    pub fn canonicalName(self: Resolution) []const u8 {
        return switch (self) {
            .reset => "none",
            .builtin => |kind| kind.canonicalName(),
        };
    }
};

pub const Spec = struct {
    kind: Kind,
    name: []const u8,
};

pub const specs = [_]Spec{
    .{ .kind = .base64_decode, .name = "base64Decode" },
    .{ .kind = .base64_decode_ext, .name = "base64DecodeExt" },
    .{ .kind = .base64_encode, .name = "base64Encode" },
    .{ .kind = .cmd_line, .name = "cmdLine" },
    .{ .kind = .compress_whitespace, .name = "compressWhitespace" },
    .{ .kind = .css_decode, .name = "cssDecode" },
    .{ .kind = .escape_seq_decode, .name = "escapeSeqDecode" },
    .{ .kind = .hex_decode, .name = "hexDecode" },
    .{ .kind = .hex_encode, .name = "hexEncode" },
    .{ .kind = .html_entity_decode, .name = "htmlEntityDecode" },
    .{ .kind = .js_decode, .name = "jsDecode" },
    .{ .kind = .length, .name = "length" },
    .{ .kind = .lowercase, .name = "lowercase" },
    .{ .kind = .md5, .name = "md5" },
    .{ .kind = .normalise_path, .name = "normalisePath" },
    .{ .kind = .normalise_path_win, .name = "normalisePathWin" },
    .{ .kind = .parity_even_7bit, .name = "parityEven7bit" },
    .{ .kind = .parity_odd_7bit, .name = "parityOdd7bit" },
    .{ .kind = .parity_zero_7bit, .name = "parityZero7bit" },
    .{ .kind = .remove_comments, .name = "removeComments" },
    .{ .kind = .remove_comments_char, .name = "removeCommentsChar" },
    .{ .kind = .remove_nulls, .name = "removeNulls" },
    .{ .kind = .remove_whitespace, .name = "removeWhitespace" },
    .{ .kind = .replace_comments, .name = "replaceComments" },
    .{ .kind = .replace_nulls, .name = "replaceNulls" },
    .{ .kind = .sha1, .name = "sha1" },
    .{ .kind = .sql_hex_decode, .name = "sqlHexDecode" },
    .{ .kind = .trim, .name = "trim" },
    .{ .kind = .trim_left, .name = "trimLeft" },
    .{ .kind = .trim_right, .name = "trimRight" },
    .{ .kind = .uppercase, .name = "uppercase" },
    .{ .kind = .url_decode, .name = "urlDecode" },
    .{ .kind = .url_decode_uni, .name = "urlDecodeUni" },
    .{ .kind = .url_encode, .name = "urlEncode" },
    .{ .kind = .utf8_to_unicode, .name = "utf8toUnicode" },
};

comptime {
    for (specs, 0..) |spec, index| {
        if (@backingInt(spec.kind) != index) @compileError("transformation specs must follow enum order");
    }
}

pub fn resolve(name: []const u8) ?Resolution {
    if (std.ascii.eqlIgnoreCase(name, "none")) return .reset;
    for (specs) |spec| {
        if (std.ascii.eqlIgnoreCase(name, spec.name)) return .{ .builtin = spec.kind };
    }
    if (std.ascii.eqlIgnoreCase(name, "normalizePath")) return .{ .builtin = .normalise_path };
    if (std.ascii.eqlIgnoreCase(name, "normalizePathWin")) return .{ .builtin = .normalise_path_win };
    return null;
}

pub const Limits = struct {
    max_input_bytes: usize = 1024 * 1024,
    max_output_bytes: usize = 4 * 1024 * 1024,
    max_pipeline_steps: usize = 64,
    max_cumulative_output_bytes: usize = 16 * 1024 * 1024,

    pub fn validate(self: Limits) error{InvalidLimits}!void {
        if (self.max_input_bytes == 0 or
            self.max_output_bytes == 0 or
            self.max_pipeline_steps == 0 or
            self.max_cumulative_output_bytes < self.max_output_bytes)
        {
            return error.InvalidLimits;
        }
    }
};

pub const Storage = enum {
    borrowed,
    executor_a,
    executor_b,
};

pub const Profile = enum {
    modsecurity,
    coraza,
};

/// Immutable ModSecurity Unicode-map values indexed by a 16-bit code point.
/// Negative and out-of-range entries are unmapped. The backing table must
/// outlive the executor and may be shared by request workers.
pub const UnicodeMap = struct {
    table: []const i32,

    pub fn lookup(self: UnicodeMap, code_point: u16) ?u8 {
        if (code_point >= self.table.len) return null;
        const mapped = self.table[code_point];
        if (mapped < 0) return null;
        return @truncate(@as(u32, @intCast(mapped)));
    }
};

pub const Options = struct {
    profile: Profile = .modsecurity,
    unicode_map: ?UnicodeMap = null,
};

pub const Result = struct {
    bytes: []const u8,
    /// Upstream transformation semantics, which can differ from byte equality.
    /// For example, `length` and non-empty parity transforms always report a
    /// change, while a single compressed tab becomes a space but reports false.
    changed: bool,
    storage: Storage,
};

pub const ApplyError = std.mem.Allocator.Error || error{
    InvalidLimits,
    InputTooLarge,
    OutputTooLarge,
    InvalidInput,
    UnsupportedTransformation,
};

/// Reusable bounded scratch for one request worker/transaction. Executor-backed
/// result bytes remain valid until that same scratch slot is reused (at least
/// one subsequent executor-backed result); borrowed results retain input life.
pub const Executor = struct {
    const Scratch = struct {
        buffer: *std.ArrayList(u8),
        storage: Storage,
    };

    allocator: std.mem.Allocator,
    limits: Limits,
    profile: Profile,
    unicode_map: ?UnicodeMap,
    buffers: [2]std.ArrayList(u8) = .{ .empty, .empty },
    next_buffer: usize = 0,

    pub fn init(allocator: std.mem.Allocator, limits: Limits) error{InvalidLimits}!Executor {
        return initWithOptions(allocator, limits, .{});
    }

    pub fn initWithProfile(allocator: std.mem.Allocator, limits: Limits, profile: Profile) error{InvalidLimits}!Executor {
        return initWithOptions(allocator, limits, .{ .profile = profile });
    }

    pub fn initWithOptions(allocator: std.mem.Allocator, limits: Limits, options: Options) error{InvalidLimits}!Executor {
        try limits.validate();
        return .{
            .allocator = allocator,
            .limits = limits,
            .profile = options.profile,
            .unicode_map = options.unicode_map,
        };
    }

    pub fn deinit(self: *Executor) void {
        for (&self.buffers) |*buffer| buffer.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn apply(self: *Executor, kind: Kind, input: []const u8) ApplyError!Result {
        if (input.len > self.limits.max_input_bytes) return error.InputTooLarge;
        return switch (kind) {
            .base64_decode => self.base64Decode(input, false),
            .base64_decode_ext => self.base64Decode(input, true),
            .base64_encode => self.base64Encode(input),
            .css_decode => self.cssDecode(input),
            .escape_seq_decode => self.escapeSeqDecode(input),
            .js_decode => self.jsDecode(input),
            .lowercase => self.mapAsciiCase(input, false),
            .uppercase => self.mapAsciiCase(input, true),
            .trim => trimResult(input, true, true),
            .trim_left => trimResult(input, true, false),
            .trim_right => trimResult(input, false, true),
            .compress_whitespace => self.compressWhitespace(input),
            .remove_whitespace => self.removeBytes(input, isRemovalWhitespace),
            .remove_nulls => self.removeBytes(input, isNull),
            .replace_nulls => self.replaceNulls(input),
            .hex_decode => self.hexDecode(input),
            .hex_encode => self.hexEncode(input),
            .sql_hex_decode => self.sqlHexDecode(input),
            .url_decode => self.urlDecode(input),
            .url_decode_uni => self.urlDecodeUni(input),
            .url_encode => self.urlEncode(input),
            .parity_even_7bit => self.parity(input, true),
            .parity_odd_7bit => self.parity(input, false),
            .parity_zero_7bit => self.parityZero(input),
            .length => self.length(input),
            else => error.UnsupportedTransformation,
        };
    }

    fn writable(self: *Executor, capacity: usize) ApplyError!Scratch {
        if (capacity > self.limits.max_output_bytes) return error.OutputTooLarge;
        const slot = self.next_buffer;
        const buffer = &self.buffers[slot];
        buffer.clearRetainingCapacity();
        try buffer.ensureTotalCapacity(self.allocator, capacity);
        self.next_buffer = (slot + 1) % self.buffers.len;
        return .{
            .buffer = buffer,
            .storage = if (slot == 0) .executor_a else .executor_b,
        };
    }

    fn finish(generated: Scratch, input: []const u8, changed: bool) Result {
        if (std.mem.eql(u8, generated.buffer.items, input)) {
            generated.buffer.clearRetainingCapacity();
            return .{ .bytes = input, .changed = changed, .storage = .borrowed };
        }
        return .{ .bytes = generated.buffer.items, .changed = changed, .storage = generated.storage };
    }

    fn mapAsciiCase(self: *Executor, input: []const u8, uppercase: bool) ApplyError!Result {
        var changed = false;
        for (input) |byte| {
            const mapped = if (uppercase) std.ascii.toUpper(byte) else std.ascii.toLower(byte);
            if (mapped != byte) {
                changed = true;
                break;
            }
        }
        if (!changed) return .{ .bytes = input, .changed = false, .storage = .borrowed };
        const generated = try self.writable(input.len);
        for (input) |byte| generated.buffer.appendAssumeCapacity(if (uppercase) std.ascii.toUpper(byte) else std.ascii.toLower(byte));
        return finish(generated, input, true);
    }

    fn cssDecode(self: *Executor, input: []const u8) ApplyError!Result {
        const first = std.mem.indexOfScalar(u8, input, '\\') orelse
            return .{ .bytes = input, .changed = false, .storage = .borrowed };
        const generated = try self.writable(input.len);
        generated.buffer.appendSliceAssumeCapacity(input[0..first]);
        var changed = self.profile == .coraza;
        var index = first;
        while (index < input.len) {
            if (input[index] != '\\') {
                generated.buffer.appendAssumeCapacity(input[index]);
                index += 1;
                continue;
            }
            if (index + 1 == input.len) {
                changed = true;
                index += 1;
                continue;
            }

            index += 1;
            var digits: usize = 0;
            while (digits < 6 and index + digits < input.len and isHex(input[index + digits])) : (digits += 1) {}
            if (digits != 0) {
                var decoded = if (digits == 1)
                    hexNibble(input[index]).?
                else
                    hexNibble(input[index + digits - 2]).? * 16 + hexNibble(input[index + digits - 1]).?;
                const full_width_check = digits == 4 or
                    (digits == 5 and input[index] == '0') or
                    (digits == 6 and input[index] == '0' and input[index + 1] == '0');
                if (full_width_check and decoded > 0 and decoded < 0x5f and
                    (input[index + digits - 4] == 'f' or input[index + digits - 4] == 'F') and
                    (input[index + digits - 3] == 'f' or input[index + digits - 3] == 'F'))
                {
                    decoded += 0x20;
                }
                generated.buffer.appendAssumeCapacity(decoded);
                index += digits;
                if (index < input.len and isAsciiWhitespace(input[index])) index += 1;
                changed = true;
            } else if (input[index] == '\n') {
                index += 1;
                changed = true;
            } else {
                generated.buffer.appendAssumeCapacity(input[index]);
                index += 1;
            }
        }
        return finish(generated, input, changed);
    }

    fn escapeSeqDecode(self: *Executor, input: []const u8) ApplyError!Result {
        const first = std.mem.indexOfScalar(u8, input, '\\') orelse
            return .{ .bytes = input, .changed = false, .storage = .borrowed };
        const generated = try self.writable(input.len);
        generated.buffer.appendSliceAssumeCapacity(input[0..first]);
        var changed = false;
        var index = first;
        while (index < input.len) {
            if (input[index] != '\\' or index + 1 == input.len) {
                generated.buffer.appendAssumeCapacity(input[index]);
                index += 1;
                continue;
            }

            const escaped = input[index + 1];
            if (cEscapeByte(escaped)) |decoded| {
                generated.buffer.appendAssumeCapacity(decoded);
                index += 2;
            } else if ((escaped == 'x' or escaped == 'X') and index + 3 < input.len and
                isHex(input[index + 2]) and isHex(input[index + 3]))
            {
                generated.buffer.appendAssumeCapacity(hexNibble(input[index + 2]).? * 16 + hexNibble(input[index + 3]).?);
                index += 4;
            } else if (isOctal(escaped)) {
                var digits: usize = 1;
                var decoded: u16 = escaped - '0';
                while (digits < 3 and index + 1 + digits < input.len and isOctal(input[index + 1 + digits])) : (digits += 1) {
                    decoded = decoded * 8 + input[index + 1 + digits] - '0';
                }
                generated.buffer.appendAssumeCapacity(@truncate(decoded));
                index += 1 + digits;
            } else {
                generated.buffer.appendAssumeCapacity(escaped);
                index += 2;
            }
            changed = true;
        }
        return finish(generated, input, changed);
    }

    fn jsDecode(self: *Executor, input: []const u8) ApplyError!Result {
        const first = std.mem.indexOfScalar(u8, input, '\\') orelse
            return .{ .bytes = input, .changed = false, .storage = .borrowed };
        const generated = try self.writable(input.len);
        generated.buffer.appendSliceAssumeCapacity(input[0..first]);
        var changed = false;
        var index = first;
        while (index < input.len) {
            if (input[index] != '\\') {
                generated.buffer.appendAssumeCapacity(input[index]);
                index += 1;
            } else if (index + 5 < input.len and input[index + 1] == 'u' and
                isHex(input[index + 2]) and isHex(input[index + 3]) and
                isHex(input[index + 4]) and isHex(input[index + 5]))
            {
                const code_point = decodeHexU16(input[index + 2 .. index + 6]);
                var decoded: u8 = @truncate(code_point);
                if (decoded > 0 and decoded < 0x5f and (code_point & 0xff00) == 0xff00) decoded += 0x20;
                generated.buffer.appendAssumeCapacity(decoded);
                index += 6;
                changed = true;
            } else if (index + 3 < input.len and input[index + 1] == 'x' and
                isHex(input[index + 2]) and isHex(input[index + 3]))
            {
                generated.buffer.appendAssumeCapacity(hexNibble(input[index + 2]).? * 16 + hexNibble(input[index + 3]).?);
                index += 4;
                changed = true;
            } else if (index + 1 < input.len and isOctal(input[index + 1])) {
                var digits: usize = 1;
                while (digits < 3 and index + 1 + digits < input.len and isOctal(input[index + 1 + digits])) : (digits += 1) {}
                if (digits == 3 and input[index + 1] > '3') digits = 2;
                var decoded: u8 = 0;
                for (input[index + 1 .. index + 1 + digits]) |digit| decoded = decoded * 8 + digit - '0';
                generated.buffer.appendAssumeCapacity(decoded);
                index += 1 + digits;
                changed = true;
            } else if (index + 1 < input.len) {
                generated.buffer.appendAssumeCapacity(cEscapeByte(input[index + 1]) orelse input[index + 1]);
                index += 2;
                changed = true;
            } else {
                generated.buffer.appendAssumeCapacity(input[index]);
                index += 1;
            }
        }
        return finish(generated, input, changed);
    }

    fn compressWhitespace(self: *Executor, input: []const u8) ApplyError!Result {
        var first: ?usize = null;
        for (input, 0..) |byte, index| {
            if (isAsciiWhitespace(byte)) {
                first = index;
                break;
            }
        }
        if (first == null) return .{ .bytes = input, .changed = false, .storage = .borrowed };
        const generated = try self.writable(input.len);
        generated.buffer.appendSliceAssumeCapacity(input[0..first.?]);
        var in_whitespace = false;
        for (input[first.?..]) |byte| {
            if (isAsciiWhitespace(byte)) {
                if (in_whitespace) continue;
                in_whitespace = true;
                generated.buffer.appendAssumeCapacity(' ');
            } else {
                in_whitespace = false;
                generated.buffer.appendAssumeCapacity(byte);
            }
        }
        return finish(generated, input, generated.buffer.items.len != input.len);
    }

    fn removeBytes(self: *Executor, input: []const u8, comptime predicate: fn (u8) bool) ApplyError!Result {
        var first: ?usize = null;
        for (input, 0..) |byte, index| {
            if (predicate(byte)) {
                first = index;
                break;
            }
        }
        if (first == null) return .{ .bytes = input, .changed = false, .storage = .borrowed };
        const generated = try self.writable(input.len - 1);
        generated.buffer.appendSliceAssumeCapacity(input[0..first.?]);
        for (input[first.? + 1 ..]) |byte| if (!predicate(byte)) generated.buffer.appendAssumeCapacity(byte);
        return finish(generated, input, true);
    }

    fn replaceNulls(self: *Executor, input: []const u8) ApplyError!Result {
        if (std.mem.indexOfScalar(u8, input, 0) == null)
            return .{ .bytes = input, .changed = false, .storage = .borrowed };
        const generated = try self.writable(input.len);
        for (input) |byte| generated.buffer.appendAssumeCapacity(if (byte == 0) ' ' else byte);
        return finish(generated, input, true);
    }

    fn hexDecode(self: *Executor, input: []const u8) ApplyError!Result {
        if (self.profile == .coraza) {
            if (input.len % 2 != 0) return error.InvalidInput;
            for (input) |byte| if (!isHex(byte)) return error.InvalidInput;
        } else if (input.len == 0) {
            return .{ .bytes = input, .changed = false, .storage = .borrowed };
        }
        const generated = try self.writable(input.len / 2);
        var index: usize = 0;
        while (index + 1 < input.len) : (index += 2) {
            const high = if (self.profile == .coraza) hexNibble(input[index]).? else modSecurityHexNibble(input[index]);
            const low = if (self.profile == .coraza) hexNibble(input[index + 1]).? else modSecurityHexNibble(input[index + 1]);
            generated.buffer.appendAssumeCapacity(high *% 16 +% low);
        }
        return finish(generated, input, true);
    }

    fn base64Encode(self: *Executor, input: []const u8) ApplyError!Result {
        if (input.len == 0)
            return .{ .bytes = input, .changed = self.profile == .coraza, .storage = .borrowed };
        const groups = std.math.add(usize, input.len, 2) catch return error.OutputTooLarge;
        const capacity = std.math.mul(usize, groups / 3, 4) catch return error.OutputTooLarge;
        const generated = try self.writable(capacity);
        const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        var index: usize = 0;
        while (index + 3 <= input.len) : (index += 3) {
            const bits = (@as(u24, input[index]) << 16) | (@as(u24, input[index + 1]) << 8) | input[index + 2];
            generated.buffer.appendAssumeCapacity(alphabet[@intCast((bits >> 18) & 0x3f)]);
            generated.buffer.appendAssumeCapacity(alphabet[@intCast((bits >> 12) & 0x3f)]);
            generated.buffer.appendAssumeCapacity(alphabet[@intCast((bits >> 6) & 0x3f)]);
            generated.buffer.appendAssumeCapacity(alphabet[@intCast(bits & 0x3f)]);
        }
        const remaining = input.len - index;
        if (remaining != 0) {
            const first: u24 = @as(u24, input[index]) << 16;
            const second: u24 = if (remaining == 2) @as(u24, input[index + 1]) << 8 else 0;
            const bits = first | second;
            generated.buffer.appendAssumeCapacity(alphabet[@intCast((bits >> 18) & 0x3f)]);
            generated.buffer.appendAssumeCapacity(alphabet[@intCast((bits >> 12) & 0x3f)]);
            generated.buffer.appendAssumeCapacity(if (remaining == 2) alphabet[@intCast((bits >> 6) & 0x3f)] else '=');
            generated.buffer.appendAssumeCapacity('=');
        }
        return finish(generated, input, true);
    }

    fn base64Decode(self: *Executor, input: []const u8, extended: bool) ApplyError!Result {
        if (input.len == 0) return .{ .bytes = input, .changed = false, .storage = .borrowed };
        const base_capacity = std.math.mul(usize, input.len / 4, 3) catch return error.OutputTooLarge;
        const capacity = std.math.add(usize, base_capacity, 2) catch return error.OutputTooLarge;
        const generated = try self.writable(capacity);
        var accumulator: u32 = 0;
        var sextets: u3 = 0;
        var padding: u3 = 0;
        var saw_padding = false;
        var invalid = false;

        const strict_modsecurity = self.profile == .modsecurity and !extended;
        for (input) |byte| {
            if (strict_modsecurity and byte == 0) break;
            if (byte == '=') {
                if (self.profile == .modsecurity and extended) continue;
                saw_padding = true;
                padding +|= 1;
                continue;
            }
            if (base64Value(byte)) |value| {
                if (saw_padding) {
                    invalid = true;
                    break;
                }
                accumulator = (accumulator << 6) | value;
                sextets += 1;
                if (sextets == 4) {
                    generated.buffer.appendAssumeCapacity(@intCast((accumulator >> 16) & 0xff));
                    generated.buffer.appendAssumeCapacity(@intCast((accumulator >> 8) & 0xff));
                    generated.buffer.appendAssumeCapacity(@intCast(accumulator & 0xff));
                    accumulator = 0;
                    sextets = 0;
                }
                continue;
            }

            const ignored = if (extended)
                if (self.profile == .modsecurity) true else byte == '.' or isCorazaBase64Whitespace(byte)
            else
                byte == '\r' or byte == '\n';
            if (ignored) continue;
            if (self.profile == .coraza) break;
            invalid = true;
            break;
        }

        if (strict_modsecurity) {
            const valid_padding = switch (sextets) {
                0 => padding == 0,
                2 => padding == 0 or padding == 2,
                3 => padding == 0 or padding == 1,
                else => false,
            };
            if (invalid or !valid_padding) {
                generated.buffer.clearRetainingCapacity();
                return .{ .bytes = input, .changed = false, .storage = .borrowed };
            }
        }
        switch (sextets) {
            2 => {
                accumulator <<= 12;
                generated.buffer.appendAssumeCapacity(@intCast((accumulator >> 16) & 0xff));
            },
            3 => {
                accumulator <<= 6;
                generated.buffer.appendAssumeCapacity(@intCast((accumulator >> 16) & 0xff));
                generated.buffer.appendAssumeCapacity(@intCast((accumulator >> 8) & 0xff));
            },
            else => {},
        }
        return finish(generated, input, true);
    }

    fn hexEncode(self: *Executor, input: []const u8) ApplyError!Result {
        if (input.len == 0)
            return .{ .bytes = input, .changed = self.profile == .coraza, .storage = .borrowed };
        const capacity = std.math.mul(usize, input.len, 2) catch return error.OutputTooLarge;
        const generated = try self.writable(capacity);
        const digits = "0123456789abcdef";
        for (input) |byte| {
            generated.buffer.appendAssumeCapacity(digits[byte >> 4]);
            generated.buffer.appendAssumeCapacity(digits[byte & 0x0f]);
        }
        return finish(generated, input, true);
    }

    fn sqlHexDecode(self: *Executor, input: []const u8) ApplyError!Result {
        var first: ?usize = null;
        var index: usize = 0;
        while (index + 3 < input.len) : (index += 1) {
            if (input[index] == '0' and
                (input[index + 1] == 'x' or input[index + 1] == 'X') and
                isHex(input[index + 2]) and
                isHex(input[index + 3]))
            {
                first = index;
                break;
            }
        }
        if (first == null) return .{ .bytes = input, .changed = false, .storage = .borrowed };

        const generated = try self.writable(input.len - 2);
        generated.buffer.appendSliceAssumeCapacity(input[0..first.?]);
        index = first.?;
        while (index < input.len) {
            if (index + 3 < input.len and
                input[index] == '0' and
                (input[index + 1] == 'x' or input[index + 1] == 'X') and
                isHex(input[index + 2]) and
                isHex(input[index + 3]))
            {
                index += 2;
                while (index + 1 < input.len and isHex(input[index]) and isHex(input[index + 1])) {
                    generated.buffer.appendAssumeCapacity(hexNibble(input[index]).? * 16 + hexNibble(input[index + 1]).?);
                    index += 2;
                }
            } else {
                generated.buffer.appendAssumeCapacity(input[index]);
                index += 1;
            }
        }
        return finish(generated, input, true);
    }

    fn urlDecode(self: *Executor, input: []const u8) ApplyError!Result {
        return self.urlDecodeInternal(input, false);
    }

    fn urlDecodeUni(self: *Executor, input: []const u8) ApplyError!Result {
        return self.urlDecodeInternal(input, true);
    }

    fn urlDecodeInternal(self: *Executor, input: []const u8, unicode: bool) ApplyError!Result {
        var changed = false;
        var index: usize = 0;
        while (index < input.len) : (index += 1) {
            if (input[index] == '+') {
                changed = true;
                break;
            }
            if (input[index] == '%') {
                if (self.profile == .coraza or
                    (unicode and isValidUrlUnicodeEscape(input, index)) or
                    (index + 2 < input.len and isHex(input[index + 1]) and isHex(input[index + 2])))
                {
                    changed = true;
                    break;
                }
            }
        }
        if (!changed) return .{ .bytes = input, .changed = false, .storage = .borrowed };

        const generated = try self.writable(input.len);
        index = 0;
        while (index < input.len) {
            if (unicode and isValidUrlUnicodeEscape(input, index)) {
                const code_point = decodeHexU16(input[index + 2 .. index + 6]);
                var decoded = if (self.unicode_map) |unicode_map|
                    unicode_map.lookup(code_point)
                else
                    null;
                if (decoded == null) {
                    decoded = @truncate(code_point);
                    if (decoded.? > 0 and decoded.? < 0x5f and (code_point & 0xff00) == 0xff00) {
                        decoded.? += 0x20;
                    }
                }
                generated.buffer.appendAssumeCapacity(decoded.?);
                index += 6;
            } else if (unicode and input[index] == '%' and index + 1 < input.len and
                (input[index + 1] == 'u' or input[index + 1] == 'U'))
            {
                generated.buffer.appendSliceAssumeCapacity(input[index .. index + 2]);
                index += 2;
            } else if (input[index] == '%' and index + 2 < input.len and isHex(input[index + 1]) and isHex(input[index + 2])) {
                generated.buffer.appendAssumeCapacity(hexNibble(input[index + 1]).? * 16 + hexNibble(input[index + 2]).?);
                index += 3;
            } else {
                generated.buffer.appendAssumeCapacity(if (input[index] == '+') ' ' else input[index]);
                index += 1;
            }
        }
        return finish(generated, input, true);
    }

    fn urlEncode(self: *Executor, input: []const u8) ApplyError!Result {
        var changed = false;
        for (input) |byte| {
            if (!isUrlUnescaped(byte)) {
                changed = true;
                break;
            }
        }
        if (!changed) return .{ .bytes = input, .changed = false, .storage = .borrowed };
        const capacity = std.math.mul(usize, input.len, 3) catch return error.OutputTooLarge;
        const generated = try self.writable(capacity);
        const digits = "0123456789abcdef";
        for (input) |byte| {
            if (byte == ' ') {
                generated.buffer.appendAssumeCapacity('+');
            } else if (isUrlUnescaped(byte)) {
                generated.buffer.appendAssumeCapacity(byte);
            } else {
                generated.buffer.appendAssumeCapacity('%');
                generated.buffer.appendAssumeCapacity(digits[byte >> 4]);
                generated.buffer.appendAssumeCapacity(digits[byte & 0x0f]);
            }
        }
        return finish(generated, input, true);
    }

    fn parity(self: *Executor, input: []const u8, even: bool) ApplyError!Result {
        if (input.len == 0) return .{ .bytes = input, .changed = false, .storage = .borrowed };
        const generated = try self.writable(input.len);
        for (input) |byte| {
            const seven = byte & 0x7f;
            const odd_ones = @popCount(seven) % 2 == 1;
            const high: u8 = if (if (even) odd_ones else !odd_ones) 0x80 else 0;
            generated.buffer.appendAssumeCapacity(seven | high);
        }
        return finish(generated, input, true);
    }

    fn parityZero(self: *Executor, input: []const u8) ApplyError!Result {
        if (input.len == 0) return .{ .bytes = input, .changed = false, .storage = .borrowed };
        const generated = try self.writable(input.len);
        for (input) |byte| generated.buffer.appendAssumeCapacity(byte & 0x7f);
        return finish(generated, input, true);
    }

    fn length(self: *Executor, input: []const u8) ApplyError!Result {
        var storage: [32]u8 = undefined;
        const rendered = std.fmt.bufPrint(&storage, "{d}", .{input.len}) catch unreachable;
        const generated = try self.writable(rendered.len);
        generated.buffer.appendSliceAssumeCapacity(rendered);
        return finish(generated, input, true);
    }
};

fn trimResult(input: []const u8, left: bool, right: bool) Result {
    var start: usize = 0;
    var end = input.len;
    if (left) {
        while (start < end and isAsciiWhitespace(input[start])) : (start += 1) {}
    }
    if (right) {
        while (end > start and isAsciiWhitespace(input[end - 1])) : (end -= 1) {}
    }
    return .{ .bytes = input[start..end], .changed = start != 0 or end != input.len, .storage = .borrowed };
}

fn isAsciiWhitespace(byte: u8) bool {
    return switch (byte) {
        ' ', '\t', '\n', '\r', 0x0b, 0x0c => true,
        else => false,
    };
}

fn isRemovalWhitespace(byte: u8) bool {
    return isAsciiWhitespace(byte) or byte == 0xa0 or byte == 0xc2;
}

fn isNull(byte: u8) bool {
    return byte == 0;
}

fn cEscapeByte(byte: u8) ?u8 {
    return switch (byte) {
        'a' => 0x07,
        'b' => 0x08,
        'f' => 0x0c,
        'n' => '\n',
        'r' => '\r',
        't' => '\t',
        'v' => 0x0b,
        '\\', '?', '\'', '"' => byte,
        else => null,
    };
}

fn isOctal(byte: u8) bool {
    return byte >= '0' and byte <= '7';
}

fn isHex(byte: u8) bool {
    return hexNibble(byte) != null;
}

fn hexNibble(byte: u8) ?u8 {
    return switch (byte) {
        '0'...'9' => byte - '0',
        'a'...'f' => byte - 'a' + 10,
        'A'...'F' => byte - 'A' + 10,
        else => null,
    };
}

fn modSecurityHexNibble(byte: u8) u8 {
    return if (byte >= 'A') ((byte & 0xdf) -% 'A') +% 10 else byte -% '0';
}

fn isUrlUnescaped(byte: u8) bool {
    return byte == '*' or std.ascii.isAlphanumeric(byte);
}

fn isValidUrlUnicodeEscape(input: []const u8, index: usize) bool {
    return index + 5 < input.len and
        input[index] == '%' and
        (input[index + 1] == 'u' or input[index + 1] == 'U') and
        isHex(input[index + 2]) and
        isHex(input[index + 3]) and
        isHex(input[index + 4]) and
        isHex(input[index + 5]);
}

fn decodeHexU16(input: []const u8) u16 {
    return (@as(u16, hexNibble(input[0]).?) << 12) |
        (@as(u16, hexNibble(input[1]).?) << 8) |
        (@as(u16, hexNibble(input[2]).?) << 4) |
        hexNibble(input[3]).?;
}

fn base64Value(byte: u8) ?u6 {
    return switch (byte) {
        'A'...'Z' => @intCast(byte - 'A'),
        'a'...'z' => @intCast(byte - 'a' + 26),
        '0'...'9' => @intCast(byte - '0' + 52),
        '+' => 62,
        '/' => 63,
        else => null,
    };
}

fn isCorazaBase64Whitespace(byte: u8) bool {
    return isAsciiWhitespace(byte) or byte == 0x85 or byte == 0xa0;
}

test "stable transformation union and aliases resolve canonically" {
    try std.testing.expectEqual(@as(usize, 35), specs.len);
    for (specs) |spec| {
        try std.testing.expectEqual(spec.kind, (resolve(spec.name) orelse return error.MissingTransformation).builtin);
        const uppercase = try std.ascii.allocUpperString(std.testing.allocator, spec.name);
        defer std.testing.allocator.free(uppercase);
        try std.testing.expectEqual(spec.kind, (resolve(uppercase) orelse return error.MissingTransformation).builtin);
        try std.testing.expectEqualStrings(spec.name, spec.kind.canonicalName());
    }
    try std.testing.expectEqual(Resolution.reset, resolve("NoNe").?);
    try std.testing.expectEqual(Kind.normalise_path, resolve("normalizePath").?.builtin);
    try std.testing.expectEqual(Kind.normalise_path_win, resolve("NORMALIZEPATHWIN").?.builtin);
    try std.testing.expect(resolve("notAStableTransformation") == null);
}

test "bounded executor preserves borrowed and upstream changed semantics" {
    var executor = try Executor.init(std.testing.allocator, .{});
    defer executor.deinit();

    const unchanged = try executor.apply(.lowercase, "already lower");
    try std.testing.expectEqual(Storage.borrowed, unchanged.storage);
    try std.testing.expect(!unchanged.changed);
    try std.testing.expectEqualStrings("already lower", unchanged.bytes);

    const lower = try executor.apply(.lowercase, "A\xffZ");
    try std.testing.expectEqualStrings("a\xffz", lower.bytes);
    try std.testing.expect(lower.changed);
    const upper = try executor.apply(.uppercase, "a\xffz");
    try std.testing.expectEqualStrings("A\xffZ", upper.bytes);

    const trimmed = try executor.apply(.trim, " \tvalue\r\n");
    try std.testing.expectEqual(Storage.borrowed, trimmed.storage);
    try std.testing.expectEqualStrings("value", trimmed.bytes);
    try std.testing.expect(trimmed.changed);

    const compressed_same_length = try executor.apply(.compress_whitespace, "\t");
    try std.testing.expectEqualStrings(" ", compressed_same_length.bytes);
    try std.testing.expect(!compressed_same_length.changed);
    const compressed = try executor.apply(.compress_whitespace, "\t a \n\nb");
    try std.testing.expectEqualStrings(" a b", compressed.bytes);
    try std.testing.expect(compressed.changed);
}

test "filter parity and length transformations are binary exact" {
    var executor = try Executor.init(std.testing.allocator, .{});
    defer executor.deinit();

    try std.testing.expectEqualStrings("ab", (try executor.apply(.remove_nulls, "a\x00b\x00")).bytes);
    try std.testing.expectEqualStrings("a b ", (try executor.apply(.replace_nulls, "a\x00b\x00")).bytes);
    try std.testing.expectEqualStrings("ab", (try executor.apply(.remove_whitespace, " \ta\xc2\xa0b\r")).bytes);

    const zero = try executor.apply(.parity_zero_7bit, &.{ 0xff, 0x80, 0x41 });
    try std.testing.expectEqualSlices(u8, &.{ 0x7f, 0x00, 0x41 }, zero.bytes);
    try std.testing.expect(zero.changed);
    try std.testing.expectEqualSlices(u8, &.{ 0x41, 0xc3 }, (try executor.apply(.parity_even_7bit, "AC")).bytes);
    try std.testing.expectEqualSlices(u8, &.{ 0xc1, 0x43 }, (try executor.apply(.parity_odd_7bit, "AC")).bytes);

    const length = try executor.apply(.length, "abc\x00");
    try std.testing.expectEqualStrings("4", length.bytes);
    try std.testing.expect(length.changed);
}

test "hex profiles preserve pinned malformed and empty-input behavior" {
    var modsecurity = try Executor.initWithProfile(std.testing.allocator, .{}, .modsecurity);
    defer modsecurity.deinit();
    var coraza = try Executor.initWithProfile(std.testing.allocator, .{}, .coraza);
    defer coraza.deinit();

    try std.testing.expectEqualStrings("Test\x00Case", (try modsecurity.apply(.hex_decode, "546573740043617365")).bytes);
    try std.testing.expectEqualStrings("546573740043617365", (try modsecurity.apply(.hex_encode, "Test\x00Case")).bytes);
    try std.testing.expectEqualStrings("A", (try modsecurity.apply(.hex_decode, "414")).bytes);
    try std.testing.expect(!(try modsecurity.apply(.hex_decode, "")).changed);
    try std.testing.expect((try coraza.apply(.hex_decode, "")).changed);
    try std.testing.expect((try coraza.apply(.hex_encode, "")).changed);
    try std.testing.expectError(error.InvalidInput, coraza.apply(.hex_decode, "414"));
    try std.testing.expectError(error.InvalidInput, coraza.apply(.hex_decode, "0z"));
}

test "SQL hex decoding preserves malformed prefixes and decodes complete runs" {
    var executor = try Executor.init(std.testing.allocator, .{});
    defer executor.deinit();

    try std.testing.expectEqualStrings("ABC", (try executor.apply(.sql_hex_decode, "0x414243")).bytes);
    try std.testing.expectEqualStrings("aABCz  !", (try executor.apply(.sql_hex_decode, "a0x414243z 0X20!")).bytes);
    try std.testing.expectEqualSlices(u8, &.{ 0, 0xff, 'z' }, (try executor.apply(.sql_hex_decode, "0x00ffz")).bytes);

    for ([_][]const u8{ "", "0x", "0x4", "0xGG", "prefix 0x4" }) |malformed| {
        const result = try executor.apply(.sql_hex_decode, malformed);
        try std.testing.expectEqual(Storage.borrowed, result.storage);
        try std.testing.expect(!result.changed);
        try std.testing.expectEqualStrings(malformed, result.bytes);
    }
}

test "Base64 profiles separate strict partial and forgiving decoding" {
    var modsecurity = try Executor.initWithProfile(std.testing.allocator, .{}, .modsecurity);
    defer modsecurity.deinit();
    var coraza = try Executor.initWithProfile(std.testing.allocator, .{}, .coraza);
    defer coraza.deinit();

    try std.testing.expectEqualStrings("VGVzdENhc2U=", (try modsecurity.apply(.base64_encode, "TestCase")).bytes);
    try std.testing.expectEqualStrings("TestCase", (try modsecurity.apply(.base64_decode, "VGVzdENhc2U=")).bytes);
    try std.testing.expectEqualStrings("TestCase1", (try modsecurity.apply(.base64_decode, "VGVzdENhc2Ux")).bytes);
    try std.testing.expectEqualStrings("Test\x00Case", (try modsecurity.apply(.base64_decode, "VGVzdABDYXNl")).bytes);

    const strict_invalid = try modsecurity.apply(.base64_decode, "VGVz!dA==");
    try std.testing.expectEqual(Storage.borrowed, strict_invalid.storage);
    try std.testing.expect(!strict_invalid.changed);
    try std.testing.expectEqualStrings("VGVz!dA==", strict_invalid.bytes);
    try std.testing.expectEqualStrings("Test", (try coraza.apply(.base64_decode, "VGVzdA!ignored")).bytes);
    try std.testing.expectEqualStrings("Test", (try modsecurity.apply(.base64_decode_ext, "V.G V\n z-dA==")).bytes);
    try std.testing.expectEqualStrings("Test", (try coraza.apply(.base64_decode_ext, "V.G V\n zdA==")).bytes);

    try std.testing.expect(!(try modsecurity.apply(.base64_encode, "")).changed);
    try std.testing.expect((try coraza.apply(.base64_encode, "")).changed);
    try std.testing.expect(!(try coraza.apply(.base64_decode, "")).changed);
}

test "URL encoding is byte-oriented and malformed decoding is non-strict" {
    var executor = try Executor.init(std.testing.allocator, .{});
    defer executor.deinit();

    try std.testing.expectEqualStrings("Test Case", (try executor.apply(.url_decode, "Test+Case")).bytes);
    try std.testing.expectEqualStrings("% ", (try executor.apply(.url_decode, "%%20")).bytes);
    try std.testing.expectEqualStrings("%0g ", (try executor.apply(.url_decode, "%0g%20")).bytes);
    const malformed = try executor.apply(.url_decode, "%0%gg");
    try std.testing.expectEqual(Storage.borrowed, malformed.storage);
    try std.testing.expect(!malformed.changed);
    try std.testing.expectEqualStrings("%0%gg", malformed.bytes);

    try std.testing.expectEqualStrings("Test+Case", (try executor.apply(.url_encode, "Test Case")).bytes);
    try std.testing.expectEqualStrings("*AZaz09%2f%00", (try executor.apply(.url_encode, "*AZaz09/\x00")).bytes);
}

test "URL Unicode decoding matches profile flags and IIS full-width folding" {
    var modsecurity = try Executor.initWithProfile(std.testing.allocator, .{}, .modsecurity);
    defer modsecurity.deinit();
    var coraza = try Executor.initWithProfile(std.testing.allocator, .{}, .coraza);
    defer coraza.deinit();

    try std.testing.expectEqualStrings("Test Case", (try modsecurity.apply(.url_decode_uni, "Test%u0020Case")).bytes);
    try std.testing.expectEqualStrings("ABC", (try modsecurity.apply(.url_decode_uni, "%u0041%U0042%43")).bytes);
    try std.testing.expectEqualStrings("!~", (try modsecurity.apply(.url_decode_uni, "%uff01%uFF5e")).bytes);
    try std.testing.expectEqualSlices(u8, &.{ 0, 0xff }, (try modsecurity.apply(.url_decode_uni, "%u1100%u00ff")).bytes);
    try std.testing.expectEqualStrings("%u000g ", (try modsecurity.apply(.url_decode_uni, "%u000g%u0020")).bytes);
    try std.testing.expectEqualStrings("%u", (try modsecurity.apply(.url_decode_uni, "%u")).bytes);

    const modsecurity_malformed = try modsecurity.apply(.url_decode_uni, "%gg");
    try std.testing.expect(!modsecurity_malformed.changed);
    const coraza_malformed = try coraza.apply(.url_decode_uni, "%gg");
    try std.testing.expect(coraza_malformed.changed);
    try std.testing.expectEqual(Storage.borrowed, coraza_malformed.storage);
    try std.testing.expectEqualStrings("%gg", coraza_malformed.bytes);
    try std.testing.expect((try coraza.apply(.url_decode, "%gg")).changed);

    var table: [0x42]i32 = undefined;
    @memset(&table, -1);
    table[0x41] = 'z';
    var mapped = try Executor.initWithOptions(std.testing.allocator, .{}, .{
        .profile = .modsecurity,
        .unicode_map = .{ .table = &table },
    });
    defer mapped.deinit();
    try std.testing.expectEqualStrings("zB", (try mapped.apply(.url_decode_uni, "%u0041%u0042")).bytes);
}

test "CSS decoding preserves six-digit boundaries and profile changed flags" {
    var modsecurity = try Executor.initWithProfile(std.testing.allocator, .{}, .modsecurity);
    defer modsecurity.deinit();
    var coraza = try Executor.initWithProfile(std.testing.allocator, .{}, .coraza);
    defer coraza.deinit();

    try std.testing.expectEqualStrings("\x1a\x01AV7V7\x01x\x01x", (try modsecurity.apply(.css_decode, "\\1A\\1 A\\1234567\\123456 7\\1x\\1 x")).bytes);
    try std.testing.expectEqualStrings("\n\x0b\x0fnrtv?'\"\x00\x12#4EV!~\x00  string", (try modsecurity.apply(.css_decode, "\\a\\b\\f\\n\\r\\t\\v\\?\\'\\\"\\\x00\\12\\123\\1234\\12345\\123456\\ff01\\ff5e\\\n\\\x00  string")).bytes);
    try std.testing.expectEqualStrings("test", (try modsecurity.apply(.css_decode, "test\\")).bytes);

    const escaped_literal = try modsecurity.apply(.css_decode, "\\q");
    try std.testing.expectEqualStrings("q", escaped_literal.bytes);
    try std.testing.expect(!escaped_literal.changed);
    try std.testing.expect((try coraza.apply(.css_decode, "\\q")).changed);
    try std.testing.expectEqualSlices(u8, &.{ 0, 'x' }, (try modsecurity.apply(.css_decode, "\\0x")).bytes);
}

test "C escape decoding handles simple hex octal and malformed sequences" {
    var executor = try Executor.init(std.testing.allocator, .{});
    defer executor.deinit();

    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x07, 0x08, 0x0c, '\n', '\r', '\t', 0x0b, '?', '\'', '"', 0, 10, 'S', 0, 0xff },
        (try executor.apply(.escape_seq_decode, "\\a\\b\\f\\n\\r\\t\\v\\?\\'\\\"\\0\\12\\123\\x00\\xff")).bytes,
    );
    try std.testing.expectEqualSlices(u8, &.{ '8', '9', 0xb6, 'x', 'a', 'g', 'x', 'g', 'a', 10, '3' }, (try executor.apply(.escape_seq_decode, "\\8\\9\\666\\xag\\xga\\0123")).bytes);

    const trailing = try executor.apply(.escape_seq_decode, "value\\");
    try std.testing.expectEqualStrings("value\\", trailing.bytes);
    try std.testing.expect(!trailing.changed);
    try std.testing.expectEqualStrings("q", (try executor.apply(.escape_seq_decode, "\\q")).bytes);
}

test "JavaScript decoding handles Unicode hex octal and escaped literals" {
    var executor = try Executor.init(std.testing.allocator, .{});
    defer executor.deinit();

    try std.testing.expectEqualSlices(
        u8,
        &.{ '\\', 'a', '\\', 'b', '\\', 'f', '\\', 'n', '\\', 'r', '\\', 't', '\\', 'v', '?', '\'', '"', 0, 10, 'S', 0, 0xff },
        (try executor.apply(.js_decode, "\\\\a\\\\b\\\\f\\\\n\\\\r\\\\t\\\\v\\?\\'\\\"\\0\\12\\123\\x00\\xff")).bytes,
    );
    try std.testing.expectEqualStrings("A!~", (try executor.apply(.js_decode, "\\u0041\\uff01\\uFF5e")).bytes);
    try std.testing.expectEqualStrings("?7", (try executor.apply(.js_decode, "\\777")).bytes);
    try std.testing.expectEqualStrings("uUxxg", (try executor.apply(.js_decode, "\\u\\U\\x\\xg")).bytes);

    const trailing = try executor.apply(.js_decode, "\\");
    try std.testing.expectEqualStrings("\\", trailing.bytes);
    try std.testing.expect(!trailing.changed);
}

test "executor validates deterministic input and output limits" {
    try std.testing.expectError(error.InvalidLimits, Executor.init(std.testing.allocator, .{ .max_input_bytes = 0 }));
    var executor = try Executor.init(std.testing.allocator, .{
        .max_input_bytes = 3,
        .max_output_bytes = 1,
        .max_cumulative_output_bytes = 1,
    });
    defer executor.deinit();
    try std.testing.expectError(error.InputTooLarge, executor.apply(.lowercase, "four"));
    try std.testing.expectError(error.OutputTooLarge, executor.apply(.uppercase, "ab"));
    try std.testing.expectError(error.OutputTooLarge, executor.apply(.url_encode, "!"));
    try std.testing.expectError(error.UnsupportedTransformation, executor.apply(.cmd_line, "x"));
}

test "executor scratch ownership is exhaustive-allocation-failure safe" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, struct {
        fn run(allocator: std.mem.Allocator) !void {
            var executor = try Executor.init(allocator, .{});
            defer executor.deinit();
            try std.testing.expectEqualStrings(" mixed whitespace ", (try executor.apply(.compress_whitespace, "\t mixed\n\nwhitespace \r")).bytes);
            try std.testing.expectEqualStrings("MIXED", (try executor.apply(.uppercase, "mixed")).bytes);
            try std.testing.expectEqualSlices(u8, &.{ 0x41, 0xc3 }, (try executor.apply(.parity_even_7bit, "AC")).bytes);
        }
    }.run, .{});
}
