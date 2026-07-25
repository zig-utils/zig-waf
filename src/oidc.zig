//! OpenID Connect ID-token verification for console login (#58).
//!
//! This module answers one question: does this ID token prove that *this*
//! identity provider authenticated *this* subject for *this* console, right now?
//! Everything it does is a precondition of that answer, and anything it cannot
//! check is rejected rather than assumed — an unverifiable token is worth exactly
//! as much as a forged one.
//!
//! Deliberately not here:
//!
//!   * Discovery and JWKS fetching. Those are HTTP with a destination policy,
//!     which the caller already has to own (see `remote_rules.zig` for the same
//!     separation). Verification takes keys as bytes so it stays a pure function
//!     of its inputs and can be tested exhaustively without a network.
//!   * `none` and HMAC (`HS*`) algorithms. A token whose "signature" is a shared
//!     secret cannot distinguish the provider from anyone else holding it, and
//!     `alg: none` is the canonical JWT vulnerability. The algorithm comes from
//!     the *key*, never from the token's own header, so a token cannot nominate
//!     how it would like to be verified.

const std = @import("std");

pub const Error = error{
    /// Not three base64url segments, or a segment that is not valid base64url.
    Malformed,
    /// The header or payload is not an object, or a required claim is missing or
    /// of the wrong type.
    InvalidClaims,
    /// The signature does not verify under the given key.
    InvalidSignature,
    /// The token's header names an algorithm the key cannot verify, so accepting
    /// it would mean verifying something other than what was signed.
    AlgorithmMismatch,
    /// The issuer, audience, or nonce is not the expected one.
    Untrusted,
    /// `exp` has passed, or `iat`/`nbf` is in the future beyond the allowed skew.
    Expired,
    /// The key material is not a usable public key.
    InvalidKey,
    OutOfMemory,
};

/// A provider signing key, from a JWKS entry. The algorithm is a property of the
/// key, so a token cannot choose how it is verified.
pub const Key = union(enum) {
    /// RSASSA-PKCS1-v1_5 with SHA-256 — the algorithm nearly every provider uses.
    rs256: struct {
        /// The modulus, big-endian ("n" in a JWKS, base64url-decoded).
        modulus: []const u8,
        /// The public exponent, big-endian ("e", usually 65537).
        exponent: []const u8,
    },
    /// ECDSA on P-256 with SHA-256, for providers that use it.
    es256: struct {
        /// The uncompressed point, 0x04 ‖ X ‖ Y, or the 64-byte X ‖ Y form.
        point: []const u8,
    },

    /// The `alg` value a token must carry to be verified with this key.
    pub fn algorithm(self: Key) []const u8 {
        return switch (self) {
            .rs256 => "RS256",
            .es256 => "ES256",
        };
    }
};

/// What the token has to assert to be accepted.
pub const Expectations = struct {
    /// The provider that must have issued it, matched exactly.
    issuer: []const u8,
    /// This console's client id, which must appear in `aud`.
    audience: []const u8,
    /// The nonce sent in the authentication request, if one was. Checking it is
    /// what ties the token to *this* login attempt rather than a replay of an
    /// earlier one, so when a nonce was sent, a token without it is rejected.
    nonce: ?[]const u8 = null,
    /// Seconds of clock skew tolerated between this host and the provider.
    leeway_seconds: i64 = 60,
    /// Now, as a Unix timestamp. Passed in rather than read from the clock so
    /// verification is a pure function and expiry is testable.
    now: i64,
};

/// A verified token's identity claims, owned by the caller.
pub const Identity = struct {
    /// The provider's stable identifier for the person. This, not the email, is
    /// what an account is linked to: an email address can be reassigned to someone
    /// else, and at that moment a linkage by email hands them the old account.
    subject: []const u8,
    /// The email claim, if the provider sent one. Informational.
    email: ?[]const u8,
    /// Whether the provider says it verified that email.
    email_verified: bool,

    pub fn deinit(self: *Identity, allocator: std.mem.Allocator) void {
        allocator.free(self.subject);
        if (self.email) |email| allocator.free(email);
        self.* = undefined;
    }
};

/// The largest token this will look at. A provider's ID token is a few hundred
/// bytes; this bounds a hostile one.
pub const max_token_bytes = 8 * 1024;

/// Verify an ID token and return its identity claims (caller `deinit`s them).
///
/// Every check that can fail does, in a defined order, and any failure is a
/// rejection: there is no path that returns claims from a token whose signature,
/// issuer, audience, nonce, or lifetime was not confirmed.
pub fn verify(
    allocator: std.mem.Allocator,
    token: []const u8,
    key: Key,
    expectations: Expectations,
) Error!Identity {
    if (token.len > max_token_bytes) return error.Malformed;

    // Split into the three JWS segments. The signature covers "header.payload"
    // exactly as it appears, so the signing input is taken from the token rather
    // than re-encoded from parsed values.
    const first_dot = std.mem.indexOfScalar(u8, token, '.') orelse return error.Malformed;
    const rest = token[first_dot + 1 ..];
    const second_dot_in_rest = std.mem.indexOfScalar(u8, rest, '.') orelse return error.Malformed;
    const signing_input = token[0 .. first_dot + 1 + second_dot_in_rest];
    const header_b64 = token[0..first_dot];
    const payload_b64 = rest[0..second_dot_in_rest];
    const signature_b64 = rest[second_dot_in_rest + 1 ..];
    if (header_b64.len == 0 or payload_b64.len == 0 or signature_b64.len == 0) return error.Malformed;
    // A fourth segment means this is not a JWS the way this code reads it (a JWE,
    // or something malformed); refuse rather than verify the wrong bytes.
    if (std.mem.indexOfScalar(u8, signature_b64, '.') != null) return error.Malformed;

    // The header decides only which algorithm the token *claims*; the key decides
    // what is actually used. A token asking for `none`, or for HMAC, therefore
    // cannot get it — it simply fails to match the key's algorithm.
    var header_buffer: [1024]u8 = undefined;
    const header = try decodeSegment(header_b64, &header_buffer);
    if (!try headerDeclares(allocator, header, key.algorithm())) return error.AlgorithmMismatch;

    var signature_buffer: [1024]u8 = undefined;
    const signature = try decodeSegment(signature_b64, &signature_buffer);
    try verifySignature(key, signing_input, signature);

    var payload_buffer: [max_token_bytes]u8 = undefined;
    const payload = try decodeSegment(payload_b64, &payload_buffer);
    return validateClaims(allocator, payload, expectations);
}

fn decodeSegment(segment: []const u8, buffer: []u8) Error![]const u8 {
    const decoder = std.base64.url_safe_no_pad.Decoder;
    const size = decoder.calcSizeForSlice(segment) catch return error.Malformed;
    if (size > buffer.len) return error.Malformed;
    decoder.decode(buffer[0..size], segment) catch return error.Malformed;
    return buffer[0..size];
}

/// Whether the header's `alg` is exactly `expected`. `typ` is checked when
/// present: a token labelled as something other than a JWT is not one.
fn headerDeclares(allocator: std.mem.Allocator, header: []const u8, expected: []const u8) Error!bool {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, header, .{}) catch return error.InvalidClaims;
    defer parsed.deinit();
    const object = switch (parsed.value) {
        .object => |object| object,
        else => return error.InvalidClaims,
    };
    if (object.get("typ")) |typ| switch (typ) {
        .string => |text| if (!std.ascii.eqlIgnoreCase(text, "JWT")) return false,
        else => return error.InvalidClaims,
    };
    const alg = object.get("alg") orelse return error.InvalidClaims;
    return switch (alg) {
        .string => |text| std.mem.eql(u8, text, expected),
        else => error.InvalidClaims,
    };
}

fn verifySignature(key: Key, signing_input: []const u8, signature: []const u8) Error!void {
    switch (key) {
        .rs256 => |material| {
            const public_key = std.crypto.Certificate.rsa.PublicKey.fromBytes(material.exponent, material.modulus) catch
                return error.InvalidKey;
            // A signature is exactly the modulus length; a shorter or longer one is
            // not a signature for this key. Only the key sizes providers actually
            // publish are accepted, since the verifier needs the length at compile
            // time and an unrecognized size must not silently pick another.
            if (signature.len != material.modulus.len) return error.InvalidSignature;
            inline for (.{ 256, 384, 512 }) |modulus_len| {
                if (material.modulus.len == modulus_len) {
                    return std.crypto.Certificate.rsa.PKCS1v1_5Signature.verify(
                        modulus_len,
                        signature[0..modulus_len].*,
                        signing_input,
                        public_key,
                        std.crypto.hash.sha2.Sha256,
                    ) catch error.InvalidSignature;
                }
            }
            return error.InvalidKey;
        },
        .es256 => |material| {
            const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
            // JWS carries R ‖ S, fixed width — not the DER encoding X.509 uses.
            if (signature.len != Ecdsa.Signature.encoded_length) return error.InvalidSignature;
            const point = if (material.point.len == 64) blk: {
                var uncompressed: [65]u8 = undefined;
                uncompressed[0] = 4;
                @memcpy(uncompressed[1..], material.point);
                break :blk uncompressed;
            } else if (material.point.len == 65) material.point[0..65].* else return error.InvalidKey;
            const public_key = Ecdsa.PublicKey.fromSec1(&point) catch return error.InvalidKey;
            const parsed = Ecdsa.Signature.fromBytes(signature[0..Ecdsa.Signature.encoded_length].*);
            parsed.verify(signing_input, public_key) catch return error.InvalidSignature;
        },
    }
}

fn validateClaims(allocator: std.mem.Allocator, payload: []const u8, expectations: Expectations) Error!Identity {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, payload, .{}) catch return error.InvalidClaims;
    defer parsed.deinit();
    const object = switch (parsed.value) {
        .object => |object| object,
        else => return error.InvalidClaims,
    };

    const issuer = try stringClaim(object, "iss") orelse return error.InvalidClaims;
    if (!std.mem.eql(u8, issuer, expectations.issuer)) return error.Untrusted;

    // `aud` is a string or an array of strings; this console's client id has to be
    // in it, or the token was minted for somebody else and says so.
    if (!try audienceContains(object, expectations.audience)) return error.Untrusted;

    const expires = try integerClaim(object, "exp") orelse return error.InvalidClaims;
    if (expires + expectations.leeway_seconds <= expectations.now) return error.Expired;
    // A token issued in the future is either a clock problem or a forgery; either
    // way it is not evidence of a login that has happened.
    if (try integerClaim(object, "iat")) |issued| {
        if (issued - expectations.leeway_seconds > expectations.now) return error.Expired;
    }
    if (try integerClaim(object, "nbf")) |not_before| {
        if (not_before - expectations.leeway_seconds > expectations.now) return error.Expired;
    }

    if (expectations.nonce) |expected_nonce| {
        const nonce = try stringClaim(object, "nonce") orelse return error.Untrusted;
        if (!constantTimeEql(nonce, expected_nonce)) return error.Untrusted;
    }

    const subject = try stringClaim(object, "sub") orelse return error.InvalidClaims;
    if (subject.len == 0) return error.InvalidClaims;

    // Copied out, so the claims outlive the parsed tree rather than pointing into
    // memory that is about to be freed.
    const owned_subject = try allocator.dupe(u8, subject);
    errdefer allocator.free(owned_subject);
    const owned_email = if (try stringClaim(object, "email")) |email| try allocator.dupe(u8, email) else null;
    return .{
        .subject = owned_subject,
        .email = owned_email,
        .email_verified = switch (object.get("email_verified") orelse std.json.Value{ .bool = false }) {
            .bool => |value| value,
            // Providers have been known to send "true" as a string; only a real
            // boolean is treated as an assertion.
            else => false,
        },
    };
}

/// Compare without leaking how far the values matched. A nonce is a secret this
/// login attempt chose, and `std.crypto.timing_safe.eql` takes fixed-size arrays,
/// which a claim of unknown length is not.
fn constantTimeEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var difference: u8 = 0;
    for (a, b) |left, right| difference |= left ^ right;
    return difference == 0;
}

fn stringClaim(object: std.json.ObjectMap, name: []const u8) Error!?[]const u8 {
    const value = object.get(name) orelse return null;
    return switch (value) {
        .string => |text| text,
        .null => null,
        else => error.InvalidClaims,
    };
}

fn integerClaim(object: std.json.ObjectMap, name: []const u8) Error!?i64 {
    const value = object.get(name) orelse return null;
    return switch (value) {
        .integer => |number| number,
        // Timestamps are seconds; a fractional one is truncated toward the past,
        // which cannot extend a token's life.
        .float => |number| @intFromFloat(@floor(number)),
        .null => null,
        else => error.InvalidClaims,
    };
}

fn audienceContains(object: std.json.ObjectMap, audience: []const u8) Error!bool {
    const value = object.get("aud") orelse return error.InvalidClaims;
    return switch (value) {
        .string => |text| std.mem.eql(u8, text, audience),
        .array => |items| {
            for (items.items) |item| switch (item) {
                .string => |text| if (std.mem.eql(u8, text, audience)) return true,
                else => return error.InvalidClaims,
            };
            return false;
        },
        else => error.InvalidClaims,
    };
}

// ---- tests --------------------------------------------------------------

const testing = std.testing;

/// Build a token from its three parts, base64url-encoding header and payload and
/// signing "header.payload" with `key_pair` — what a provider does.
fn signEs256(
    allocator: std.mem.Allocator,
    header_json: []const u8,
    payload_json: []const u8,
    key_pair: std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair,
) ![]u8 {
    const encoder = std.base64.url_safe_no_pad.Encoder;
    var header_b64: [512]u8 = undefined;
    var payload_b64: [2048]u8 = undefined;
    const header = encoder.encode(&header_b64, header_json);
    const payload = encoder.encode(&payload_b64, payload_json);
    const signing_input = try std.fmt.allocPrint(allocator, "{s}.{s}", .{ header, payload });
    defer allocator.free(signing_input);
    const signature = try key_pair.sign(signing_input, null);
    var signature_b64: [256]u8 = undefined;
    const encoded = encoder.encode(&signature_b64, &signature.toBytes());
    return std.fmt.allocPrint(allocator, "{s}.{s}", .{ signing_input, encoded });
}

/// A key borrowing `storage`, which the caller keeps alive — the point cannot be
/// returned by value from here without the Key pointing at a dead temporary.
fn es256Key(key_pair: std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair, storage: *[65]u8) Key {
    storage.* = key_pair.public_key.toUncompressedSec1();
    return .{ .es256 = .{ .point = storage } };
}

const test_header = "{\"alg\":\"ES256\",\"typ\":\"JWT\",\"kid\":\"k1\"}";

test "a well-formed token verifies and yields its subject" {
    const allocator = testing.allocator;
    const key_pair = try std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair.generateDeterministic(@splat(3));
    const token = try signEs256(
        allocator,
        test_header,
        \\{"iss":"https://idp.example.com","aud":"waf-console","sub":"user-42","exp":2000000000,"iat":1999999000,"email":"a@example.com","email_verified":true}
    ,
        key_pair,
    );
    defer allocator.free(token);

    var point: [65]u8 = undefined;
    var identity = try verify(allocator, token, es256Key(key_pair, &point), .{
        .issuer = "https://idp.example.com",
        .audience = "waf-console",
        .now = 1999999500,
    });
    defer identity.deinit(allocator);
    try testing.expectEqualStrings("user-42", identity.subject);
    try testing.expectEqualStrings("a@example.com", identity.email.?);
    try testing.expect(identity.email_verified);
}

test "a token signed by another key, or tampered with, is rejected" {
    const allocator = testing.allocator;
    const key_pair = try std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair.generateDeterministic(@splat(3));
    const attacker = try std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair.generateDeterministic(@splat(4));
    const claims =
        \\{"iss":"https://idp.example.com","aud":"waf-console","sub":"user-42","exp":2000000000}
    ;
    const expectations: Expectations = .{
        .issuer = "https://idp.example.com",
        .audience = "waf-console",
        .now = 1999999500,
    };

    var point: [65]u8 = undefined;
    const key = es256Key(key_pair, &point);

    // Signed by someone else entirely.
    const forged = try signEs256(allocator, test_header, claims, attacker);
    defer allocator.free(forged);
    try testing.expectError(error.InvalidSignature, verify(allocator, forged, key, expectations));

    // A genuine token whose payload was edited afterwards: the claims no longer
    // match what was signed.
    const token = try signEs256(allocator, test_header, claims, key_pair);
    defer allocator.free(token);
    const tampered = try allocator.dupe(u8, token);
    defer allocator.free(tampered);
    // Flip a character inside the payload segment.
    const first_dot = std.mem.indexOfScalar(u8, tampered, '.').?;
    tampered[first_dot + 5] = if (tampered[first_dot + 5] == 'A') 'B' else 'A';
    try testing.expectError(error.InvalidSignature, verify(allocator, tampered, key, expectations));

    // A truncated signature segment is not decodable base64, and is refused as
    // malformed before any key is involved.
    const truncated = try allocator.dupe(u8, token[0 .. token.len - 3]);
    defer allocator.free(truncated);
    try testing.expectError(error.Malformed, verify(allocator, truncated, key, expectations));

    // A signature that decodes cleanly but is the wrong length for the algorithm is
    // rejected as a signature, not as a malformed token.
    const last_dot = std.mem.lastIndexOfScalar(u8, token, '.').?;
    const short = try std.fmt.allocPrint(allocator, "{s}.{s}", .{
        token[0..last_dot],
        "AAAAAAAA", // six bytes: not a P-256 signature
    });
    defer allocator.free(short);
    try testing.expectError(error.InvalidSignature, verify(allocator, short, key, expectations));
}

test "a token cannot choose how it is verified" {
    const allocator = testing.allocator;
    const key_pair = try std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair.generateDeterministic(@splat(3));
    var point: [65]u8 = undefined;
    const key = es256Key(key_pair, &point);
    const claims =
        \\{"iss":"https://idp.example.com","aud":"waf-console","sub":"user-42","exp":2000000000}
    ;
    const expectations: Expectations = .{
        .issuer = "https://idp.example.com",
        .audience = "waf-console",
        .now = 1999999500,
    };

    // The canonical JWT attack: a token declaring `alg: none` with an empty
    // signature. The algorithm comes from the key, so this cannot match.
    const encoder = std.base64.url_safe_no_pad.Encoder;
    var header_b64: [256]u8 = undefined;
    var payload_b64: [1024]u8 = undefined;
    const unsigned = try std.fmt.allocPrint(allocator, "{s}.{s}.{s}", .{
        encoder.encode(&header_b64, "{\"alg\":\"none\",\"typ\":\"JWT\"}"),
        encoder.encode(&payload_b64, claims),
        "AA", // a signature segment must exist, so it is not even empty
    });
    defer allocator.free(unsigned);
    try testing.expectError(error.AlgorithmMismatch, verify(allocator, unsigned, key, expectations));

    // Algorithm confusion: a token asking to be verified as HMAC, so that the
    // provider's *public* key would become the shared secret.
    const confused = try std.fmt.allocPrint(allocator, "{s}.{s}.{s}", .{
        encoder.encode(&header_b64, "{\"alg\":\"HS256\",\"typ\":\"JWT\"}"),
        encoder.encode(&payload_b64, claims),
        "c2lnbmF0dXJl",
    });
    defer allocator.free(confused);
    try testing.expectError(error.AlgorithmMismatch, verify(allocator, confused, key, expectations));

    // A token whose header declares a different real algorithm than the key.
    const wrong_alg = try signEs256(allocator, "{\"alg\":\"RS256\",\"typ\":\"JWT\"}", claims, key_pair);
    defer allocator.free(wrong_alg);
    try testing.expectError(error.AlgorithmMismatch, verify(allocator, wrong_alg, key, expectations));

    // Something that is not a JWT at all.
    try testing.expectError(error.Malformed, verify(allocator, "not.a.token", key, expectations));
    try testing.expectError(error.Malformed, verify(allocator, "onlyonesegment", key, expectations));
    try testing.expectError(error.Malformed, verify(allocator, "a.b", key, expectations));
    // Five segments is a JWE, not a JWS this code can verify.
    try testing.expectError(error.Malformed, verify(allocator, "a.b.c.d.e", key, expectations));
}

test "issuer, audience, nonce, and lifetime are all required to match" {
    const allocator = testing.allocator;
    const key_pair = try std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair.generateDeterministic(@splat(3));
    var point: [65]u8 = undefined;
    const key = es256Key(key_pair, &point);

    // Another provider's token, signed by a key we happen to trust for this issuer,
    // is still not from the issuer it claims.
    {
        const token = try signEs256(allocator, test_header,
            \\{"iss":"https://evil.example.com","aud":"waf-console","sub":"user-42","exp":2000000000}
        , key_pair);
        defer allocator.free(token);
        try testing.expectError(error.Untrusted, verify(allocator, token, key, .{
            .issuer = "https://idp.example.com",
            .audience = "waf-console",
            .now = 1999999500,
        }));
    }

    // A token minted for a different client: valid, but not for this console.
    {
        const token = try signEs256(allocator, test_header,
            \\{"iss":"https://idp.example.com","aud":"some-other-app","sub":"user-42","exp":2000000000}
        , key_pair);
        defer allocator.free(token);
        try testing.expectError(error.Untrusted, verify(allocator, token, key, .{
            .issuer = "https://idp.example.com",
            .audience = "waf-console",
            .now = 1999999500,
        }));
    }

    // `aud` may be an array; membership is what counts.
    {
        const token = try signEs256(allocator, test_header,
            \\{"iss":"https://idp.example.com","aud":["other","waf-console"],"sub":"user-42","exp":2000000000}
        , key_pair);
        defer allocator.free(token);
        var identity = try verify(allocator, token, key, .{
            .issuer = "https://idp.example.com",
            .audience = "waf-console",
            .now = 1999999500,
        });
        defer identity.deinit(allocator);
        try testing.expectEqualStrings("user-42", identity.subject);
    }

    // Expiry, with the leeway applied — and a token issued in the future refused.
    {
        const token = try signEs256(allocator, test_header,
            \\{"iss":"https://idp.example.com","aud":"waf-console","sub":"user-42","exp":1000,"iat":900}
        , key_pair);
        defer allocator.free(token);
        const base: Expectations = .{ .issuer = "https://idp.example.com", .audience = "waf-console", .now = 950 };
        var still_valid = try verify(allocator, token, key, base);
        still_valid.deinit(allocator);
        // Past expiry plus the 60-second leeway.
        try testing.expectError(error.Expired, verify(allocator, token, key, .{
            .issuer = base.issuer,
            .audience = base.audience,
            .now = 1100,
        }));
        // Inside the leeway, still accepted.
        var within = try verify(allocator, token, key, .{
            .issuer = base.issuer,
            .audience = base.audience,
            .now = 1030,
        });
        within.deinit(allocator);
        // Before it was issued: a clock problem or a forgery, not evidence of a
        // login that has happened.
        try testing.expectError(error.Expired, verify(allocator, token, key, .{
            .issuer = base.issuer,
            .audience = base.audience,
            .now = 800,
        }));
    }

    // A nonce ties the token to this login attempt. When one was sent, a token
    // without it, or with another, is a replay.
    {
        const with_nonce = try signEs256(allocator, test_header,
            \\{"iss":"https://idp.example.com","aud":"waf-console","sub":"user-42","exp":2000000000,"nonce":"n-abc"}
        , key_pair);
        defer allocator.free(with_nonce);
        const base: Expectations = .{ .issuer = "https://idp.example.com", .audience = "waf-console", .now = 1999999500 };
        var matched = try verify(allocator, with_nonce, key, .{
            .issuer = base.issuer,
            .audience = base.audience,
            .nonce = "n-abc",
            .now = base.now,
        });
        matched.deinit(allocator);
        try testing.expectError(error.Untrusted, verify(allocator, with_nonce, key, .{
            .issuer = base.issuer,
            .audience = base.audience,
            .nonce = "n-xyz",
            .now = base.now,
        }));

        const without_nonce = try signEs256(allocator, test_header,
            \\{"iss":"https://idp.example.com","aud":"waf-console","sub":"user-42","exp":2000000000}
        , key_pair);
        defer allocator.free(without_nonce);
        try testing.expectError(error.Untrusted, verify(allocator, without_nonce, key, .{
            .issuer = base.issuer,
            .audience = base.audience,
            .nonce = "n-abc",
            .now = base.now,
        }));
    }
}

test "claims that are missing or of the wrong type are rejected" {
    const allocator = testing.allocator;
    const key_pair = try std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair.generateDeterministic(@splat(3));
    var point: [65]u8 = undefined;
    const key = es256Key(key_pair, &point);
    const base: Expectations = .{ .issuer = "https://idp.example.com", .audience = "waf-console", .now = 1999999500 };

    const cases = [_][]const u8{
        // No subject: nothing to link an account to.
        \\{"iss":"https://idp.example.com","aud":"waf-console","exp":2000000000}
        ,
        // An empty subject is not an identifier.
        \\{"iss":"https://idp.example.com","aud":"waf-console","sub":"","exp":2000000000}
        ,
        // No expiry: a token that never stops being valid.
        \\{"iss":"https://idp.example.com","aud":"waf-console","sub":"user-42"}
        ,
        // No audience at all.
        \\{"iss":"https://idp.example.com","sub":"user-42","exp":2000000000}
        ,
        // A subject of the wrong type.
        \\{"iss":"https://idp.example.com","aud":"waf-console","sub":42,"exp":2000000000}
        ,
        // An expiry that is not a number.
        \\{"iss":"https://idp.example.com","aud":"waf-console","sub":"user-42","exp":"2000000000"}
        ,
        // A payload that is not an object.
        \\["iss","aud"]
        ,
    };
    for (cases) |claims| {
        const token = try signEs256(allocator, test_header, claims, key_pair);
        defer allocator.free(token);
        try testing.expectError(error.InvalidClaims, verify(allocator, token, key, base));
    }

    // `email_verified` sent as a string is not an assertion that it was verified.
    const stringly = try signEs256(allocator, test_header,
        \\{"iss":"https://idp.example.com","aud":"waf-console","sub":"user-42","exp":2000000000,"email":"a@example.com","email_verified":"true"}
    , key_pair);
    defer allocator.free(stringly);
    var identity = try verify(allocator, stringly, key, base);
    defer identity.deinit(allocator);
    try testing.expect(!identity.email_verified);
}
