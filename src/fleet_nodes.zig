//! Node identity for the fleet control plane (#50): one-time enrollment, the
//! certificate lifecycle a node authenticates with, replay prevention, protocol
//! version negotiation, and the capability set that decides what may be sent to a
//! node.
//!
//! The question every operation here answers is *which node is this, and may it
//! still act*. That makes the failure modes specific, and each is closed
//! deliberately rather than left to a caller's discipline:
//!
//! - An enrollment token is single-use and expiring, and only its hash is stored. A
//!   replayable token is a permanent fleet credential sitting in whatever
//!   provisioning system carried it, and a stolen database should not yield one that
//!   still works.
//! - Claiming a token is one statement, not a read followed by a write. Two nodes
//!   racing on the same token is the ordinary case in an autoscaling group, and a
//!   check-then-use would let both win.
//! - A certificate authenticates a node only inside its validity window and only
//!   while unrevoked, and revocation takes effect on the next authentication rather
//!   than at the next refresh of some cache.
//! - Rotation overlaps: a new certificate is issued while the old one is still
//!   valid, so a node that is mid-request when its credential is replaced does not
//!   lose its identity. Rotation that cuts over instantly is how a fleet goes
//!   silent.
//! - A nonce is accepted once. Enforcement is the primary key, so two concurrent
//!   replays cannot both pass the way they can between a check and an insert.
//!
//! What is *not* here: issuing the certificate itself. Signing a CSR needs an X.509
//! CA, which arrives with the TLS work (#43); this module owns the lifecycle state —
//! which fingerprint is valid for which node, until when, and what a revocation
//! means — which is what an mTLS terminator consults on every connection and what an
//! operator reads during an incident.

const std = @import("std");
const pg = @import("pg.zig");
const fleet_auth = @import("fleet_auth.zig");

pub const Error = pg.Error || error{
    RandomFailed,
    /// The token does not exist, has expired, or has already been claimed. One
    /// error for all three: telling a caller which would let it probe for tokens
    /// that exist.
    TokenUnusable,
    /// The nonce has already been used by this node — a replayed request.
    ReplayedNonce,
    /// A fingerprint that is not 64 lowercase hex characters. Rejected on the way
    /// in so the table cannot hold a value no certificate can ever match.
    MalformedFingerprint,
    /// The node speaks a protocol version this control plane does not support.
    UnsupportedProtocolVersion,
};

/// A certificate fingerprint: the SHA-256 of the DER encoding, lowercase hex. This
/// is what an mTLS terminator computes from a presented client certificate.
pub const fingerprint_len = 64;

/// Whether `text` is a well-formed fingerprint. Anything else is refused rather than
/// stored: a fingerprint with an uppercase digit or a stray colon would compare
/// unequal to the same certificate's real fingerprint forever, and the resulting
/// failure — a node that cannot authenticate with a certificate the console shows as
/// valid — is a genuinely hard one to read.
pub fn isFingerprint(text: []const u8) bool {
    if (text.len != fingerprint_len) return false;
    for (text) |byte| switch (byte) {
        '0'...'9', 'a'...'f' => {},
        else => return false,
    };
    return true;
}

/// The node-to-control-plane protocol.
pub const protocol = struct {
    /// The version this build speaks.
    pub const current: u16 = 1;

    /// The oldest version still accepted. A node below it is refused rather than
    /// served on a best-effort basis: a node that cannot be told what to enforce is
    /// worse than a node that knows it is unsupported, because it looks healthy.
    pub const minimum: u16 = 1;

    /// The version both sides will speak, or an error when there is no overlap.
    /// Negotiating down to the node's version — rather than insisting on the newest
    /// — is what lets a fleet be upgraded one node at a time.
    pub fn negotiate(node_version: u16) error{UnsupportedProtocolVersion}!u16 {
        if (node_version < minimum) return error.UnsupportedProtocolVersion;
        return @min(node_version, current);
    }
};

/// One-time enrollment tokens (#50): the credential a node presents once, to trade
/// for an identity.
pub const EnrollmentTokenRepository = struct {
    conn: *pg.Conn,

    /// Issue a token, returning its secret text. The secret is returned here and
    /// nowhere else — only its hash is stored — so a token that is lost is reissued
    /// rather than recovered.
    ///
    /// `ttl_seconds` is required and bounded by the caller's own policy: a token
    /// without an expiry is a credential nobody remembers to revoke.
    pub fn issue(
        self: EnrollmentTokenRepository,
        io: std.Io,
        label: [:0]const u8,
        created_by: [:0]const u8,
        ttl_seconds: u32,
        out: *[fleet_auth.secret_text_len]u8,
    ) Error!void {
        if (ttl_seconds == 0) return error.QueryFailed;
        try fleet_auth.generateSecret(io, out);
        var hash: [fleet_auth.digest_hex_len]u8 = undefined;
        fleet_auth.hashSecret(out, &hash);
        const token_hash = try Terminated.init(&hash);

        var ttl_buffer: [16]u8 = undefined;
        const ttl = try formatSeconds(&ttl_buffer, ttl_seconds);
        try self.conn.execParams(
            \\INSERT INTO enrollment_tokens (token_hash, label, created_by, expires_at)
            \\VALUES ($1, $2, $3, now() + make_interval(secs => $4::int))
        , &.{ token_hash.slice(), label, created_by, ttl });
    }

    /// Claim a token for `node_id`, consuming it.
    ///
    /// The claim is a single statement whose WHERE clause carries every condition —
    /// unclaimed, unexpired, matching hash — so the row is consumed by the same
    /// statement that qualifies it. Reading the token first and updating it after
    /// would let two nodes starting together both pass the read, and an enrollment
    /// token that can be used twice is not one-time.
    pub fn claim(self: EnrollmentTokenRepository, secret: []const u8, node_id: [:0]const u8) Error!void {
        var hash: [fleet_auth.digest_hex_len]u8 = undefined;
        fleet_auth.hashSecret(secret, &hash);
        const token_hash = try Terminated.init(&hash);
        const claimed = try self.conn.execParamsOptCount(
            \\UPDATE enrollment_tokens SET claimed_at = now(), claimed_by = $2::uuid
            \\WHERE token_hash = $1 AND claimed_at IS NULL AND withdrawn_at IS NULL
            \\  AND expires_at > now()
        , &.{ token_hash.slice(), node_id });
        if (claimed == 0) return error.TokenUnusable;
    }

    /// Withdraw an unclaimed token — what an abandoned provisioning run needs.
    ///
    /// Recorded as a withdrawal rather than as an expiry moved into the past: the two
    /// are different facts to whoever reads the trail afterwards, and a token whose
    /// expiry preceded its creation would contradict the schema's own check.
    /// Already-claimed tokens are untouched, because the node that used one is
    /// enrolled and pretending otherwise would not un-enroll it. Returns whether a
    /// token was withdrawn.
    pub fn withdraw(self: EnrollmentTokenRepository, label: [:0]const u8) Error!bool {
        const affected = try self.conn.execParamsOptCount(
            \\UPDATE enrollment_tokens SET withdrawn_at = now()
            \\WHERE label = $1 AND claimed_at IS NULL AND withdrawn_at IS NULL AND expires_at > now()
        , &.{label});
        return affected != 0;
    }

    /// How many tokens are still usable — the credentials currently outstanding,
    /// which is what an operator wants to know before going home.
    pub fn outstanding(self: EnrollmentTokenRepository, allocator: std.mem.Allocator) Error!usize {
        const text = try self.conn.queryScalar(
            allocator,
            "SELECT count(*) FROM enrollment_tokens WHERE claimed_at IS NULL AND withdrawn_at IS NULL AND expires_at > now()",
        ) orelse return 0;
        defer allocator.free(text);
        return std.fmt.parseInt(usize, text, 10) catch error.QueryFailed;
    }

    /// Delete expired, unclaimed tokens. Claimed ones are kept: they are the record
    /// of which token enrolled which node, which is the audit trail of how a node
    /// got into the fleet.
    pub fn purgeExpired(self: EnrollmentTokenRepository) Error!usize {
        return self.conn.execParamsOptCount(
            "DELETE FROM enrollment_tokens WHERE claimed_at IS NULL AND (expires_at <= now() OR withdrawn_at IS NOT NULL)",
            &.{},
        );
    }
};

/// The certificate lifecycle a node's identity rests on (#50).
pub const CertificateRepository = struct {
    conn: *pg.Conn,

    /// Record a certificate issued to a node, valid for `lifetime_seconds` from now.
    ///
    /// Short lifetimes are the point: a compromised key that expires in a day needs
    /// the attacker to keep stealing it, and a revocation that has to reach every
    /// verifier is a mechanism that fails quietly. The lifetime is the caller's
    /// policy, but zero is refused — a certificate valid for no time is a
    /// configuration mistake that would present as an authentication failure.
    pub fn record(
        self: CertificateRepository,
        node_id: [:0]const u8,
        fingerprint: []const u8,
        serial: [:0]const u8,
        lifetime_seconds: u32,
    ) Error!void {
        if (!isFingerprint(fingerprint)) return error.MalformedFingerprint;
        if (lifetime_seconds == 0) return error.QueryFailed;
        const print = try Terminated.init(fingerprint);
        var buffer: [16]u8 = undefined;
        const lifetime = try formatSeconds(&buffer, lifetime_seconds);
        try self.conn.execParams(
            \\INSERT INTO node_certificates (node_id, fingerprint, serial, not_before, not_after)
            \\VALUES ($1::uuid, $2, $3, now(), now() + make_interval(secs => $4::int))
        , &.{ node_id, print.slice(), serial, lifetime });
    }

    /// The node a presented fingerprint authenticates as, or null if it
    /// authenticates as nobody.
    ///
    /// Null covers unknown, not-yet-valid, expired, and revoked, and the caller
    /// cannot tell which — nor should it: an mTLS terminator's job is to decide
    /// whether this connection has an identity, and a distinction between "expired"
    /// and "revoked" in that answer is information for whoever is holding the
    /// certificate.
    pub fn authenticate(
        self: CertificateRepository,
        allocator: std.mem.Allocator,
        fingerprint: []const u8,
    ) Error!?[]u8 {
        if (!isFingerprint(fingerprint)) return error.MalformedFingerprint;
        const print = try Terminated.init(fingerprint);
        return self.conn.queryScalarParams(
            allocator,
            \\SELECT c.node_id::text FROM node_certificates c
            \\JOIN nodes n ON n.node_id = c.node_id
            \\WHERE c.fingerprint = $1
            \\  AND c.revoked_at IS NULL
            \\  AND c.not_before <= now() AND c.not_after > now()
            \\  AND n.status = 'active'
        ,
            &.{print.slice()},
        );
    }

    /// Revoke a certificate, with a reason. Returns whether one was revoked.
    ///
    /// The reason is required by the schema, not by convention: a revoked
    /// certificate with no recorded reason is one nobody can distinguish from a
    /// mistake, and the safe reading of a mistake is to re-issue — which is exactly
    /// what must not happen after a key compromise.
    pub fn revoke(self: CertificateRepository, fingerprint: []const u8, reason: [:0]const u8) Error!bool {
        if (!isFingerprint(fingerprint)) return error.MalformedFingerprint;
        if (reason.len == 0) return error.QueryFailed;
        const print = try Terminated.init(fingerprint);
        const affected = try self.conn.execParamsOptCount(
            \\UPDATE node_certificates SET revoked_at = now(), revocation_reason = $2
            \\WHERE fingerprint = $1 AND revoked_at IS NULL
        , &.{ print.slice(), reason });
        return affected != 0;
    }

    /// Revoke every unrevoked certificate a node holds — what a decommissioned or
    /// compromised node needs, since revoking the one certificate an operator knows
    /// about leaves any others working. Returns how many were revoked.
    pub fn revokeAllFor(self: CertificateRepository, node_id: [:0]const u8, reason: [:0]const u8) Error!usize {
        if (reason.len == 0) return error.QueryFailed;
        return self.conn.execParamsOptCount(
            \\UPDATE node_certificates SET revoked_at = now(), revocation_reason = $2
            \\WHERE node_id = $1::uuid AND revoked_at IS NULL
        , &.{ node_id, reason });
    }

    /// Rotate a node's certificate: record the replacement, leaving the outgoing one
    /// valid until it expires on its own.
    ///
    /// The overlap is the whole design. A node holds its current certificate until
    /// it has the new one working, and both authenticate during the changeover, so a
    /// rotation does not depend on the node and the control plane agreeing on an
    /// instant. Revoking the old certificate here instead would turn every rotation
    /// into a window in which an in-flight request loses its identity.
    pub fn rotate(
        self: CertificateRepository,
        node_id: [:0]const u8,
        fingerprint: []const u8,
        serial: [:0]const u8,
        lifetime_seconds: u32,
    ) Error!void {
        return self.record(node_id, fingerprint, serial, lifetime_seconds);
    }

    /// Whether a node needs to rotate: it has no certificate that will still be
    /// valid in `within_seconds`.
    ///
    /// Asked about the node rather than about one certificate, because "this
    /// certificate expires soon" is not a problem if a newer one is already in
    /// place — and a rotation triggered on that basis would issue a new certificate
    /// on every check.
    pub fn needsRotation(self: CertificateRepository, allocator: std.mem.Allocator, node_id: [:0]const u8, within_seconds: u32) Error!bool {
        var buffer: [16]u8 = undefined;
        const horizon = try formatSeconds(&buffer, within_seconds);
        const text = try self.conn.queryScalarParams(
            allocator,
            \\SELECT count(*) FROM node_certificates
            \\WHERE node_id = $1::uuid AND revoked_at IS NULL
            \\  AND not_after > now() + make_interval(secs => $2::int)
        ,
            &.{ node_id, horizon },
        ) orelse return true;
        defer allocator.free(text);
        const usable = std.fmt.parseInt(usize, text, 10) catch return error.QueryFailed;
        return usable == 0;
    }

    /// The nodes that need to rotate within `within_seconds`, ordered — the work
    /// list a rotation job walks. The cursor yields column (0) node_id; the caller
    /// `deinit`s it.
    pub fn rotationDue(self: CertificateRepository, within_seconds: u32) Error!pg.Rows {
        var buffer: [16]u8 = undefined;
        const horizon = try formatSeconds(&buffer, within_seconds);
        return self.conn.query(
            \\SELECT n.node_id::text FROM nodes n
            \\WHERE n.status = 'active'
            \\  AND NOT EXISTS (
            \\    SELECT 1 FROM node_certificates c
            \\    WHERE c.node_id = n.node_id AND c.revoked_at IS NULL
            \\      AND c.not_after > now() + make_interval(secs => $1::int)
            \\  )
            \\ORDER BY n.node_id
        , &.{horizon});
    }

    /// How many unrevoked, unexpired certificates a node holds. More than one is
    /// normal mid-rotation and a problem if it persists, which is why this is
    /// observable rather than assumed.
    pub fn activeCount(self: CertificateRepository, allocator: std.mem.Allocator, node_id: [:0]const u8) Error!usize {
        const text = try self.conn.queryScalarParams(
            allocator,
            \\SELECT count(*) FROM node_certificates
            \\WHERE node_id = $1::uuid AND revoked_at IS NULL AND not_after > now()
        ,
            &.{node_id},
        ) orelse return 0;
        defer allocator.free(text);
        return std.fmt.parseInt(usize, text, 10) catch error.QueryFailed;
    }
};

/// Replay prevention for node requests (#50).
///
/// A node stamps each request with a nonce; the ledger accepts each one once, within
/// a bounded window. The window is what keeps the ledger finite: without an expiry it
/// grows without limit, and a table that must be kept forever is one an operator
/// eventually truncates — silently removing the protection.
pub const NonceLedger = struct {
    conn: *pg.Conn,

    /// Accept a nonce, or fail with `ReplayedNonce` if this node has used it.
    ///
    /// The primary key does the work: a repeat is a unique violation from the insert
    /// itself, so two concurrent replays cannot both be accepted the way they can
    /// when a SELECT decides and an INSERT follows.
    pub fn accept(self: NonceLedger, node_id: [:0]const u8, nonce: []const u8, ttl_seconds: u32) Error!void {
        if (nonce.len == 0 or nonce.len > 128) return error.QueryFailed;
        if (ttl_seconds == 0) return error.QueryFailed;
        const value = try Terminated.init(nonce);
        var buffer: [16]u8 = undefined;
        const ttl = try formatSeconds(&buffer, ttl_seconds);
        const inserted = self.conn.execParamsOptCount(
            \\INSERT INTO node_nonces (node_id, nonce, expires_at)
            \\VALUES ($1::uuid, $2, now() + make_interval(secs => $3::int))
            \\ON CONFLICT (node_id, nonce) DO NOTHING
        , &.{ node_id, value.slice(), ttl }) catch |err| return err;
        if (inserted == 0) return error.ReplayedNonce;
    }

    /// Delete nonces past their window. A nonce outside the window cannot be
    /// replayed usefully — the request carrying it is itself rejected as stale — so
    /// keeping it buys nothing and costs a table that only grows.
    pub fn purgeExpired(self: NonceLedger) Error!usize {
        return self.conn.execParamsOptCount("DELETE FROM node_nonces WHERE expires_at <= now()", &.{});
    }

    pub fn count(self: NonceLedger, allocator: std.mem.Allocator) Error!usize {
        const text = try self.conn.queryScalar(allocator, "SELECT count(*) FROM node_nonces") orelse return 0;
        defer allocator.free(text);
        return std.fmt.parseInt(usize, text, 10) catch error.QueryFailed;
    }
};

/// What a node can do, and what version it speaks (#50) — the inventory the control
/// plane consults before sending a node something it cannot use.
pub const CapabilityRepository = struct {
    conn: *pg.Conn,

    /// Record the capabilities and protocol version a node reported, and negotiate
    /// the version to speak.
    ///
    /// A node that reports an unsupported version is refused here rather than
    /// recorded and worked around later. `capabilities_json` is a JSON array of
    /// names, stored as jsonb so a containment query is indexed rather than a scan.
    pub fn report(
        self: CapabilityRepository,
        node_id: [:0]const u8,
        capabilities_json: [:0]const u8,
        node_protocol_version: u16,
    ) Error!u16 {
        const negotiated = try protocol.negotiate(node_protocol_version);
        var buffer: [8]u8 = undefined;
        const text = std.fmt.bufPrint(&buffer, "{d}", .{negotiated}) catch return error.QueryFailed;
        buffer[text.len] = 0;
        const updated = try self.conn.execParamsOptCount(
            \\UPDATE nodes SET capabilities = $2::jsonb, protocol_version = $3::int
            \\WHERE node_id = $1::uuid
        , &.{ node_id, capabilities_json, buffer[0..text.len :0] });
        if (updated == 0) return error.QueryFailed; // no such node
        return negotiated;
    }

    /// Whether a node reported a named capability.
    pub fn supports(self: CapabilityRepository, allocator: std.mem.Allocator, node_id: [:0]const u8, capability: [:0]const u8) Error!bool {
        const text = try self.conn.queryScalarParams(
            allocator,
            "SELECT (capabilities @> to_jsonb($2::text))::text FROM nodes WHERE node_id = $1::uuid",
            &.{ node_id, capability },
        ) orelse return false;
        defer allocator.free(text);
        return std.mem.eql(u8, text, "true");
    }

    /// The active nodes that did *not* report `capability`, ordered — who a policy
    /// needing it cannot be rolled out to.
    ///
    /// This is the question worth asking before a rollout rather than after: a node
    /// sent rules it cannot evaluate does not fail loudly, it silently enforces less
    /// than the operator believes it is enforcing.
    pub fn lacking(self: CapabilityRepository, capability: [:0]const u8) Error!pg.Rows {
        return self.conn.query(
            \\SELECT node_id::text FROM nodes
            \\WHERE status = 'active' AND NOT (capabilities @> to_jsonb($1::text))
            \\ORDER BY node_id
        , &.{capability});
    }

    /// The oldest protocol version any active node speaks, or null when no node has
    /// reported one — the ceiling on what the control plane may assume of the fleet.
    pub fn oldestProtocolVersion(self: CapabilityRepository, allocator: std.mem.Allocator) Error!?u16 {
        const text = try self.conn.queryScalar(
            allocator,
            "SELECT min(protocol_version)::text FROM nodes WHERE status = 'active' AND protocol_version > 0",
        ) orelse return null;
        defer allocator.free(text);
        return std.fmt.parseInt(u16, text, 10) catch error.QueryFailed;
    }
};

/// Render seconds as a null-terminated decimal for a bind parameter. libpq takes
/// text, and `make_interval(secs => $n::int)` is how a duration reaches SQL without
/// interpolating it into the statement.
fn formatSeconds(buffer: *[16]u8, seconds: u32) error{QueryFailed}![:0]const u8 {
    const text = std.fmt.bufPrint(buffer, "{d}", .{seconds}) catch return error.QueryFailed;
    buffer[text.len] = 0;
    return buffer[0..text.len :0];
}

/// A null-terminated copy of a borrowed value, for libpq's text parameters.
///
/// Each holder owns its own storage rather than sharing one buffer: two values
/// terminated for the same statement would otherwise alias, and the second would
/// overwrite the first — a bug whose symptom is a query that binds the same value
/// twice, which is far harder to see than it is to prevent.
const Terminated = struct {
    buffer: [129]u8 = undefined,
    length: usize = 0,

    fn init(value: []const u8) error{QueryFailed}!Terminated {
        var result: Terminated = .{};
        if (value.len >= result.buffer.len) return error.QueryFailed;
        @memcpy(result.buffer[0..value.len], value);
        result.buffer[value.len] = 0;
        result.length = value.len;
        return result;
    }

    fn slice(self: *const Terminated) [:0]const u8 {
        return self.buffer[0..self.length :0];
    }
};

// ---- tests --------------------------------------------------------------

const fleet = @import("fleet.zig");
const testing = std.testing;

fn testDb() !pg.TestSchema {
    var db = try pg.TestSchema.open(testing.allocator);
    _ = fleet.apply(&db.conn, testing.allocator) catch |err| {
        db.close();
        return err;
    };
    return db;
}

/// Whether a fingerprint authenticates, freeing the node id it resolves to. The
/// repository returns owned memory, so a test that only checked for null would leak
/// on every success.
fn authenticates(certificates: CertificateRepository, fingerprint: []const u8) !bool {
    const node_id = try certificates.authenticate(testing.allocator, fingerprint) orelse return false;
    testing.allocator.free(node_id);
    return true;
}

/// A node to hang identity off. The certificate and nonce tables reference `nodes`,
/// so a test that skipped this would be testing the foreign key.
fn enrollTestNode(db: *pg.TestSchema, node_id: [:0]const u8) !void {
    const nodes = fleet.NodeRepository{ .conn = &db.conn };
    try nodes.enroll(node_id, "host.example.com", "1.0.0");
}

test "a fingerprint is accepted only in the one form a certificate produces" {
    // 64 lowercase hex, and nothing else. The rejected forms are the ones a human
    // pastes from a tool that prints colons or uppercase, which would be stored
    // happily and then never match anything.
    const valid = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    try testing.expect(isFingerprint(valid));
    try testing.expect(!isFingerprint("0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef"));
    try testing.expect(!isFingerprint("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde")); // 63
    try testing.expect(!isFingerprint(valid ++ "0")); // 65
    try testing.expect(!isFingerprint("01:23:45:67:89:ab:cd:ef"));
    try testing.expect(!isFingerprint(""));
}

test "version negotiation speaks the older side's version and refuses what it cannot serve" {
    // A node newer than the control plane is served at the control plane's version;
    // a node at the control plane's version gets exactly that.
    try testing.expectEqual(@as(u16, protocol.current), try protocol.negotiate(protocol.current));
    try testing.expectEqual(@as(u16, protocol.current), try protocol.negotiate(protocol.current + 7));
    // Below the minimum there is no version to fall back to, so it is an error
    // rather than a downgrade: a node that cannot be told what to enforce must know
    // it is unsupported.
    try testing.expectError(error.UnsupportedProtocolVersion, protocol.negotiate(protocol.minimum - 1));
}

test "an enrollment token works once, and its hash is all the database holds" {
    var db = try testDb();
    defer db.close();
    const io = std.testing.io;
    const tokens = EnrollmentTokenRepository{ .conn = &db.conn };

    var secret: [fleet_auth.secret_text_len]u8 = undefined;
    try tokens.issue(io, "rack-7", "admin@example.com", 3600, &secret);

    // The secret is not recoverable from the row: what is stored is a hash of it.
    const stored = (try db.conn.queryScalar(testing.allocator, "SELECT token_hash FROM enrollment_tokens")).?;
    defer testing.allocator.free(stored);
    try testing.expectEqual(@as(usize, fleet_auth.digest_hex_len), stored.len);
    try testing.expect(std.mem.indexOf(u8, stored, &secret) == null);
    try testing.expectEqual(@as(usize, 1), try tokens.outstanding(testing.allocator));

    const node_id: [:0]const u8 = "11111111-2222-3333-4444-555555555555";
    try enrollTestNode(&db, node_id);
    try tokens.claim(&secret, node_id);

    // Single-use: the same secret does not work twice, and the token is no longer
    // outstanding.
    try testing.expectError(error.TokenUnusable, tokens.claim(&secret, node_id));
    try testing.expectEqual(@as(usize, 0), try tokens.outstanding(testing.allocator));

    // The claim is recorded against the node that used it, which is the audit trail
    // of how that node entered the fleet.
    const claimed_by = (try db.conn.queryScalar(testing.allocator, "SELECT claimed_by::text FROM enrollment_tokens")).?;
    defer testing.allocator.free(claimed_by);
    try testing.expectEqualStrings(node_id, claimed_by);

    // An unknown secret is the same error as a used one: which it was is what an
    // attacker probing for live tokens wants to learn.
    var other: [fleet_auth.secret_text_len]u8 = undefined;
    try fleet_auth.generateSecret(io, &other);
    try testing.expectError(error.TokenUnusable, tokens.claim(&other, node_id));
}

test "an expired or withdrawn enrollment token cannot be claimed" {
    var db = try testDb();
    defer db.close();
    const io = std.testing.io;
    const tokens = EnrollmentTokenRepository{ .conn = &db.conn };
    const node_id: [:0]const u8 = "11111111-2222-3333-4444-555555555555";
    try enrollTestNode(&db, node_id);

    // Expiry is enforced by the claim itself, not by a sweeper that may not have
    // run: a token whose window has passed is unusable the moment it passes.
    var expiring: [fleet_auth.secret_text_len]u8 = undefined;
    try tokens.issue(io, "short", "admin@example.com", 3600, &expiring);
    try db.conn.exec(
        \\UPDATE enrollment_tokens SET created_at = now() - interval '2 hours',
        \\  expires_at = now() - interval '1 second' WHERE label = 'short'
    );
    try testing.expectError(error.TokenUnusable, tokens.claim(&expiring, node_id));

    // Withdrawal takes an unclaimed token out of use.
    var withdrawn: [fleet_auth.secret_text_len]u8 = undefined;
    try tokens.issue(io, "abandoned", "admin@example.com", 3600, &withdrawn);
    try testing.expect(try tokens.withdraw("abandoned"));
    try testing.expectError(error.TokenUnusable, tokens.claim(&withdrawn, node_id));
    // Nothing left to withdraw under that label.
    try testing.expect(!(try tokens.withdraw("abandoned")));

    // Purging removes expired unclaimed tokens and keeps the claimed ones, because
    // the claimed rows are the record of which token enrolled which node.
    var used: [fleet_auth.secret_text_len]u8 = undefined;
    try tokens.issue(io, "used", "admin@example.com", 3600, &used);
    try tokens.claim(&used, node_id);
    try db.conn.exec(
        \\UPDATE enrollment_tokens SET created_at = now() - interval '2 hours',
        \\  expires_at = now() - interval '1 second'
    );
    // Both spent tokens go; the claimed one stays as the record of how a node
    // entered the fleet.
    try testing.expectEqual(@as(usize, 2), try tokens.purgeExpired()); // short + abandoned
    const remaining = (try db.conn.queryScalar(testing.allocator, "SELECT count(*) FROM enrollment_tokens")).?;
    defer testing.allocator.free(remaining);
    try testing.expectEqualStrings("1", remaining);
}

test "a certificate authenticates only inside its window and only while unrevoked" {
    var db = try testDb();
    defer db.close();
    const certificates = CertificateRepository{ .conn = &db.conn };
    const node_id: [:0]const u8 = "11111111-2222-3333-4444-555555555555";
    try enrollTestNode(&db, node_id);

    const print = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    try certificates.record(node_id, print, "serial-1", 3600);

    const authenticated = (try certificates.authenticate(testing.allocator, print)).?;
    defer testing.allocator.free(authenticated);
    try testing.expectEqualStrings(node_id, authenticated);

    // A fingerprint nobody issued authenticates as nobody, rather than as an error a
    // caller might treat as "try again".
    const unknown = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    try testing.expect(!(try authenticates(certificates, unknown)));
    // A malformed one is refused on the way in, so it cannot be stored either.
    try testing.expectError(error.MalformedFingerprint, certificates.authenticate(testing.allocator, "nope"));
    try testing.expectError(error.MalformedFingerprint, certificates.record(node_id, "nope", "serial-x", 3600));

    // Expiry: the window closes on its own, with nothing having to run.
    try db.conn.exec(
        \\UPDATE node_certificates SET not_before = now() - interval '2 hours',
        \\  not_after = now() - interval '1 second'
    );
    try testing.expect(!(try authenticates(certificates, print)));
    try db.conn.exec("UPDATE node_certificates SET not_after = now() + interval '1 hour'");
    try testing.expect(try authenticates(certificates, print));

    // Not yet valid is refused too: a certificate issued for a future window is not
    // usable now.
    try db.conn.exec("UPDATE node_certificates SET not_before = now() + interval '1 hour', not_after = now() + interval '2 hours'");
    try testing.expect(!(try authenticates(certificates, print)));
    try db.conn.exec("UPDATE node_certificates SET not_before = now() - interval '1 minute', not_after = now() + interval '1 hour'");

    // Revocation takes effect on the next authentication, and carries its reason.
    try testing.expect(try certificates.revoke(print, "key compromise"));
    try testing.expect(!(try authenticates(certificates, print)));
    try testing.expect(!(try certificates.revoke(print, "again"))); // already revoked
    const reason = (try db.conn.queryScalar(testing.allocator, "SELECT revocation_reason FROM node_certificates")).?;
    defer testing.allocator.free(reason);
    try testing.expectEqualStrings("key compromise", reason);
    // A revocation without a reason is refused: an unexplained revocation reads as a
    // mistake, and the safe reading of a mistake is to re-issue.
    try testing.expectError(error.QueryFailed, certificates.revoke(unknown, ""));

    // A retired node's certificate stops authenticating even though the certificate
    // itself is still valid — identity follows the node, not the file.
    const second = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    try certificates.record(node_id, second, "serial-2", 3600);
    try testing.expect(try authenticates(certificates, second));
    try db.conn.exec("UPDATE nodes SET status = 'retired'");
    try testing.expect(!(try authenticates(certificates, second)));
}

test "rotation overlaps, so a node is never without an identity" {
    var db = try testDb();
    defer db.close();
    const certificates = CertificateRepository{ .conn = &db.conn };
    const node_id: [:0]const u8 = "11111111-2222-3333-4444-555555555555";
    try enrollTestNode(&db, node_id);

    // A node with no certificate needs one.
    try testing.expect(try certificates.needsRotation(testing.allocator, node_id, 300));

    const old = "1111111111111111111111111111111111111111111111111111111111111111";
    try certificates.record(node_id, old, "serial-1", 3600);
    try testing.expect(!(try certificates.needsRotation(testing.allocator, node_id, 300)));
    // Asked about a horizon beyond the certificate's life, rotation is due.
    try testing.expect(try certificates.needsRotation(testing.allocator, node_id, 7200));

    // Rotating leaves the outgoing certificate valid: both authenticate during the
    // changeover, which is what keeps an in-flight request from losing its identity.
    const new = "2222222222222222222222222222222222222222222222222222222222222222";
    try certificates.rotate(node_id, new, "serial-2", 3600);
    try testing.expectEqual(@as(usize, 2), try certificates.activeCount(testing.allocator, node_id));
    try testing.expect(try authenticates(certificates, old));
    try testing.expect(try authenticates(certificates, new));

    // Once the node confirms the new one, the old is revoked and only the new works.
    try testing.expect(try certificates.revoke(old, "rotated"));
    try testing.expectEqual(@as(usize, 1), try certificates.activeCount(testing.allocator, node_id));
    try testing.expect(!(try authenticates(certificates, old)));
    try testing.expect(try authenticates(certificates, new));

    // The rotation work list names the nodes that need one, and stops naming them
    // once they have it.
    try db.conn.exec("UPDATE node_certificates SET not_after = now() + interval '1 minute' WHERE fingerprint = '" ++ new ++ "'");
    var due = try certificates.rotationDue(300);
    defer due.deinit();
    try testing.expectEqual(@as(usize, 1), due.len());
    try testing.expect(due.next());
    try testing.expectEqualStrings(node_id, due.get(0));

    // Decommissioning revokes everything the node holds, not just the one an
    // operator happened to know about.
    try certificates.record(node_id, "3333333333333333333333333333333333333333333333333333333333333333", "serial-3", 3600);
    try testing.expectEqual(@as(usize, 2), try certificates.revokeAllFor(node_id, "decommissioned"));
    try testing.expectEqual(@as(usize, 0), try certificates.activeCount(testing.allocator, node_id));
}

test "a nonce is accepted once, and the ledger does not grow without bound" {
    var db = try testDb();
    defer db.close();
    const ledger = NonceLedger{ .conn = &db.conn };
    const node_id: [:0]const u8 = "11111111-2222-3333-4444-555555555555";
    const other_id: [:0]const u8 = "99999999-8888-7777-6666-555555555555";
    try enrollTestNode(&db, node_id);
    try enrollTestNode(&db, other_id);

    try ledger.accept(node_id, "nonce-a", 300);
    // The replay is refused. This is the whole point: the same signed request
    // captured and re-sent must not be honoured twice.
    try testing.expectError(error.ReplayedNonce, ledger.accept(node_id, "nonce-a", 300));

    // Nonces are per node, so two nodes independently choosing the same value do not
    // lock each other out — they would, if the ledger were keyed on the nonce alone.
    try ledger.accept(other_id, "nonce-a", 300);

    // A different nonce from the same node is fine.
    try ledger.accept(node_id, "nonce-b", 300);
    try testing.expectEqual(@as(usize, 3), try ledger.count(testing.allocator));

    // Bounds: an empty or oversized nonce is refused rather than stored.
    try testing.expectError(error.QueryFailed, ledger.accept(node_id, "", 300));
    const oversized: [129]u8 = @splat('x');
    try testing.expectError(error.QueryFailed, ledger.accept(node_id, &oversized, 300));
    try testing.expectError(error.QueryFailed, ledger.accept(node_id, "nonce-c", 0));

    // Purging keeps the ledger finite. Without it the table only grows, and a table
    // that must be kept forever is one someone eventually truncates — quietly
    // removing the protection.
    try db.conn.exec("UPDATE node_nonces SET expires_at = now() - interval '1 second' WHERE nonce = 'nonce-a'");
    try testing.expectEqual(@as(usize, 2), try ledger.purgeExpired());
    try testing.expectEqual(@as(usize, 1), try ledger.count(testing.allocator));
    // And a purged nonce may be used again, which is safe: the request carrying it
    // is itself rejected as stale long before that.
    try ledger.accept(node_id, "nonce-a", 300);
}

test "capabilities decide what a node may be sent, and the version is negotiated" {
    var db = try testDb();
    defer db.close();
    const capabilities = CapabilityRepository{ .conn = &db.conn };
    const modern: [:0]const u8 = "11111111-2222-3333-4444-555555555555";
    const legacy: [:0]const u8 = "99999999-8888-7777-6666-555555555555";
    try enrollTestNode(&db, modern);
    try enrollTestNode(&db, legacy);

    try testing.expectEqual(
        @as(u16, protocol.current),
        try capabilities.report(modern, "[\"detectSQLi\",\"detectXSS\",\"xml\"]", protocol.current),
    );
    try testing.expectEqual(@as(u16, protocol.current), try capabilities.report(legacy, "[\"detectSQLi\"]", protocol.current));

    try testing.expect(try capabilities.supports(testing.allocator, modern, "xml"));
    try testing.expect(!(try capabilities.supports(testing.allocator, legacy, "xml")));
    // An unreported capability is absent, not assumed — the default has to be "does
    // not support it", because sending rules a node cannot evaluate makes it enforce
    // less than the operator believes without failing.
    try testing.expect(!(try capabilities.supports(testing.allocator, modern, "hyperscan")));

    // Who a policy needing `xml` cannot go to.
    var lacking = try capabilities.lacking("xml");
    defer lacking.deinit();
    try testing.expectEqual(@as(usize, 1), lacking.len());
    try testing.expect(lacking.next());
    try testing.expectEqualStrings(legacy, lacking.get(0));

    // The fleet's floor is what the control plane may assume of every node.
    try testing.expectEqual(@as(?u16, protocol.current), try capabilities.oldestProtocolVersion(testing.allocator));

    // A node that speaks nothing this build supports is refused, and its recorded
    // state is left alone rather than half-updated.
    try testing.expectError(error.UnsupportedProtocolVersion, capabilities.report(legacy, "[]", protocol.minimum - 1));
    try testing.expect(try capabilities.supports(testing.allocator, legacy, "detectSQLi"));

    // Reporting for a node that is not enrolled fails rather than silently doing
    // nothing, which is what an UPDATE matching no row would otherwise be.
    try testing.expectError(
        error.QueryFailed,
        capabilities.report("00000000-0000-0000-0000-000000000000", "[]", protocol.current),
    );
}

test "a claim in flight blocks a competing claim, and the loser is refused" {
    // Two nodes starting at the same moment is the ordinary case in an autoscaling
    // group. What this shows is that the claims are serialized: while one is in
    // flight the other waits on the row rather than proceeding alongside it, and once
    // the first commits the second is refused.
    //
    // What it does not show — because a single call cannot produce the interleaving —
    // is the case that makes the predicate load-bearing: a read that observes the
    // token as free, then a write that lands after someone else's claim committed. It
    // is prevented by construction rather than by test, since the conditions and the
    // mutation are one statement, so there is no moment between them for a claim to
    // land in.
    var db = try testDb();
    defer db.close();
    const io = std.testing.io;
    const first = EnrollmentTokenRepository{ .conn = &db.conn };

    var secret: [fleet_auth.secret_text_len]u8 = undefined;
    try first.issue(io, "rack-7", "admin@example.com", 3600, &secret);

    const node_a: [:0]const u8 = "11111111-2222-3333-4444-555555555555";
    const node_b: [:0]const u8 = "99999999-8888-7777-6666-555555555555";
    try enrollTestNode(&db, node_a);
    try enrollTestNode(&db, node_b);

    // A second connection to the same private schema — the other node.
    var other_conn = try pg.Conn.open(db.dsn);
    defer other_conn.close();
    const second = EnrollmentTokenRepository{ .conn = &other_conn };
    // Bounded, so a blocked claim fails the statement instead of hanging this test
    // forever. That the statement blocks at all is the property under test.
    try other_conn.setStatementTimeout(500);

    // Node A claims inside an open transaction, holding the row.
    try db.conn.exec("BEGIN");
    try first.claim(&secret, node_a);

    // Node B's claim cannot proceed while A holds the row: it waits, and hits the
    // timeout. If it returned successfully here, one token would have enrolled two
    // nodes.
    try testing.expectError(error.QueryFailed, second.claim(&secret, node_b));

    try db.conn.exec("COMMIT");

    // With A's claim committed, B sees the token as spent — the ordinary refusal,
    // reached without B ever having held it.
    try testing.expectError(error.TokenUnusable, second.claim(&secret, node_b));

    // And the token records A, not B.
    const claimed_by = (try db.conn.queryScalar(testing.allocator, "SELECT claimed_by::text FROM enrollment_tokens")).?;
    defer testing.allocator.free(claimed_by);
    try testing.expectEqualStrings(node_a, claimed_by);
}
