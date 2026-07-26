//! Console identity and authorization for the fleet control plane (#58): local
//! users, role-based authorization, API tokens, and sessions over the schema in
//! `fleet.zig`.
//!
//! Two kinds of secret live here and they are protected differently on purpose.
//! A password is chosen by a person, so it is low-entropy and worth attacking
//! offline: it is stored as an argon2id hash, whose cost is the defence. A token
//! or session id is generated here with 256 bits of entropy, so guessing it is
//! not a threat and the only requirement is that a stolen database does not yield
//! usable credentials: those are stored as SHA-256 hashes. Using argon2 for them
//! instead would put a deliberately expensive hash on the path of every API
//! request — a denial-of-service vector bought for no security.
//!
//! Nothing here stores a secret in recoverable form. `issueToken` and
//! `openSession` return the secret exactly once, to be shown to its owner or set
//! as a cookie; afterwards only its hash exists.

const std = @import("std");
const pg = @import("pg.zig");
const authz = @import("authz.zig");

/// Roles and actions live in `authz.zig` so the API surface can name them without
/// depending on a database. Re-exported here because this is where callers expect
/// identity to live.
pub const Role = authz.Role;
pub const Action = authz.Action;

/// The length of a generated credential's text form. 32 random bytes, so guessing
/// one is not a threat model, rendered as URL-safe base64 without padding.
pub const secret_text_len = std.base64.url_safe_no_pad.Encoder.calcSize(32);

/// A hex SHA-256 digest, the stored form of a generated credential.
pub const digest_hex_len = std.crypto.hash.sha2.Sha256.digest_length * 2;

/// Generate a credential: 256 bits from the operating system's secure source,
/// rendered URL-safe so it can be a bearer token or a cookie value unencoded.
pub fn generateSecret(io: std.Io, out: *[secret_text_len]u8) error{RandomFailed}!void {
    var raw: [32]u8 = undefined;
    io.randomSecure(&raw) catch return error.RandomFailed;
    _ = std.base64.url_safe_no_pad.Encoder.encode(out, &raw);
}

/// The stored form of a generated credential: a hex SHA-256 digest. Sound for
/// high-entropy secrets, and cheap enough to sit on every request.
pub fn hashSecret(secret: []const u8, out: *[digest_hex_len]u8) void {
    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(secret, &digest, .{});
    const hex = "0123456789abcdef";
    for (digest, 0..) |byte, index| {
        out[index * 2] = hex[byte >> 4];
        out[index * 2 + 1] = hex[byte & 0x0f];
    }
}

/// argon2id cost. RFC 9106's second recommended configuration (64 MiB, three
/// passes), which is affordable for an interactive login and expensive enough that
/// a stolen hash is not a password.
pub const password_params: std.crypto.pwhash.argon2.Params = .{ .t = 3, .m = 65536, .p = 1 };

/// The buffer a PHC-encoded argon2id hash needs. The encoding carries the
/// parameters and salt alongside the digest, so a hash verifies against the cost
/// it was created with even after that cost is raised.
pub const password_hash_len = 128;

pub const Error = pg.Error || error{ RandomFailed, HashFailed };

/// Local users, their roles, and their federated identities (#58).
pub const UserRepository = struct {
    conn: *pg.Conn,

    /// Create a user with a password. The password is hashed with argon2id before
    /// it reaches the database and is never stored in recoverable form.
    pub fn create(
        self: UserRepository,
        allocator: std.mem.Allocator,
        io: std.Io,
        email: [:0]const u8,
        password: []const u8,
        role: Role,
    ) Error!void {
        var buffer: [password_hash_len]u8 = undefined;
        const hash = std.crypto.pwhash.argon2.strHash(
            password,
            .{ .allocator = allocator, .params = password_params },
            &buffer,
            io,
        ) catch return error.HashFailed;
        if (hash.len >= buffer.len) return error.HashFailed;
        buffer[hash.len] = 0;
        try self.conn.execParams(
            "INSERT INTO users (email, role, password_hash) VALUES ($1, $2, $3)",
            &.{ email, role.text(), buffer[0..hash.len :0] },
        );
    }

    /// Create a user who authenticates through an identity provider. No password
    /// exists for such an account, so none can be guessed or leaked.
    pub fn createFederated(
        self: UserRepository,
        email: [:0]const u8,
        oidc_subject: [:0]const u8,
        role: Role,
    ) Error!void {
        try self.conn.execParams(
            "INSERT INTO users (email, role, oidc_subject) VALUES ($1, $2, $3)",
            &.{ email, role.text(), oidc_subject },
        );
    }

    /// Verify a password and return the role it grants, or null when the email is
    /// unknown, the account is disabled, the account has no password, or the
    /// password is wrong. The caller cannot tell these apart: which one it was is
    /// exactly what an attacker probing for valid accounts wants to learn.
    pub fn authenticate(
        self: UserRepository,
        allocator: std.mem.Allocator,
        io: std.Io,
        email: [:0]const u8,
        password: []const u8,
    ) Error!?Role {
        var rows = try self.conn.query(
            \\SELECT role, coalesce(password_hash, '') FROM users
            \\WHERE email = $1 AND disabled_at IS NULL
        , &.{email});
        defer rows.deinit();
        if (!rows.next()) return null;
        const stored = rows.get(1);
        if (stored.len == 0) return null; // federated account: no password to verify
        std.crypto.pwhash.argon2.strVerify(stored, password, .{ .allocator = allocator }, io) catch return null;
        return Role.parse(rows.get(0));
    }

    /// The role a federated subject grants, or null when the subject is unknown or
    /// the account is disabled. The identity provider has already authenticated the
    /// person; this maps that assertion onto a local role.
    pub fn authenticateFederated(self: UserRepository, oidc_subject: [:0]const u8) Error!?Role {
        var rows = try self.conn.query(
            "SELECT role FROM users WHERE oidc_subject = $1 AND disabled_at IS NULL",
            &.{oidc_subject},
        );
        defer rows.deinit();
        if (!rows.next()) return null;
        return Role.parse(rows.get(0));
    }

    /// Disable or re-enable an account. Disabling is preferred to deletion: it
    /// revokes access immediately while keeping the account referenced by the
    /// administrative record of what it did.
    pub fn setDisabled(self: UserRepository, email: [:0]const u8, disabled: bool) Error!void {
        try self.conn.execParams(
            if (disabled)
                "UPDATE users SET disabled_at = now() WHERE email = $1 AND disabled_at IS NULL"
            else
                "UPDATE users SET disabled_at = NULL WHERE email = $1",
            &.{email},
        );
    }

    /// Change a role.
    pub fn setRole(self: UserRepository, email: [:0]const u8, role: Role) Error!void {
        try self.conn.execParams("UPDATE users SET role = $2 WHERE email = $1", &.{ email, role.text() });
    }

    /// The role recorded for an account, ignoring whether it is disabled — for
    /// administration screens, not for authorization.
    pub fn roleOf(self: UserRepository, email: [:0]const u8) Error!?Role {
        var rows = try self.conn.query("SELECT role FROM users WHERE email = $1", &.{email});
        defer rows.deinit();
        if (!rows.next()) return null;
        return Role.parse(rows.get(0));
    }
};

/// API tokens: long-lived credentials for automation, verified on every request
/// (#58).
pub const TokenRepository = struct {
    conn: *pg.Conn,

    /// Issue a token for a user and return its secret — the only time it exists in
    /// recoverable form. `lifetime_seconds` of null means it does not expire.
    pub fn issue(
        self: TokenRepository,
        io: std.Io,
        email: [:0]const u8,
        name: [:0]const u8,
        lifetime_seconds: ?u32,
        out: *[secret_text_len]u8,
    ) Error!void {
        try generateSecret(io, out);
        var hash: [digest_hex_len + 1]u8 = undefined;
        hashSecret(out, hash[0..digest_hex_len]);
        hash[digest_hex_len] = 0;

        var seconds_buffer: [16]u8 = undefined;
        const lifetime: ?[:0]const u8 = if (lifetime_seconds) |seconds| blk: {
            const written = std.fmt.bufPrint(&seconds_buffer, "{d}", .{seconds}) catch return error.QueryFailed;
            seconds_buffer[written.len] = 0;
            break :blk seconds_buffer[0..written.len :0];
        } else null;

        // The token is attached to the user by email in one statement, so a token
        // for an unknown user inserts nothing rather than dangling.
        const inserted = try self.conn.execParamsOptCount(
            \\INSERT INTO api_tokens (user_id, name, token_hash, expires_at)
            \\SELECT id, $2, $3, CASE WHEN $4::int IS NULL THEN NULL
            \\                        ELSE now() + make_interval(secs => $4::int) END
            \\FROM users WHERE email = $1
        , &.{ email, name, hash[0..digest_hex_len :0], lifetime });
        if (inserted == 0) return error.QueryFailed;
    }

    /// The role a token grants, or null when it is unknown, expired, revoked, or
    /// belongs to a disabled user. A successful check stamps `last_used_at`, so an
    /// unused token is visible as such when deciding what to revoke.
    pub fn authenticate(self: TokenRepository, secret: []const u8) Error!?Role {
        var hash: [digest_hex_len + 1]u8 = undefined;
        hashSecret(secret, hash[0..digest_hex_len]);
        hash[digest_hex_len] = 0;
        var rows = try self.conn.query(
            \\UPDATE api_tokens t SET last_used_at = now()
            \\FROM users u
            \\WHERE t.user_id = u.id
            \\  AND t.token_hash = $1
            \\  AND t.revoked_at IS NULL
            \\  AND (t.expires_at IS NULL OR t.expires_at > now())
            \\  AND u.disabled_at IS NULL
            \\RETURNING u.role
        , &.{hash[0..digest_hex_len :0]});
        defer rows.deinit();
        if (!rows.next()) return null;
        return Role.parse(rows.get(0));
    }

    /// Revoke one of a user's tokens by name. Revocation is recorded rather than
    /// deleted, so a token that was used remains accounted for.
    pub fn revoke(self: TokenRepository, email: [:0]const u8, name: [:0]const u8) Error!void {
        try self.conn.execParams(
            \\UPDATE api_tokens t SET revoked_at = now()
            \\WHERE t.name = $2 AND t.revoked_at IS NULL
            \\  AND t.user_id = (SELECT id FROM users WHERE email = $1)
        , &.{ email, name });
    }

    /// How many tokens a user holds that are still usable.
    pub fn activeCount(self: TokenRepository, allocator: std.mem.Allocator, email: [:0]const u8) Error!?[]u8 {
        return self.conn.queryScalarParams(
            allocator,
            \\SELECT count(*) FROM api_tokens t JOIN users u ON u.id = t.user_id
            \\WHERE u.email = $1 AND t.revoked_at IS NULL
            \\  AND (t.expires_at IS NULL OR t.expires_at > now())
        ,
            &.{email},
        );
    }
};

/// Browser sessions: short-lived credentials issued after a login (#58).
pub const SessionRepository = struct {
    conn: *pg.Conn,

    /// Open a session for a user and return its secret — the value to set as a
    /// cookie, and the only time it exists in recoverable form. Sessions always
    /// expire; there is no unbounded lifetime, because a session is a convenience
    /// and an abandoned browser should not stay authorized indefinitely.
    pub fn open(
        self: SessionRepository,
        io: std.Io,
        email: [:0]const u8,
        lifetime_seconds: u32,
        out: *[secret_text_len]u8,
    ) Error!void {
        try generateSecret(io, out);
        var hash: [digest_hex_len + 1]u8 = undefined;
        hashSecret(out, hash[0..digest_hex_len]);
        hash[digest_hex_len] = 0;
        var seconds_buffer: [16]u8 = undefined;
        const written = std.fmt.bufPrint(&seconds_buffer, "{d}", .{lifetime_seconds}) catch return error.QueryFailed;
        seconds_buffer[written.len] = 0;

        const inserted = try self.conn.execParamsOptCount(
            \\INSERT INTO sessions (user_id, token_hash, expires_at)
            \\SELECT id, $2, now() + make_interval(secs => $3::int) FROM users
            \\WHERE email = $1 AND disabled_at IS NULL
        , &.{ email, hash[0..digest_hex_len :0], seconds_buffer[0..written.len :0] });
        if (inserted == 0) return error.QueryFailed;
    }

    /// The role a session grants, or null when it is unknown, expired, revoked, or
    /// its user is disabled — so disabling an account ends its sessions without
    /// having to find them.
    pub fn authenticate(self: SessionRepository, secret: []const u8) Error!?Role {
        var hash: [digest_hex_len + 1]u8 = undefined;
        hashSecret(secret, hash[0..digest_hex_len]);
        hash[digest_hex_len] = 0;
        var rows = try self.conn.query(
            \\SELECT u.role FROM sessions s JOIN users u ON u.id = s.user_id
            \\WHERE s.token_hash = $1 AND s.revoked_at IS NULL
            \\  AND s.expires_at > now() AND u.disabled_at IS NULL
        , &.{hash[0..digest_hex_len :0]});
        defer rows.deinit();
        if (!rows.next()) return null;
        return Role.parse(rows.get(0));
    }

    /// End one session — a logout.
    pub fn revoke(self: SessionRepository, secret: []const u8) Error!void {
        var hash: [digest_hex_len + 1]u8 = undefined;
        hashSecret(secret, hash[0..digest_hex_len]);
        hash[digest_hex_len] = 0;
        try self.conn.execParams(
            "UPDATE sessions SET revoked_at = now() WHERE token_hash = $1 AND revoked_at IS NULL",
            &.{hash[0..digest_hex_len :0]},
        );
    }

    /// End every session a user holds — what a password change or a compromise
    /// requires.
    pub fn revokeAllFor(self: SessionRepository, allocator: std.mem.Allocator, email: [:0]const u8) Error!?[]u8 {
        return self.conn.queryScalarParams(
            allocator,
            \\WITH ended AS (
            \\  UPDATE sessions s SET revoked_at = now()
            \\  WHERE s.revoked_at IS NULL
            \\    AND s.user_id = (SELECT id FROM users WHERE email = $1)
            \\  RETURNING 1
            \\) SELECT count(*) FROM ended
        ,
            &.{email},
        );
    }

    /// Delete sessions that expired before now. Expired sessions are already
    /// unusable, so this is housekeeping rather than a security control — which is
    /// why authentication checks expiry itself instead of relying on it having run.
    pub fn pruneExpired(self: SessionRepository, allocator: std.mem.Allocator) Error!?[]u8 {
        return self.conn.queryScalar(
            allocator,
            \\WITH deleted AS (
            \\  DELETE FROM sessions WHERE expires_at <= now() RETURNING 1
            \\) SELECT count(*) FROM deleted
            ,
        );
    }
};

// ---- tests --------------------------------------------------------------

const testing = std.testing;
const fleet = @import("fleet.zig");

test "roles authorize by action, and an unknown role grants nothing" {
    try testing.expectEqual(Role.viewer, Role.parse("viewer").?);
    try testing.expectEqual(Role.admin, Role.parse("admin").?);
    // A role the schema does not allow cannot be turned into one that is: parsing
    // fails rather than falling back to the least or most privileged.
    try testing.expect(Role.parse("superuser") == null);
    try testing.expect(Role.parse("") == null);
    try testing.expect(Role.parse("Admin") == null);

    // Everyone reads; only operators and admins change policy; only admins change
    // who may do so.
    for ([_]Role{ .viewer, .operator, .admin }) |role| {
        try testing.expect(role.can(.view_events));
        try testing.expect(role.can(.export_events));
    }
    try testing.expect(!Role.viewer.can(.manage_rulesets));
    try testing.expect(!Role.viewer.can(.drive_rollout));
    try testing.expect(Role.operator.can(.manage_rulesets));
    try testing.expect(Role.operator.can(.drive_rollout));
    try testing.expect(!Role.operator.can(.manage_users));
    try testing.expect(!Role.operator.can(.manage_settings));
    try testing.expect(Role.admin.can(.manage_users));
    try testing.expect(Role.admin.can(.manage_tokens));
}

test "generated secrets are unique and stored only as hashes" {
    const io = std.testing.io;
    var first: [secret_text_len]u8 = undefined;
    var second: [secret_text_len]u8 = undefined;
    try generateSecret(io, &first);
    try generateSecret(io, &second);
    try testing.expect(!std.mem.eql(u8, &first, &second));

    // URL-safe, so a token can be a bearer header or a cookie value unencoded.
    for (first) |byte| try testing.expect(std.ascii.isAlphanumeric(byte) or byte == '-' or byte == '_');

    // Hashing is deterministic, hides the secret, and is stable in length.
    var hash_a: [digest_hex_len]u8 = undefined;
    var hash_b: [digest_hex_len]u8 = undefined;
    hashSecret(&first, &hash_a);
    hashSecret(&first, &hash_b);
    try testing.expectEqualSlices(u8, &hash_a, &hash_b);
    try testing.expect(std.mem.indexOf(u8, &hash_a, first[0..8]) == null);
    var hash_c: [digest_hex_len]u8 = undefined;
    hashSecret(&second, &hash_c);
    try testing.expect(!std.mem.eql(u8, &hash_a, &hash_c));
}

/// A schema-isolated connection with the fleet schema applied, as in fleet.zig.
fn testDb() !pg.TestSchema {
    var db = try pg.TestSchema.open(testing.allocator);
    _ = fleet.apply(&db.conn, testing.allocator) catch |err| {
        db.close();
        return err;
    };
    return db;
}

test "password authentication accepts the password and nothing else" {
    var db = try testDb();
    defer db.close();
    const io = std.testing.io;
    const users = UserRepository{ .conn = &db.conn };

    try users.create(testing.allocator, io, "op@example.com", "correct horse battery staple", .operator);

    // The stored hash is not the password, and carries its own parameters so it
    // still verifies after the cost is raised.
    const stored = (try db.conn.queryScalar(testing.allocator, "SELECT password_hash FROM users WHERE email = 'op@example.com'")).?;
    defer testing.allocator.free(stored);
    try testing.expect(std.mem.startsWith(u8, stored, "$argon2id$"));
    try testing.expect(std.mem.indexOf(u8, stored, "correct horse") == null);

    try testing.expectEqual(Role.operator, (try users.authenticate(testing.allocator, io, "op@example.com", "correct horse battery staple")).?);
    // Wrong password, unknown email, and a near miss are all just null — which of
    // them it was is what an attacker probing for accounts wants to learn.
    try testing.expect((try users.authenticate(testing.allocator, io, "op@example.com", "correct horse battery stapl")) == null);
    try testing.expect((try users.authenticate(testing.allocator, io, "op@example.com", "")) == null);
    try testing.expect((try users.authenticate(testing.allocator, io, "nobody@example.com", "correct horse battery staple")) == null);

    // A disabled account authenticates as nothing, without deleting the record of
    // what it did.
    try users.setDisabled("op@example.com", true);
    try testing.expect((try users.authenticate(testing.allocator, io, "op@example.com", "correct horse battery staple")) == null);
    try users.setDisabled("op@example.com", false);
    try testing.expectEqual(Role.operator, (try users.authenticate(testing.allocator, io, "op@example.com", "correct horse battery staple")).?);

    // A role change takes effect on the next authentication.
    try users.setRole("op@example.com", .admin);
    try testing.expectEqual(Role.admin, (try users.authenticate(testing.allocator, io, "op@example.com", "correct horse battery staple")).?);

    // A federated account has no password, so no password authenticates it.
    try users.createFederated("sso@example.com", "sub-abc", .viewer);
    try testing.expect((try users.authenticate(testing.allocator, io, "sso@example.com", "")) == null);
    try testing.expect((try users.authenticate(testing.allocator, io, "sso@example.com", "guess")) == null);
    try testing.expectEqual(Role.viewer, (try users.authenticateFederated("sub-abc")).?);
    try testing.expect((try users.authenticateFederated("sub-unknown")) == null);
    try users.setDisabled("sso@example.com", true);
    try testing.expect((try users.authenticateFederated("sub-abc")) == null);
}

test "API tokens authenticate until they expire or are revoked" {
    var db = try testDb();
    defer db.close();
    const io = std.testing.io;
    const users = UserRepository{ .conn = &db.conn };
    const tokens = TokenRepository{ .conn = &db.conn };
    try users.create(testing.allocator, io, "ci@example.com", "a long enough passphrase", .operator);

    var secret: [secret_text_len]u8 = undefined;
    try tokens.issue(io, "ci@example.com", "deploy", null, &secret);
    try testing.expectEqual(Role.operator, (try tokens.authenticate(&secret)).?);

    // Only the hash is stored, so the database does not hold a usable credential.
    const stored = (try db.conn.queryScalar(testing.allocator, "SELECT token_hash FROM api_tokens")).?;
    defer testing.allocator.free(stored);
    try testing.expectEqual(@as(usize, digest_hex_len), stored.len);
    try testing.expect(!std.mem.eql(u8, stored, &secret));

    // Using a token records that it was used, so an unused one is visible as such.
    const used = (try db.conn.queryScalar(testing.allocator, "SELECT count(*) FROM api_tokens WHERE last_used_at IS NOT NULL")).?;
    defer testing.allocator.free(used);
    try testing.expectEqualStrings("1", used);

    // A secret that was never issued is not a credential.
    try testing.expect((try tokens.authenticate("not-a-real-token")) == null);
    try testing.expect((try tokens.authenticate("")) == null);

    // An expired token stops working. The lifetime is applied by the database, so
    // this backdates it rather than sleeping.
    var expiring: [secret_text_len]u8 = undefined;
    try tokens.issue(io, "ci@example.com", "short", 3600, &expiring);
    try testing.expectEqual(Role.operator, (try tokens.authenticate(&expiring)).?);
    try db.conn.exec("UPDATE api_tokens SET expires_at = now() - interval '1 second' WHERE name = 'short'");
    try testing.expect((try tokens.authenticate(&expiring)) == null);

    // Revocation is immediate and recorded rather than deleted.
    try tokens.revoke("ci@example.com", "deploy");
    try testing.expect((try tokens.authenticate(&secret)) == null);
    {
        const active = (try tokens.activeCount(testing.allocator, "ci@example.com")).?;
        defer testing.allocator.free(active);
        try testing.expectEqualStrings("0", active);
        const rows = (try db.conn.queryScalar(testing.allocator, "SELECT count(*) FROM api_tokens")).?;
        defer testing.allocator.free(rows);
        try testing.expectEqualStrings("2", rows);
    }

    // A token cannot be issued for an unknown user, rather than dangling.
    var orphan: [secret_text_len]u8 = undefined;
    try testing.expectError(error.QueryFailed, tokens.issue(io, "nobody@example.com", "x", null, &orphan));

    // Disabling the user disables every token it holds, without finding them.
    var live: [secret_text_len]u8 = undefined;
    try tokens.issue(io, "ci@example.com", "still-good", null, &live);
    try testing.expectEqual(Role.operator, (try tokens.authenticate(&live)).?);
    try users.setDisabled("ci@example.com", true);
    try testing.expect((try tokens.authenticate(&live)) == null);
}

test "sessions expire, revoke, and end with their user" {
    var db = try testDb();
    defer db.close();
    const io = std.testing.io;
    const users = UserRepository{ .conn = &db.conn };
    const sessions = SessionRepository{ .conn = &db.conn };
    try users.create(testing.allocator, io, "admin@example.com", "another long passphrase", .admin);

    var cookie: [secret_text_len]u8 = undefined;
    try sessions.open(io, "admin@example.com", 3600, &cookie);
    try testing.expectEqual(Role.admin, (try sessions.authenticate(&cookie)).?);
    try testing.expect((try sessions.authenticate("forged")) == null);

    // A logout ends that session only.
    var second: [secret_text_len]u8 = undefined;
    try sessions.open(io, "admin@example.com", 3600, &second);
    try sessions.revoke(&cookie);
    try testing.expect((try sessions.authenticate(&cookie)) == null);
    try testing.expectEqual(Role.admin, (try sessions.authenticate(&second)).?);

    // Ending every session is one operation — what a password change requires.
    var third: [secret_text_len]u8 = undefined;
    try sessions.open(io, "admin@example.com", 3600, &third);
    {
        const ended = (try sessions.revokeAllFor(testing.allocator, "admin@example.com")).?;
        defer testing.allocator.free(ended);
        try testing.expectEqualStrings("2", ended); // the already-revoked one is not re-ended
    }
    try testing.expect((try sessions.authenticate(&second)) == null);
    try testing.expect((try sessions.authenticate(&third)) == null);

    // An expired session is rejected by authentication itself, not by housekeeping
    // having run first.
    var expiring: [secret_text_len]u8 = undefined;
    try sessions.open(io, "admin@example.com", 3600, &expiring);
    try db.conn.exec("UPDATE sessions SET expires_at = now() - interval '1 second' WHERE revoked_at IS NULL");
    try testing.expect((try sessions.authenticate(&expiring)) == null);
    {
        const pruned = (try sessions.pruneExpired(testing.allocator)).?;
        defer testing.allocator.free(pruned);
        try testing.expectEqualStrings("1", pruned); // only the expired one
    }

    // A session cannot be opened for a disabled user.
    try users.setDisabled("admin@example.com", true);
    var refused: [secret_text_len]u8 = undefined;
    try testing.expectError(error.QueryFailed, sessions.open(io, "admin@example.com", 3600, &refused));
}
