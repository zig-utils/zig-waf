//! Console authorization vocabulary: who exists, and what each may do (#58).
//!
//! Deliberately independent of storage and of the API surface. Roles and actions are
//! the shared language between the identity layer that authenticates a caller
//! (`fleet_auth.zig`, which needs a database) and the API surface that authorizes one
//! (`api.zig`, which must not). Keeping them here means the route table can state its
//! requirements without dragging libpq into every build that reads them.

const std = @import("std");

/// What a console identity is allowed to do. A fixed set, mirrored by a CHECK
/// constraint in the schema, so an unrecognized role cannot be stored and later
/// be interpreted as one of these.
pub const Role = enum {
    /// Read the fleet, events, and policies.
    viewer,
    /// Change policy and drive rollouts, but not who may do so.
    operator,
    /// Everything, including identity and settings.
    admin,

    pub fn text(self: Role) [:0]const u8 {
        return switch (self) {
            .viewer => "viewer",
            .operator => "operator",
            .admin => "admin",
        };
    }

    pub fn parse(text_value: []const u8) ?Role {
        if (std.mem.eql(u8, text_value, "viewer")) return .viewer;
        if (std.mem.eql(u8, text_value, "operator")) return .operator;
        if (std.mem.eql(u8, text_value, "admin")) return .admin;
        return null; // an unknown role grants nothing rather than defaulting
    }

    /// Whether this role may perform `action`. Authorization is a total function
    /// over an enumerated set of actions rather than a string comparison at each
    /// call site, so a new action has to be classified here to be permitted
    /// anywhere.
    pub fn can(self: Role, action: Action) bool {
        return switch (action) {
            .view_fleet, .view_events, .export_events => true, // every role reads
            .manage_rulesets, .drive_rollout, .manage_alerts => self != .viewer,
            .manage_users, .manage_settings, .manage_tokens => self == .admin,
        };
    }
};

/// Everything authorization is asked about. Enumerated so `Role.can` is
/// exhaustive: adding an action without deciding who may do it will not compile.
pub const Action = enum {
    view_fleet,
    view_events,
    export_events,
    manage_rulesets,
    drive_rollout,
    manage_alerts,
    manage_users,
    manage_settings,
    manage_tokens,
};
