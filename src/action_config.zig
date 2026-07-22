//! Allocation-free parsers for typed SecLang action configuration.

const std = @import("std");

pub const ParseError = error{
    MissingValue,
    InvalidName,
    InvalidCollection,
    InvalidVariable,
    InvalidOperation,
    InvalidNumber,
    NumberOutOfRange,
};

pub const AllowScope = enum {
    transaction,
    phase,
    request,
};

pub const EngineMode = enum {
    on,
    off,
    detection_only,
};

pub const AuditEngine = enum {
    on,
    off,
    relevant_only,
};

pub const ControlKind = enum {
    audit_engine,
    audit_log_parts,
    force_request_body_variable,
    request_body_access,
    request_body_limit,
    request_body_processor,
    response_body_access,
    rule_engine,
    rule_remove_by_id,
    rule_remove_by_tag,
    rule_remove_target_by_id,
    rule_remove_target_by_tag,
};

pub const BodyProcessor = enum {
    json,
    xml,
    urlencoded,
};

pub const Control = struct {
    kind: ControlKind,
    value: []const u8,
};

pub const Severity = enum(u3) {
    emergency = 0,
    alert = 1,
    critical = 2,
    err = 3,
    warning = 4,
    notice = 5,
    info = 6,
    debug = 7,
};

pub const Collection = enum {
    tx,
    ip,
    session,
    user,
    global,
    resource,

    pub fn parse(value: []const u8) ?Collection {
        inline for (std.meta.tags(Collection)) |candidate| {
            if (std.ascii.eqlIgnoreCase(value, @tagName(candidate))) return candidate;
        }
        return null;
    }

    pub fn persistent(self: Collection) bool {
        return self != .tx;
    }
};

pub const Assignment = struct {
    name: []const u8,
    value: []const u8,
};

pub const SetVarOperation = enum { set_one, set, remove, add, subtract };

pub const SetVar = struct {
    collection: Collection,
    key: []const u8,
    operation: SetVarOperation,
    operand: ?[]const u8,
};

pub const PersistentBinding = struct {
    collection: Collection,
    key: []const u8,
};

pub const Expiration = struct {
    collection: Collection,
    key: []const u8,
    seconds: []const u8,
};

pub const Deprecation = struct {
    collection: Collection,
    key: []const u8,
    amount: []const u8,
    period_seconds: []const u8,
};

pub fn parseSeverity(value: []const u8) ParseError!Severity {
    if (value.len == 0) return error.MissingValue;
    const names = [_]struct { name: []const u8, value: Severity }{
        .{ .name = "EMERGENCY", .value = .emergency },
        .{ .name = "ALERT", .value = .alert },
        .{ .name = "CRITICAL", .value = .critical },
        .{ .name = "ERROR", .value = .err },
        .{ .name = "WARNING", .value = .warning },
        .{ .name = "WARN", .value = .warning },
        .{ .name = "NOTICE", .value = .notice },
        .{ .name = "INFO", .value = .info },
        .{ .name = "INFORMATIONAL", .value = .info },
        .{ .name = "DEBUG", .value = .debug },
    };
    for (names) |entry| if (std.ascii.eqlIgnoreCase(value, entry.name)) return entry.value;
    const number = parseUnsigned(value) catch return error.InvalidNumber;
    if (number > 7) return error.NumberOutOfRange;
    return @fromBackingInt(@intCast(number));
}

pub fn parseQuality(value: []const u8) ParseError!u4 {
    if (value.len == 0) return error.MissingValue;
    const number = parseUnsigned(value) catch return error.InvalidNumber;
    if (number < 1 or number > 9) return error.NumberOutOfRange;
    return @intCast(number);
}

pub fn parseAssignment(value: []const u8) ParseError!Assignment {
    const equals = std.mem.indexOfScalar(u8, value, '=') orelse return error.InvalidOperation;
    if (equals == 0) return error.InvalidName;
    return .{ .name = value[0..equals], .value = value[equals + 1 ..] };
}

pub fn parseSetVar(value: []const u8) ParseError!SetVar {
    if (value.len == 0) return error.MissingValue;
    var expression = value;
    const remove = expression[0] == '!';
    if (remove) {
        expression = expression[1..];
        if (expression.len == 0 or std.mem.indexOfScalar(u8, expression, '=') != null)
            return error.InvalidOperation;
    }
    const equals = std.mem.indexOfScalar(u8, expression, '=');
    const variable = if (equals) |index| expression[0..index] else expression;
    const parsed = try parseVariable(variable);
    if (remove) return .{ .collection = parsed.collection, .key = parsed.key, .operation = .remove, .operand = null };
    const operand = if (equals) |index| expression[index + 1 ..] else return .{
        .collection = parsed.collection,
        .key = parsed.key,
        .operation = .set_one,
        .operand = null,
    };
    if (operand.len > 1 and (operand[0] == '+' or operand[0] == '-')) return .{
        .collection = parsed.collection,
        .key = parsed.key,
        .operation = if (operand[0] == '+') .add else .subtract,
        .operand = operand[1..],
    };
    return .{ .collection = parsed.collection, .key = parsed.key, .operation = .set, .operand = operand };
}

pub fn parseInitCollection(value: []const u8) ParseError!PersistentBinding {
    const assignment = try parseAssignment(value);
    const collection = Collection.parse(assignment.name) orelse return error.InvalidCollection;
    if (collection != .ip and collection != .global and collection != .resource)
        return error.InvalidCollection;
    if (assignment.value.len == 0) return error.MissingValue;
    return .{ .collection = collection, .key = assignment.value };
}

pub fn parseExpiration(value: []const u8) ParseError!Expiration {
    const assignment = try parseAssignment(value);
    const variable = try parseVariable(assignment.name);
    if (!variable.collection.persistent()) return error.InvalidCollection;
    if (assignment.value.len == 0) return error.MissingValue;
    return .{ .collection = variable.collection, .key = variable.key, .seconds = assignment.value };
}

pub fn parseDeprecation(value: []const u8) ParseError!Deprecation {
    const assignment = try parseAssignment(value);
    const variable = try parseVariable(assignment.name);
    if (!variable.collection.persistent()) return error.InvalidCollection;
    const slash = std.mem.indexOfScalar(u8, assignment.value, '/') orelse return error.InvalidOperation;
    if (slash == 0 or slash + 1 == assignment.value.len or
        std.mem.indexOfScalarPos(u8, assignment.value, slash + 1, '/') != null)
    {
        return error.InvalidOperation;
    }
    return .{
        .collection = variable.collection,
        .key = variable.key,
        .amount = assignment.value[0..slash],
        .period_seconds = assignment.value[slash + 1 ..],
    };
}

pub fn parsePositiveU32(value: []const u8) ParseError!u32 {
    const number = parseUnsigned(value) catch return error.InvalidNumber;
    if (number == 0 or number > std.math.maxInt(u32)) return error.NumberOutOfRange;
    return @intCast(number);
}

pub fn parseAllowScope(value: ?[]const u8) ParseError!AllowScope {
    const raw = value orelse return .transaction;
    if (raw.len == 0) return .transaction;
    if (std.ascii.eqlIgnoreCase(raw, "phase")) return .phase;
    if (std.ascii.eqlIgnoreCase(raw, "request")) return .request;
    return error.InvalidOperation;
}

pub fn parseStatus(value: []const u8) ParseError!u16 {
    const number = parseUnsigned(value) catch return error.InvalidNumber;
    if (number < 100 or number > 599) return error.NumberOutOfRange;
    return @intCast(number);
}

pub fn parseSkip(value: []const u8) ParseError!u32 {
    return parsePositiveU32(value);
}

pub fn parseEngineMode(value: []const u8) ParseError!EngineMode {
    if (std.ascii.eqlIgnoreCase(value, "on")) return .on;
    if (std.ascii.eqlIgnoreCase(value, "off")) return .off;
    if (std.ascii.eqlIgnoreCase(value, "detectiononly")) return .detection_only;
    return error.InvalidOperation;
}

pub fn parseAuditEngine(value: []const u8) ParseError!AuditEngine {
    if (std.ascii.eqlIgnoreCase(value, "on")) return .on;
    if (std.ascii.eqlIgnoreCase(value, "off")) return .off;
    if (std.ascii.eqlIgnoreCase(value, "relevantonly")) return .relevant_only;
    return error.InvalidOperation;
}

pub fn parseBoolean(value: []const u8) ParseError!bool {
    if (std.ascii.eqlIgnoreCase(value, "on")) return true;
    if (std.ascii.eqlIgnoreCase(value, "off")) return false;
    return error.InvalidOperation;
}

pub fn parseControl(value: []const u8) ParseError!Control {
    const assignment = try parseAssignment(value);
    if (assignment.value.len == 0) return error.MissingValue;
    const kinds = [_]struct { name: []const u8, kind: ControlKind }{
        .{ .name = "auditEngine", .kind = .audit_engine },
        .{ .name = "auditLogParts", .kind = .audit_log_parts },
        .{ .name = "forceRequestBodyVariable", .kind = .force_request_body_variable },
        .{ .name = "requestBodyAccess", .kind = .request_body_access },
        .{ .name = "requestBodyLimit", .kind = .request_body_limit },
        .{ .name = "requestBodyProcessor", .kind = .request_body_processor },
        .{ .name = "responseBodyAccess", .kind = .response_body_access },
        .{ .name = "ruleEngine", .kind = .rule_engine },
        .{ .name = "ruleRemoveById", .kind = .rule_remove_by_id },
        .{ .name = "ruleRemoveByTag", .kind = .rule_remove_by_tag },
        .{ .name = "ruleRemoveTargetById", .kind = .rule_remove_target_by_id },
        .{ .name = "ruleRemoveTargetByTag", .kind = .rule_remove_target_by_tag },
    };
    for (kinds) |entry| if (std.ascii.eqlIgnoreCase(assignment.name, entry.name))
        return .{ .kind = entry.kind, .value = assignment.value };
    return error.InvalidName;
}

pub fn parseBodyProcessor(value: []const u8) ParseError!BodyProcessor {
    if (std.ascii.eqlIgnoreCase(value, "json")) return .json;
    if (std.ascii.eqlIgnoreCase(value, "xml")) return .xml;
    if (std.ascii.eqlIgnoreCase(value, "urlencoded")) return .urlencoded;
    return error.InvalidOperation;
}

pub fn parsePositiveUsize(value: []const u8) ParseError!usize {
    const number = parseUnsigned(value) catch return error.InvalidNumber;
    if (number == 0 or number > std.math.maxInt(usize)) return error.NumberOutOfRange;
    return @intCast(number);
}

fn parseVariable(value: []const u8) ParseError!struct { collection: Collection, key: []const u8 } {
    const dot = std.mem.indexOfScalar(u8, value, '.') orelse return error.InvalidVariable;
    if (dot == 0 or dot + 1 == value.len) return error.InvalidVariable;
    const collection = Collection.parse(value[0..dot]) orelse return error.InvalidCollection;
    return .{ .collection = collection, .key = value[dot + 1 ..] };
}

fn parseUnsigned(value: []const u8) !u64 {
    if (value.len == 0) return error.InvalidCharacter;
    var result: u64 = 0;
    for (value) |byte| {
        if (byte < '0' or byte > '9') return error.InvalidCharacter;
        result = std.math.mul(u64, result, 10) catch return error.Overflow;
        result = std.math.add(u64, result, byte - '0') catch return error.Overflow;
    }
    return result;
}

test "severity accepts the stable numeric and symbolic union" {
    try std.testing.expectEqual(Severity.emergency, try parseSeverity("0"));
    try std.testing.expectEqual(Severity.critical, try parseSeverity("critical"));
    try std.testing.expectEqual(Severity.warning, try parseSeverity("WARN"));
    try std.testing.expectEqual(Severity.info, try parseSeverity("informational"));
    try std.testing.expectEqual(Severity.debug, try parseSeverity("7"));
    try std.testing.expectError(error.NumberOutOfRange, parseSeverity("8"));
    try std.testing.expectError(error.InvalidNumber, parseSeverity("2tail"));
}

test "maturity and accuracy use the documented one through nine scale" {
    try std.testing.expectEqual(@as(u4, 1), try parseQuality("1"));
    try std.testing.expectEqual(@as(u4, 9), try parseQuality("9"));
    try std.testing.expectError(error.NumberOutOfRange, parseQuality("0"));
    try std.testing.expectError(error.NumberOutOfRange, parseQuality("10"));
}

test "setvar classifies set delete and checked arithmetic syntax without allocation" {
    try std.testing.expectEqualDeep(SetVar{ .collection = .tx, .key = "score", .operation = .set_one, .operand = null }, try parseSetVar("TX.score"));
    try std.testing.expectEqualDeep(SetVar{ .collection = .tx, .key = "score", .operation = .set, .operand = "" }, try parseSetVar("tx.score="));
    try std.testing.expectEqualDeep(SetVar{ .collection = .ip, .key = "%{MATCHED_VAR_NAME}", .operation = .add, .operand = "%{TX.delta}" }, try parseSetVar("IP.%{MATCHED_VAR_NAME}=+%{TX.delta}"));
    try std.testing.expectEqualDeep(SetVar{ .collection = .session, .key = "flag", .operation = .remove, .operand = null }, try parseSetVar("!SESSION.flag"));
    try std.testing.expectError(error.InvalidOperation, parseSetVar("!TX.flag=1"));
    try std.testing.expectError(error.InvalidCollection, parseSetVar("ARGS.flag=1"));
    try std.testing.expectError(error.InvalidVariable, parseSetVar("TX."));
}

test "environment persistent binding expiration and decay grammars are distinct" {
    try std.testing.expectEqualDeep(Assignment{ .name = "flag", .value = "%{TX.value}" }, try parseAssignment("flag=%{TX.value}"));
    try std.testing.expectEqualDeep(PersistentBinding{ .collection = .ip, .key = "%{REMOTE_ADDR}" }, try parseInitCollection("ip=%{REMOTE_ADDR}"));
    try std.testing.expectError(error.InvalidCollection, parseInitCollection("session=abc"));
    try std.testing.expectEqualDeep(Expiration{ .collection = .user, .key = "score", .seconds = "%{TX.ttl}" }, try parseExpiration("USER.score=%{TX.ttl}"));
    try std.testing.expectError(error.InvalidCollection, parseExpiration("TX.score=60"));
    try std.testing.expectEqualDeep(Deprecation{ .collection = .global, .key = "score", .amount = "5", .period_seconds = "60" }, try parseDeprecation("GLOBAL.score=5/60"));
    try std.testing.expectError(error.InvalidOperation, parseDeprecation("IP.score=5/60/2"));
    try std.testing.expectEqual(@as(u32, 60), try parsePositiveU32("60"));
    try std.testing.expectError(error.NumberOutOfRange, parsePositiveU32("0"));
}

test "allow status skip and runtime modes validate without allocation" {
    try std.testing.expectEqual(AllowScope.transaction, try parseAllowScope(null));
    try std.testing.expectEqual(AllowScope.transaction, try parseAllowScope(""));
    try std.testing.expectEqual(AllowScope.phase, try parseAllowScope("PHASE"));
    try std.testing.expectEqual(AllowScope.request, try parseAllowScope("request"));
    try std.testing.expectError(error.InvalidOperation, parseAllowScope("response"));

    try std.testing.expectEqual(@as(u16, 100), try parseStatus("100"));
    try std.testing.expectEqual(@as(u16, 599), try parseStatus("599"));
    try std.testing.expectError(error.NumberOutOfRange, parseStatus("99"));
    try std.testing.expectError(error.InvalidNumber, parseStatus("403x"));
    try std.testing.expectEqual(@as(u32, 2), try parseSkip("2"));
    try std.testing.expectError(error.NumberOutOfRange, parseSkip("0"));

    try std.testing.expectEqual(EngineMode.detection_only, try parseEngineMode("DetectionOnly"));
    try std.testing.expectEqual(AuditEngine.relevant_only, try parseAuditEngine("RelevantOnly"));
    try std.testing.expect(try parseBoolean("ON"));
    try std.testing.expect(!(try parseBoolean("off")));
    try std.testing.expectError(error.InvalidOperation, parseEngineMode("enabled"));
    try std.testing.expectError(error.InvalidOperation, parseAuditEngine("sometimes"));
    try std.testing.expectError(error.InvalidOperation, parseBoolean("yes"));
}

test "runtime control names and body values parse without allocation" {
    try std.testing.expectEqualDeep(Control{ .kind = .rule_engine, .value = "DetectionOnly" }, try parseControl("ruleEngine=DetectionOnly"));
    try std.testing.expectEqualDeep(Control{ .kind = .rule_remove_target_by_id, .value = "942100;ARGS:password" }, try parseControl("ruleRemoveTargetById=942100;ARGS:password"));
    try std.testing.expectEqual(BodyProcessor.json, try parseBodyProcessor("JSON"));
    try std.testing.expectEqual(BodyProcessor.urlencoded, try parseBodyProcessor("urlencoded"));
    try std.testing.expectEqual(@as(usize, 1048576), try parsePositiveUsize("1048576"));
    try std.testing.expectError(error.InvalidName, parseControl("unknown=On"));
    try std.testing.expectError(error.InvalidOperation, parseControl("ruleEngine"));
    try std.testing.expectError(error.MissingValue, parseControl("ruleEngine="));
    try std.testing.expectError(error.InvalidOperation, parseBodyProcessor("multipart"));
    try std.testing.expectError(error.NumberOutOfRange, parsePositiveUsize("0"));
}
