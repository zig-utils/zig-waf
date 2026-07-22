//! Canonical stable directive inventory and schema metadata.

const std = @import("std");
const plan_mod = @import("plan.zig");
const seclang = @import("seclang/root.zig");

pub const Id = enum(u8) {
    sec_rule,
    sec_action,
    sec_default_action,
    sec_marker,
    sec_component_signature,
    sec_rule_engine,
    sec_conn_engine,
    sec_conn_read_state_limit,
    sec_conn_write_state_limit,
    sec_web_app_id,
    sec_server_signature,
    sec_sensor_id,
    sec_status_engine,
    sec_rule_script,
    sec_request_body_access,
    sec_request_body_limit,
    sec_request_body_no_files_limit,
    sec_request_body_in_memory_limit,
    sec_request_body_limit_action,
    sec_request_body_json_depth_limit,
    sec_response_body_access,
    sec_response_body_limit,
    sec_response_body_limit_action,
    sec_response_body_mime_type,
    sec_response_body_mime_types_clear,
    sec_arguments_limit,
    sec_argument_separator,
    sec_cookie_format,
    sec_cookie_v0_separator,
    sec_stream_in_body_inspection,
    sec_stream_out_body_inspection,
    sec_content_injection,
    sec_disable_backend_compression,
    sec_audit_engine,
    sec_audit_log,
    sec_audit_log2,
    sec_audit_log_type,
    sec_audit_log_format,
    sec_audit_log_storage_dir,
    sec_audit_log_dir_mode,
    sec_audit_log_file_mode,
    sec_audit_log_relevant_status,
    sec_audit_log_parts,
    sec_audit_log_prefix,
    sec_debug_log,
    sec_debug_log_level,
    sec_guardian_log,
    sec_data_dir,
    sec_tmp_dir,
    sec_upload_dir,
    sec_upload_file_mode,
    sec_upload_file_limit,
    sec_upload_keep_files,
    sec_tmp_save_uploaded_files,
    sec_chroot_dir,
    sec_rule_remove_by_id,
    sec_rule_remove_by_msg,
    sec_rule_remove_by_tag,
    sec_rule_update_target_by_id,
    sec_rule_update_target_by_msg,
    sec_rule_update_target_by_tag,
    sec_rule_update_action_by_id,
    sec_rule_inheritance,
    sec_rule_perf_time,
    sec_intercept_on_error,
    sec_ignore_rule_compilation_errors,
    sec_cache_transformations,
    sec_pcre_match_limit,
    sec_pcre_match_limit_recursion,
    sec_rx_pre_filter,
    sec_remote_rules,
    sec_remote_rules_fail_action,
    sec_collection_timeout,
    sec_geo_lookup_db,
    sec_gsb_lookup_db,
    sec_http_bl_key,
    sec_dataset,
    sec_hash_engine,
    sec_hash_key,
    sec_hash_param,
    sec_hash_method_rx,
    sec_hash_method_pm,
    sec_unicode_map,
    sec_unicode_map_file,
    sec_xml_external_entity,
    sec_parse_xml_into_args,
};

pub const Schema = enum {
    rule,
    action,
    default_action,
    marker,
    text,
    toggle,
    rule_engine,
    connection_engine,
    unsigned,
    limit_action,
    mime_type,
    clear,
    byte_separator,
    cookie_format,
    audit_engine,
    audit_log_type,
    audit_log_format,
    audit_parts,
    octal_mode,
    upload_keep_files,
    remote_fail_action,
    path,
    regex,
    id_ranges,
    rule_update,
    remote_rules,
    dataset,
    hash_parameter,
    unicode_map,
};

pub const Repeatability = enum { singular_replace, singular_error, append };

pub const Capability = enum(u6) {
    core,
    request_body,
    response_body,
    audit_log,
    debug_log,
    upload,
    rule_updates,
    regex_limits,
    remote_rules,
    datasets,
    geo_lookup,
    gsb_lookup,
    http_blocklist,
    hashing,
    unicode_map,
    xml,
    connection_limits,
    rule_script,
};

pub const CapabilitySet = struct {
    bits: u64 = 0,

    pub fn full() CapabilitySet {
        var result: CapabilitySet = .{};
        inline for (std.meta.tags(Capability)) |capability| result.bits |= bit(capability);
        return result;
    }

    pub fn coreOnly() CapabilitySet {
        return .{ .bits = bit(.core) };
    }

    pub fn has(self: CapabilitySet, capability: Capability) bool {
        return self.bits & bit(capability) != 0;
    }

    fn bit(capability: Capability) u64 {
        return @as(u64, 1) << @backingInt(capability);
    }
};

pub const Presence = struct {
    modsecurity: bool,
    coraza: bool,
    crs: bool = false,
};

pub const Entry = struct {
    id: Id,
    name: []const u8,
    schema: Schema,
    repeatability: Repeatability = .singular_replace,
    capability: Capability = .core,
    presence: Presence,
    sensitive: bool = false,
    owner_issue: u16,
};

pub const DiagnosticCode = enum {
    unknown_directive,
    unavailable_capability,
    invalid_argument_count,
    invalid_value,

    pub fn id(self: DiagnosticCode) []const u8 {
        return switch (self) {
            .unknown_directive => "WAF-DIRECTIVE-0101",
            .unavailable_capability => "WAF-DIRECTIVE-0102",
            .invalid_argument_count => "WAF-DIRECTIVE-0103",
            .invalid_value => "WAF-DIRECTIVE-0104",
        };
    }

    pub fn message(self: DiagnosticCode) []const u8 {
        return switch (self) {
            .unknown_directive => "directive is not in the stable compatibility union",
            .unavailable_capability => "directive requires a capability unavailable in this build",
            .invalid_argument_count => "directive argument count does not match its canonical schema",
            .invalid_value => "directive value does not match its canonical schema",
        };
    }
};

pub const Diagnostic = struct {
    code: DiagnosticCode,
    primary: seclang.source.Span,
    directive: ?Id = null,
    sensitive: bool = false,
    message: []const u8,
};

pub const ValidationOutcome = union(enum) {
    valid,
    diagnostic: Diagnostic,
};

pub const RuleEngine = enum { on, off, detection_only };
pub const ConnectionEngine = enum { on, off };
pub const LimitAction = enum { reject, process_partial };
pub const AuditEngine = enum { on, off, relevant_only };
pub const AuditLogType = enum { serial, concurrent, https };
pub const AuditLogFormat = enum { native, json };
pub const UploadKeepFiles = enum { on, off, relevant_only };
pub const RemoteFailAction = enum { abort, warn };
pub const Fingerprint = [32]u8;

pub const Value = union(enum) {
    text: []const u8,
    toggle: bool,
    rule_engine: RuleEngine,
    connection_engine: ConnectionEngine,
    unsigned: u64,
    limit_action: LimitAction,
    byte_separator: u8,
    cookie_format: u1,
    audit_engine: AuditEngine,
    audit_log_type: AuditLogType,
    audit_log_format: AuditLogFormat,
    audit_parts: []const u8,
    octal_mode: u16,
    upload_keep_files: UploadKeepFiles,
    remote_fail_action: RemoteFailAction,
};

pub const DecodedValue = struct {
    source: seclang.source.Span,
    value: Value,
};

pub const ConfigurationOutcome = union(enum) {
    configuration: Configuration,
    diagnostic: Diagnostic,
};

/// Immutable typed view over a plan. The plan owner must outlive this value.
pub const Configuration = struct {
    plan: *const plan_mod.Plan,
    capabilities: CapabilitySet,
    fingerprint: Fingerprint,

    pub fn init(plan: *const plan_mod.Plan, capabilities: CapabilitySet) ConfigurationOutcome {
        switch (validatePlan(plan, capabilities)) {
            .valid => {},
            .diagnostic => |value| return .{ .diagnostic = value },
        }
        var result = Configuration{
            .plan = plan,
            .capabilities = capabilities,
            .fingerprint = undefined,
        };
        result.fingerprint = computeConfigurationFingerprint(&result);
        return .{ .configuration = result };
    }

    /// Return the last source occurrence. This is the effective occurrence for
    /// singular replacement directives; append directives retain all entries.
    pub fn latest(self: *const Configuration, id: Id) ?DecodedDirective {
        var index = self.plan.directives.len;
        while (index > 0) {
            index -= 1;
            const directive = &self.plan.directives[index];
            const name = self.plan.string(directive.name) orelse continue;
            const entry = lookup(name) orelse continue;
            if (entry.id == id) return .{ .plan = self.plan, .entry = entry, .directive = directive };
        }
        return null;
    }

    pub fn occurrences(self: *const Configuration, id: Id) OccurrenceIterator {
        return .{ .plan = self.plan, .id = id };
    }
};

pub const DecodedDirective = struct {
    plan: *const plan_mod.Plan,
    entry: *const Entry,
    directive: *const plan_mod.Directive,

    pub fn values(self: DecodedDirective) ValueIterator {
        const start: usize = self.directive.arguments_start;
        const count: usize = self.directive.arguments_count;
        return .{
            .plan = self.plan,
            .entry = self.entry,
            .arguments = self.plan.arguments[start..][0..count],
        };
    }
};

pub const OccurrenceIterator = struct {
    plan: *const plan_mod.Plan,
    id: Id,
    index: usize = 0,

    pub fn next(self: *OccurrenceIterator) ?DecodedDirective {
        while (self.index < self.plan.directives.len) {
            const directive = &self.plan.directives[self.index];
            self.index += 1;
            const name = self.plan.string(directive.name) orelse continue;
            const entry = lookup(name) orelse continue;
            if (entry.id == self.id) return .{ .plan = self.plan, .entry = entry, .directive = directive };
        }
        return null;
    }
};

pub const ValueIterator = struct {
    plan: *const plan_mod.Plan,
    entry: *const Entry,
    arguments: []const plan_mod.Argument,
    index: usize = 0,

    pub fn next(self: *ValueIterator) ?DecodedValue {
        if (self.index >= self.arguments.len) return null;
        const index = self.index;
        self.index += 1;
        const argument = self.arguments[index];
        const raw = self.plan.string(argument.raw) orelse unreachable;
        const value = argumentContent(raw, argument.quote);
        return .{ .source = argument.source, .value = decodeValue(self.entry.schema, index, value) };
    }
};

const Arity = struct { minimum: usize, maximum: usize };

const M = Presence{ .modsecurity = true, .coraza = false };
const C = Presence{ .modsecurity = false, .coraza = true };
const MC = Presence{ .modsecurity = true, .coraza = true };
const MCR = Presence{ .modsecurity = true, .coraza = true, .crs = true };

pub const registry = [_]Entry{
    row(.sec_rule, "SecRule", .rule, .append, .core, MCR, 13),
    row(.sec_action, "SecAction", .action, .append, .core, MCR, 13),
    row(.sec_default_action, "SecDefaultAction", .default_action, .append, .core, MCR, 13),
    row(.sec_marker, "SecMarker", .marker, .append, .core, MC, 13),
    row(.sec_component_signature, "SecComponentSignature", .text, .append, .core, MC, 13),
    row(.sec_rule_engine, "SecRuleEngine", .rule_engine, .singular_replace, .core, MCR, 13),
    row(.sec_conn_engine, "SecConnEngine", .connection_engine, .singular_replace, .connection_limits, MC, 13),
    row(.sec_conn_read_state_limit, "SecConnReadStateLimit", .unsigned, .singular_replace, .connection_limits, MC, 13),
    row(.sec_conn_write_state_limit, "SecConnWriteStateLimit", .unsigned, .singular_replace, .connection_limits, MC, 13),
    row(.sec_web_app_id, "SecWebAppId", .text, .singular_replace, .core, MC, 13),
    row(.sec_server_signature, "SecServerSignature", .text, .singular_replace, .core, MC, 13),
    row(.sec_sensor_id, "SecSensorId", .text, .singular_replace, .core, MC, 13),
    row(.sec_status_engine, "SecStatusEngine", .toggle, .singular_replace, .core, M, 13),
    row(.sec_rule_script, "SecRuleScript", .path, .append, .rule_script, MC, 22),

    row(.sec_request_body_access, "SecRequestBodyAccess", .toggle, .singular_replace, .request_body, MCR, 27),
    row(.sec_request_body_limit, "SecRequestBodyLimit", .unsigned, .singular_replace, .request_body, MCR, 25),
    row(.sec_request_body_no_files_limit, "SecRequestBodyNoFilesLimit", .unsigned, .singular_replace, .request_body, MC, 25),
    row(.sec_request_body_in_memory_limit, "SecRequestBodyInMemoryLimit", .unsigned, .singular_replace, .request_body, MC, 25),
    row(.sec_request_body_limit_action, "SecRequestBodyLimitAction", .limit_action, .singular_replace, .request_body, MC, 25),
    row(.sec_request_body_json_depth_limit, "SecRequestBodyJsonDepthLimit", .unsigned, .singular_replace, .request_body, MC, 27),
    row(.sec_response_body_access, "SecResponseBodyAccess", .toggle, .singular_replace, .response_body, MC, 29),
    row(.sec_response_body_limit, "SecResponseBodyLimit", .unsigned, .singular_replace, .response_body, MC, 29),
    row(.sec_response_body_limit_action, "SecResponseBodyLimitAction", .limit_action, .singular_replace, .response_body, MC, 29),
    row(.sec_response_body_mime_type, "SecResponseBodyMimeType", .mime_type, .append, .response_body, MC, 29),
    row(.sec_response_body_mime_types_clear, "SecResponseBodyMimeTypesClear", .clear, .singular_replace, .response_body, MC, 29),
    row(.sec_arguments_limit, "SecArgumentsLimit", .unsigned, .singular_replace, .request_body, MC, 24),
    row(.sec_argument_separator, "SecArgumentSeparator", .byte_separator, .singular_replace, .request_body, MC, 24),
    row(.sec_cookie_format, "SecCookieFormat", .cookie_format, .singular_replace, .request_body, MC, 24),
    row(.sec_cookie_v0_separator, "SecCookieV0Separator", .byte_separator, .singular_replace, .request_body, M, 24),
    row(.sec_stream_in_body_inspection, "SecStreamInBodyInspection", .toggle, .singular_replace, .request_body, M, 25),
    row(.sec_stream_out_body_inspection, "SecStreamOutBodyInspection", .toggle, .singular_replace, .response_body, M, 29),
    row(.sec_content_injection, "SecContentInjection", .toggle, .singular_replace, .response_body, M, 29),
    row(.sec_disable_backend_compression, "SecDisableBackendCompression", .toggle, .singular_replace, .response_body, M, 29),

    row(.sec_audit_engine, "SecAuditEngine", .audit_engine, .singular_replace, .audit_log, MC, 30),
    row(.sec_audit_log, "SecAuditLog", .path, .singular_replace, .audit_log, MC, 31),
    row(.sec_audit_log2, "SecAuditLog2", .path, .singular_replace, .audit_log, M, 31),
    row(.sec_audit_log_type, "SecAuditLogType", .audit_log_type, .singular_replace, .audit_log, MC, 31),
    row(.sec_audit_log_format, "SecAuditLogFormat", .audit_log_format, .singular_replace, .audit_log, MC, 30),
    row(.sec_audit_log_storage_dir, "SecAuditLogStorageDir", .path, .singular_replace, .audit_log, MC, 31),
    row(.sec_audit_log_dir_mode, "SecAuditLogDirMode", .octal_mode, .singular_replace, .audit_log, MC, 31),
    row(.sec_audit_log_file_mode, "SecAuditLogFileMode", .octal_mode, .singular_replace, .audit_log, MC, 31),
    row(.sec_audit_log_relevant_status, "SecAuditLogRelevantStatus", .regex, .singular_replace, .audit_log, MC, 30),
    row(.sec_audit_log_parts, "SecAuditLogParts", .audit_parts, .singular_replace, .audit_log, MC, 30),
    row(.sec_audit_log_prefix, "SecAuditLogPrefix", .text, .singular_replace, .audit_log, M, 31),
    row(.sec_debug_log, "SecDebugLog", .path, .singular_replace, .debug_log, MC, 32),
    row(.sec_debug_log_level, "SecDebugLogLevel", .unsigned, .singular_replace, .debug_log, MC, 32),
    row(.sec_guardian_log, "SecGuardianLog", .path, .singular_replace, .audit_log, M, 31),

    row(.sec_data_dir, "SecDataDir", .path, .singular_replace, .core, MC, 10),
    row(.sec_tmp_dir, "SecTmpDir", .path, .singular_replace, .upload, MC, 26),
    row(.sec_upload_dir, "SecUploadDir", .path, .singular_replace, .upload, MC, 26),
    row(.sec_upload_file_mode, "SecUploadFileMode", .octal_mode, .singular_replace, .upload, MC, 26),
    row(.sec_upload_file_limit, "SecUploadFileLimit", .unsigned, .singular_replace, .upload, MC, 26),
    row(.sec_upload_keep_files, "SecUploadKeepFiles", .upload_keep_files, .singular_replace, .upload, MC, 26),
    row(.sec_tmp_save_uploaded_files, "SecTmpSaveUploadedFiles", .toggle, .singular_replace, .upload, M, 26),
    row(.sec_chroot_dir, "SecChrootDir", .path, .singular_replace, .core, M, 72),

    row(.sec_rule_remove_by_id, "SecRuleRemoveById", .id_ranges, .append, .rule_updates, MC, 14),
    row(.sec_rule_remove_by_msg, "SecRuleRemoveByMsg", .regex, .append, .rule_updates, MC, 14),
    row(.sec_rule_remove_by_tag, "SecRuleRemoveByTag", .regex, .append, .rule_updates, MC, 14),
    row(.sec_rule_update_target_by_id, "SecRuleUpdateTargetById", .rule_update, .append, .rule_updates, MC, 14),
    row(.sec_rule_update_target_by_msg, "SecRuleUpdateTargetByMsg", .rule_update, .append, .rule_updates, MC, 14),
    row(.sec_rule_update_target_by_tag, "SecRuleUpdateTargetByTag", .rule_update, .append, .rule_updates, MC, 14),
    row(.sec_rule_update_action_by_id, "SecRuleUpdateActionById", .rule_update, .append, .rule_updates, MC, 14),
    row(.sec_rule_inheritance, "SecRuleInheritance", .toggle, .singular_replace, .rule_updates, M, 14),
    row(.sec_rule_perf_time, "SecRulePerfTime", .unsigned, .singular_replace, .core, MC, 32),
    row(.sec_intercept_on_error, "SecInterceptOnError", .toggle, .singular_replace, .core, M, 16),
    row(.sec_ignore_rule_compilation_errors, "SecIgnoreRuleCompilationErrors", .toggle, .singular_replace, .core, C, 13),
    row(.sec_cache_transformations, "SecCacheTransformations", .toggle, .singular_replace, .core, M, 17),
    row(.sec_pcre_match_limit, "SecPcreMatchLimit", .unsigned, .singular_replace, .regex_limits, MC, 18),
    row(.sec_pcre_match_limit_recursion, "SecPcreMatchLimitRecursion", .unsigned, .singular_replace, .regex_limits, MC, 18),
    row(.sec_rx_pre_filter, "SecRxPreFilter", .toggle, .singular_replace, .regex_limits, C, 18),

    secretRow(.sec_remote_rules, "SecRemoteRules", .remote_rules, .append, .remote_rules, MC, 14),
    row(.sec_remote_rules_fail_action, "SecRemoteRulesFailAction", .remote_fail_action, .singular_replace, .remote_rules, MC, 14),
    row(.sec_collection_timeout, "SecCollectionTimeout", .unsigned, .singular_replace, .core, MC, 10),
    row(.sec_geo_lookup_db, "SecGeoLookupDb", .path, .singular_replace, .geo_lookup, M, 21),
    row(.sec_gsb_lookup_db, "SecGsbLookupDb", .path, .singular_replace, .gsb_lookup, MC, 21),
    secretRow(.sec_http_bl_key, "SecHttpBlKey", .text, .singular_replace, .http_blocklist, MC, 21),
    row(.sec_dataset, "SecDataset", .dataset, .append, .datasets, C, 19),
    row(.sec_hash_engine, "SecHashEngine", .toggle, .singular_replace, .hashing, MC, 21),
    secretRow(.sec_hash_key, "SecHashKey", .hash_parameter, .singular_replace, .hashing, MC, 21),
    row(.sec_hash_param, "SecHashParam", .hash_parameter, .append, .hashing, MC, 21),
    row(.sec_hash_method_rx, "SecHashMethodRx", .hash_parameter, .append, .hashing, MC, 21),
    row(.sec_hash_method_pm, "SecHashMethodPm", .hash_parameter, .append, .hashing, MC, 21),
    row(.sec_unicode_map, "SecUnicodeMap", .unicode_map, .singular_replace, .unicode_map, C, 17),
    row(.sec_unicode_map_file, "SecUnicodeMapFile", .unicode_map, .singular_replace, .unicode_map, M, 17),
    row(.sec_xml_external_entity, "SecXmlExternalEntity", .toggle, .singular_replace, .xml, M, 28),
    row(.sec_parse_xml_into_args, "SecParseXmlIntoArgs", .toggle, .singular_replace, .xml, M, 28),
};

fn row(
    id: Id,
    name: []const u8,
    schema: Schema,
    repeatability: Repeatability,
    capability: Capability,
    presence: Presence,
    owner_issue: u16,
) Entry {
    return .{
        .id = id,
        .name = name,
        .schema = schema,
        .repeatability = repeatability,
        .capability = capability,
        .presence = presence,
        .owner_issue = owner_issue,
    };
}

fn secretRow(
    id: Id,
    name: []const u8,
    schema: Schema,
    repeatability: Repeatability,
    capability: Capability,
    presence: Presence,
    owner_issue: u16,
) Entry {
    var result = row(id, name, schema, repeatability, capability, presence, owner_issue);
    result.sensitive = true;
    return result;
}

pub fn lookup(name: []const u8) ?*const Entry {
    for (&registry) |*entry| if (std.ascii.eqlIgnoreCase(name, entry.name)) return entry;
    return null;
}

pub fn get(id: Id) *const Entry {
    return &registry[@backingInt(id)];
}

/// Validate the complete immutable plan before it can be published by a WAF.
/// Values remain borrowed from the plan; diagnostics never interpolate input.
pub fn validatePlan(compiled: *const plan_mod.Plan, capabilities: CapabilitySet) ValidationOutcome {
    for (compiled.directives) |directive| {
        switch (directive.kind) {
            .include, .include_optional => continue,
            else => {},
        }
        const name = compiled.string(directive.name) orelse
            return diagnostic(.unknown_directive, directive.source, null, false);
        const entry = lookup(name) orelse
            return diagnostic(.unknown_directive, directive.source, null, false);
        if (!capabilities.has(entry.capability))
            return diagnostic(.unavailable_capability, directive.source, entry.id, entry.sensitive);

        const start: usize = directive.arguments_start;
        const count: usize = directive.arguments_count;
        if (start > compiled.arguments.len or count > compiled.arguments.len - start)
            return diagnostic(.invalid_argument_count, directive.source, entry.id, entry.sensitive);
        const arguments = compiled.arguments[start..][0..count];
        const expected = arity(entry.id);
        if (arguments.len < expected.minimum or arguments.len > expected.maximum)
            return diagnostic(.invalid_argument_count, directive.source, entry.id, entry.sensitive);
        if (!validValues(compiled, entry, arguments)) {
            const primary = if (arguments.len == 0) directive.source else arguments[0].source;
            return diagnostic(.invalid_value, primary, entry.id, entry.sensitive);
        }
    }
    return .valid;
}

fn diagnostic(
    code: DiagnosticCode,
    primary: seclang.source.Span,
    directive: ?Id,
    sensitive: bool,
) ValidationOutcome {
    return .{ .diagnostic = .{
        .code = code,
        .primary = primary,
        .directive = directive,
        .sensitive = sensitive,
        .message = code.message(),
    } };
}

fn arity(id: Id) Arity {
    return switch (id) {
        .sec_rule => .{ .minimum = 2, .maximum = 3 },
        .sec_response_body_mime_types_clear => .{ .minimum = 0, .maximum = 0 },
        .sec_response_body_mime_type => .{ .minimum = 1, .maximum = std.math.maxInt(usize) },
        .sec_remote_rules,
        .sec_rule_update_target_by_id,
        .sec_rule_update_target_by_msg,
        .sec_rule_update_target_by_tag,
        .sec_rule_update_action_by_id,
        .sec_dataset,
        => .{ .minimum = 2, .maximum = 2 },
        .sec_hash_param,
        .sec_hash_method_rx,
        .sec_hash_method_pm,
        .sec_unicode_map,
        .sec_unicode_map_file,
        => .{ .minimum = 1, .maximum = 2 },
        else => .{ .minimum = 1, .maximum = 1 },
    };
}

fn validValues(compiled: *const plan_mod.Plan, entry: *const Entry, arguments: []const plan_mod.Argument) bool {
    if (entry.schema == .clear) return arguments.len == 0;
    for (arguments) |argument| {
        const raw = compiled.string(argument.raw) orelse return false;
        if (argumentContent(raw, argument.quote).len == 0) return false;
    }
    if (arguments.len == 0) return true;
    const raw = compiled.string(arguments[0].raw) orelse return false;
    const value = argumentContent(raw, arguments[0].quote);
    return switch (entry.schema) {
        .toggle => enumValue(value, &.{ "On", "Off" }),
        .rule_engine => enumValue(value, &.{ "On", "Off", "DetectionOnly" }),
        .connection_engine => enumValue(value, &.{ "On", "Off" }),
        .unsigned => validateUnsigned(entry.id, value),
        .limit_action => enumValue(value, &.{ "Reject", "ProcessPartial" }),
        .byte_separator => value.len == 1,
        .cookie_format => enumValue(value, &.{ "0", "1" }),
        .audit_engine => enumValue(value, &.{ "On", "Off", "RelevantOnly" }),
        .audit_log_type => enumValue(value, &.{ "Serial", "Concurrent", "HTTPS" }),
        .audit_log_format => enumValue(value, &.{ "Native", "JSON" }),
        .audit_parts => validAuditParts(value),
        .octal_mode => parseOctalMode(value) != null,
        .upload_keep_files => enumValue(value, &.{ "On", "Off", "RelevantOnly" }),
        .remote_fail_action => enumValue(value, &.{ "Abort", "Warn" }),
        .rule,
        .action,
        .default_action,
        .marker,
        .text,
        .mime_type,
        .clear,
        .path,
        .regex,
        .id_ranges,
        .rule_update,
        .remote_rules,
        .dataset,
        .hash_parameter,
        .unicode_map,
        => true,
    };
}

fn argumentContent(raw: []const u8, quote: seclang.lexer.Quote) []const u8 {
    if (raw.len < 2) return raw;
    return switch (quote) {
        .single => if (raw[0] == '\'' and raw[raw.len - 1] == '\'') raw[1 .. raw.len - 1] else raw,
        .double => if (raw[0] == '"' and raw[raw.len - 1] == '"') raw[1 .. raw.len - 1] else raw,
        else => raw,
    };
}

fn enumValue(value: []const u8, allowed: []const []const u8) bool {
    for (allowed) |candidate| if (std.ascii.eqlIgnoreCase(value, candidate)) return true;
    return false;
}

fn validateUnsigned(id: Id, value: []const u8) bool {
    const parsed = parseUnsigned(value) orelse return false;
    return switch (id) {
        .sec_debug_log_level => parsed <= 9,
        else => true,
    };
}

fn parseUnsigned(value: []const u8) ?u64 {
    if (value.len == 0) return null;
    var parsed: u64 = 0;
    for (value) |byte| {
        if (!std.ascii.isDigit(byte)) return null;
        parsed = std.math.mul(u64, parsed, 10) catch return null;
        parsed = std.math.add(u64, parsed, byte - '0') catch return null;
    }
    return parsed;
}

fn parseOctalMode(value: []const u8) ?u16 {
    if (value.len == 0 or value.len > 4) return null;
    var parsed: u16 = 0;
    for (value) |byte| {
        if (byte < '0' or byte > '7') return null;
        parsed = std.math.mul(u16, parsed, 8) catch return null;
        parsed = std.math.add(u16, parsed, byte - '0') catch return null;
    }
    if (parsed > 0o7777) return null;
    return parsed;
}

fn validAuditParts(value: []const u8) bool {
    var saw_part = false;
    for (value) |byte| {
        if (byte == '+' or byte == '-') continue;
        if (!std.ascii.isAlphabetic(byte)) return false;
        saw_part = true;
    }
    return saw_part;
}

fn decodeValue(schema: Schema, index: usize, value: []const u8) Value {
    _ = index;
    return switch (schema) {
        .toggle => .{ .toggle = std.ascii.eqlIgnoreCase(value, "On") },
        .rule_engine => .{ .rule_engine = if (std.ascii.eqlIgnoreCase(value, "On"))
            .on
        else if (std.ascii.eqlIgnoreCase(value, "Off"))
            .off
        else
            .detection_only },
        .connection_engine => .{ .connection_engine = if (std.ascii.eqlIgnoreCase(value, "On")) .on else .off },
        .unsigned => .{ .unsigned = parseUnsigned(value).? },
        .limit_action => .{ .limit_action = if (std.ascii.eqlIgnoreCase(value, "Reject")) .reject else .process_partial },
        .byte_separator => .{ .byte_separator = value[0] },
        .cookie_format => .{ .cookie_format = if (value[0] == '1') 1 else 0 },
        .audit_engine => .{ .audit_engine = if (std.ascii.eqlIgnoreCase(value, "On"))
            .on
        else if (std.ascii.eqlIgnoreCase(value, "Off"))
            .off
        else
            .relevant_only },
        .audit_log_type => .{ .audit_log_type = if (std.ascii.eqlIgnoreCase(value, "Serial"))
            .serial
        else if (std.ascii.eqlIgnoreCase(value, "Concurrent"))
            .concurrent
        else
            .https },
        .audit_log_format => .{ .audit_log_format = if (std.ascii.eqlIgnoreCase(value, "Native")) .native else .json },
        .audit_parts => .{ .audit_parts = value },
        .octal_mode => .{ .octal_mode = parseOctalMode(value).? },
        .upload_keep_files => .{ .upload_keep_files = if (std.ascii.eqlIgnoreCase(value, "On"))
            .on
        else if (std.ascii.eqlIgnoreCase(value, "Off"))
            .off
        else
            .relevant_only },
        .remote_fail_action => .{ .remote_fail_action = if (std.ascii.eqlIgnoreCase(value, "Abort")) .abort else .warn },
        .rule,
        .action,
        .default_action,
        .marker,
        .text,
        .mime_type,
        .path,
        .regex,
        .id_ranges,
        .rule_update,
        .remote_rules,
        .dataset,
        .hash_parameter,
        .unicode_map,
        => .{ .text = value },
        .clear => unreachable,
    };
}

fn computeConfigurationFingerprint(configuration: *const Configuration) Fingerprint {
    var hasher = std.crypto.hash.Blake3.init(.{});
    hasher.update("zig-waf typed directive configuration\x00");
    for (registry) |entry| {
        hashByte(&hasher, @backingInt(entry.id));
        if (entry.repeatability == .append) {
            var count: u32 = 0;
            var counter = configuration.occurrences(entry.id);
            while (counter.next() != null) count += 1;
            hashU32(&hasher, count);
            var occurrences = configuration.occurrences(entry.id);
            while (occurrences.next()) |directive| hashDecodedDirective(&hasher, directive);
        } else if (configuration.latest(entry.id)) |directive| {
            hashByte(&hasher, 1);
            hashDecodedDirective(&hasher, directive);
        } else {
            hashByte(&hasher, 0);
        }
    }
    var result: Fingerprint = undefined;
    hasher.final(&result);
    return result;
}

fn hashDecodedDirective(hasher: *std.crypto.hash.Blake3, directive: DecodedDirective) void {
    hashByte(hasher, @backingInt(directive.entry.id));
    hashU32(hasher, directive.directive.arguments_count);
    if (directive.entry.sensitive) {
        hasher.update("<redacted>");
        return;
    }
    var values = directive.values();
    while (values.next()) |value| hashDecodedValue(hasher, value.value);
}

fn hashDecodedValue(hasher: *std.crypto.hash.Blake3, value: Value) void {
    hashByte(hasher, @backingInt(std.meta.activeTag(value)));
    switch (value) {
        .text => |bytes| hashBytes(hasher, bytes),
        .toggle => |enabled| hashByte(hasher, @intFromBool(enabled)),
        .rule_engine => |item| hashByte(hasher, @backingInt(item)),
        .connection_engine => |item| hashByte(hasher, @backingInt(item)),
        .unsigned => |item| hashU64(hasher, item),
        .limit_action => |item| hashByte(hasher, @backingInt(item)),
        .byte_separator => |item| hashByte(hasher, item),
        .cookie_format => |item| hashByte(hasher, item),
        .audit_engine => |item| hashByte(hasher, @backingInt(item)),
        .audit_log_type => |item| hashByte(hasher, @backingInt(item)),
        .audit_log_format => |item| hashByte(hasher, @backingInt(item)),
        .audit_parts => |bytes| hashBytes(hasher, bytes),
        .octal_mode => |item| hashU16(hasher, item),
        .upload_keep_files => |item| hashByte(hasher, @backingInt(item)),
        .remote_fail_action => |item| hashByte(hasher, @backingInt(item)),
    }
}

fn hashBytes(hasher: *std.crypto.hash.Blake3, value: []const u8) void {
    hashU32(hasher, @intCast(value.len));
    hasher.update(value);
}

fn hashByte(hasher: *std.crypto.hash.Blake3, value: u8) void {
    hasher.update(&.{value});
}

fn hashU16(hasher: *std.crypto.hash.Blake3, value: u16) void {
    var bytes: [2]u8 = undefined;
    std.mem.writeInt(u16, &bytes, value, .little);
    hasher.update(&bytes);
}

fn hashU32(hasher: *std.crypto.hash.Blake3, value: u32) void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, value, .little);
    hasher.update(&bytes);
}

fn hashU64(hasher: *std.crypto.hash.Blake3, value: u64) void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, value, .little);
    hasher.update(&bytes);
}

test "stable union has one canonical case insensitive entry per id" {
    try std.testing.expectEqual(std.meta.fieldNames(Id).len, registry.len);
    try std.testing.expectEqual(@as(usize, 86), registry.len);
    for (registry, 0..) |entry, index| {
        try std.testing.expectEqual(index, @backingInt(entry.id));
        try std.testing.expectEqual(entry.id, lookup(entry.name).?.id);
        var lowered: [64]u8 = undefined;
        try std.testing.expect(entry.name.len <= lowered.len);
        const lower = lowered[0..entry.name.len];
        for (entry.name, lower) |byte, *destination| destination.* = std.ascii.toLower(byte);
        try std.testing.expectEqual(entry.id, lookup(lower).?.id);
        try std.testing.expect(entry.owner_issue > 0);
        for (registry[0..index]) |prior| try std.testing.expect(!std.ascii.eqlIgnoreCase(prior.name, entry.name));
    }
    try std.testing.expect(lookup("SecDefinitelyUnknown") == null);
}

test "capability and secrecy metadata are explicit" {
    const core = CapabilitySet.coreOnly();
    try std.testing.expect(core.has(.core));
    try std.testing.expect(!core.has(.remote_rules));
    try std.testing.expect(CapabilitySet.full().has(.remote_rules));
    try std.testing.expect(lookup("SecRemoteRules").?.sensitive);
    try std.testing.expect(lookup("SecHashKey").?.sensitive);
    try std.testing.expect(lookup("SecHttpBlKey").?.sensitive);
    try std.testing.expect(!lookup("SecRuleEngine").?.sensitive);
}

test "plan validation recognizes the union and decodes strict scalar schemas" {
    const input =
        \\SecRuleEngine DetectionOnly
        \\SecRequestBodyAccess On
        \\SecRequestBodyLimit 1048576
        \\SecResponseBodyMimeTypesClear
        \\SecResponseBodyMimeType application/json text/plain text/html
        \\SecAuditEngine RelevantOnly
        \\SecAuditLogType Concurrent
        \\SecAuditLogFormat JSON
        \\SecAuditLogParts ABIJDEFHZ
        \\SecAuditLogFileMode 0640
        \\SecRemoteRulesFailAction Warn
        \\SecRule ARGS "@contains attack" "id:1,deny"
    ;
    const compiled = try compileTestPlan(input);
    defer compiled.deinit();
    try std.testing.expectEqual(ValidationOutcome.valid, validatePlan(compiled, .full()));
}

test "reduced builds reject unavailable directives before publication" {
    const compiled = try compileTestPlan("SecAuditEngine On");
    defer compiled.deinit();
    const outcome = validatePlan(compiled, .coreOnly());
    try std.testing.expectEqual(DiagnosticCode.unavailable_capability, outcome.diagnostic.code);
    try std.testing.expectEqual(Id.sec_audit_engine, outcome.diagnostic.directive.?);
    try std.testing.expectEqualStrings("WAF-DIRECTIVE-0102", outcome.diagnostic.code.id());
}

test "unknown directives and malformed values have stable non-echoing diagnostics" {
    const unknown = try compileTestPlan("SecMystery enabled");
    defer unknown.deinit();
    try std.testing.expectEqual(DiagnosticCode.unknown_directive, validatePlan(unknown, .full()).diagnostic.code);

    const malformed = try compileTestPlan("SecRequestBodyLimit 1MiB");
    defer malformed.deinit();
    try std.testing.expectEqual(DiagnosticCode.invalid_value, validatePlan(malformed, .full()).diagnostic.code);

    const secret = try compileTestPlan("SecHashKey \"\"");
    defer secret.deinit();
    const secret_failure = validatePlan(secret, .full()).diagnostic;
    try std.testing.expect(secret_failure.sensitive);
    try std.testing.expect(std.mem.indexOf(u8, secret_failure.message, "HashKey") == null);
}

test "strict enum arity debug and file mode validation rejects malformed input" {
    const cases = [_][]const u8{
        "SecRuleEngine Enabled",
        "SecResponseBodyMimeTypesClear unexpected",
        "SecDebugLogLevel 10",
        "SecAuditLogFileMode 0680",
        "SecRemoteRules only-one-argument",
    };
    for (cases) |input| {
        const compiled = try compileTestPlan(input);
        defer compiled.deinit();
        switch (validatePlan(compiled, .full())) {
            .valid => return error.TestExpectedEqual,
            .diagnostic => {},
        }
    }
}

test "typed configuration preserves order and exposes normalized effective values" {
    const compiled = try compileTestPlan(
        \\SecRuleEngine Off
        \\SecRuleEngine ON
        \\SecRequestBodyLimit 1048576
        \\SecAuditLogFileMode 0640
        \\SecResponseBodyMimeType application/json text/plain
        \\SecResponseBodyMimeType text/html
    );
    defer compiled.deinit();
    var configuration = Configuration.init(compiled, .full()).configuration;

    var rule_engine_values = configuration.latest(.sec_rule_engine).?.values();
    try std.testing.expectEqual(RuleEngine.on, rule_engine_values.next().?.value.rule_engine);
    try std.testing.expect(rule_engine_values.next() == null);
    var body_limit_values = configuration.latest(.sec_request_body_limit).?.values();
    try std.testing.expectEqual(@as(u64, 1_048_576), body_limit_values.next().?.value.unsigned);
    var file_mode_values = configuration.latest(.sec_audit_log_file_mode).?.values();
    try std.testing.expectEqual(@as(u16, 0o640), file_mode_values.next().?.value.octal_mode);

    var mime_occurrences = configuration.occurrences(.sec_response_body_mime_type);
    var mime_count: usize = 0;
    while (mime_occurrences.next()) |occurrence| {
        var values = occurrence.values();
        while (values.next()) |_| mime_count += 1;
    }
    try std.testing.expectEqual(@as(usize, 3), mime_count);
}

test "configuration fingerprints normalize enums and replacement while excluding secrets" {
    const first_plan = try compileTestPlan(
        \\SecRuleEngine Off
        \\SecRuleEngine ON
        \\SecHashKey first-secret
    );
    defer first_plan.deinit();
    const second_plan = try compileTestPlan(
        \\SecRuleEngine on
        \\SecHashKey second-secret
    );
    defer second_plan.deinit();
    const first = Configuration.init(first_plan, .full()).configuration;
    const second = Configuration.init(second_plan, .full()).configuration;
    try std.testing.expectEqualSlices(u8, &first.fingerprint, &second.fingerprint);

    const changed_plan = try compileTestPlan(
        \\SecRuleEngine DetectionOnly
        \\SecHashKey second-secret
    );
    defer changed_plan.deinit();
    const changed = Configuration.init(changed_plan, .full()).configuration;
    try std.testing.expect(!std.mem.eql(u8, &first.fingerprint, &changed.fingerprint));
}

fn compileTestPlan(input: []const u8) !*plan_mod.Plan {
    var parsed = try seclang.parser.parseBytes(std.testing.allocator, "directives.conf", input, .{}, .{});
    defer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};
    return plan_mod.compile(std.testing.allocator, &parsed.registry, &documents, .{});
}
