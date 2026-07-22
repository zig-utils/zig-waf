//! Canonical stable directive inventory and schema metadata.

const std = @import("std");

pub const Id = enum(u8) {
    sec_rule,
    sec_action,
    sec_default_action,
    sec_marker,
    sec_component_signature,
    sec_rule_engine,
    sec_conn_engine,
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
    sec_unicode_code_page,
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
    row(.sec_web_app_id, "SecWebAppId", .text, .singular_replace, .core, MC, 13),
    row(.sec_server_signature, "SecServerSignature", .text, .singular_replace, .core, MC, 13),
    row(.sec_sensor_id, "SecSensorId", .text, .singular_replace, .core, MC, 13),
    row(.sec_status_engine, "SecStatusEngine", .toggle, .singular_replace, .core, M, 13),
    row(.sec_rule_script, "SecRuleScript", .path, .append, .rule_script, M, 22),

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
    row(.sec_upload_keep_files, "SecUploadKeepFiles", .limit_action, .singular_replace, .upload, MC, 26),
    row(.sec_tmp_save_uploaded_files, "SecTmpSaveUploadedFiles", .toggle, .singular_replace, .upload, M, 26),
    row(.sec_chroot_dir, "SecChrootDir", .path, .singular_replace, .core, M, 72),

    row(.sec_rule_remove_by_id, "SecRuleRemoveById", .id_ranges, .append, .rule_updates, MC, 14),
    row(.sec_rule_remove_by_msg, "SecRuleRemoveByMsg", .regex, .append, .rule_updates, MC, 14),
    row(.sec_rule_remove_by_tag, "SecRuleRemoveByTag", .regex, .append, .rule_updates, MC, 14),
    row(.sec_rule_update_target_by_id, "SecRuleUpdateTargetById", .rule_update, .append, .rule_updates, MC, 14),
    row(.sec_rule_update_target_by_msg, "SecRuleUpdateTargetByMsg", .rule_update, .append, .rule_updates, M, 14),
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
    row(.sec_remote_rules_fail_action, "SecRemoteRulesFailAction", .limit_action, .singular_replace, .remote_rules, MC, 14),
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
    row(.sec_unicode_map_file, "SecUnicodeMapFile", .unicode_map, .singular_replace, .unicode_map, MC, 17),
    row(.sec_unicode_code_page, "SecUnicodeCodePage", .unsigned, .singular_replace, .unicode_map, M, 17),
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

test "stable union has one canonical case insensitive entry per id" {
    try std.testing.expectEqual(std.meta.fieldNames(Id).len, registry.len);
    try std.testing.expectEqual(@as(usize, 85), registry.len);
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
