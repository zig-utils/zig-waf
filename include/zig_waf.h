#ifndef ZIG_WAF_H
#define ZIG_WAF_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 1.1: host operator registration, zig_waf_config_t.plugins, and
 * zig_waf_transaction_plugin_unavailable_count. */
#define ZIG_WAF_ABI_VERSION 0x00010001u

typedef struct zig_waf zig_waf_t;
typedef struct zig_waf_transaction zig_waf_transaction_t;
typedef struct zig_waf_plugins zig_waf_plugins_t;

typedef enum zig_waf_status {
    ZIG_WAF_OK = 0,
    ZIG_WAF_ERROR_INVALID_ARGUMENT = 1,
    ZIG_WAF_ERROR_UNSUPPORTED_ABI = 2,
    ZIG_WAF_ERROR_OUT_OF_MEMORY = 3,
    ZIG_WAF_ERROR_INVALID_CONFIG = 4,
    ZIG_WAF_ERROR_INVALID_LIFECYCLE = 5,
    ZIG_WAF_ERROR_LIMIT_EXCEEDED = 6,
    ZIG_WAF_ERROR_BUSY = 7,
    ZIG_WAF_ERROR_NOT_FOUND = 8,
    ZIG_WAF_ERROR_INTERNAL = 255
} zig_waf_status_t;

typedef enum zig_waf_mode {
    ZIG_WAF_MODE_ENABLED = 0,
    ZIG_WAF_MODE_DETECTION_ONLY = 1
} zig_waf_mode_t;

typedef enum zig_waf_action {
    ZIG_WAF_ACTION_DENY = 0,
    ZIG_WAF_ACTION_REDIRECT = 1,
    ZIG_WAF_ACTION_DROP = 2,
    ZIG_WAF_ACTION_PAUSE = 3
} zig_waf_action_t;

typedef enum zig_waf_phase {
    ZIG_WAF_PHASE_REQUEST_HEADERS = 1,
    ZIG_WAF_PHASE_REQUEST_BODY = 2,
    ZIG_WAF_PHASE_RESPONSE_HEADERS = 3,
    ZIG_WAF_PHASE_RESPONSE_BODY = 4,
    ZIG_WAF_PHASE_LOGGING = 5
} zig_waf_phase_t;

enum zig_waf_feature_bit {
    ZIG_WAF_FEATURE_TRANSACTION_LIFECYCLE = UINT64_C(1) << 0,
    ZIG_WAF_FEATURE_BOUNDED_STREAMING_BODIES = UINT64_C(1) << 1,
    ZIG_WAF_FEATURE_DETECTION_ONLY = UINT64_C(1) << 2,
    ZIG_WAF_FEATURE_NATIVE_SQLI = UINT64_C(1) << 3,
    ZIG_WAF_FEATURE_SCALAR_VARIABLES = UINT64_C(1) << 4,
    ZIG_WAF_FEATURE_COLLECTION_VARIABLES = UINT64_C(1) << 5,
    ZIG_WAF_FEATURE_RUNTIME_MACROS = UINT64_C(1) << 6,
    ZIG_WAF_FEATURE_PERSISTENT_COLLECTIONS = UINT64_C(1) << 7,
    ZIG_WAF_FEATURE_ATOMIC_HOT_RELOAD = UINT64_C(1) << 8,
    ZIG_WAF_FEATURE_COMPILED_EXECUTION_PLAN = UINT64_C(1) << 9,
    ZIG_WAF_FEATURE_TRANSFORMATION_EXECUTION = UINT64_C(1) << 10,
    ZIG_WAF_FEATURE_PLUGIN_OPERATORS = UINT64_C(1) << 11
};

/* Every bit the library can report. A bit outside this mask is one this header
 * predates: ignore it rather than guess what it means. */
#define ZIG_WAF_FEATURE_KNOWN_BITS ( \
    ZIG_WAF_FEATURE_TRANSACTION_LIFECYCLE | ZIG_WAF_FEATURE_BOUNDED_STREAMING_BODIES | \
    ZIG_WAF_FEATURE_DETECTION_ONLY | ZIG_WAF_FEATURE_NATIVE_SQLI | \
    ZIG_WAF_FEATURE_SCALAR_VARIABLES | ZIG_WAF_FEATURE_COLLECTION_VARIABLES | \
    ZIG_WAF_FEATURE_RUNTIME_MACROS | ZIG_WAF_FEATURE_PERSISTENT_COLLECTIONS | \
    ZIG_WAF_FEATURE_ATOMIC_HOT_RELOAD | ZIG_WAF_FEATURE_COMPILED_EXECUTION_PLAN | \
    ZIG_WAF_FEATURE_TRANSFORMATION_EXECUTION | ZIG_WAF_FEATURE_PLUGIN_OPERATORS)

typedef struct zig_waf_config {
    uint32_t struct_size;
    uint32_t abi_version;
    uint32_t mode;
    uint32_t reserved0;
    size_t max_request_target_bytes;
    size_t max_header_count;
    size_t max_header_bytes;
    size_t max_request_body_bytes;
    size_t max_response_body_bytes;
    /* ABI 1.1: host operators the rule compiler may resolve, or NULL. Read only
     * when abi_version is 1.1 or later; it occupies what was reserved[0]. */
    const zig_waf_plugins_t *plugins;
    uint64_t reserved[7];
} zig_waf_config_t;

typedef struct zig_waf_features {
    uint32_t struct_size;
    uint32_t abi_version;
    uint64_t feature_bits;
    uint32_t highest_phase;
    uint32_t reserved0;
    uint64_t reserved[4];
} zig_waf_features_t;

typedef struct zig_waf_intervention {
    uint32_t struct_size;
    uint32_t abi_version;
    uint32_t action;
    uint16_t status;
    uint8_t enforced;
    uint8_t has_rule_id;
    uint32_t rule_id;
    uint64_t reserved[4];
} zig_waf_intervention_t;

/* What a host operator answers. Any other value is treated as UNAVAILABLE. */
typedef enum zig_waf_operator_outcome {
    ZIG_WAF_OPERATOR_NO_MATCH = 0,
    ZIG_WAF_OPERATOR_MATCH = 1,
    ZIG_WAF_OPERATOR_UNAVAILABLE = 2
} zig_waf_operator_outcome_t;

/* A host operator. parameter is the rule's operator argument after macro
 * expansion, input the transformed value under inspection; both are borrowed
 * for the call only, and a pointer whose length is 0 must not be read.
 *
 * It runs on the request path and must not block: no file, socket or process
 * work. Answer from state maintained elsewhere, and return UNAVAILABLE when that
 * state cannot answer. UNAVAILABLE does not match but is counted (see
 * zig_waf_transaction_plugin_unavailable_count), because an operator that could
 * not run is not an input found clean. It may run concurrently on several
 * threads. */
typedef zig_waf_operator_outcome_t (*zig_waf_operator_fn)(
    void *context,
    const uint8_t *parameter,
    size_t parameter_len,
    const uint8_t *input,
    size_t input_len);

uint32_t zig_waf_abi_version(void);
zig_waf_status_t zig_waf_query_features(zig_waf_features_t *out_features);
zig_waf_status_t zig_waf_create(const zig_waf_config_t *config, zig_waf_t **out_waf);

/* Create a WAF whose rule set is compiled from a SecLang configuration.
 * Returns ZIG_WAF_ERROR_INVALID_CONFIG on a parse/compile error. */
zig_waf_status_t zig_waf_create_with_rules(
    const zig_waf_config_t *config,
    const uint8_t *rules,
    size_t rules_len,
    zig_waf_t **out_waf);

/* Like zig_waf_create_with_rules, but resolves @pmFromFile / @ipMatchFromFile
 * data files relative to data_dir (SecDataDir semantics), confined to it. */
zig_waf_status_t zig_waf_create_with_rules_at(
    const zig_waf_config_t *config,
    const uint8_t *rules,
    size_t rules_len,
    const uint8_t *data_dir,
    size_t data_dir_len,
    zig_waf_t **out_waf);
zig_waf_status_t zig_waf_destroy(zig_waf_t *waf);

/* Host operators (ABI 1.1). Register into a plugins set, point
 * zig_waf_config_t.plugins at it, and create the WAF: a rule naming a registered
 * operator compiles, and one naming an operator nothing provides still fails
 * with ZIG_WAF_ERROR_INVALID_CONFIG. Each WAF copies the registrations it was
 * created with, so the set may be destroyed or extended afterwards; context and
 * callback must stay valid until every WAF created with them is destroyed.
 *
 * name is letters, digits and underscores, with or without a leading '@', and
 * matched case-insensitively. An invalid name, a NULL callback, or a name
 * already registered returns ZIG_WAF_ERROR_INVALID_ARGUMENT. A plugins set is
 * not thread-safe; build it before sharing the config. */
zig_waf_status_t zig_waf_plugins_create(zig_waf_plugins_t **out_plugins);
void zig_waf_plugins_destroy(zig_waf_plugins_t *plugins);
zig_waf_status_t zig_waf_register_operator(
    zig_waf_plugins_t *plugins,
    const uint8_t *name,
    size_t name_len,
    void *context,
    zig_waf_operator_fn callback);

zig_waf_status_t zig_waf_transaction_create(zig_waf_t *waf, zig_waf_transaction_t **out_transaction);
void zig_waf_transaction_destroy(zig_waf_transaction_t *transaction);
zig_waf_status_t zig_waf_transaction_process_connection(
    zig_waf_transaction_t *transaction,
    const uint8_t *client_address,
    size_t client_address_len,
    uint16_t client_port,
    const uint8_t *server_address,
    size_t server_address_len,
    uint16_t server_port);
zig_waf_status_t zig_waf_transaction_process_uri(
    zig_waf_transaction_t *transaction,
    const uint8_t *uri,
    size_t uri_len,
    const uint8_t *method,
    size_t method_len,
    const uint8_t *protocol,
    size_t protocol_len);
zig_waf_status_t zig_waf_transaction_add_request_header(
    zig_waf_transaction_t *transaction,
    const uint8_t *name,
    size_t name_len,
    const uint8_t *value,
    size_t value_len);
zig_waf_status_t zig_waf_transaction_process_request_headers(zig_waf_transaction_t *transaction);
zig_waf_status_t zig_waf_transaction_write_request_body(
    zig_waf_transaction_t *transaction,
    const uint8_t *chunk,
    size_t chunk_len);
zig_waf_status_t zig_waf_transaction_process_request_body(zig_waf_transaction_t *transaction);
zig_waf_status_t zig_waf_transaction_add_response_header(
    zig_waf_transaction_t *transaction,
    const uint8_t *name,
    size_t name_len,
    const uint8_t *value,
    size_t value_len);
zig_waf_status_t zig_waf_transaction_process_response_headers(
    zig_waf_transaction_t *transaction,
    uint16_t status,
    const uint8_t *protocol,
    size_t protocol_len);
zig_waf_status_t zig_waf_transaction_write_response_body(
    zig_waf_transaction_t *transaction,
    const uint8_t *chunk,
    size_t chunk_len);
zig_waf_status_t zig_waf_transaction_process_response_body(zig_waf_transaction_t *transaction);
zig_waf_status_t zig_waf_transaction_process_logging(zig_waf_transaction_t *transaction);

/* Evaluate every rule in a phase (1=request headers .. 5=logging) against the
 * current transaction state and apply matches; then read the decision with
 * zig_waf_transaction_intervention. */
zig_waf_status_t zig_waf_transaction_evaluate_phase(
    zig_waf_transaction_t *transaction,
    uint32_t phase);
zig_waf_status_t zig_waf_transaction_intervention(
    const zig_waf_transaction_t *transaction,
    zig_waf_intervention_t *out_intervention);

/* How many times a host operator answered UNAVAILABLE in this transaction. */
zig_waf_status_t zig_waf_transaction_plugin_unavailable_count(
    const zig_waf_transaction_t *transaction,
    uint64_t *out_count);

/* Serialize the audit record. format: 0 serial, 1 JSON, 2 legacy JSON, 3 OCSF,
 * or ZIG_WAF_AUDIT_FORMAT_CONFIGURED to use the SecAuditLogFormat directive
 * (defaulting to native/serial). On success out_buffer and out_len describe a
 * buffer the caller must release with zig_waf_free(). */
#define ZIG_WAF_AUDIT_FORMAT_CONFIGURED 0xFFFFFFFFu
zig_waf_status_t zig_waf_transaction_serialize_audit_log(
    zig_waf_transaction_t *transaction,
    uint32_t format,
    uint8_t **out_buffer,
    size_t *out_len);

/* Release a buffer returned by the ABI (e.g. the audit-log serializer). */
void zig_waf_free(uint8_t *pointer, size_t len);

#ifdef __cplusplus
}
#endif

#endif
