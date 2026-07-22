#ifndef ZIG_WAF_H
#define ZIG_WAF_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZIG_WAF_ABI_VERSION 0x00010000u

typedef struct zig_waf zig_waf_t;
typedef struct zig_waf_transaction zig_waf_transaction_t;

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

enum zig_waf_feature_bit {
    ZIG_WAF_FEATURE_TRANSACTION_LIFECYCLE = UINT64_C(1) << 0,
    ZIG_WAF_FEATURE_BOUNDED_STREAMING_BODIES = UINT64_C(1) << 1,
    ZIG_WAF_FEATURE_DETECTION_ONLY = UINT64_C(1) << 2,
    ZIG_WAF_FEATURE_NATIVE_SQLI = UINT64_C(1) << 3,
    ZIG_WAF_FEATURE_SCALAR_VARIABLES = UINT64_C(1) << 4,
    ZIG_WAF_FEATURE_ATOMIC_HOT_RELOAD = UINT64_C(1) << 5
};

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
    uint64_t reserved[8];
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

uint32_t zig_waf_abi_version(void);
zig_waf_status_t zig_waf_query_features(zig_waf_features_t *out_features);
zig_waf_status_t zig_waf_create(const zig_waf_config_t *config, zig_waf_t **out_waf);
zig_waf_status_t zig_waf_destroy(zig_waf_t *waf);

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
zig_waf_status_t zig_waf_transaction_intervention(
    const zig_waf_transaction_t *transaction,
    zig_waf_intervention_t *out_intervention);

#ifdef __cplusplus
}
#endif

#endif
