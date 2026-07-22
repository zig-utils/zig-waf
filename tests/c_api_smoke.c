#include "zig_waf.h"

#include <assert.h>
#include <string.h>

int main(void) {
    assert(zig_waf_abi_version() == ZIG_WAF_ABI_VERSION);

    zig_waf_features_t features = {0};
    features.struct_size = sizeof(features);
    features.abi_version = ZIG_WAF_ABI_VERSION;
    assert(zig_waf_query_features(&features) == ZIG_WAF_OK);
    assert((features.feature_bits & ZIG_WAF_FEATURE_TRANSACTION_LIFECYCLE) != 0);

    zig_waf_config_t config = {0};
    config.struct_size = sizeof(config);
    config.abi_version = ZIG_WAF_ABI_VERSION;
    config.mode = ZIG_WAF_MODE_DETECTION_ONLY;
    config.max_request_target_bytes = 4096;
    config.max_header_count = 32;
    config.max_header_bytes = 8192;
    config.max_request_body_bytes = 1024;
    config.max_response_body_bytes = 1024;

    zig_waf_t *waf = NULL;
    assert(zig_waf_create(&config, &waf) == ZIG_WAF_OK);
    assert(waf != NULL);

    zig_waf_transaction_t *transaction = NULL;
    assert(zig_waf_transaction_create(waf, &transaction) == ZIG_WAF_OK);
    assert(zig_waf_destroy(waf) == ZIG_WAF_ERROR_BUSY);

    const char client[] = "127.0.0.1";
    const char server[] = "127.0.0.1";
    const char uri[] = "/login";
    const char method[] = "POST";
    const char protocol[] = "HTTP/1.1";
    const char header_name[] = "content-type";
    const char header_value[] = "application/json";
    const char body[] = "{}";

    assert(zig_waf_transaction_process_connection(
               transaction,
               (const uint8_t *)client,
               strlen(client),
               12345,
               (const uint8_t *)server,
               strlen(server),
               443) == ZIG_WAF_OK);
    assert(zig_waf_transaction_process_uri(
               transaction,
               (const uint8_t *)uri,
               strlen(uri),
               (const uint8_t *)method,
               strlen(method),
               (const uint8_t *)protocol,
               strlen(protocol)) == ZIG_WAF_OK);
    assert(zig_waf_transaction_add_request_header(
               transaction,
               (const uint8_t *)header_name,
               strlen(header_name),
               (const uint8_t *)header_value,
               strlen(header_value)) == ZIG_WAF_OK);
    assert(zig_waf_transaction_process_request_headers(transaction) == ZIG_WAF_OK);
    assert(zig_waf_transaction_write_request_body(
               transaction,
               (const uint8_t *)body,
               strlen(body)) == ZIG_WAF_OK);
    assert(zig_waf_transaction_process_request_body(transaction) == ZIG_WAF_OK);
    assert(zig_waf_transaction_process_response_headers(
               transaction,
               200,
               (const uint8_t *)protocol,
               strlen(protocol)) == ZIG_WAF_OK);
    assert(zig_waf_transaction_process_logging(transaction) == ZIG_WAF_OK);

    zig_waf_transaction_destroy(transaction);
    assert(zig_waf_destroy(waf) == ZIG_WAF_OK);
    return 0;
}
