/* zig-waf through its C ABI, the way a connector embeds it. */
#include "lab.h"
#include "zig_waf.h"

#ifndef ZIG_WAF_LAB_VERSION
#define ZIG_WAF_LAB_VERSION "unknown"
#endif

#define S(x) (const uint8_t *)(x), strlen(x)

static void *create(const char *rules, size_t rules_len, const char *rules_path, const char *data_dir) {
    (void)rules_path;
    zig_waf_config_t config = {0};
    config.struct_size = sizeof(config);
    config.abi_version = ZIG_WAF_ABI_VERSION;
    config.mode = ZIG_WAF_MODE_ENABLED;
    /* The same limits the base configuration gives the other engines. */
    config.max_request_target_bytes = 8192;
    config.max_header_count = 64;
    config.max_header_bytes = 16384;
    config.max_request_body_bytes = 131072;
    config.max_response_body_bytes = 131072;
    zig_waf_t *waf = NULL;
    zig_waf_status_t status = zig_waf_create_with_rules_at(
        &config, (const uint8_t *)rules, rules_len, S(data_dir), &waf);
    if (status != ZIG_WAF_OK) {
        fprintf(stderr, "zig-waf: rules did not compile (status %d)\n", (int)status);
        return NULL;
    }
    return waf;
}

static int inspect(void *engine, const lab_request *r) {
    zig_waf_transaction_t *tx = NULL;
    if (zig_waf_transaction_create(engine, &tx) != ZIG_WAF_OK) return -1;
    int verdict = -1;
    if (zig_waf_transaction_process_connection(tx, S("203.0.113.7"), 51234, S("198.51.100.1"), 443) != ZIG_WAF_OK) goto done;
    if (zig_waf_transaction_process_uri(tx, S(r->uri), S(r->method), S(r->protocol)) != ZIG_WAF_OK) goto done;
    for (size_t i = 0; i < r->header_count; i++) {
        const lab_header *h = &r->headers[i];
        if (zig_waf_transaction_add_request_header(tx, (const uint8_t *)h->name, h->name_len,
                (const uint8_t *)h->value, h->value_len) != ZIG_WAF_OK)
            goto done;
    }
    if (zig_waf_transaction_process_request_headers(tx) != ZIG_WAF_OK) goto done;
    if (zig_waf_transaction_evaluate_phase(tx, 1) != ZIG_WAF_OK) goto done;

    zig_waf_intervention_t decision = {0};
    decision.struct_size = sizeof(decision);
    decision.abi_version = ZIG_WAF_ABI_VERSION;
    zig_waf_status_t found = zig_waf_transaction_intervention(tx, &decision);
    if (found == ZIG_WAF_OK && decision.enforced) {
        verdict = 1;
        goto done;
    }

    if (r->body_len && zig_waf_transaction_write_request_body(tx, r->body, r->body_len) != ZIG_WAF_OK) goto done;
    if (zig_waf_transaction_process_request_body(tx) != ZIG_WAF_OK) goto done;
    if (zig_waf_transaction_evaluate_phase(tx, 2) != ZIG_WAF_OK) goto done;
    found = zig_waf_transaction_intervention(tx, &decision);
    if (found == ZIG_WAF_OK) verdict = decision.enforced ? 1 : 0;
    else if (found == ZIG_WAF_ERROR_NOT_FOUND) verdict = 0;

done:
    zig_waf_transaction_destroy(tx);
    return verdict;
}

static void destroy(void *engine) { zig_waf_destroy(engine); }

int main(int argc, char **argv) {
    static const lab_engine engine = {
        .name = "zig-waf",
        .version = ZIG_WAF_LAB_VERSION,
        .create = create,
        .inspect = inspect,
        .destroy = destroy,
    };
    return lab_main(argc, argv, &engine);
}
