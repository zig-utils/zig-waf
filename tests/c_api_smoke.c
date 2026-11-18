#include "zig_waf.h"

#include <assert.h>
#include <string.h>

/* A host operator standing in for a scanner: it records what the engine asked
 * and answers whatever the test sets. */
struct recorder {
    zig_waf_operator_outcome_t answer;
    int calls;
    char parameter[64];
    size_t parameter_len;
    char input[64];
    size_t input_len;
};

static zig_waf_operator_outcome_t record(
    void *context,
    const uint8_t *parameter,
    size_t parameter_len,
    const uint8_t *input,
    size_t input_len) {
    struct recorder *self = (struct recorder *)context;
    self->calls += 1;
    self->parameter_len = parameter_len < sizeof(self->parameter) ? parameter_len : sizeof(self->parameter);
    if (self->parameter_len != 0) memcpy(self->parameter, parameter, self->parameter_len);
    self->input_len = input_len < sizeof(self->input) ? input_len : sizeof(self->input);
    if (self->input_len != 0) memcpy(self->input, input, self->input_len);
    return self->answer;
}

/* Run GET uri through phase 1; returns the intervention status (0 if none) and
 * stores the transaction's unavailable count. */
static uint16_t run_request(zig_waf_t *waf, const char *uri, uint64_t *unavailable) {
    const char ip[] = "127.0.0.1";
    const char method[] = "GET";
    const char protocol[] = "HTTP/1.1";
    zig_waf_transaction_t *tx = NULL;
    assert(zig_waf_transaction_create(waf, &tx) == ZIG_WAF_OK);
    assert(zig_waf_transaction_process_connection(tx, (const uint8_t *)ip, strlen(ip), 1,
                                                  (const uint8_t *)ip, strlen(ip), 80) == ZIG_WAF_OK);
    assert(zig_waf_transaction_process_uri(tx, (const uint8_t *)uri, strlen(uri),
                                           (const uint8_t *)method, strlen(method),
                                           (const uint8_t *)protocol, strlen(protocol)) == ZIG_WAF_OK);
    assert(zig_waf_transaction_process_request_headers(tx) == ZIG_WAF_OK);
    assert(zig_waf_transaction_evaluate_phase(tx, ZIG_WAF_PHASE_REQUEST_HEADERS) == ZIG_WAF_OK);
    zig_waf_intervention_t decision = {0};
    decision.struct_size = sizeof(decision);
    decision.abi_version = ZIG_WAF_ABI_VERSION;
    uint16_t status = 0;
    zig_waf_status_t found = zig_waf_transaction_intervention(tx, &decision);
    if (found == ZIG_WAF_OK) status = decision.status;
    else assert(found == ZIG_WAF_ERROR_NOT_FOUND);
    assert(zig_waf_transaction_plugin_unavailable_count(tx, unavailable) == ZIG_WAF_OK);
    zig_waf_transaction_destroy(tx);
    return status;
}

int main(void) {
    assert(zig_waf_abi_version() == ZIG_WAF_ABI_VERSION);

    zig_waf_features_t features = {0};
    features.struct_size = sizeof(features);
    features.abi_version = ZIG_WAF_ABI_VERSION;
    assert(zig_waf_query_features(&features) == ZIG_WAF_OK);
    assert((features.feature_bits & ZIG_WAF_FEATURE_TRANSACTION_LIFECYCLE) != 0);
    assert((features.feature_bits & ZIG_WAF_FEATURE_SCALAR_VARIABLES) != 0);
    assert((features.feature_bits & ZIG_WAF_FEATURE_ATOMIC_HOT_RELOAD) != 0);
    /* The header names every bit the library reports, and reports every bit the
     * header names: a bit published at the wrong position would otherwise test a
     * different feature than the one its name promises. */
    assert(features.feature_bits == ZIG_WAF_FEATURE_KNOWN_BITS);
    assert(features.highest_phase == ZIG_WAF_PHASE_LOGGING);

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
    /* Evaluate the request-headers phase (no rules loaded → no intervention). */
    assert(zig_waf_transaction_evaluate_phase(transaction, ZIG_WAF_PHASE_REQUEST_HEADERS) == ZIG_WAF_OK);
    assert(zig_waf_transaction_evaluate_phase(transaction, 99) == ZIG_WAF_ERROR_INVALID_ARGUMENT);
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

    /* Serialize the audit record over the ABI and release it. */
    uint8_t *audit = NULL;
    size_t audit_len = 0;
    assert(zig_waf_transaction_serialize_audit_log(transaction, 0, &audit, &audit_len) == ZIG_WAF_OK);
    assert(audit != NULL && audit_len > 0);
    /* The serial format opens with the section-A boundary marker. */
    assert(strncmp((const char *)audit, "--", 2) == 0);
    zig_waf_free(audit, audit_len);
    /* An unknown format id is rejected. */
    assert(zig_waf_transaction_serialize_audit_log(transaction, 99, &audit, &audit_len) == ZIG_WAF_ERROR_INVALID_ARGUMENT);

    zig_waf_transaction_destroy(transaction);
    assert(zig_waf_destroy(waf) == ZIG_WAF_OK);

    /* Full flow: a WAF with rules blocks a matching request over the ABI. */
    const char rules[] =
        "SecRule ARGS \"@rx attack\" \"id:1,phase:1,deny,status:403\"\n";
    zig_waf_t *rwaf = NULL;
    assert(zig_waf_create_with_rules(&config, (const uint8_t *)rules, strlen(rules), &rwaf) == ZIG_WAF_OK);
    zig_waf_transaction_t *rtx = NULL;
    assert(zig_waf_transaction_create(rwaf, &rtx) == ZIG_WAF_OK);
    assert(zig_waf_transaction_process_connection(rtx, (const uint8_t *)client, strlen(client), 1,
                                                  (const uint8_t *)server, strlen(server), 80) == ZIG_WAF_OK);
    const char attack_uri[] = "/p?q=attack-here";
    assert(zig_waf_transaction_process_uri(rtx, (const uint8_t *)attack_uri, strlen(attack_uri),
                                           (const uint8_t *)method, strlen(method),
                                           (const uint8_t *)protocol, strlen(protocol)) == ZIG_WAF_OK);
    assert(zig_waf_transaction_process_request_headers(rtx) == ZIG_WAF_OK);
    assert(zig_waf_transaction_evaluate_phase(rtx, ZIG_WAF_PHASE_REQUEST_HEADERS) == ZIG_WAF_OK);
    zig_waf_intervention_t decision = {0};
    decision.struct_size = sizeof(decision);
    decision.abi_version = ZIG_WAF_ABI_VERSION;
    assert(zig_waf_transaction_intervention(rtx, &decision) == ZIG_WAF_OK);
    assert(decision.status == 403);
    zig_waf_transaction_destroy(rtx);
    assert(zig_waf_destroy(rwaf) == ZIG_WAF_OK);

    /* An invalid config is rejected. */
    const char bad[] = "SecRule ARGS \"@rx x\" \"id:1,phase:99\"\n";
    zig_waf_t *bwaf = NULL;
    assert(zig_waf_create_with_rules(&config, (const uint8_t *)bad, strlen(bad), &bwaf) == ZIG_WAF_ERROR_INVALID_CONFIG);

    /* Host operators (ABI 1.1). */
    assert((features.feature_bits & ZIG_WAF_FEATURE_PLUGIN_OPERATORS) != 0);
    const char scan_rules[] =
        "SecRule ARGS:file \"@inspectFile mail-profile\" \"id:20,phase:1,deny,status:403,t:lowercase\"\n";
    config.mode = ZIG_WAF_MODE_ENABLED;

    /* With no operator registered, a rule naming one does not compile. */
    zig_waf_t *unregistered = NULL;
    assert(zig_waf_create_with_rules(&config, (const uint8_t *)scan_rules, strlen(scan_rules), &unregistered) ==
           ZIG_WAF_ERROR_INVALID_CONFIG);

    struct recorder scanner = {0};
    scanner.answer = ZIG_WAF_OPERATOR_MATCH;
    zig_waf_plugins_t *plugins = NULL;
    assert(zig_waf_plugins_create(&plugins) == ZIG_WAF_OK);
    const char operator_name[] = "inspectFile";
    assert(zig_waf_register_operator(plugins, (const uint8_t *)operator_name, strlen(operator_name), &scanner, record) ==
           ZIG_WAF_OK);
    assert(zig_waf_register_operator(plugins, (const uint8_t *)operator_name, strlen(operator_name), &scanner, record) ==
           ZIG_WAF_ERROR_INVALID_ARGUMENT);
    assert(zig_waf_register_operator(plugins, (const uint8_t *)operator_name, strlen(operator_name), &scanner, NULL) ==
           ZIG_WAF_ERROR_INVALID_ARGUMENT);

    /* Registered on a set the config does not name, it still does not compile. */
    assert(zig_waf_create_with_rules(&config, (const uint8_t *)scan_rules, strlen(scan_rules), &unregistered) ==
           ZIG_WAF_ERROR_INVALID_CONFIG);

    config.plugins = plugins;
    zig_waf_t *swaf = NULL;
    assert(zig_waf_create_with_rules(&config, (const uint8_t *)scan_rules, strlen(scan_rules), &swaf) == ZIG_WAF_OK);
    /* The WAF copied the registration; the set is no longer needed. */
    zig_waf_plugins_destroy(plugins);
    config.plugins = NULL;

    uint64_t unavailable = 99;
    assert(run_request(swaf, "/upload?file=EICAR.COM", &unavailable) == 403);
    assert(unavailable == 0);
    assert(scanner.calls == 1);
    assert(scanner.parameter_len == strlen("mail-profile"));
    assert(memcmp(scanner.parameter, "mail-profile", scanner.parameter_len) == 0);
    /* The operator sees the value after the rule's transformations. */
    assert(scanner.input_len == strlen("eicar.com"));
    assert(memcmp(scanner.input, "eicar.com", scanner.input_len) == 0);

    scanner.answer = ZIG_WAF_OPERATOR_NO_MATCH;
    assert(run_request(swaf, "/upload?file=notes.txt", &unavailable) == 0);
    assert(unavailable == 0);

    /* A scanner that cannot answer does not block, and is counted, so the
     * connector can tell an unscanned request from a clean one. */
    scanner.answer = ZIG_WAF_OPERATOR_UNAVAILABLE;
    assert(run_request(swaf, "/upload?file=EICAR.COM", &unavailable) == 0);
    assert(unavailable == 1);
    assert(scanner.calls == 3);

    assert(zig_waf_destroy(swaf) == ZIG_WAF_OK);

    return 0;
}
