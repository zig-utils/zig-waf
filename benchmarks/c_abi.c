/* C ABI benchmark: what a fired rule costs a host that embeds the library.
 *
 * Every other benchmark drives the engine through the Zig API with the caller's
 * allocator, so none of them sees the allocator the C ABI chooses for itself. When
 * that was the page allocator, each of the dozens of small allocations a fired rule
 * makes became an mmap/munmap pair, and an unconditional `pass,nolog` SecAction
 * cost about 100 us (zig-utils/zig-waf#82). Through the Zig API the same rule cost
 * about 1 us, so nothing noticed.
 *
 * This times zig_waf_transaction_evaluate_phase(tx, 1) the way a connector calls
 * it, over a phase made of unconditional SecActions like the initialization rules
 * CRS runs on every request. It reports the cost per transaction and per fired
 * rule, and fails when the per-rule cost exceeds the threshold it is given (0
 * measures without enforcing).
 *
 * A second phase holds rules that inspect and do not match: `@rx` patterns and
 * `@pm` phrase lists over REQUEST_URI, the shape of most of CRS. Their cost is
 * dominated by the operator, and compiling that operator on every evaluation
 * instead of once per WAF made full CRS cost milliseconds per request
 * (zig-utils/zig-waf#83). That cost is gated separately.
 *
 * Usage: c-abi-benchmark [iterations] [max-ns-per-fired-rule] [max-ns-per-inspecting-rule] */

#include "zig_waf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define FIRED_RULES 32
#define INSPECTING_RULES 32
#define WARMUP 200

static uint64_t now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000u + (uint64_t)t.tv_nsec;
}

static zig_waf_t *create(const char *rules) {
    zig_waf_config_t config = {0};
    config.struct_size = sizeof(config);
    config.abi_version = ZIG_WAF_ABI_VERSION;
    config.mode = ZIG_WAF_MODE_ENABLED;
    config.max_request_target_bytes = 4096;
    config.max_header_count = 64;
    config.max_header_bytes = 16384;
    config.max_request_body_bytes = 4096;
    config.max_response_body_bytes = 4096;
    zig_waf_t *waf = NULL;
    if (zig_waf_create_with_rules(&config, (const uint8_t *)rules, strlen(rules), &waf) != ZIG_WAF_OK) {
        fprintf(stderr, "c-abi-benchmark: rule set did not compile\n");
        exit(2);
    }
    return waf;
}

/* Mean nanoseconds spent in evaluate_phase(tx, 1), over `iterations`
 * transactions of a minimal GET, after a warm-up. */
static double phase_one_ns(zig_waf_t *waf, size_t iterations) {
    static const char ip[] = "127.0.0.1", uri[] = "/x", method[] = "GET", protocol[] = "HTTP/1.1";
    uint64_t total = 0;
    for (size_t i = 0; i < iterations + WARMUP; i++) {
        zig_waf_transaction_t *tx = NULL;
        if (zig_waf_transaction_create(waf, &tx) != ZIG_WAF_OK ||
            zig_waf_transaction_process_connection(tx, (const uint8_t *)ip, strlen(ip), 40000,
                (const uint8_t *)ip, strlen(ip), 80) != ZIG_WAF_OK ||
            zig_waf_transaction_process_uri(tx, (const uint8_t *)uri, strlen(uri),
                (const uint8_t *)method, strlen(method), (const uint8_t *)protocol, strlen(protocol)) != ZIG_WAF_OK ||
            zig_waf_transaction_process_request_headers(tx) != ZIG_WAF_OK) {
            fprintf(stderr, "c-abi-benchmark: transaction setup failed\n");
            exit(2);
        }
        uint64_t started = now_ns();
        zig_waf_status_t status = zig_waf_transaction_evaluate_phase(tx, 1);
        uint64_t elapsed = now_ns() - started;
        if (status != ZIG_WAF_OK) {
            fprintf(stderr, "c-abi-benchmark: evaluate_phase returned %d\n", (int)status);
            exit(2);
        }
        zig_waf_transaction_destroy(tx);
        if (i >= WARMUP) total += elapsed;
    }
    return (double)total / (double)iterations;
}

int main(int argc, char **argv) {
    size_t iterations = argc > 1 ? (size_t)strtoull(argv[1], NULL, 10) : 5000;
    double max_ns_per_rule = argc > 2 ? strtod(argv[2], NULL) : 0;
    double max_ns_per_inspecting_rule = argc > 3 ? strtod(argv[3], NULL) : 0;
    if (iterations == 0) iterations = 1;

    /* The baseline has no phase-1 rule, so it measures the loop and nothing else. */
    zig_waf_t *baseline = create("SecRule ARGS \"@rx never\" \"id:1,phase:2,pass,nolog\"\n");

    /* Half no-op, half literal setvar: firing is the cost under test, and an
     * unconditional rule that only passes was the slowest case in #82. */
    char rules[FIRED_RULES * 96];
    size_t used = 0;
    for (int i = 0; i < FIRED_RULES; i++) {
        if (i % 2 == 0)
            used += (size_t)snprintf(rules + used, sizeof(rules) - used,
                "SecAction \"id:%d,phase:1,pass,nolog\"\n", 100 + i);
        else
            used += (size_t)snprintf(rules + used, sizeof(rules) - used,
                "SecAction \"id:%d,phase:1,pass,nolog,setvar:tx.v%d=1\"\n", 100 + i, i);
    }
    zig_waf_t *fired = create(rules);

    /* Patterns sized like CRS's: alternations, classes and quantifiers that take
     * the regex compiler real work, and phrase lists that build an automaton. The
     * URI they inspect matches none of them, so every rule runs its operator once
     * and fires nothing. Each stays on zig-regex's Thompson engine (no `(?i)`,
     * lazy quantifier, repeated group or lookaround), whose cost is steady
     * enough to gate on. The WAF shares backtracking patterns the same way; the
     * engine tests cover those. */
    static const char *patterns[] = {
        "(?:union|select|insert|update|delete)[\\s/*]+(?:all[\\s/*]+)?(?:select|from|into)",
        "<script[^>]*>",
        "\\.\\./(?:etc|windows|boot)/",
        "[;|`]\\s*(?:cat|wget|curl|nc|bash|sh)\\b",
    };
    static const char *phrases =
        "passwd shadow htaccess web.config wp-config.php id_rsa authorized_keys .git/config .env phpinfo";
    char inspecting[INSPECTING_RULES * 192];
    used = 0;
    for (int i = 0; i < INSPECTING_RULES; i++) {
        if (i % 2 == 0)
            used += (size_t)snprintf(inspecting + used, sizeof(inspecting) - used,
                "SecRule REQUEST_URI \"@rx %s\" \"id:%d,phase:1,pass,nolog\"\n",
                patterns[(i / 2) % 4], 200 + i);
        else
            used += (size_t)snprintf(inspecting + used, sizeof(inspecting) - used,
                "SecRule REQUEST_URI \"@pm %s\" \"id:%d,phase:1,pass,nolog\"\n", phrases, 200 + i);
    }
    zig_waf_t *inspected = create(inspecting);

    double empty = phase_one_ns(baseline, iterations);
    double full = phase_one_ns(fired, iterations);
    double inspecting_ns = phase_one_ns(inspected, iterations);
    double per_rule = (full - empty) / FIRED_RULES;
    double per_inspecting_rule = (inspecting_ns - empty) / INSPECTING_RULES;
    printf("c-abi phase 1, no rules:              %10.0f ns/transaction\n", empty);
    printf("c-abi phase 1, %d fired SecActions:   %10.0f ns/transaction\n", FIRED_RULES, full);
    printf("c-abi cost per fired rule:            %10.0f ns\n", per_rule);
    printf("c-abi phase 1, %d @rx/@pm, no match:  %10.0f ns/transaction\n", INSPECTING_RULES, inspecting_ns);
    printf("c-abi cost per inspecting rule:       %10.0f ns\n", per_inspecting_rule);

    zig_waf_destroy(inspected);
    zig_waf_destroy(fired);
    zig_waf_destroy(baseline);

    int failed = 0;
    if (max_ns_per_rule > 0 && per_rule > max_ns_per_rule) {
        fprintf(stderr, "c-abi-benchmark: %.0f ns per fired rule exceeds the %.0f ns gate\n", per_rule, max_ns_per_rule);
        failed = 1;
    }
    if (max_ns_per_inspecting_rule > 0 && per_inspecting_rule > max_ns_per_inspecting_rule) {
        fprintf(stderr, "c-abi-benchmark: %.0f ns per inspecting rule exceeds the %.0f ns gate\n",
            per_inspecting_rule, max_ns_per_inspecting_rule);
        failed = 1;
    }
    return failed;
}
