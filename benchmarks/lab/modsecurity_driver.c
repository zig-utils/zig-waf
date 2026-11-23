/* ModSecurity v3 (libmodsecurity) through its C API, the way its nginx
 * connector embeds it.
 *
 * The log callback discards every message. libmodsecurity formats a message for
 * each matched rule whether or not anyone reads it, and without a callback it
 * prints them to stdout, which would put terminal I/O inside the timed span.
 * A discarding callback is what a connector that drops logs installs; the other
 * two engines log nothing either. */
#include "lab.h"

#include <modsecurity/intervention.h>
#include <modsecurity/modsecurity.h>
#include <modsecurity/rules_set.h>
#include <modsecurity/transaction.h>

typedef struct {
    ModSecurity *modsec;
    RulesSet *rules;
} engine_state;

static void discard_log(void *data, const void *message) {
    (void)data;
    (void)message;
}

static void *create(const char *rules, size_t rules_len, const char *rules_path, const char *data_dir) {
    (void)rules;
    (void)rules_len;
    (void)data_dir;
    engine_state *state = calloc(1, sizeof(*state));
    if (!state) return NULL;
    state->modsec = msc_init();
    msc_set_connector_info(state->modsec, "zig-waf benchmark lab");
    msc_set_log_cb(state->modsec, discard_log);
    state->rules = msc_create_rules_set();
    const char *error = NULL;
    /* Loading by path makes @pmFromFile resolve next to the rule file, which is
     * where the orchestrator puts the data files for every engine. */
    if (msc_rules_add_file(state->rules, rules_path, &error) < 0) {
        fprintf(stderr, "modsecurity: rules did not load: %s\n", error ? error : "(no message)");
        return NULL;
    }
    return state;
}

/* "HTTP/1.1" -> "1.1": libmodsecurity takes the method and the bare version. */
static const char *bare_version(const char *protocol) {
    return strncmp(protocol, "HTTP/", 5) == 0 ? protocol + 5 : protocol;
}

static int decided(Transaction *tx, int *verdict) {
    ModSecurityIntervention it;
    memset(&it, 0, sizeof(it));
    it.status = 200;
    int disruptive = msc_intervention(tx, &it);
    free(it.url);
    free(it.log);
    if (disruptive || it.disruptive) {
        *verdict = 1;
        return 1;
    }
    return 0;
}

static int inspect(void *engine, const lab_request *r) {
    engine_state *state = engine;
    Transaction *tx = msc_new_transaction(state->modsec, state->rules, NULL);
    if (!tx) return -1;
    int verdict = 0;
    msc_process_connection(tx, "203.0.113.7", 51234, "198.51.100.1", 443);
    msc_process_uri(tx, r->uri, r->method, bare_version(r->protocol));
    for (size_t i = 0; i < r->header_count; i++) {
        const lab_header *h = &r->headers[i];
        msc_add_n_request_header(tx, (const unsigned char *)h->name, h->name_len,
            (const unsigned char *)h->value, h->value_len);
    }
    msc_process_request_headers(tx);
    if (decided(tx, &verdict)) goto done;
    if (r->body_len) msc_append_request_body(tx, r->body, r->body_len);
    msc_process_request_body(tx);
    decided(tx, &verdict);
done:
    msc_transaction_cleanup(tx);
    return verdict;
}

static void destroy(void *engine) {
    engine_state *state = engine;
    msc_rules_cleanup(state->rules);
    msc_cleanup(state->modsec);
    free(state);
}

int main(int argc, char **argv) {
    static const lab_engine engine = {
        .name = "modsecurity",
        .version = "3.0.16",
        .create = create,
        .inspect = inspect,
        .destroy = destroy,
    };
    return lab_main(argc, argv, &engine);
}
