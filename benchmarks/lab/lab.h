/* Shared harness for the C drivers of the benchmark lab (zig-utils/zig-waf#6).
 *
 * Each engine is driven by a small program that links only that engine. The
 * zig-waf and ModSecurity drivers are C and include this file; the Coraza driver
 * is Go and reimplements the same loop (coraza/main.go). All three take the same
 * arguments, read the same rule file and scenario, time the same span and print
 * the same JSON object, so the only thing that differs between their numbers is
 * the engine.
 *
 * The timed span of one request is everything an embedding host pays for:
 * create the transaction, hand it the connection, URI, headers and body, run
 * request phases 1 and 2, read the decision, and destroy the transaction. Rule
 * loading is timed separately, and response phases are not run: the issue is
 * about inspecting requests, and every engine's response path is a separate
 * benchmark.
 *
 * Usage: <driver> <rules.conf> <data-dir> <scenario.lab> <iterations> <threads>
 * The JSON goes to stdout, or to the file named by LAB_RESULT when it is set.
 */
#ifndef ZIG_WAF_LAB_H
#define ZIG_WAF_LAB_H

#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>

#define LAB_MAX_HEADERS 32
#define LAB_MAX_REQUESTS 64
#define LAB_WARMUP 200

typedef struct {
    const char *name;
    size_t name_len;
    const char *value;
    size_t value_len;
} lab_header;

typedef struct {
    int expect_block;
    const char *method;
    const char *uri;
    const char *protocol;
    lab_header headers[LAB_MAX_HEADERS];
    size_t header_count;
    unsigned char *body;
    size_t body_len;
} lab_request;

/* One engine, behind the three calls the harness needs. `inspect` returns 1
 * when the engine blocked the request, 0 when it let it through, and -1 when
 * the engine reported an error, which fails the run. It is called from several
 * threads at once with the same engine. */
typedef struct {
    const char *name;
    const char *version;
    void *(*create)(const char *rules, size_t rules_len, const char *rules_path, const char *data_dir);
    int (*inspect)(void *engine, const lab_request *request);
    void (*destroy)(void *engine);
} lab_engine;

static uint64_t lab_now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000u + (uint64_t)t.tv_nsec;
}

static void lab_die(const char *what) {
    fprintf(stderr, "lab: %s\n", what);
    exit(2);
}

static char *lab_read_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) lab_die("cannot open an input file");
    if (fseek(f, 0, SEEK_END) != 0) lab_die("cannot size an input file");
    long n = ftell(f);
    if (n < 0) lab_die("cannot size an input file");
    rewind(f);
    char *bytes = malloc((size_t)n + 1);
    if (!bytes || fread(bytes, 1, (size_t)n, f) != (size_t)n) lab_die("cannot read an input file");
    fclose(f);
    bytes[n] = 0;
    *out_len = (size_t)n;
    return bytes;
}

static int lab_hex(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Bodies are written with %XX escapes so a scenario file stays one line per
 * field and can still carry any byte. */
static unsigned char *lab_percent_decode(const char *text, size_t *out_len) {
    size_t n = strlen(text);
    unsigned char *out = malloc(n + 1);
    if (!out) lab_die("out of memory");
    size_t used = 0;
    for (size_t i = 0; i < n; i++) {
        if (text[i] == '%' && i + 2 < n && lab_hex(text[i + 1]) >= 0 && lab_hex(text[i + 2]) >= 0) {
            out[used++] = (unsigned char)(lab_hex(text[i + 1]) * 16 + lab_hex(text[i + 2]));
            i += 2;
        } else {
            out[used++] = (unsigned char)text[i];
        }
    }
    *out_len = used;
    return out;
}

static char *lab_next_field(char **cursor) {
    char *p = *cursor;
    while (*p == ' ') p++;
    if (!*p) return NULL;
    char *start = p;
    while (*p && *p != ' ') p++;
    if (*p) *p++ = 0;
    *cursor = p;
    return start;
}

/* The scenario format (see scenarios/README.md):
 *   request <pass|block> <METHOD> <URI> <PROTOCOL>
 *   header <Name>: <value>
 *   body <percent-encoded bytes>
 *   end
 * Blank lines and lines starting with '#' are ignored, as is a `rules` line,
 * which only the orchestrator reads. */
static size_t lab_load_scenario(const char *path, lab_request *requests) {
    size_t len = 0;
    char *text = lab_read_file(path, &len);
    size_t count = 0;
    lab_request *current = NULL;
    char *line = text;
    while (line && *line) {
        char *newline = strchr(line, '\n');
        if (newline) *newline = 0;
        size_t line_len = strlen(line);
        if (line_len && line[line_len - 1] == '\r') line[--line_len] = 0;

        if (line_len == 0 || line[0] == '#' || strncmp(line, "rules ", 6) == 0) {
            /* nothing */
        } else if (strncmp(line, "request ", 8) == 0) {
            if (current) lab_die("scenario: `request` before `end`");
            if (count == LAB_MAX_REQUESTS) lab_die("scenario: too many requests");
            current = &requests[count];
            memset(current, 0, sizeof(*current));
            char *cursor = line + 8;
            char *expect = lab_next_field(&cursor);
            current->method = lab_next_field(&cursor);
            current->uri = lab_next_field(&cursor);
            current->protocol = lab_next_field(&cursor);
            if (!expect || !current->method || !current->uri || !current->protocol)
                lab_die("scenario: `request` needs an expectation, method, URI and protocol");
            if (strcmp(expect, "block") == 0) current->expect_block = 1;
            else if (strcmp(expect, "pass") != 0) lab_die("scenario: expectation must be pass or block");
        } else if (strncmp(line, "header ", 7) == 0) {
            if (!current) lab_die("scenario: `header` outside a request");
            if (current->header_count == LAB_MAX_HEADERS) lab_die("scenario: too many headers");
            char *name = line + 7;
            char *colon = strchr(name, ':');
            if (!colon) lab_die("scenario: header without ':'");
            *colon = 0;
            char *value = colon + 1;
            while (*value == ' ') value++;
            lab_header *h = &current->headers[current->header_count++];
            h->name = name;
            h->name_len = strlen(name);
            h->value = value;
            h->value_len = strlen(value);
        } else if (strncmp(line, "body ", 5) == 0) {
            if (!current) lab_die("scenario: `body` outside a request");
            current->body = lab_percent_decode(line + 5, &current->body_len);
        } else if (strcmp(line, "end") == 0) {
            if (!current) lab_die("scenario: `end` without `request`");
            current = NULL;
            count++;
        } else {
            lab_die("scenario: unknown line");
        }
        line = newline ? newline + 1 : NULL;
    }
    if (current) lab_die("scenario: last request has no `end`");
    if (count == 0) lab_die("scenario: no requests");
    /* `text` stays allocated: the requests point into it. */
    return count;
}

/* Allocation counting is optional. When the run is started with the lab's
 * malloc interposer loaded (alloc_count.c), it exports this function and the
 * driver reports allocations per request; otherwise they print as null. The
 * orchestrator does that in a separate run, so counting never slows the timed
 * one. */
typedef void (*lab_alloc_snapshot_fn)(uint64_t *calls, uint64_t *bytes);

typedef struct {
    const lab_engine *engine;
    void *instance;
    const lab_request *requests;
    size_t request_count;
    size_t iterations;
    size_t offset;
    uint64_t *samples;
    size_t blocked;
    size_t mismatches;
    int failed;
} lab_worker;

static void *lab_worker_run(void *argument) {
    lab_worker *w = argument;
    for (size_t i = 0; i < w->iterations; i++) {
        const lab_request *r = &w->requests[(w->offset + i) % w->request_count];
        uint64_t started = lab_now_ns();
        int verdict = w->engine->inspect(w->instance, r);
        w->samples[i] = lab_now_ns() - started;
        if (verdict < 0) {
            w->failed = 1;
            return NULL;
        }
        if (verdict) w->blocked++;
        if (verdict != r->expect_block) w->mismatches++;
    }
    return NULL;
}

static int lab_compare(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return x < y ? -1 : x > y;
}

static uint64_t lab_peak_rss_bytes(void) {
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) != 0) return 0;
#ifdef __APPLE__
    return (uint64_t)usage.ru_maxrss; /* bytes on macOS */
#else
    return (uint64_t)usage.ru_maxrss * 1024u; /* kilobytes on Linux */
#endif
}

static int lab_main(int argc, char **argv, const lab_engine *engine) {
    if (argc != 6) {
        fprintf(stderr, "usage: %s <rules.conf> <data-dir> <scenario.lab> <iterations> <threads>\n", argv[0]);
        return 2;
    }
    const char *rules_path = argv[1];
    const char *data_dir = argv[2];
    size_t iterations = (size_t)strtoull(argv[4], NULL, 10);
    size_t threads = (size_t)strtoull(argv[5], NULL, 10);
    if (iterations == 0 || threads == 0 || threads > 256) lab_die("iterations and threads must be positive");

    static lab_request requests[LAB_MAX_REQUESTS];
    size_t request_count = lab_load_scenario(argv[3], requests);
    size_t rules_len = 0;
    char *rules = lab_read_file(rules_path, &rules_len);

    uint64_t load_started = lab_now_ns();
    void *instance = engine->create(rules, rules_len, rules_path, data_dir);
    uint64_t load_ns = lab_now_ns() - load_started;
    if (!instance) lab_die("the engine did not load the rules");

    /* Warm up on one thread, and check every request once: a scenario whose
     * expectations the engine does not meet still runs, but says so. */
    for (size_t i = 0; i < LAB_WARMUP; i++)
        if (engine->inspect(instance, &requests[i % request_count]) < 0) lab_die("the engine failed during warm-up");

    lab_alloc_snapshot_fn snapshot = (lab_alloc_snapshot_fn)dlsym(RTLD_DEFAULT, "lab_alloc_snapshot");
    uint64_t calls_before = 0, bytes_before = 0, calls_after = 0, bytes_after = 0;

    size_t per_thread = (iterations + threads - 1) / threads;
    size_t total = per_thread * threads;
    uint64_t *samples = malloc(total * sizeof(uint64_t));
    lab_worker *workers = calloc(threads, sizeof(lab_worker));
    pthread_t *handles = calloc(threads, sizeof(pthread_t));
    if (!samples || !workers || !handles) lab_die("out of memory");
    for (size_t t = 0; t < threads; t++) {
        workers[t] = (lab_worker){
            .engine = engine,
            .instance = instance,
            .requests = requests,
            .request_count = request_count,
            .iterations = per_thread,
            .offset = t,
            .samples = samples + t * per_thread,
        };
    }

    if (snapshot) snapshot(&calls_before, &bytes_before);
    uint64_t started = lab_now_ns();
    if (threads == 1) {
        lab_worker_run(&workers[0]);
    } else {
        for (size_t t = 0; t < threads; t++)
            if (pthread_create(&handles[t], NULL, lab_worker_run, &workers[t]) != 0) lab_die("cannot start a thread");
        for (size_t t = 0; t < threads; t++) pthread_join(handles[t], NULL);
    }
    uint64_t elapsed = lab_now_ns() - started;
    if (snapshot) snapshot(&calls_after, &bytes_after);

    size_t blocked = 0, mismatches = 0;
    for (size_t t = 0; t < threads; t++) {
        if (workers[t].failed) lab_die("the engine reported an error");
        blocked += workers[t].blocked;
        mismatches += workers[t].mismatches;
    }

    uint64_t sum = 0;
    for (size_t i = 0; i < total; i++) sum += samples[i];
    qsort(samples, total, sizeof(uint64_t), lab_compare);

    /* The orchestrator samples the driver as a separate process and cannot read
     * its stdout, so it names a file in LAB_RESULT instead. */
    const char *result_path = getenv("LAB_RESULT");
    FILE *out = result_path ? fopen(result_path, "w") : stdout;
    if (!out) lab_die("cannot open LAB_RESULT");
    fprintf(out, "{\"engine\":\"%s\",\"version\":\"%s\",\"threads\":%zu,\"requests\":%zu,\"distinct_requests\":%zu,"
           "\"blocked\":%zu,\"mismatches\":%zu,\"load_ns\":%llu,\"p50_ns\":%llu,\"p99_ns\":%llu,\"p999_ns\":%llu,"
           "\"mean_ns\":%llu,\"throughput_rps\":%llu,\"peak_rss_bytes\":%llu,",
        engine->name, engine->version, threads, total, request_count, blocked, mismatches,
        (unsigned long long)load_ns, (unsigned long long)samples[total / 2],
        (unsigned long long)samples[(total * 99) / 100], (unsigned long long)samples[(total * 999) / 1000],
        (unsigned long long)(sum / total),
        (unsigned long long)(elapsed ? (uint64_t)total * 1000000000u / elapsed : 0),
        (unsigned long long)lab_peak_rss_bytes());
    if (snapshot)
        fprintf(out, "\"allocs_per_request\":%.2f,\"alloc_bytes_per_request\":%.1f}\n",
            (double)(calls_after - calls_before) / (double)total, (double)(bytes_after - bytes_before) / (double)total);
    else
        fprintf(out, "\"allocs_per_request\":null,\"alloc_bytes_per_request\":null}\n");
    if (out != stdout) fclose(out);

    engine->destroy(instance);
    return 0;
}

#endif
