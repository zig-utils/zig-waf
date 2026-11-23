/* Counts heap allocations for the C drivers of the benchmark lab.
 *
 * Loaded into a driver with DYLD_INSERT_LIBRARIES (macOS) or LD_PRELOAD
 * (Linux), it counts every malloc, calloc, realloc, posix_memalign and
 * aligned_alloc call and the bytes requested, from any library in the process:
 * libmodsecurity's C++ operator new ends in malloc, and zig-waf's C ABI
 * allocates through the C allocator. The driver finds lab_alloc_snapshot with
 * dlsym and reads it around its timed loop.
 *
 * Counting costs an atomic add per call, so the orchestrator runs it in a
 * separate pass and never reports latency from that pass. */
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

static _Atomic uint64_t calls;
static _Atomic uint64_t bytes;

static inline void note(size_t size) {
    atomic_fetch_add_explicit(&calls, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&bytes, size, memory_order_relaxed);
}

__attribute__((visibility("default"))) void lab_alloc_snapshot(uint64_t *out_calls, uint64_t *out_bytes) {
    *out_calls = atomic_load_explicit(&calls, memory_order_relaxed);
    *out_bytes = atomic_load_explicit(&bytes, memory_order_relaxed);
}

#if defined(__APPLE__)

#include <malloc/malloc.h>
#include <stdlib.h>

static void *lab_malloc(size_t size) { note(size); return malloc(size); }
static void *lab_calloc(size_t count, size_t size) { note(count * size); return calloc(count, size); }
static void *lab_realloc(void *pointer, size_t size) { note(size); return realloc(pointer, size); }
static int lab_posix_memalign(void **out, size_t alignment, size_t size) {
    note(size);
    return posix_memalign(out, alignment, size);
}
static void *lab_aligned_alloc(size_t alignment, size_t size) { note(size); return aligned_alloc(alignment, size); }

/* dyld rebinds every other image's calls to the left-hand functions to these.
 * Calls from inside this file still reach the real ones. */
#define LAB_INTERPOSE(replacement, original)                                                   \
    __attribute__((used)) static const struct {                                                \
        const void *replacement_fn;                                                            \
        const void *original_fn;                                                               \
    } lab_interpose_##original __attribute__((section("__DATA,__interpose"))) = {             \
        (const void *)(unsigned long)&replacement, (const void *)(unsigned long)&original};

LAB_INTERPOSE(lab_malloc, malloc)
LAB_INTERPOSE(lab_calloc, calloc)
LAB_INTERPOSE(lab_realloc, realloc)
LAB_INTERPOSE(lab_posix_memalign, posix_memalign)
LAB_INTERPOSE(lab_aligned_alloc, aligned_alloc)

#elif defined(__linux__)

/* glibc exports its allocator under these names, so the wrappers can reach it
 * without dlsym, which itself allocates. */
extern void *__libc_malloc(size_t);
extern void *__libc_calloc(size_t, size_t);
extern void *__libc_realloc(void *, size_t);
extern void *__libc_memalign(size_t, size_t);

void *malloc(size_t size) { note(size); return __libc_malloc(size); }
void *calloc(size_t count, size_t size) { note(count * size); return __libc_calloc(count, size); }
void *realloc(void *pointer, size_t size) { note(size); return __libc_realloc(pointer, size); }
int posix_memalign(void **out, size_t alignment, size_t size) {
    note(size);
    void *pointer = __libc_memalign(alignment, size);
    if (!pointer) return 12; /* ENOMEM */
    *out = pointer;
    return 0;
}
void *aligned_alloc(size_t alignment, size_t size) { note(size); return __libc_memalign(alignment, size); }

#else
#error "alloc_count.c supports macOS and Linux"
#endif
