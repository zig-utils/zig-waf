# Benchmark lab: zig-waf, ModSecurity and Coraza

`zig build lab` runs zig-waf, ModSecurity 3.0.16 and Coraza 3.7.0 on the same
rules and the same requests, measured at the same points, and writes the results
to `zig-out/lab/results.md` and `results.json` (zig-utils/zig-waf#6).

A comparison is only worth reading if nothing but the engine differs, so the lab
holds everything else fixed:

- **One rule file.** Every scenario's rules are assembled into a single file that
  all three engines load: `benchmarks/lab/base.conf`, then for CRS
  `crs-setup.conf.example` and `rules/*.conf` in name order. CRS's data files are
  copied next to it, because each engine resolves `@pmFromFile` relative to the
  rule file.
- **One request set.** Each scenario in `benchmarks/lab/scenarios` lists its
  requests and what every engine should decide for each
  ([format](../benchmarks/lab/scenarios/README.md)).
- **One timed span.** Per request: create the transaction, give it the
  connection, URI, headers and body, run request phases 1 and 2, read the
  decision, destroy the transaction. That is what an embedding host pays.
  Loading the rules is timed separately. Response phases are not run.
- **One way to embed each engine.** Each engine has its own driver, built the way
  its connectors embed it: zig-waf through its C ABI, ModSecurity through
  libmodsecurity's C API, Coraza through its Go API. The two C drivers share
  `benchmarks/lab/lab.h`, and the Go driver reimplements the same loop.
- **One way to measure memory.** Each driver runs as its own process, sampled from
  outside by zig-bench's process sampler at 20 Hz: peak RSS and peak private
  dirty memory (`phys_footprint` on macOS).
- **No logging.** All three log nothing. ModSecurity is given a callback that
  discards messages, because without one it prints every match to stdout.

The run fails if any engine reports an error or decides a request differently
from its scenario. A timing for a request one engine blocked and another passed
is not a comparison, so a disagreement is a finding to explain before any number
is published.

## Running it

The lab needs a CRS checkout, libmodsecurity built under a prefix, and Go on
`PATH`. It also needs Zig 0.17.0-dev.1857 or newer, because zig-bench, the lazy
dependency that samples memory, requires it. Nothing else in the build fetches
zig-bench.

```sh
# ModSecurity v3.0.16, built into a prefix next to its checkout
git clone https://github.com/owasp-modsecurity/ModSecurity.git ../modsecurity
cd ../modsecurity && git checkout v3.0.16 && git submodule update --init --recursive
./build.sh
./configure --prefix="$PWD/install" --with-pcre2 --with-libxml --with-yajl \
  --without-lua --without-maxmind --without-geoip --without-ssdeep --without-lmdb --without-curl
make -j8 && make install
cd -

zig build lab -Doptimize=ReleaseFast \
  -Dlab-crs=../owasp-crs \
  -Dlab-modsecurity=../modsecurity/install \
  -Dlab-zig-waf-version="$(git rev-parse --short HEAD)"
```

On macOS with Homebrew, pass each library's prefix to `configure`, for example
`--with-pcre2=/opt/homebrew/opt/pcre2`.

Options:

| Option | Default | Meaning |
| --- | --- | --- |
| `-Dlab-crs` | required | CRS checkout to load |
| `-Dlab-modsecurity` | required | libmodsecurity install prefix (`include/` and `lib/`) |
| `-Dlab-iterations` | 2000 | Timed requests per run |
| `-Dlab-output` | `zig-out/lab` | Where rule files and results go |
| `-Dlab-zig-waf-version` | `dev` | Label for zig-waf in the results |

The lab refuses to run unless the build is ReleaseFast. A Debug build measures
Zig's safety checks, not the engine.

Coraza and its dependencies come from the Go module pinned in
`benchmarks/lab/coraza/go.sum`. CI already checks out ModSecurity and Coraza at
the same pinned commits for its parser and inventory tests.

## Scenarios

| Scenario | Rules | Requests |
| --- | --- | --- |
| `no-rules` | base only | One clean GET: what embedding the engine costs before any rule runs |
| `crs-get` | CRS PL1 | Five clean browser GETs with seven headers and a cookie |
| `crs-get-h2` | CRS PL1 | The same GETs with protocol `HTTP/2.0` |
| `crs-attacks` | CRS PL1 | One attack per family: SQL injection, XSS, path traversal, command injection, PHP wrapper injection; and `host=x && uname -a`, which only the rules in #89 detect |
| `crs-form-post` | CRS PL1 | A clean 973-byte urlencoded form |
| `crs-json-post` | CRS PL1 | A clean 741-byte JSON order, parsed by the JSON body processor |
| `crs-mixed` | CRS PL1 | Eight clean requests to two attacks, run on 1 and 4 threads sharing one engine |

## What the numbers mean, and what they don't

- **Latency** is per request, sorted, with p50, p99 and p99.9 picked from the
  sorted samples. Throughput is requests divided by the timed loop's wall time,
  so on 4 threads it is aggregate throughput.
- **Allocations** for the two C engines come from a malloc interposer
  (`benchmarks/lab/alloc_count.c`) loaded into a separate, shorter run, so
  counting never slows the timed one. It counts every allocation call in the
  process, whichever library made it. For Coraza they come from the Go runtime's
  `Mallocs` and `TotalAlloc`. A Go heap object and a malloc call are not the same
  unit, so compare each engine's allocations across scenarios rather than across
  engines.
- **Memory** is the whole process: the engine, the compiled rules, and a small
  driver. Coraza's figure includes the Go runtime.
- **HTTP versions.** An embedded engine sees only the protocol string, so
  `crs-get-h2` measures what CRS does with `HTTP/2.0`, not HTTP/2 framing,
  HPACK or streams. Those belong to a server, which is outside this lab.
- **One machine, one run.** The numbers below are from one developer machine. Run
  the lab on the hardware you care about, and compare engines within a run
  rather than across machines.

## Results

Measured 2026-11-24 on an Apple M-series Mac (macOS, arm64) at zig-waf
`f6a40a2`, with OWASP CRS 4.28.0 at paranoia level 1. Other work was running on
the machine (load average 5 to 6), so read the ratios between engines in each
row group rather than the absolute times. The single-run tails (p99.9 over
2,000 samples) are the noisiest figures.

2000 timed requests per run, CRS data files: 21, aarch64-macos.

| Scenario | Threads | Engine | p50 | p99 | p99.9 | Throughput | Allocs/req | Alloc KiB/req | Peak RSS | Peak dirty | Load | Blocked | Mismatches |
| --- | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| no-rules | 1 | zig-waf f6a40a2 | 3.0 µs | 3.0 µs | 22.0 µs | 370027 rps | 8 | 19.8 | 2.8 MiB | 0.2 MiB | 1.81 ms | 0/2000 | 0 |
| no-rules | 1 | modsecurity 3.0.16 | 13.0 µs | 16.0 µs | 61.0 µs | 75287 rps | 269 | 38.5 | 3.8 MiB | 0.1 MiB | 7.15 ms | 0/2000 | 0 |
| no-rules | 1 | coraza 3.7.0 | 3.4 µs | 14.8 µs | 282.6 µs | 218050 rps | 77 | 2.8 | 21.1 MiB | 9.9 MiB | 2.46 ms | 0/2000 | 0 |
| crs-get | 1 | zig-waf f6a40a2 | 1.42 ms | 1.83 ms | 2.30 ms | 704 rps | 6222 | 1118.1 | 35.7 MiB | 34.2 MiB | 39.64 ms | 0/2000 | 0 |
| crs-get | 1 | modsecurity 3.0.16 | 800.0 µs | 1.05 ms | 1.40 ms | 1248 rps | 11557 | 962.8 | 37.0 MiB | 35.0 MiB | 176.85 ms | 0/2000 | 0 |
| crs-get | 1 | coraza 3.7.0 | 659.4 µs | 1.35 ms | 2.45 ms | 1467 rps | 2829 | 165.0 | 70.7 MiB | 60.8 MiB | 58.26 ms | 0/2000 | 0 |
| crs-get-h2 | 1 | zig-waf f6a40a2 | 1.43 ms | 3.10 ms | 14.43 ms | 671 rps | 6222 | 1118.1 | 34.9 MiB | 33.5 MiB | 36.38 ms | 0/2000 | 0 |
| crs-get-h2 | 1 | modsecurity 3.0.16 | 813.0 µs | 1.30 ms | 1.69 ms | 1217 rps | 11536 | 961.5 | 36.3 MiB | 34.3 MiB | 170.80 ms | 0/2000 | 0 |
| crs-get-h2 | 1 | coraza 3.7.0 | 658.3 µs | 1.57 ms | 2.42 ms | 1456 rps | 2811 | 165.7 | 68.5 MiB | 60.5 MiB | 54.12 ms | 0/2000 | 0 |
| crs-attacks | 1 | zig-waf f6a40a2 | 1.66 ms | 3.72 ms | 17.12 ms | 577 rps | 6882 | 1245.7 | 35.7 MiB | 34.2 MiB | 35.02 ms | 2000/2000 | 0 |
| crs-attacks | 1 | modsecurity 3.0.16 | 914.0 µs | 1.42 ms | 2.03 ms | 1063 rps | 12259 | 1038.5 | 36.3 MiB | 34.4 MiB | 178.78 ms | 2000/2000 | 0 |
| crs-attacks | 1 | coraza 3.7.0 | 806.7 µs | 1.27 ms | 2.38 ms | 1217 rps | 3100 | 167.6 | 71.7 MiB | 62.0 MiB | 52.60 ms | 2000/2000 | 0 |
| crs-form-post | 1 | zig-waf f6a40a2 | 8.39 ms | 12.60 ms | 41.21 ms | 115 rps | 25269 | 3867.4 | 35.3 MiB | 33.9 MiB | 36.00 ms | 0/2000 | 0 |
| crs-form-post | 1 | modsecurity 3.0.16 | 1.46 ms | 2.01 ms | 3.24 ms | 668 rps | 17956 | 1868.5 | 36.1 MiB | 34.2 MiB | 172.11 ms | 0/2000 | 0 |
| crs-form-post | 1 | coraza 3.7.0 | 5.26 ms | 13.37 ms | 81.31 ms | 173 rps | 3897 | 343.2 | 67.2 MiB | 60.3 MiB | 59.15 ms | 0/2000 | 0 |
| crs-json-post | 1 | zig-waf f6a40a2 | 11.09 ms | 14.79 ms | 33.27 ms | 88 rps | 34702 | 7106.0 | 35.1 MiB | 33.6 MiB | 38.40 ms | 0/2000 | 0 |
| crs-json-post | 1 | modsecurity 3.0.16 | 4.83 ms | 6.89 ms | 12.80 ms | 203 rps | 95109 | 5941.5 | 36.4 MiB | 34.4 MiB | 159.07 ms | 0/2000 | 0 |
| crs-json-post | 1 | coraza 3.7.0 | 6.75 ms | 9.32 ms | 39.29 ms | 144 rps | 7622 | 1108.1 | 72.1 MiB | 64.1 MiB | 53.47 ms | 0/2000 | 0 |
| crs-mixed | 1 | zig-waf f6a40a2 | 1.55 ms | 3.05 ms | 14.14 ms | 618 rps | 6418 | 1150.4 | 35.5 MiB | 34.1 MiB | 39.97 ms | 400/2000 | 0 |
| crs-mixed | 1 | modsecurity 3.0.16 | 845.0 µs | 1.18 ms | 2.32 ms | 1208 rps | 11923 | 995.3 | 36.4 MiB | 34.5 MiB | 168.32 ms | 400/2000 | 0 |
| crs-mixed | 1 | coraza 3.7.0 | 706.6 µs | 1.42 ms | 2.20 ms | 1390 rps | 2909 | 170.9 | 70.2 MiB | 60.3 MiB | 51.13 ms | 400/2000 | 0 |
| crs-mixed | 4 | zig-waf f6a40a2 | 1.78 ms | 3.11 ms | 4.14 ms | 2235 rps | 6418 | 1150.4 | 36.4 MiB | 35.0 MiB | 36.05 ms | 400/2000 | 0 |
| crs-mixed | 4 | modsecurity 3.0.16 | 1.27 ms | 1.66 ms | 2.55 ms | 3165 rps | 11923 | 995.3 | 37.9 MiB | 35.9 MiB | 166.43 ms | 400/2000 | 0 |
| crs-mixed | 4 | coraza 3.7.0 | 701.1 µs | 2.57 ms | 5.17 ms | 5086 rps | 2912 | 179.6 | 81.1 MiB | 69.4 MiB | 57.11 ms | 400/2000 | 0 |

### Findings

- **Every engine made the same decision on every request.** All 2,000 attacks
  were blocked by all three, and no clean request was blocked by any.
- **With no rules, zig-waf is the cheapest to embed**: 3.0 µs per request and 8
  allocations, against ModSecurity's 13 µs and 269 allocations and Coraza's
  3.4 µs.
- **With CRS, zig-waf is the slowest of the three.** A clean GET takes 1.42 ms
  against ModSecurity's 0.80 ms and Coraza's 0.66 ms. The gap is widest on
  bodies: the 973-byte form takes 8.4 ms against ModSecurity's 1.5 ms (5.7×), and
  the JSON body 11.1 ms against 4.8 ms (2.3×).
- **zig-waf allocates the most bytes per CRS request**: 1.1 MiB for a GET and
  3.8 MiB for the form, against ModSecurity's 0.9 and 1.8 MiB. Its allocation
  count is lower than ModSecurity's on GETs (6,222 against 11,557), so the
  number of allocations alone does not explain the gap.
- **zig-waf loads CRS fastest**: about 36 to 40 ms, against ModSecurity's 160 to
  180 ms and Coraza's 50 to 60 ms. With CRS loaded it holds about 35 MiB
  resident, close to ModSecurity's 36 to 38 MiB and about half of Coraza's 67 to
  81 MiB.
- **On 4 threads** sharing one engine, all three scale: zig-waf from 618 to
  2,235 requests per second, ModSecurity from 1,208 to 3,165, and Coraza from
  1,390 to 5,086.

The CRS request path, and the body path above all, is where zig-waf has the most
to gain, and this lab is the measurement to judge that work by.

### After the rule fixes (#89, #90)

The first run above measured a zig-waf that silently skipped 18 CRS rules,
because zig-regex could not compile their patterns (#89), and that compiled
`@rx` without dotall (#90). With both fixed, every CRS rule runs. The same lab on
the same machine, 2,000 requests per run:

| Scenario | zig-waf f6a40a2 | zig-waf with #89 and #90 | ModSecurity 3.0.16 | Coraza 3.7.0 |
| --- | ---: | ---: | ---: | ---: |
| `crs-get` | 1.42 ms | 6.78 ms | 0.85 ms | 0.66 ms |
| `crs-form-post` | 8.39 ms | 20.40 ms | 1.45 ms | 5.11 ms |
| `crs-json-post` | 11.09 ms | 95.54 ms | 4.69 ms | 6.69 ms |

p50 per request. All three engines decided every request the same way, including
`host=x && uname -a`, which zig-waf let through before. The added time is almost
all five PL1 Unix command-injection rules (932230, 932235, 932250, 932260 and
932340), which now run for the first time. zig-regex takes 0.5 to 2 ms per search
on their command lists, where PCRE2 with JIT takes about 25 µs. Making zig-regex
fast on CRS's patterns is zig-utils/zig-regex#56.

### After cutting zig-waf's own request cost (#87)

Most of that time was not the searches themselves. Each value got a fresh
zig-regex matcher, which built its lazy DFAs from nothing, so no rule ever ran
warm. zig-regex 0.5.2 keeps the DFAs behind its shared `isMatch` warm across
calls and threads, and zig-waf now asks that shared regex whether a value
matches before it looks for captures (see [operators](operators.md)). The same
lab on the same machine, 2,000 requests per run, Coraza included:

| Scenario | zig-waf 5666abd | zig-waf with #87 | ModSecurity 3.0.16 | Coraza 3.7.0 |
| --- | ---: | ---: | ---: | ---: |
| `crs-get` | 6.78 ms | 0.65 ms | 0.86 ms | 0.67 ms |
| `crs-get-h2` | — | 0.65 ms | 0.84 ms | 0.67 ms |
| `crs-attacks` | — | 0.71 ms | 0.89 ms | 0.79 ms |
| `crs-form-post` | 20.40 ms | 1.15 ms | 1.46 ms | 5.21 ms |
| `crs-json-post` | 95.54 ms | 1.66 ms | 4.91 ms | 7.09 ms |
| `crs-mixed` | — | 0.70 ms | 0.87 ms | 0.71 ms |
| `crs-mixed`, 4 threads | — | 0.75 ms | 1.38 ms | 0.76 ms |

p50 per request; 5666abd was recorded only for the three scenarios #87 set out
to cut. All three engines decided every request the same way, with zero
mismatches in every row. zig-waf now has the lowest median on every CRS
scenario. On the bodies the lead is clear; on GETs and the mixed run it is 2 to
4% ahead of Coraza, which is within this lab's run-to-run noise. On the 4-thread
mixed run it serves 4,791 requests per second against ModSecurity's 2,784 and
Coraza's 4,863. It also allocates less than
before: 3,684 allocations and 576 KiB for a clean GET, down from 6,222 and
1.1 MiB at `f6a40a2`.

Two costs came with it:

- **Memory.** With CRS loaded zig-waf holds about 90 MiB resident, against
  ModSecurity's 36 MiB and Coraza's 70 MiB, and 35 MiB before. Almost all of it
  is the second, spans-only compile of each pattern: about 60 MB for CRS's 294
  patterns, against 15 MB for the capturing compiles. Compiling the second one
  only for the 164 patterns that need zig-regex's backtracker would save about
  4 MB, so the fix belongs in zig-regex's compiled programs, not here. CRS also
  takes about 70 ms to load instead of 36 to 40 ms, still faster than
  ModSecurity's 180 to 200 ms.
- **The first requests.** The DFAs are built while requests run, so the first
  requests after a load are slower. Timed from the first request with no
  warm-up: a clean GET takes 9.4 ms, then 3.3 and 4.4 ms, and settles at about
  0.6 ms by the tenth. The form takes 19.8 ms and the JSON body 23.4 ms the
  first time, then 1.1 to 1.5 ms and 1.6 to 2.0 ms.
