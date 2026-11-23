// Coraza v3 through its Go API, the way its http.Handler middleware embeds it.
//
// This is the Go half of the benchmark lab (zig-utils/zig-waf#6). It takes the
// same arguments as the C drivers (../lab.h), times the same span per request
// and prints the same JSON object. Allocations come from runtime.MemStats, read
// around the timed loop, so they count Go heap objects rather than malloc calls.
//
// Usage: coraza-driver <rules.conf> <data-dir> <scenario.lab> <iterations> <threads>
// The JSON goes to stdout, or to the file named by LAB_RESULT when it is set.
package main

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

const warmup = 200

type header struct{ name, value string }

type request struct {
	expectBlock bool
	method      string
	uri         string
	protocol    string
	headers     []header
	body        []byte
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "lab: "+format+"\n", args...)
	os.Exit(2)
}

func percentDecode(text string) []byte {
	out := make([]byte, 0, len(text))
	for i := 0; i < len(text); i++ {
		if text[i] == '%' && i+2 < len(text) {
			if v, err := strconv.ParseUint(text[i+1:i+3], 16, 8); err == nil {
				out = append(out, byte(v))
				i += 2
				continue
			}
		}
		out = append(out, text[i])
	}
	return out
}

// loadScenario reads the format documented in ../scenarios/README.md, exactly
// as lab_load_scenario in ../lab.h does.
func loadScenario(path string) []request {
	file, err := os.Open(path)
	if err != nil {
		die("cannot open the scenario: %v", err)
	}
	defer file.Close()
	var requests []request
	var current *request
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		switch {
		case line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "rules "):
		case strings.HasPrefix(line, "request "):
			if current != nil {
				die("scenario: `request` before `end`")
			}
			fields := strings.Fields(line[len("request "):])
			if len(fields) != 4 || (fields[0] != "pass" && fields[0] != "block") {
				die("scenario: `request` needs pass|block, method, URI and protocol")
			}
			current = &request{expectBlock: fields[0] == "block", method: fields[1], uri: fields[2], protocol: fields[3]}
		case strings.HasPrefix(line, "header "):
			if current == nil {
				die("scenario: `header` outside a request")
			}
			name, value, ok := strings.Cut(line[len("header "):], ":")
			if !ok {
				die("scenario: header without ':'")
			}
			current.headers = append(current.headers, header{name, strings.TrimLeft(value, " ")})
		case strings.HasPrefix(line, "body "):
			if current == nil {
				die("scenario: `body` outside a request")
			}
			current.body = percentDecode(line[len("body "):])
		case line == "end":
			if current == nil {
				die("scenario: `end` without `request`")
			}
			requests = append(requests, *current)
			current = nil
		default:
			die("scenario: unknown line %q", line)
		}
	}
	if current != nil {
		die("scenario: last request has no `end`")
	}
	if len(requests) == 0 {
		die("scenario: no requests")
	}
	return requests
}

// inspect runs one request through the same span as the C drivers: create the
// transaction, connection, URI, headers, phase 1, body, phase 2, decision,
// close. It reports true when Coraza interrupted the request.
func inspect(waf coraza.WAF, r *request) (bool, error) {
	tx := waf.NewTransaction()
	defer tx.Close()
	tx.ProcessConnection("203.0.113.7", 51234, "198.51.100.1", 443)
	tx.ProcessURI(r.uri, r.method, r.protocol)
	for _, h := range r.headers {
		tx.AddRequestHeader(h.name, h.value)
	}
	if it := tx.ProcessRequestHeaders(); it != nil {
		return blocks(it), nil
	}
	if len(r.body) > 0 {
		it, _, err := tx.WriteRequestBody(r.body)
		if err != nil {
			return false, err
		}
		if it != nil {
			return blocks(it), nil
		}
	}
	it, err := tx.ProcessRequestBody()
	if err != nil {
		return false, err
	}
	return it != nil && blocks(it), nil
}

func blocks(it *types.Interruption) bool { return it.Action != "allow" }

func peakRSSBytes() uint64 {
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		return 0
	}
	if runtime.GOOS == "darwin" {
		return uint64(usage.Maxrss) // bytes
	}
	return uint64(usage.Maxrss) * 1024 // kilobytes
}

func coraza3Version() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range info.Deps {
			if dep.Path == "github.com/corazawaf/coraza/v3" {
				return strings.TrimPrefix(dep.Version, "v")
			}
		}
	}
	return "unknown"
}

func main() {
	if len(os.Args) != 6 {
		fmt.Fprintf(os.Stderr, "usage: %s <rules.conf> <data-dir> <scenario.lab> <iterations> <threads>\n", os.Args[0])
		os.Exit(2)
	}
	rulesPath := os.Args[1]
	iterations, err1 := strconv.Atoi(os.Args[4])
	threads, err2 := strconv.Atoi(os.Args[5])
	if err1 != nil || err2 != nil || iterations <= 0 || threads <= 0 || threads > 256 {
		die("iterations and threads must be positive")
	}
	requests := loadScenario(os.Args[3])

	loadStarted := time.Now()
	// Loading by path makes @pmFromFile resolve next to the rule file, as the
	// other drivers do.
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectivesFromFile(rulesPath))
	loadNs := time.Since(loadStarted).Nanoseconds()
	if err != nil {
		die("the engine did not load the rules: %v", err)
	}

	for i := 0; i < warmup; i++ {
		if _, err := inspect(waf, &requests[i%len(requests)]); err != nil {
			die("the engine failed during warm-up: %v", err)
		}
	}

	perThread := (iterations + threads - 1) / threads
	total := perThread * threads
	samples := make([]int64, total)
	blocked := make([]int, threads)
	mismatches := make([]int, threads)
	failures := make([]error, threads)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	started := time.Now()
	var group sync.WaitGroup
	for t := 0; t < threads; t++ {
		group.Add(1)
		go func(t int) {
			defer group.Done()
			mine := samples[t*perThread : (t+1)*perThread]
			for i := range mine {
				r := &requests[(t+i)%len(requests)]
				began := time.Now()
				verdict, err := inspect(waf, r)
				mine[i] = time.Since(began).Nanoseconds()
				if err != nil {
					failures[t] = err
					return
				}
				if verdict {
					blocked[t]++
				}
				if verdict != r.expectBlock {
					mismatches[t]++
				}
			}
		}(t)
	}
	group.Wait()
	elapsed := time.Since(started).Nanoseconds()
	runtime.ReadMemStats(&after)

	totalBlocked, totalMismatches := 0, 0
	for t := 0; t < threads; t++ {
		if failures[t] != nil {
			die("the engine reported an error: %v", failures[t])
		}
		totalBlocked += blocked[t]
		totalMismatches += mismatches[t]
	}
	var sum int64
	for _, s := range samples {
		sum += s
	}
	sort.Slice(samples, func(a, b int) bool { return samples[a] < samples[b] })
	throughput := int64(0)
	if elapsed > 0 {
		throughput = int64(total) * int64(time.Second) / elapsed
	}

	// The orchestrator samples the driver as a separate process and cannot read
	// its stdout, so it names a file in LAB_RESULT instead.
	out := os.Stdout
	if path := os.Getenv("LAB_RESULT"); path != "" {
		file, err := os.Create(path)
		if err != nil {
			die("cannot open LAB_RESULT: %v", err)
		}
		defer file.Close()
		out = file
	}
	fmt.Fprintf(out, "{\"engine\":\"coraza\",\"version\":\"%s\",\"threads\":%d,\"requests\":%d,\"distinct_requests\":%d,"+
		"\"blocked\":%d,\"mismatches\":%d,\"load_ns\":%d,\"p50_ns\":%d,\"p99_ns\":%d,\"p999_ns\":%d,"+
		"\"mean_ns\":%d,\"throughput_rps\":%d,\"peak_rss_bytes\":%d,"+
		"\"allocs_per_request\":%.2f,\"alloc_bytes_per_request\":%.1f}\n",
		coraza3Version(), threads, total, len(requests), totalBlocked, totalMismatches, loadNs,
		samples[total/2], samples[(total*99)/100], samples[(total*999)/1000], sum/int64(total), throughput,
		peakRSSBytes(),
		float64(after.Mallocs-before.Mallocs)/float64(total), float64(after.TotalAlloc-before.TotalAlloc)/float64(total))
}
