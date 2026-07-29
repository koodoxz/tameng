package protocol

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"
)

const checkBudget = 5 * time.Second

func newTestGuard() *Guard {
	return NewGuard(&Config{})
}

// FuzzGuardCheckRequest feeds arbitrary raw HTTP/1.1 request bytes through
// net/http's parser and then into the protocol guard. This exercises the
// smuggling, CRLF and header-injection regex paths with header shapes that a
// hand-written test would never produce (duplicate CL, absurd header counts,
// non-UTF8 header values, chunked bodies).
func FuzzGuardCheckRequest(f *testing.F) {
	seeds := []string{
		"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
		"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello",
		"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\n",
		"GET /%0d%0aSet-Cookie:x HTTP/1.1\r\nHost: a\r\n\r\n",
		"GET /?a=%0D%0A HTTP/1.1\r\nHost: a\r\nX-Forwarded-For: 1\r\nX-Forwarded-For: 2\r\nX-Forwarded-For: 3\r\nX-Forwarded-For: 4\r\n\r\n",
		"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: identity, chunked\r\n\r\n",
		"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 999999999999999999\r\n\r\nx",
		"GET /\x00\x01 HTTP/1.1\r\nHost: a\r\nX-B: \xff\xfe\r\n\r\n",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, raw []byte) {
		req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
		if err != nil {
			t.Skip() // not a parseable request; nothing for the guard to see
		}
		// Drain lazily-parsed bodies so ContentLength/Body are in a realistic state.
		if req.Body != nil {
			io.CopyN(io.Discard, req.Body, 1<<16)
		}

		g := newTestGuard()

		start := time.Now()
		violations := g.CheckRequest(req)
		if d := time.Since(start); d > checkBudget {
			t.Fatalf("CheckRequest exceeded budget: %v", d)
		}

		for i, v := range violations {
			if v.Type == "" {
				t.Fatalf("violation %d has empty Type", i)
			}
		}
		_ = g.Stats()
	})
}

// FuzzGuardCheckGraphQL fuzzes the GraphQL depth/complexity estimator, which
// does its own brace accounting and integer arithmetic on untrusted input.
func FuzzGuardCheckGraphQL(f *testing.F) {
	seeds := []string{
		"",
		"{ user { name } }",
		"}}}}}}}}}}",
		"{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{",
		"query($a:Int){f(a:$a){b(c:1){d}}}}",
		"\x00\xff{(",
		"{" + string(make([]byte, 1024)),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, query string) {
		g := newTestGuard()

		start := time.Now()
		violations := g.CheckGraphQL(query)
		if d := time.Since(start); d > checkBudget {
			t.Fatalf("CheckGraphQL exceeded budget: %v", d)
		}

		// Depth must never be negative and complexity must never wrap to a
		// negative value via integer overflow.
		depth := g.calculateGraphQLDepth(query)
		if depth < 0 {
			t.Fatalf("negative GraphQL depth %d for query %q", depth, query)
		}
		if c := g.calculateGraphQLComplexity(query); c < 0 {
			t.Fatalf("negative GraphQL complexity %d (integer overflow) for len=%d", c, len(query))
		}
		for i, v := range violations {
			if v.Type == "" {
				t.Fatalf("violation %d has empty Type", i)
			}
		}
	})
}

// TestGuardCheckRequestConcurrentCounters exercises Guard.CheckRequest from many
// goroutines, mirroring how it is invoked from the HTTP middleware chain. Run
// with -race.
func TestGuardCheckRequestConcurrentCounters(t *testing.T) {
	g := newTestGuard()

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(
					[]byte("GET /?a=b HTTP/1.1\r\nHost: a\r\nX-Forwarded-For: 1.2.3.4\r\n\r\n"))))
				if err != nil {
					t.Error(err)
					return
				}
				g.CheckRequest(req)
			}
		}()
	}
	wg.Wait()

	if got := g.requestsChecked.Load(); got != 16*200 {
		t.Errorf("requestsChecked = %d, want %d (lost increments under concurrency)", got, 16*200)
	}
}

// TestGuardStats_ReflectsCheckRequestCounts asserts Stats() returns the exact
// counter values CheckRequest accumulated, not just that it runs without a
// race. A clean request and a CRLF-injection request are distinguished by
// their expected violation count.
func TestGuardStats_ReflectsCheckRequestCounts(t *testing.T) {
	g := newTestGuard()

	clean, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(
		[]byte("GET /?a=b HTTP/1.1\r\nHost: a\r\n\r\n"))))
	if err != nil {
		t.Fatal(err)
	}
	g.CheckRequest(clean)

	injected, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(
		[]byte("GET /?a=%0d%0aInjected HTTP/1.1\r\nHost: a\r\n\r\n"))))
	if err != nil {
		t.Fatal(err)
	}
	violations := g.CheckRequest(injected)
	if len(violations) == 0 {
		t.Fatal("expected the CRLF-injection request to produce at least one violation")
	}

	stats := g.Stats()
	if got := stats["requests_checked"]; got != int64(2) {
		t.Errorf("Stats()[\"requests_checked\"] = %v, want 2", got)
	}
	if got := stats["violations"]; got != int64(len(violations)) {
		t.Errorf("Stats()[\"violations\"] = %v, want %d", got, len(violations))
	}
}
