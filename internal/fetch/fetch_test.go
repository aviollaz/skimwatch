package fetch

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRobotsAndPoliteness(t *testing.T) {
	var mu sync.Mutex
	var hits []time.Time
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits = append(hits, time.Now())
		mu.Unlock()
		if r.URL.Path == "/robots.txt" {
			io.WriteString(w, "User-agent: *\nDisallow: /private\nAllow: /private/ok\n\nUser-agent: other\nDisallow: /\n")
			return
		}
		io.WriteString(w, strings.Repeat("x", 100))
	}))
	defer srv.Close()

	f := New(Options{UserAgent: "skimwatch/test", Delay: 50 * time.Millisecond, Timeout: 5 * time.Second, MaxBodyBytes: 10, RespectRobots: true})
	ctx := context.Background()

	r, err := f.Get(ctx, srv.URL+"/page")
	if err != nil {
		t.Fatal(err)
	}
	if !r.Truncated || len(r.Body) != 10 {
		t.Errorf("body should be capped at 10 bytes, got %d (truncated=%v)", len(r.Body), r.Truncated)
	}
	if _, err := f.Get(ctx, srv.URL+"/private/x"); !errors.As(err, &ErrDisallowed{}) {
		t.Errorf("robots.txt should block /private/x, got %v", err)
	}
	if _, err := f.Get(ctx, srv.URL+"/private/ok"); err != nil {
		t.Errorf("Allow should win for /private/ok: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	for i := 1; i < len(hits); i++ {
		if gap := hits[i].Sub(hits[i-1]); gap < 45*time.Millisecond {
			t.Errorf("requests %d and %d were only %v apart", i-1, i, gap)
		}
	}
}
