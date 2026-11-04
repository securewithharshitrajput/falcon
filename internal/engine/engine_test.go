package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestDoCapturesStatusHeadersBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test", "yes")
		w.WriteHeader(201)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	eng := New(DefaultConfig())
	defer eng.Close()
	resp := eng.Do(context.Background(), Request{Method: "GET", URL: srv.URL})
	if resp.Status != 201 {
		t.Errorf("Status=%d, want 201", resp.Status)
	}
	if resp.Header.Get("X-Test") != "yes" {
		t.Errorf("header dropped: %v", resp.Header)
	}
	if string(resp.Body) != `{"ok":true}` {
		t.Errorf("body=%q", resp.Body)
	}
}

func TestDoAllPreservesOrderUnderConcurrency(t *testing.T) {
	// Each request asks the server to respond after a tiny randomish delay,
	// so finish order differs from fire order — DoAll must still return
	// responses indexed to match requests.
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte(r.URL.Path))
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.Concurrency = 5
	eng := New(cfg)
	defer eng.Close()

	const N = 20
	reqs := make([]Request, N)
	for i := range reqs {
		reqs[i] = Request{Method: "GET", URL: srv.URL + "/" + pathOf(i)}
	}
	resps := eng.DoAll(context.Background(), reqs)
	for i, r := range resps {
		if string(r.Body) != "/"+pathOf(i) {
			t.Errorf("resp[%d] body = %q, want %q — order broken", i, r.Body, "/"+pathOf(i))
		}
	}
	if hits.Load() != N {
		t.Errorf("hits=%d, want %d", hits.Load(), N)
	}
}

func pathOf(i int) string {
	return "x" + itoa(i)
}
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	n := len(b)
	for i > 0 {
		n--
		b[n] = byte('0' + i%10)
		i /= 10
	}
	return string(b[n:])
}

func TestEngineRespectsTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.Write([]byte("slow"))
	}))
	defer srv.Close()
	cfg := DefaultConfig()
	cfg.Timeout = 50 * time.Millisecond
	eng := New(cfg)
	defer eng.Close()
	resp := eng.Do(context.Background(), Request{Method: "GET", URL: srv.URL})
	if resp.Err == nil {
		t.Error("expected timeout error, got none")
	}
}
