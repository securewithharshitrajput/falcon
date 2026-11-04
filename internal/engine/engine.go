// Package engine is falcon's HTTP layer: a small, parallelizable client that
// knows nothing about auth or specs, only about firing a request and capturing
// its response in a form the diff layer can reason about. Deliberately
// simpler than a full worker-pool fuzzer — authenticated API testing fires
// handfuls of requests per endpoint (one per identity × method), not
// thousands, so prioritize response capture quality over raw throughput.
package engine

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// Request is one unit of work. Headers includes any auth injected by an
// identity (bearer, cookie, basic). Meta rides along so callers can correlate
// responses with the test case that produced them without a side map.
type Request struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    []byte
	Meta    any
}

// Response is the captured result. Falcon's diff layer looks at Status and
// Body (plus a few headers like Content-Type) — the fields are deliberately
// minimal since a diff of 5 fields is tractable to reason about while a
// diff of 20 is not.
type Response struct {
	Req      Request
	Status   int
	Header   http.Header
	Body     []byte
	Length   int
	Duration time.Duration
	Err      error
}

// Config tunes the engine.
type Config struct {
	Concurrency        int
	Timeout            time.Duration
	MaxBodyBytes       int64
	UserAgent          string
	ProxyURL           string
	InsecureSkipVerify bool
	FollowRedirect     bool
}

// DefaultConfig returns sane defaults for falcon: 10 concurrent requests
// (the diff workload is small, higher concurrency just makes correlation
// logs harder to read), a reasonable timeout, and 2 MiB body cap (API
// responses are rarely larger and if they are, the diff logic only needs
// the shape, not the whole payload).
func DefaultConfig() Config {
	return Config{
		Concurrency:    10,
		Timeout:        15 * time.Second,
		MaxBodyBytes:   2 * 1024 * 1024,
		UserAgent:      "falcon/0.1 (+authorized-testing)",
		FollowRedirect: false,
	}
}

// Engine is a reusable HTTP client wrapper. It holds the Transport and an
// http.Client; Close releases connection pool resources (relevant for
// repeated runs in a test suite, free in a one-shot CLI process).
type Engine struct {
	cfg       Config
	client    *http.Client
	transport *http.Transport
}

// New builds an Engine. ProxyURL (if set) must parse successfully; invalid
// values become a non-fatal engine with proxying disabled, and the caller
// can surface the warning if it wants to be strict.
func New(cfg Config) *Engine {
	tr := &http.Transport{
		MaxIdleConns:        cfg.Concurrency * 2,
		MaxIdleConnsPerHost: cfg.Concurrency * 2,
		MaxConnsPerHost:     cfg.Concurrency * 2,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: cfg.InsecureSkipVerify},
		ForceAttemptHTTP2:   true,
	}
	if cfg.ProxyURL != "" {
		if p, err := url.Parse(cfg.ProxyURL); err == nil {
			tr.Proxy = http.ProxyURL(p)
			tr.ForceAttemptHTTP2 = false // Burp-style MITM proxies dislike h2 negotiation
		}
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   cfg.Timeout,
	}
	if !cfg.FollowRedirect {
		client.CheckRedirect = func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return &Engine{cfg: cfg, client: client, transport: tr}
}

// Close releases the engine's idle connection pool.
func (e *Engine) Close() {
	e.transport.CloseIdleConnections()
}

// Do fires one request and captures the response. Any error (dial failure,
// timeout, body read error) is stored on Response.Err rather than returned
// separately — the diff layer wants to reason about failed requests
// uniformly ("this identity got a timeout, the other got 200").
func (e *Engine) Do(ctx context.Context, req Request) Response {
	start := time.Now()
	var body io.Reader
	if len(req.Body) > 0 {
		body = bytes.NewReader(req.Body)
	}
	hr, err := http.NewRequestWithContext(ctx, req.Method, req.URL, body)
	if err != nil {
		return Response{Req: req, Err: err, Duration: time.Since(start)}
	}
	hr.Header.Set("User-Agent", e.cfg.UserAgent)
	for k, v := range req.Headers {
		hr.Header.Set(k, v)
	}
	resp, err := e.client.Do(hr)
	if err != nil {
		return Response{Req: req, Err: err, Duration: time.Since(start)}
	}
	defer resp.Body.Close()
	cap := e.cfg.MaxBodyBytes
	if cap <= 0 {
		cap = 1 << 20
	}
	buf, _ := io.ReadAll(io.LimitReader(resp.Body, cap))
	return Response{
		Req:      req,
		Status:   resp.StatusCode,
		Header:   resp.Header,
		Body:     buf,
		Length:   len(buf),
		Duration: time.Since(start),
	}
}

// DoAll fires reqs concurrently up to cfg.Concurrency and returns responses
// IN THE SAME ORDER as the input — critical for falcon's correlated diffs,
// where responses[i] must still correspond to reqs[i] after the batch.
func (e *Engine) DoAll(ctx context.Context, reqs []Request) []Response {
	out := make([]Response, len(reqs))
	sem := make(chan struct{}, e.cfg.Concurrency)
	var wg sync.WaitGroup
	for i := range reqs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				out[i] = Response{Req: reqs[i], Err: ctx.Err()}
				return
			}
			defer func() { <-sem }()
			out[i] = e.Do(ctx, reqs[i])
		}(i)
	}
	wg.Wait()
	return out
}
