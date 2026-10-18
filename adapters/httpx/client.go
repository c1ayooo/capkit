package httpx

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/c1ayooo/capkit"
)

// Client is the gate-aware HTTPDoer injected into kits. It enforces scope on
// the initial URL and every redirect hop, and applies per-host rate limiting.
type Client struct {
	Base         *http.Client
	Scope        capkit.ScopeChecker
	Limiter      capkit.Limiter
	Audit        capkit.AuditSink
	Clock        capkit.Clock
	MaxBodyBytes int64
	RateLimit    capkit.RateLimitSpec
}

func New(scope capkit.ScopeChecker, limiter capkit.Limiter, audit capkit.AuditSink) *Client {
	return &Client{Scope: scope, Limiter: limiter, Audit: audit, MaxBodyBytes: 10 << 20}
}

func (c *Client) Do(ctx context.Context, req capkit.Request) (*capkit.Response, error) {
	cc, _ := capkit.CallContextFrom(ctx)
	target, err := capkit.TargetFromURL(cc.ProjectID, req.URL)
	if err != nil {
		return nil, capkit.InvalidInput(err.Error())
	}
	if c.Scope == nil {
		return nil, capkit.ScopeDenied("scope checker is not configured")
	}
	if err := c.Scope.Check(ctx, target); err != nil {
		return nil, err
	}
	spec := c.RateLimit
	if spec.PerSecond <= 0 {
		spec = capkit.RateLimitSpec{PerSecond: 10, Burst: 5, Concurrency: 4}
	}
	if c.Limiter != nil {
		release, err := c.Limiter.Acquire(ctx, target.Key(), spec)
		if err != nil {
			return nil, err
		}
		defer release()
	}

	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	base := c.Base
	if base == nil {
		base = &http.Client{}
	}
	client := *base
	client.Timeout = timeout
	if req.Proxy != "" {
		var transport http.RoundTripper = http.DefaultTransport
		if base, ok := http.DefaultTransport.(*http.Transport); ok {
			transport = base.Clone()
		}
		if u, perr := url.Parse(req.Proxy); perr == nil {
			if t, ok := transport.(*http.Transport); ok {
				t.Proxy = http.ProxyURL(u)
			}
		}
		client.Transport = transport
	}
	client.CheckRedirect = func(next *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("too many redirects")
		}
		t, terr := capkit.TargetFromURL(cc.ProjectID, next.URL.String())
		if terr != nil {
			return terr
		}
		return c.Scope.Check(next.Context(), t)
	}

	var body io.Reader
	if len(req.Body) > 0 {
		body = bytes.NewReader(req.Body)
	}
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	httpReq, err := http.NewRequestWithContext(ctx, method, req.URL, body)
	if err != nil {
		return nil, capkit.InvalidInput(err.Error())
	}
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}

	started := time.Now()
	if c.Clock != nil {
		started = c.Clock.Now()
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		c.audit(ctx, cc, target, "error", err.Error(), time.Since(started))
		return nil, capkit.Unavailable(err.Error())
	}
	defer resp.Body.Close()

	max := c.MaxBodyBytes
	if max <= 0 {
		max = 10 << 20
	}
	data, readErr := io.ReadAll(io.LimitReader(resp.Body, max))
	if readErr != nil {
		return nil, capkit.Unavailable("read response: " + readErr.Error())
	}
	headers := map[string][]string{}
	for k, vs := range resp.Header {
		headers[k] = append([]string(nil), vs...)
	}
	finalURL := req.URL
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}
	c.audit(ctx, cc, target, "ok", "", time.Since(started))
	return &capkit.Response{
		Status: resp.StatusCode, Headers: headers, Body: data,
		Duration: time.Since(started), FinalURL: finalURL,
	}, nil
}

func (c *Client) audit(ctx context.Context, cc capkit.CallContext, target capkit.Target, status, errMsg string, d time.Duration) {
	if c.Audit == nil {
		return
	}
	c.Audit.Record(ctx, capkit.AuditEvent{
		TraceID: cc.TraceID, Actor: cc.Actor, ProjectID: cc.ProjectID, TaskID: cc.TaskID,
		Capability: "httpkit", Tool: "http", Risk: capkit.RiskMedium,
		Targets: []capkit.Target{target}, Phase: "http", Status: status, Error: errMsg,
		DurationMS: d.Milliseconds(), StartedAt: time.Now().Add(-d), FinishedAt: time.Now(),
	})
}
