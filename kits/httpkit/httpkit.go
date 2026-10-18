package httpkit

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/c1ayooo/capkit"
)

// Kit exposes structured HTTP probing. It uses only the injected HTTPDoer,
// so scope/rate/audit gates cannot be bypassed.
type Kit struct {
	HTTP     capkit.HTTPDoer
	Evidence capkit.EvidenceSink
	IDs      capkit.IDGenerator
}

func New(deps capkit.Deps) *Kit {
	return &Kit{HTTP: deps.HTTP, Evidence: deps.Evidence, IDs: deps.IDs}
}

func (k *Kit) Manifest() capkit.Manifest {
	return capkit.Manifest{
		Name: "httpkit", Version: "0.1.0", APIVersion: "v1",
		Requires: []string{"scope", "limiter", "audit", "http"},
		Tools: []capkit.ToolSpec{{
			Name:        "http_probe",
			Description: "Structured HTTP request through the runtime's gate-aware client. Returns status, headers and a bounded body preview; the full exchange is recorded as evidence when an EvidenceSink is configured.",
			InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "url":{"type":"string","description":"http(s) URL"},
    "method":{"type":"string","description":"HTTP method (default GET)"},
    "headers":{"type":"object","description":"request headers"},
    "body":{"type":"string","description":"request body"},
    "timeout_ms":{"type":"integer","description":"overall timeout in ms (default 20000)"},
    "proxy":{"type":"string","description":"optional http/socks5 proxy URL"}
  },
  "required":["url"]
}`),
			Risk:         capkit.RiskMedium,
			OutputSchema: json.RawMessage(`{"type":"object","properties":{"status":{"type":"integer"},"headers":{"type":"object"},"body":{"type":"string"},"body_bytes":{"type":"integer"},"duration_ms":{"type":"integer"},"final_url":{"type":"string"}}}`),
			RateLimit:    capkit.RateLimitSpec{PerSecond: 10, Burst: 5, Concurrency: 4},
			ExtractTargets: func(input json.RawMessage) ([]capkit.Target, error) {
				var in probeInput
				if err := json.Unmarshal(input, &in); err != nil {
					return nil, err
				}
				if strings.TrimSpace(in.URL) == "" {
					return nil, fmt.Errorf("url is required")
				}
				t, err := capkit.TargetFromURL(0, in.URL)
				if err != nil {
					return nil, err
				}
				return []capkit.Target{t}, nil
			},
		}},
	}
}

type probeInput struct {
	URL       string            `json:"url"`
	Method    string            `json:"method"`
	Headers   map[string]string `json:"headers"`
	Body      string            `json:"body"`
	TimeoutMS int               `json:"timeout_ms"`
	Proxy     string            `json:"proxy"`
}

func (k *Kit) Call(ctx context.Context, call capkit.Call) (capkit.Result, error) {
	switch call.Tool {
	case "http_probe":
		return k.probe(ctx, call)
	default:
		return capkit.FailResult(capkit.NotFound("unknown tool: " + call.Tool)), nil
	}
}

func (k *Kit) probe(ctx context.Context, call capkit.Call) (capkit.Result, error) {
	var in probeInput
	if err := json.Unmarshal(call.Input, &in); err != nil {
		return capkit.FailResult(capkit.InvalidInput(err.Error())), nil
	}
	if k.HTTP == nil {
		return capkit.FailResult(capkit.Unavailable("http doer is not configured")), nil
	}
	timeout := time.Duration(in.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	method := strings.ToUpper(strings.TrimSpace(in.Method))
	if method == "" {
		method = "GET"
	}
	req := capkit.Request{
		Method: method, URL: in.URL, Headers: in.Headers,
		Body: []byte(in.Body), Proxy: in.Proxy, Timeout: timeout,
	}
	res, err := k.HTTP.Do(ctx, req)
	if err != nil {
		return capkit.FailResult(err), nil
	}

	preview := res.Body
	if len(preview) > 64*1024 {
		preview = preview[:64*1024]
	}
	out := map[string]any{
		"status": res.Status, "headers": res.Headers, "body": string(preview),
		"body_bytes": len(res.Body), "duration_ms": res.Duration.Milliseconds(),
		"final_url": res.FinalURL,
	}
	result, _ := capkit.DataResult(out)

	if k.Evidence != nil {
		target, _ := capkit.TargetFromURL(call.Context.ProjectID, in.URL)
		reqText := fmt.Sprintf("%s %s\n", method, in.URL)
		for key, value := range in.Headers {
			reqText += key + ": " + value + "\n"
		}
		reqText += "\n" + in.Body
		respText := fmt.Sprintf("HTTP %d\n", res.Status)
		for key, values := range res.Headers {
			for _, value := range values {
				respText += key + ": " + value + "\n"
			}
		}
		respText += "\n" + string(res.Body)
		id, err := k.Evidence.Record(ctx, capkit.Evidence{
			Kind: "http", Title: method + " " + hostOf(in.URL), Target: target,
			Request: []byte(reqText), Response: []byte(respText), CreatedAt: time.Now(),
		})
		if err == nil && id != "" {
			result.EvidenceIDs = []string{id}
		}
	}
	return result, nil
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return u.Host
}
