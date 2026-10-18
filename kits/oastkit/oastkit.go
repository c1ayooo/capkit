// Package oastkit provides out-of-band interaction helpers backed by dnslog.cn
// (or a compatible self-hosted dnslog service). It uses the external Fetcher
// port, so it is rate-limited/audited but not project-scope-checked.
package oastkit

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/capkit"
)

const DefaultBaseURL = "http://dnslog.cn"

type Client struct {
	Fetcher capkit.Fetcher
	BaseURL string

	mu     sync.Mutex
	cookie string
}

func (c *Client) base() string {
	base := strings.TrimRight(strings.TrimSpace(c.BaseURL), "/")
	if base == "" {
		base = DefaultBaseURL
	}
	return base
}

func (c *Client) GetDomain(ctx context.Context) (string, error) {
	if c.Fetcher == nil {
		return "", capkit.Unavailable("oast fetcher is not configured")
	}
	res, err := c.Fetcher.Fetch(ctx, capkit.Request{
		Method: "GET", URL: c.base() + "/getdomain.php", Timeout: 15 * time.Second,
		Headers: map[string]string{"User-Agent": "capkit-oastkit"},
	})
	if err != nil {
		return "", err
	}
	if res.Status != 200 {
		return "", capkit.Unavailable(fmt.Sprintf("dnslog getdomain HTTP %d", res.Status))
	}
	cookie := firstHeader(res.Headers, "Set-Cookie")
	domain := strings.TrimSpace(string(res.Body))
	if domain == "" {
		return "", capkit.Unavailable("dnslog returned an empty domain")
	}
	c.mu.Lock()
	c.cookie = cookie
	c.mu.Unlock()
	return domain, nil
}

func (c *Client) GetRecords(ctx context.Context, domain string, waitSec int) ([]string, error) {
	if c.Fetcher == nil {
		return nil, capkit.Unavailable("oast fetcher is not configured")
	}
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return nil, capkit.InvalidInput("domain is required")
	}
	if waitSec > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(waitSec) * time.Second):
		}
	}
	headers := map[string]string{"User-Agent": "capkit-oastkit"}
	c.mu.Lock()
	if c.cookie != "" {
		headers["Cookie"] = c.cookie
	}
	c.mu.Unlock()
	res, err := c.Fetcher.Fetch(ctx, capkit.Request{
		Method: "GET", URL: c.base() + "/getrecords.php?t=" + url.QueryEscape(domain),
		Timeout: 15 * time.Second, Headers: headers,
	})
	if err != nil {
		return nil, err
	}
	if res.Status != 200 {
		return nil, capkit.Unavailable(fmt.Sprintf("dnslog getrecords HTTP %d", res.Status))
	}
	return parseRecords(res.Body), nil
}

func parseRecords(body []byte) []string {
	raw := strings.TrimSpace(string(body))
	if raw == "" {
		return nil
	}
	var arr []string
	if json.Unmarshal([]byte(raw), &arr) == nil {
		out := make([]string, 0, len(arr))
		for _, v := range arr {
			if s := strings.TrimSpace(v); s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasSuffix(line, "%") {
			line = strings.TrimSuffix(line, "%")
		}
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func firstHeader(headers map[string][]string, name string) string {
	for k, vs := range headers {
		if strings.EqualFold(k, name) && len(vs) > 0 {
			return vs[0]
		}
	}
	return ""
}

// Kit exposes dnslog.cn as two tools.
type Kit struct {
	client   *Client
	evidence capkit.EvidenceSink
}

func New(deps capkit.Deps) *Kit {
	return &Kit{
		client:   &Client{Fetcher: deps.Fetcher},
		evidence: deps.Evidence,
	}
}

func NewCapability(deps capkit.Deps) (capkit.Capability, error) { return New(deps), nil }

func (k *Kit) Manifest() capkit.Manifest {
	return capkit.Manifest{
		Name: "oastkit", Version: "0.1.0", APIVersion: "v1",
		Requires: []string{"limiter", "audit", "fetcher"},
		Tools: []capkit.ToolSpec{
			{
				Name:           "oast_get_domain",
				Description:    "Get a fresh dnslog.cn callback domain for blind SSRF/XXE/injection verification. The domain is bound to an in-memory session cookie; follow with oast_get_records.",
				InputSchema:    json.RawMessage(`{"type":"object","properties":{}}`),
				Risk:           capkit.RiskLow,
				OutputSchema:   json.RawMessage(`{"type":"object","properties":{"domain":{"type":"string"}}}`),
				ExtractTargets: func(json.RawMessage) ([]capkit.Target, error) { return nil, nil },
			},
			{
				Name:        "oast_get_records",
				Description: "Fetch DNS interaction records for a domain returned by oast_get_domain. wait_seconds gives the target time to resolve (recommended 3-10s).",
				InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "domain":{"type":"string","description":"domain from oast_get_domain"},
    "wait_seconds":{"type":"integer","description":"wait before querying (default 0, recommended 3-10)"}
  },
  "required":["domain"]
}`),
				Risk:           capkit.RiskLow,
				OutputSchema:   json.RawMessage(`{"type":"object","properties":{"records":{"type":"array","items":{"type":"object"}},"count":{"type":"integer"}}}`),
				ExtractTargets: func(json.RawMessage) ([]capkit.Target, error) { return nil, nil },
			},
		},
	}
}

func (k *Kit) Call(ctx context.Context, call capkit.Call) (capkit.Result, error) {
	switch call.Tool {
	case "oast_get_domain":
		return k.getDomain(ctx)
	case "oast_get_records":
		return k.getRecords(ctx, call)
	default:
		return capkit.FailResult(capkit.NotFound("unknown tool: " + call.Tool)), nil
	}
}

func (k *Kit) getDomain(ctx context.Context) (capkit.Result, error) {
	domain, err := k.client.GetDomain(ctx)
	if err != nil {
		return capkit.FailResult(err), nil
	}
	res, _ := capkit.DataResult(map[string]any{"domain": domain})
	return res, nil
}

func (k *Kit) getRecords(ctx context.Context, call capkit.Call) (capkit.Result, error) {
	var in struct {
		Domain      string `json:"domain"`
		WaitSeconds int    `json:"wait_seconds"`
	}
	if err := json.Unmarshal(call.Input, &in); err != nil {
		return capkit.FailResult(capkit.InvalidInput(err.Error())), nil
	}
	records, err := k.client.GetRecords(ctx, in.Domain, in.WaitSeconds)
	if err != nil {
		return capkit.FailResult(err), nil
	}
	res, _ := capkit.DataResult(map[string]any{"domain": in.Domain, "records": records, "count": len(records)})
	if k.evidence != nil && len(records) > 0 {
		data, _ := json.Marshal(records)
		id, eerr := k.evidence.Record(ctx, capkit.Evidence{
			Kind: "oast", Title: "dnslog records " + in.Domain, Data: data, CreatedAt: time.Now(),
			Metadata: map[string]string{"domain": in.Domain, "records": fmt.Sprint(len(records))},
		})
		if eerr == nil && id != "" {
			res.EvidenceIDs = []string{id}
		}
	}
	return res, nil
}
