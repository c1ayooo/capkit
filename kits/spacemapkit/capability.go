package spacemapkit

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/c1ayooo/capkit"
)

// Manifest exposes the engine search surface. Space-mapping queries hit
// external provider APIs, so the host wires these tools with a Fetcher.
func (c *Client) Manifest() capkit.Manifest {
	return capkit.Manifest{
		Name: "spacemapkit", Version: "0.1.0", APIVersion: "v1",
		Requires: []string{"fetcher"},
		Tools: []capkit.ToolSpec{
			{
				Name:        "space_search",
				Description: "Query one space-mapping engine (fofa/zoomeye/quake/shodan/hunter) and return normalized rows. API key comes from the injected resolver, settings or environment.",
				InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "engine":{"type":"string","enum":["fofa","zoomeye","quake","shodan","hunter"],"description":"engine (default fofa)"},
    "query":{"type":"string","description":"engine query, e.g. domain=\"example.com\""},
    "size":{"type":"integer","description":"result size (default 100, max 10000)"},
    "page":{"type":"integer","description":"page (default 1)"},
    "fields":{"type":"string","description":"comma-separated engine fields (default provider set)"},
    "full":{"type":"boolean","description":"engine full/history flag where supported"}
  },
  "required":["query"]
}`),
				Risk:           capkit.RiskLow,
				OutputSchema:   json.RawMessage(`{"type":"object","properties":{"count":{"type":"integer"},"hits":{"type":"array","items":{"type":"object"}}}}`),
				ExtractTargets: func(json.RawMessage) ([]capkit.Target, error) { return nil, nil },
			},
			{
				Name:        "space_domain_search",
				Description: "Query one engine for assets of a domain using the engine-specific domain syntax.",
				InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "engine":{"type":"string","enum":["fofa","zoomeye","quake","shodan","hunter"]},
    "domain":{"type":"string"},
    "size":{"type":"integer"},
    "page":{"type":"integer"}
  },
  "required":["domain"]
}`),
				Risk:           capkit.RiskLow,
				OutputSchema:   json.RawMessage(`{"type":"object","properties":{"count":{"type":"integer"},"hits":{"type":"array","items":{"type":"object"}}}}`),
				ExtractTargets: func(json.RawMessage) ([]capkit.Target, error) { return nil, nil },
			},
			{
				Name:         "space_providers",
				Description:  "List supported space-mapping engines, whether each key is configured, and the domain query template.",
				InputSchema:  json.RawMessage(`{"type":"object","properties":{}}`),
				Risk:         capkit.RiskLow,
				OutputSchema: json.RawMessage(`{"type":"object","properties":{"providers":{"type":"array","items":{"type":"object"}}}}`),
			},
		},
	}
}

func (c *Client) Call(ctx context.Context, call capkit.Call) (capkit.Result, error) {
	switch call.Tool {
	case "space_search":
		return c.search(ctx, call.Input)
	case "space_domain_search":
		return c.domainSearch(ctx, call.Input)
	case "space_providers":
		return c.providers(), nil
	default:
		return capkit.FailResult(fmt.Errorf("unknown tool %s", call.Tool)), nil
	}
}

func (c *Client) search(ctx context.Context, input json.RawMessage) (capkit.Result, error) {
	var in struct {
		Engine string `json:"engine"`
		Query  string `json:"query"`
		Size   int    `json:"size"`
		Page   int    `json:"page"`
		Fields string `json:"fields"`
		Full   bool   `json:"full"`
	}
	if err := json.Unmarshal(input, &in); err != nil {
		return capkit.FailResult(fmt.Errorf("invalid input: %w", err)), nil
	}
	if strings.TrimSpace(in.Query) == "" {
		return capkit.FailResult(fmt.Errorf("query is required")), nil
	}
	resp, err := c.SearchProviderCtx(ctx, in.Engine, SearchRequest{
		Query: in.Query, Size: in.Size, Page: in.Page, Fields: in.Fields, Full: in.Full,
	})
	if err != nil {
		return capkit.FailResult(err), nil
	}
	return capkit.DataResult(resp)
}

func (c *Client) domainSearch(ctx context.Context, input json.RawMessage) (capkit.Result, error) {
	var in struct {
		Engine string `json:"engine"`
		Domain string `json:"domain"`
		Size   int    `json:"size"`
		Page   int    `json:"page"`
	}
	if err := json.Unmarshal(input, &in); err != nil {
		return capkit.FailResult(fmt.Errorf("invalid input: %w", err)), nil
	}
	domain := strings.TrimSpace(in.Domain)
	if domain == "" {
		return capkit.FailResult(fmt.Errorf("domain is required")), nil
	}
	resp, err := c.SearchProviderCtx(ctx, in.Engine, SearchRequest{
		Query: DomainQuery(in.Engine, domain), Size: in.Size, Page: in.Page,
	})
	if err != nil {
		return capkit.FailResult(err), nil
	}
	return capkit.DataResult(resp)
}

func (c *Client) providers() capkit.Result {
	rows := make([]map[string]any, 0, len(Providers))
	for _, p := range Providers {
		rows = append(rows, map[string]any{
			"provider": p, "display": ProviderDisplayName(p),
			"configured": c.SourceConfigured(p), "domain_query": DomainQueryTemplate(p),
		})
	}
	res, _ := capkit.DataResult(rows)
	return res
}
