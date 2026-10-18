package githubkit

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/c1ayooo/capkit"
)

// Kit exposes GitHub Code Search for leaked secrets. It uses the external
// Fetcher port (not target-scoped HTTP) and the host's GitHub token setting.
type Kit struct {
	client   *Client
	evidence capkit.EvidenceSink
}

func New(deps capkit.Deps) *Kit {
	return &Kit{
		client:   &Client{Fetcher: deps.Fetcher, Settings: deps.Settings, Limiter: deps.Limiter},
		evidence: deps.Evidence,
	}
}

func NewCapability(deps capkit.Deps) (capkit.Capability, error) { return New(deps), nil }

// SetProxyURL sets the egress proxy for GitHub API requests.
func (k *Kit) SetProxyURL(proxy string) {
	if k != nil && k.client != nil {
		k.client.ProxyURL = proxy
	}
}

func (k *Kit) Manifest() capkit.Manifest {
	return capkit.Manifest{
		Name: "githubkit", Version: "0.1.0", APIVersion: "v1",
		Requires: []string{"scope", "limiter", "audit", "fetcher", "settings"},
		Tools: []capkit.ToolSpec{
			{
				Name:        "github_secret_search",
				Description: "Search GitHub code for leaked secrets using a built-in dork template or a custom query. Returns repo/path/fragments, secret type and a static credibility hint; it does not validate the credential. Requires a GitHub token in settings (github.token).",
				InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "template_id":{"type":"string","description":"built-in dork template id (see github_dork_templates)"},
    "query":{"type":"string","description":"custom GitHub code-search query; used when template_id is empty"},
    "org":{"type":"string","description":"substitute {org} in the template"},
    "domain":{"type":"string","description":"substitute {domain} in the template; also used as the scope target"},
    "page":{"type":"integer","description":"1-based page (default 1)"},
    "per_page":{"type":"integer","description":"1-100 (default 30)"},
    "cursor":{"type":"string","description":"分页游标，用上一次返回的 page.cursor 续取下一页"}
  }
}`),
				Risk:         capkit.RiskMedium,
				OutputSchema: json.RawMessage(`{"type":"object","properties":{"total_count":{"type":"integer","description":"GitHub 报告的真实命中总数"},"incomplete":{"type":"boolean"},"truncated":{"type":"boolean"},"page":{"type":"integer"},"per_page":{"type":"integer"},"query":{"type":"string"},"items":{"type":"array","items":{"type":"object"}}}}`),
				RateLimit:    capkit.RateLimitSpec{PerSecond: 0.15, Burst: 2, Concurrency: 1},
				ExtractTargets: func(input json.RawMessage) ([]capkit.Target, error) {
					var in searchInput
					if err := json.Unmarshal(input, &in); err != nil {
						return nil, err
					}
					if strings.TrimSpace(in.Domain) == "" {
						return nil, nil
					}
					t, err := capkit.TargetFromString(0, in.Domain)
					if err != nil {
						return nil, err
					}
					return []capkit.Target{t}, nil
				},
			},
			{
				Name:           "github_dork_templates",
				Description:    "List the built-in GitHub secret-search dork templates (id, category, title, query, note).",
				InputSchema:    json.RawMessage(`{"type":"object","properties":{}}`),
				Risk:           capkit.RiskLow,
				OutputSchema:   json.RawMessage(`{"type":"object","properties":{"count":{"type":"integer"},"templates":{"type":"array","items":{"type":"object"}}}}`),
				ExtractTargets: func(json.RawMessage) ([]capkit.Target, error) { return nil, nil },
			},
		},
		Settings: []capkit.SettingSpec{{
			Key: "github.token", Type: "string", Secret: true,
			Description: "GitHub personal access token for Code Search (requires code search permission).",
		}},
	}
}

// searchDefaultPerPage mirrors the client's default so the cursor arithmetic
// matches what was actually requested.
const (
	searchDefaultPerPage = 30
	// searchMaxPerPage mirrors the API's own ceiling.
	searchMaxPerPage = 100
)

type searchInput struct {
	TemplateID string `json:"template_id"`
	Query      string `json:"query"`
	Org        string `json:"org"`
	Domain     string `json:"domain"`
	Page       int    `json:"page"`
	PerPage    int    `json:"per_page"`
	// Cursor continues a listing the way every other tool does (§5.5.4); it
	// wins over Page when both are present.
	Cursor string `json:"cursor"`
}

func (k *Kit) Call(ctx context.Context, call capkit.Call) (capkit.Result, error) {
	switch call.Tool {
	case "github_secret_search":
		return k.search(ctx, call)
	case "github_dork_templates":
		return k.templates(ctx)
	default:
		return capkit.FailResult(capkit.NotFound("unknown tool: " + call.Tool)), nil
	}
}

func (k *Kit) templates(context.Context) (capkit.Result, error) {
	res, _ := capkit.DataResult(map[string]any{"templates": Templates(), "count": len(Templates())})
	return res, nil
}

func (k *Kit) search(ctx context.Context, call capkit.Call) (capkit.Result, error) {
	var in searchInput
	if err := json.Unmarshal(call.Input, &in); err != nil {
		return capkit.FailResult(capkit.InvalidInput(err.Error())), nil
	}
	query := strings.TrimSpace(in.Query)
	label := "custom"
	if strings.TrimSpace(in.TemplateID) != "" {
		t, ok := TemplateByID(strings.TrimSpace(in.TemplateID))
		if !ok {
			return capkit.FailResult(capkit.NotFound("unknown dork template: " + in.TemplateID)), nil
		}
		query = BuildQuery(t, in.Org, in.Domain)
		label = t.ID
	}
	if query == "" {
		return capkit.FailResult(capkit.InvalidInput("query or template_id is required")), nil
	}
	perPage := capkit.FirstPositive(in.PerPage, searchDefaultPerPage)
	if perPage > searchMaxPerPage {
		perPage = searchMaxPerPage
	}
	page := in.Page
	if c := strings.TrimSpace(in.Cursor); c != "" {
		// Code search pages by page number, so translate the shared offset
		// cursor back into one.
		start, _, _, perr := capkit.PageWindow(1<<30, c, perPage)
		if perr != nil {
			return capkit.FailResult(perr), nil
		}
		if start%perPage != 0 {
			return capkit.FailResult(capkit.InvalidInput("cursor 非法，需使用上一次返回的 page.cursor")), nil
		}
		page = start/perPage + 1
	}
	if page <= 0 {
		page = 1
	}
	result, err := k.client.Search(ctx, query, page, perPage)
	if err != nil {
		return capkit.FailResult(err), nil
	}
	res, _ := capkit.DataResult(result)
	// A code search can match far more than one page; report the true total and
	// the cursor that reaches the next page.
	next := (page-1)*perPage + len(result.Items)
	res.Page = &capkit.Page{Total: result.TotalCount, HasMore: next < result.TotalCount}
	if res.Page.HasMore {
		res.Page.Cursor = capkit.CursorFor(next)
	}
	res.Truncated = result.Truncated
	if k.evidence != nil {
		data, _ := json.Marshal(result)
		target := capkit.Target{}
		if strings.TrimSpace(in.Domain) != "" {
			target, _ = capkit.TargetFromString(call.Context.ProjectID, in.Domain)
		}
		id, eerr := k.evidence.Record(ctx, capkit.Evidence{
			Kind: "github_secret", Title: "GitHub secret search: " + label, Target: target,
			Data: data, CreatedAt: time.Now(),
			Metadata: map[string]string{
				"query": query, "template": label,
				"total": fmt.Sprint(result.TotalCount), "items": fmt.Sprint(len(result.Items)),
			},
		})
		if eerr == nil && id != "" {
			res.EvidenceIDs = []string{id}
		}
	}
	return res, nil
}

// SearchURL is a helper for host UIs/tests.
func SearchURL(base, query string, page, perPage int) string {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if base == "" {
		base = "https://api.github.com"
	}
	return fmt.Sprintf("%s/search/code?q=%s&page=%d&per_page=%d", base, url.QueryEscape(query), page, perPage)
}
