package reconkit_test

import (
	"context"
	"strings"
	"testing"

	"github.com/c1ayooo/capkit/gates"
	"github.com/c1ayooo/capkit/kits/reconkit"
)

type fakeSubs struct{}

func (fakeSubs) Subdomains(context.Context, string) ([]string, error) {
	return []string{"a.example.com", "b.example.com", "a.example.com"}, nil
}

type fakeHTTP struct{}

func (fakeHTTP) Probe(_ context.Context, url string) (*reconkit.HTTPInfo, error) {
	return &reconkit.HTTPInfo{URL: url, Status: 200, Title: "Example", Server: "nginx"}, nil
}

type memSink struct{ assets []reconkit.Asset }

func (m *memSink) Emit(_ context.Context, a reconkit.Asset) error {
	m.assets = append(m.assets, a)
	return nil
}

func TestPipelineSubdomainAndHTTP(t *testing.T) {
	sink := &memSink{}
	p := &reconkit.Pipeline{
		Subs: fakeSubs{}, HTTP: fakeHTTP{}, Sink: sink,
		Scope: gates.StaticScope("example.com"), Limiter: gates.NewLimiter(),
	}
	stats, err := p.Run(context.Background(), reconkit.Options{
		Domains: []string{"example.com"}, EnableSubdomain: true, EnableHTTP: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Subdomains != 2 || stats.HTTP != 3 || stats.Assets != 6 {
		t.Fatalf("stats = %+v", stats)
	}
	if len(sink.assets) != 6 {
		t.Fatalf("assets = %d", len(sink.assets))
	}
}

func TestPipelineScopeDenied(t *testing.T) {
	sink := &memSink{}
	p := &reconkit.Pipeline{
		Subs: fakeSubs{}, Sink: sink,
		Scope: gates.StaticScope("example.com"), Limiter: gates.NewLimiter(),
	}
	stats, err := p.Run(context.Background(), reconkit.Options{
		Domains: []string{"evil.com"}, EnableSubdomain: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(sink.assets) != 0 || stats.Subdomains != 0 {
		t.Fatalf("stats=%+v assets=%d", stats, len(sink.assets))
	}
	if len(stats.Errors) == 0 || !strings.Contains(stats.Errors[0], "scope") {
		t.Fatalf("errors = %v", stats.Errors)
	}
}
