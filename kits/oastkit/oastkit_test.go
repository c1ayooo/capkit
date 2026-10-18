package oastkit

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/c1ayooo/capkit"
)

type fakeFetcher struct {
	responses []*capkit.Response
	requests  []capkit.Request
}

func (f *fakeFetcher) Fetch(_ context.Context, req capkit.Request) (*capkit.Response, error) {
	f.requests = append(f.requests, req)
	if len(f.responses) == 0 {
		return &capkit.Response{Status: 500}, nil
	}
	res := f.responses[0]
	f.responses = f.responses[1:]
	return res, nil
}

func TestOastDomainAndRecords(t *testing.T) {
	f := &fakeFetcher{responses: []*capkit.Response{
		{Status: 200, Body: []byte("abc.dnslog.cn"), Headers: map[string][]string{"Set-Cookie": {"PHPSESSID=1"}}},
		{Status: 200, Body: []byte(`["1.2.3.4","5.6.7.8"]`)},
	}}
	kit := New(capkit.Deps{Fetcher: f})
	res, err := kit.Call(context.Background(), capkit.Call{Tool: "oast_get_domain", Input: json.RawMessage(`{}`)})
	if err != nil || !res.OK {
		t.Fatalf("get domain: %v %+v", err, res)
	}
	var d struct {
		Domain string `json:"domain"`
	}
	if err := json.Unmarshal(res.Data, &d); err != nil || d.Domain != "abc.dnslog.cn" {
		t.Fatalf("domain = %+v err=%v", d, err)
	}
	res, err = kit.Call(context.Background(), capkit.Call{
		Tool:  "oast_get_records",
		Input: json.RawMessage(`{"domain":"abc.dnslog.cn"}`),
	})
	if err != nil || !res.OK {
		t.Fatalf("get records: %v %+v", err, res)
	}
	var r struct {
		Records []string `json:"records"`
		Count   int      `json:"count"`
	}
	if err := json.Unmarshal(res.Data, &r); err != nil || r.Count != 2 {
		t.Fatalf("records = %+v err=%v", r, err)
	}
	if len(f.requests) != 2 || !strings.Contains(f.requests[1].Headers["Cookie"], "PHPSESSID=1") {
		t.Fatalf("cookie not forwarded: %+v", f.requests)
	}
}

func TestParseRecordsLines(t *testing.T) {
	got := parseRecords([]byte("1.2.3.4%\n5.6.7.8%\n"))
	if len(got) != 2 || got[0] != "1.2.3.4" {
		t.Fatalf("records = %+v", got)
	}
}
