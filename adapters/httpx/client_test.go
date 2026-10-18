package httpx_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/c1ayooo/capkit"
	"github.com/c1ayooo/capkit/adapters/httpx"
	"github.com/c1ayooo/capkit/gates"
)

func TestClientOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello"))
	}))
	defer srv.Close()
	c := httpx.New(gates.StaticScope("127.0.0.1"), nil, nil)
	ctx := capkit.WithCallContext(context.Background(), capkit.CallContext{ProjectID: 1})
	res, err := c.Do(ctx, capkit.Request{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != 200 || strings.TrimSpace(string(res.Body)) != "hello" {
		t.Fatalf("response = %+v", res)
	}
}

func TestClientRejectsOutOfScope(t *testing.T) {
	c := httpx.New(gates.StaticScope("127.0.0.1"), nil, nil)
	ctx := capkit.WithCallContext(context.Background(), capkit.CallContext{ProjectID: 1})
	_, err := c.Do(ctx, capkit.Request{URL: "http://example.com/"})
	if err == nil || !strings.Contains(err.Error(), capkit.CodeScopeDenied) {
		t.Fatalf("err = %v", err)
	}
}

func TestClientRejectsOutOfScopeRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.com/", http.StatusFound)
	}))
	defer srv.Close()
	c := httpx.New(gates.StaticScope("127.0.0.1"), nil, nil)
	ctx := capkit.WithCallContext(context.Background(), capkit.CallContext{ProjectID: 1})
	_, err := c.Do(ctx, capkit.Request{URL: srv.URL})
	if err == nil || !strings.Contains(err.Error(), "scope_denied") {
		t.Fatalf("err = %v", err)
	}
}
