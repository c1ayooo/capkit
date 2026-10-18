package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"

	"github.com/c1ayooo/capkit"
	"github.com/c1ayooo/capkit/adapters/auditlog"
	"github.com/c1ayooo/capkit/adapters/httpx"
	"github.com/c1ayooo/capkit/adapters/sealer"
	"github.com/c1ayooo/capkit/adapters/settings"
	"github.com/c1ayooo/capkit/all"
	"github.com/c1ayooo/capkit/gates"
	"github.com/c1ayooo/capkit/runtime"
)

func main() {
	// A local target so the example never touches the network.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello from capkit"))
	}))
	defer srv.Close()

	reg := capkit.NewRegistry()
	if err := all.RegisterHTTP(reg); err != nil {
		log.Fatal(err)
	}

	scope := gates.StaticScope("127.0.0.1")
	limiter := gates.NewLimiter()
	audit := auditlog.NewMemory()
	httpClient := httpx.New(scope, limiter, audit)
	seal, err := sealer.New([]byte("example-key"))
	if err != nil {
		log.Fatal(err)
	}

	rt, err := runtime.New(runtime.Config{
		Scope: scope, Approval: gates.AutoApprove(),
		Limiter: limiter, Audit: audit,
		HTTP: httpClient, Settings: settings.New(nil), Sealer: seal,
	}, reg)
	if err != nil {
		log.Fatal(err)
	}

	input, _ := json.Marshal(map[string]any{"url": srv.URL})
	res, err := rt.Call(context.Background(), "http_probe", input, capkit.CallContext{
		ProjectID: 1, Actor: "example",
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("tools:", len(rt.Tools()))
	fmt.Println("ok:", res.OK)
	fmt.Println("text:", res.Text)
	fmt.Println("data:", string(res.Data))
	fmt.Println("audit events:", len(audit.Events()))
}
