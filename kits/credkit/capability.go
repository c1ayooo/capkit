package credkit

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/c1ayooo/capkit"
)

// Kit holds the injected ports for credential-use verification.
type Kit struct {
	Fetcher capkit.Fetcher
	// Endpoints optionally overrides vendor STS/IAM endpoints per provider
	// (e.g. a sovereign-cloud host). Empty values fall back to CloudEndpoints.
	Endpoints map[string]string
}

// New builds a credential kit. The host injects a Fetcher so cloud verification
// still respects proxy/timeout/rate/audit policy.
func New(fetcher capkit.Fetcher) *Kit { return &Kit{Fetcher: fetcher} }

// NewCapability is the registry constructor: it satisfies capkit.Spec.New.
func NewCapability(deps capkit.Deps) (capkit.Capability, error) {
	return New(deps.Fetcher), nil
}

// Manifest exposes the credential-use tool surface. These tools verify that a
// discovered credential works; they do not discover vulnerabilities.
func (k *Kit) Manifest() capkit.Manifest {
	return capkit.Manifest{
		Name: "credkit", Version: "0.1.0", APIVersion: "v1",
		Requires: []string{"fetcher"},
		Tools: []capkit.ToolSpec{
			{
				Name:        "credential_verify_cloud",
				Description: "Verify a cloud AK/SK with the provider's minimal-read STS/IAM call (aliyun/tencent/aws/huawei/volc). Returns validity, account identity and read-only permission surface. Verify-only; no cloud operation is performed.",
				InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "provider":{"type":"string","enum":["aliyun","tencent","aws","huawei","volc"]},
    "access_key":{"type":"string"},
    "secret_key":{"type":"string"}
  },
  "required":["provider","access_key","secret_key"]
}`),
				Risk:           capkit.RiskLow,
				OutputSchema:   json.RawMessage(`{"type":"object","properties":{"valid":{"type":"boolean"},"provider":{"type":"string"},"account":{"type":"string"},"message":{"type":"string"}}}`),
				ExtractTargets: func(json.RawMessage) ([]capkit.Target, error) { return nil, nil },
			},
			{
				Name:        "credential_verify_db",
				Description: "Verify a database credential with a live read-only connection: postgres (current_user/version/permission surface) and redis (raw PING/AUTH/INFO; reachable-without-auth means unauthenticated access). mysql/mongo are unsupported and return an explicit error. No write operation is performed.",
				InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "type":{"type":"string","enum":["postgres","redis"]},
    "host":{"type":"string"},
    "port":{"type":"integer"},
    "username":{"type":"string"},
    "password":{"type":"string"},
    "database":{"type":"string","description":"postgres optional (default postgres)"}
  },
  "required":["type","host"]
}`),
				Risk:           capkit.RiskMedium,
				OutputSchema:   json.RawMessage(`{"type":"object","properties":{"valid":{"type":"boolean"},"engine":{"type":"string"},"version":{"type":"string"},"message":{"type":"string"}}}`),
				ExtractTargets: hostPortTargets,
			},
			{
				Name:        "credential_verify_ssh",
				Description: "Verify an SSH credential with a live read-only connection: authenticate, then id (user/groups) and sudo -n true (passwordless sudo, high risk). Password or PEM private key. No write operation is performed.",
				InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "host":{"type":"string"},
    "port":{"type":"integer"},
    "username":{"type":"string"},
    "password":{"type":"string"},
    "private_key":{"type":"string","description":"PEM private key (either this or password)"}
  },
  "required":["host","username"]
}`),
				Risk:           capkit.RiskMedium,
				OutputSchema:   json.RawMessage(`{"type":"object","properties":{"valid":{"type":"boolean"},"banner":{"type":"string"},"message":{"type":"string"}}}`),
				ExtractTargets: hostPortTargets,
			},
		},
	}
}

// Call routes one tool invocation.
func (k *Kit) Call(ctx context.Context, call capkit.Call) (capkit.Result, error) {
	switch call.Tool {
	case "credential_verify_cloud":
		return k.verifyCloud(ctx, call.Input)
	case "credential_verify_db":
		return k.verifyDB(ctx, call.Input)
	case "credential_verify_ssh":
		return k.verifySSH(ctx, call.Input)
	default:
		return capkit.FailResult(fmt.Errorf("unknown tool %s", call.Tool)), nil
	}
}

func (k *Kit) verifyCloud(ctx context.Context, input json.RawMessage) (capkit.Result, error) {
	var in struct {
		Provider  string `json:"provider"`
		AccessKey string `json:"access_key"`
		SecretKey string `json:"secret_key"`
	}
	if err := json.Unmarshal(input, &in); err != nil {
		return capkit.FailResult(fmt.Errorf("invalid input: %w", err)), nil
	}
	res, err := k.Verify(ctx, in.Provider, in.AccessKey, in.SecretKey)
	if err != nil {
		return capkit.FailResult(err), nil
	}
	return capkit.DataResult(res)
}

func (k *Kit) verifyDB(ctx context.Context, input json.RawMessage) (capkit.Result, error) {
	var in DBProbeInput
	if err := json.Unmarshal(input, &in); err != nil {
		return capkit.FailResult(fmt.Errorf("invalid input: %w", err)), nil
	}
	res, err := VerifyDB(ctx, in)
	if err != nil {
		return capkit.FailResult(err), nil
	}
	return capkit.DataResult(res)
}

func (k *Kit) verifySSH(ctx context.Context, input json.RawMessage) (capkit.Result, error) {
	var in SSHProbeInput
	if err := json.Unmarshal(input, &in); err != nil {
		return capkit.FailResult(fmt.Errorf("invalid input: %w", err)), nil
	}
	res, err := VerifySSH(ctx, in)
	if err != nil {
		return capkit.FailResult(err), nil
	}
	return capkit.DataResult(res)
}

// hostPortTargets extracts a host:port target from a db/ssh tool input.
func hostPortTargets(input json.RawMessage) ([]capkit.Target, error) {
	var in struct {
		Host string `json:"host"`
		Port int    `json:"port"`
	}
	if err := json.Unmarshal(input, &in); err != nil {
		return nil, err
	}
	host := strings.TrimSpace(in.Host)
	if host == "" {
		return nil, nil
	}
	hostport := host
	if in.Port > 0 {
		hostport = net.JoinHostPort(host, strconv.Itoa(in.Port))
	}
	t, err := capkit.TargetFromString(0, hostport)
	if err != nil {
		// Fall back to a bare host target when the host isn't host:port shaped.
		return []capkit.Target{{Kind: capkit.TargetHost, Host: host}}, nil
	}
	return []capkit.Target{t}, nil
}
