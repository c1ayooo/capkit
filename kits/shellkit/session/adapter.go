// adapter.go bridges the WebShell model (Session + host Executor) to the
// capkit.Session contract, so a WebShell foothold gets the same Exec/upload/
// download surface as SSH and every downstream kit works against it unchanged.
package session

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/c1ayooo/capkit"
)

// CapabilitySession wraps a WebShell Session plus its host Executor into a
// capkit.Session.
type CapabilitySession struct {
	Shell    Session
	Executor Executor
}

// Info describes the foothold without performing I/O.
func (c *CapabilitySession) Info() capkit.SessionInfo {
	host := ""
	if u, err := url.Parse(c.Shell.URL); err == nil {
		host = u.Hostname()
	}
	kind := "webshell"
	labels := []string{}
	if c.Shell.ShellType != "" {
		labels = append(labels, c.Shell.ShellType)
	}
	return capkit.SessionInfo{
		ID: c.shellID(), Kind: kind, Host: host, User: "",
		Labels: labels,
		Meta: map[string]string{
			"url": c.Shell.URL, "protocol": c.Shell.Protocol,
			"shell_type": c.Shell.ShellType, "encoding": c.Shell.Encoding,
		},
	}
}

func (c *CapabilitySession) shellID() string {
	if c.Shell.ID != 0 {
		return fmt.Sprintf("webshell-%d", c.Shell.ID)
	}
	return ""
}

// Close is a no-op: a WebShell has no connection to tear down.
func (c *CapabilitySession) Close() error { return nil }

// Exec runs a command through the WebShell executor.
func (c *CapabilitySession) Exec(ctx context.Context, cmd string, opts capkit.ExecOpts) (capkit.Output, error) {
	if c.Executor == nil {
		return capkit.Output{}, fmt.Errorf("WebShell Executor 未注入")
	}
	if strings.TrimSpace(cmd) == "" {
		return capkit.Output{}, fmt.Errorf("命令为空")
	}
	if opts.Dir != "" {
		cmd = "cd " + capkit.ShellQuote(opts.Dir) + " && " + cmd
	}
	res, err := c.Executor.Exec(ctx, c.Shell, cmd)
	if err != nil {
		return capkit.Output{}, err
	}
	out := capkit.Output{Command: cmd, Stdout: res.Output, ExitCode: 0, EvidenceID: res.TrafficID}
	if res.HTTPStatus >= 400 {
		out.ExitCode = 1
	}
	if opts.MaxOutput > 0 && len(out.Stdout) > opts.MaxOutput {
		out.Stdout, out.Truncated = out.Stdout[:opts.MaxOutput], true
	}
	return out, nil
}

// Upload writes bytes to the remote path via the WebShell file channel.
func (c *CapabilitySession) Upload(ctx context.Context, src io.Reader, remote string) error {
	if c.Executor == nil {
		return fmt.Errorf("WebShell Executor 未注入")
	}
	if strings.TrimSpace(remote) == "" {
		return fmt.Errorf("remote 路径必填")
	}
	data, err := io.ReadAll(src)
	if err != nil {
		return err
	}
	_, err = c.Executor.File(ctx, c.Shell, FileOp{Action: "write", Path: remote, Content: data})
	return err
}

// Download reads a remote path through the WebShell file channel.
func (c *CapabilitySession) Download(ctx context.Context, remote string) (io.ReadCloser, error) {
	if c.Executor == nil {
		return nil, fmt.Errorf("WebShell Executor 未注入")
	}
	res, err := c.Executor.File(ctx, c.Shell, FileOp{Action: "read", Path: remote})
	if err != nil {
		return nil, err
	}
	data := []byte(res.Output)
	// WebShell protocols often base64 the file content; decode when it looks
	// like base64 so callers get raw bytes.
	if decoded, ok := tryBase64(res.Output); ok {
		data = decoded
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func tryBase64(s string) ([]byte, bool) {
	clean := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '+', r == '/', r == '=':
			return r
		default:
			return -1
		}
	}, strings.TrimSpace(s))
	if len(clean) < 8 || len(clean)%4 != 0 {
		return nil, false
	}
	decoded, err := base64.StdEncoding.DecodeString(clean)
	if err != nil {
		return nil, false
	}
	return decoded, true
}
