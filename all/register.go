// Package all is the batteries-included registration entry point for the
// reusable kits. The granular Register* helpers let a host register only what
// its ports support; RegisterFull is the one-shot that registers everything and
// therefore requires every port (including a SessionManager for the
// session-driven kits).
package all

import (
	"github.com/c1ayooo/capkit"
	"github.com/c1ayooo/capkit/kits/avkit"
	"github.com/c1ayooo/capkit/kits/cleanupkit"
	"github.com/c1ayooo/capkit/kits/cloudkit"
	"github.com/c1ayooo/capkit/kits/containerkit"
	"github.com/c1ayooo/capkit/kits/credkit"
	"github.com/c1ayooo/capkit/kits/enterprisekit"
	"github.com/c1ayooo/capkit/kits/exploitkit"
	"github.com/c1ayooo/capkit/kits/fingerprintkit"
	"github.com/c1ayooo/capkit/kits/githubkit"
	"github.com/c1ayooo/capkit/kits/httpkit"
	"github.com/c1ayooo/capkit/kits/icpkit"
	"github.com/c1ayooo/capkit/kits/internalnetkit"
	"github.com/c1ayooo/capkit/kits/latkit"
	"github.com/c1ayooo/capkit/kits/nucleikit"
	"github.com/c1ayooo/capkit/kits/oastkit"
	"github.com/c1ayooo/capkit/kits/persistkit"
	"github.com/c1ayooo/capkit/kits/playbookkit"
	"github.com/c1ayooo/capkit/kits/privesckit"
	"github.com/c1ayooo/capkit/kits/reconkit"
	"github.com/c1ayooo/capkit/kits/shellkit"
	"github.com/c1ayooo/capkit/kits/spacemapkit"
	"github.com/c1ayooo/capkit/kits/templatekit"
	"github.com/c1ayooo/capkit/kits/toolparse"
	"github.com/c1ayooo/capkit/kits/verifykit"
)

// RegisterCred registers the credential-use kit (cloud AK/SK, db, ssh live
// verification). The runtime must be given a Fetcher (for cloud verification;
// proxy/timeout/rate/audit policy applies). db/ssh probes are direct TCP/SSH and
// rely on the host's target authorization gate.
func RegisterCred(reg *capkit.Registry) error {
	kit := credkit.New(nil)
	return reg.Add(capkit.Spec{Manifest: kit.Manifest(), New: credkit.NewCapability})
}

// RegisterHTTP registers the HTTP capability only.
func RegisterHTTP(reg *capkit.Registry) error {
	kit := httpkit.New(capkit.Deps{})
	return reg.Add(capkit.Spec{Manifest: kit.Manifest(), New: httpkit.NewCapability})
}

// RegisterNuclei registers the nuclei execution capability.
func RegisterNuclei(reg *capkit.Registry) error {
	kit := nucleikit.New(capkit.Deps{})
	return reg.Add(capkit.Spec{Manifest: kit.Manifest(), New: nucleikit.NewCapability})
}

// RegisterVerify registers verifykit. The runtime must be given a
// FingerprintProvider, a TemplateCatalog and at least one TemplateEngine.
func RegisterVerify(reg *capkit.Registry) error {
	return reg.Add(capkit.Spec{Manifest: verifykit.Manifest(), New: verifykit.NewCapability})
}

// RegisterGithub registers the GitHub secret-search kit. The runtime must be
// given a Fetcher and Settings with github.token.
func RegisterGithub(reg *capkit.Registry) error {
	kit := githubkit.New(capkit.Deps{})
	return reg.Add(capkit.Spec{Manifest: kit.Manifest(), New: githubkit.NewCapability})
}

// RegisterOAST registers the dnslog.cn OAST kit. The runtime must be given a
// Fetcher.
func RegisterOAST(reg *capkit.Registry) error {
	kit := oastkit.New(capkit.Deps{})
	return reg.Add(capkit.Spec{Manifest: kit.Manifest(), New: oastkit.NewCapability})
}

// RegisterSpacemap registers the five-engine space-mapping kit. The runtime
// must be given a Fetcher; keys come from resolvers, settings or env.
func RegisterSpacemap(reg *capkit.Registry) error {
	kit := spacemapkit.NewClient(capkit.Deps{})
	return reg.Add(capkit.Spec{Manifest: kit.Manifest(), New: spacemapkit.NewCapability})
}

// RegisterICP registers the MIIT (工信部) ICP filing lookup kit. The runtime
// must be given a Fetcher (beian.miit.gov.cn is an external data source).
func RegisterICP(reg *capkit.Registry) error {
	kit := icpkit.New(capkit.Deps{})
	return reg.Add(capkit.Spec{Manifest: kit.Manifest(), New: icpkit.NewCapability})
}

// RegisterFingerprint registers the fingerprint detection tool. The runtime
// must supply an HTTPDoer; rules come from Deps.Fingerprints when the host
// already built a *fingerprintkit.Provider.
func RegisterFingerprint(reg *capkit.Registry) error {
	return reg.Add(capkit.Spec{Manifest: fingerprintkit.Manifest(), New: fingerprintkit.NewCapability})
}

// RegisterTemplate registers the read-only template catalog tools. Execution
// stays in the template engines (verifykit/nucleikit).
func RegisterTemplate(reg *capkit.Registry) error {
	return reg.Add(capkit.Spec{Manifest: templatekit.Manifest(), New: templatekit.NewCapability})
}

// RegisterPlaybook registers deterministic playbook execution.
func RegisterPlaybook(reg *capkit.Registry) error {
	return reg.Add(capkit.Spec{Manifest: playbookkit.Manifest(), New: playbookkit.NewCapability})
}

// RegisterRecon registers the reconnaissance pipeline. The host must wire
// providers and an AssetSink into the capability after construction.
func RegisterRecon(reg *capkit.Registry) error {
	return reg.Add(capkit.Spec{Manifest: reconkit.Manifest(), New: reconkit.NewCapability})
}

// RegisterToolParse registers the external-CLI output parsers.
func RegisterToolParse(reg *capkit.Registry) error {
	return reg.Add(capkit.Spec{Manifest: toolparse.Manifest(), New: toolparse.NewCapability})
}

// RegisterExploit registers the deterministic web-entry exploit probes
// (cmdi/ssti/lfi/sqli/ssrf + redis/msf/deser helpers). All ten tools are
// exposed to the agent. The runtime must supply an HTTPDoer; a ProcessRunner is
// needed only for msf_execute and deser_generate (otherwise those two return
// unavailable).
func RegisterExploit(reg *capkit.Registry) error {
	return reg.Add(capkit.Spec{Manifest: exploitkit.Manifest(), New: exploitkit.NewCapability})
}

// RegisterSession registers the foothold/session tools (session_open/exec/
// upload/download, tunnel_open, list, close). The runtime must supply a
// capkit.SessionManager (Deps.Sessions) with at least one opener registered.
func RegisterSession(reg *capkit.Registry) error {
	return reg.Add(capkit.Spec{Manifest: shellkit.Manifest(), New: shellkit.NewCapability})
}

// RegisterPostExploitation registers the five session-driven kits: privesckit
// (enumeration + advice), internalnetkit, persistkit, cleanupkit and avkit
// (AV/EDR identification). Every one of them resolves its target from
// Deps.Sessions, so they share the same gate chain (scope → approval →
// ratelimit → audit) as session_open.
//
// cleanupkit never runs without an explicit preview + plan_id + confirm, and
// persistkit's apply tool requires confirm=true; both are additionally gated by
// the runtime's approval gate because they are high risk.
func RegisterPostExploitation(reg *capkit.Registry) error {
	kits := []struct {
		name string
		fn   func(capkit.Deps) (capkit.Capability, error)
	}{
		{"privesckit", privesckit.NewCapability},
		{"internalnetkit", internalnetkit.NewCapability},
		{"persistkit", persistkit.NewCapability},
		{"cleanupkit", cleanupkit.NewCapability},
		{"avkit", avkit.NewCapability},
	}
	for _, k := range kits {
		c, err := k.fn(capkit.Deps{})
		if err != nil {
			return err
		}
		if err := reg.Add(capkit.Spec{Manifest: c.Manifest(), New: k.fn}); err != nil {
			return err
		}
	}
	return nil
}

// RegisterContainer registers the container/k8s detection and escape-triage
// kit. The runtime must supply an HTTPDoer (for the four network probes) and,
// for container_escape_check, a capkit.SessionManager.
func RegisterContainer(reg *capkit.Registry) error {
	return reg.Add(capkit.Spec{Manifest: containerkit.Manifest(), New: containerkit.NewCapability})
}

// RegisterLateral registers the lateral-movement argv builders (psexec/wmiexec/
// smbexec, pass-the-hash, WinRM, Kerberoast/AS-REP/DCSync). Every tool is a
// subprocess invocation, so the runtime must supply a ProcessRunner; the
// impacket/NetExec binaries themselves stay outside this module (docs §6.2:
// copyleft code is never imported).
func RegisterLateral(reg *capkit.Registry) error {
	return reg.Add(capkit.Spec{Manifest: latkit.Manifest(), New: latkit.NewCapability})
}

// RegisterCloud registers the five cloud-asset tools (cloud_ak_verify,
// cloud_asset_list, cloud_iam_list, cloud_storage_list, cloud_run_command). The
// runtime must supply an HTTPDoer; credentials arrive per call and are never
// retained, and every vendor request stays behind the host's scope/rate/audit
// gates. cloud_run_command is high risk and therefore approval-gated.
//
// Provider coverage is honest rather than uniform: AWS, Alibaba and Tencent
// implement all five; Huawei implements verify, asset listing and IAM listing,
// and reports cloud_storage_list / cloud_run_command as unsupported because the
// OBS SDK and the ECS cloud-assistant API are outside huaweicloud-sdk-go-v3.
func RegisterCloud(reg *capkit.Registry) error {
	kit := cloudkit.New(capkit.Deps{})
	return reg.Add(capkit.Spec{Manifest: kit.Manifest(), New: cloudkit.NewCapability})
}

// RegisterEnterprise registers the enterprise-data-source tools. The resolver
// is host-supplied (it resolves cookies/keys from the host's session vault), so
// this helper takes it explicitly rather than reading it from capkit.Deps.
func RegisterEnterprise(reg *capkit.Registry, resolver enterprisekit.ProviderResolver) error {
	kit := enterprisekit.NewKit(resolver)
	return reg.Add(capkit.Spec{
		Manifest: kit.Manifest(),
		New:      func(capkit.Deps) (capkit.Capability, error) { return kit, nil },
	})
}

// Register registers the minimal, port-free baseline: the HTTP probe and the
// nuclei runner. Everything else declares a port and is registered by the more
// specific helpers (or by RegisterFull).
func Register(reg *capkit.Registry) error {
	if err := RegisterHTTP(reg); err != nil {
		return err
	}
	return RegisterNuclei(reg)
}

// RegisterFull additionally registers verifykit, githubkit, oastkit,
// spacemapkit, icpkit, exploitkit, shellkit's session tools, the post-
// exploitation kits (privesc/internalnet/persist/cleanup/av), containerkit,
// latkit and cloudkit. Only use it when the host supplies fingerprints/templates/
// template_engines/fetcher/settings/a SessionManager/a ProcessRunner/an HTTPDoer
// and has an approval gate configured (the session, lateral-movement, exploit
// and cloud-assistant tools are high risk).
//
// reconkit and enterprisekit are deliberately NOT here: both need host-injected
// collaborators that capkit.Deps cannot carry (an AssetSink/provider set for
// recon, a ProviderResolver for enterprise), so hosts register them with
// RegisterRecon / RegisterEnterprise instead.
func RegisterFull(reg *capkit.Registry) error {
	if err := Register(reg); err != nil {
		return err
	}
	if err := RegisterVerify(reg); err != nil {
		return err
	}
	if err := RegisterGithub(reg); err != nil {
		return err
	}
	if err := RegisterOAST(reg); err != nil {
		return err
	}
	if err := RegisterSpacemap(reg); err != nil {
		return err
	}
	if err := RegisterICP(reg); err != nil {
		return err
	}
	if err := RegisterFingerprint(reg); err != nil {
		return err
	}
	if err := RegisterTemplate(reg); err != nil {
		return err
	}
	if err := RegisterToolParse(reg); err != nil {
		return err
	}
	if err := RegisterPlaybook(reg); err != nil {
		return err
	}
	if err := RegisterExploit(reg); err != nil {
		return err
	}
	if err := RegisterSession(reg); err != nil {
		return err
	}
	if err := RegisterContainer(reg); err != nil {
		return err
	}
	if err := RegisterLateral(reg); err != nil {
		return err
	}
	if err := RegisterPostExploitation(reg); err != nil {
		return err
	}
	if err := RegisterCloud(reg); err != nil {
		return err
	}
	return RegisterCred(reg)
}
