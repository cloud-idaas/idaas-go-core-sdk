# Security Policy

## Reporting a Vulnerability

The IDaaS Go Core SDK team takes security vulnerabilities seriously. We
appreciate your efforts to responsibly disclose your findings.

**Do not open public GitHub issues for security vulnerabilities.**

Instead, please report them privately via
[GitHub Security Advisories](https://github.com/cloud-idaas/idaas-go-core-sdk/security/advisories/new).
Include:

- A description of the vulnerability and its impact.
- The affected version(s) (check the version with `http.GetSdkVersion()` or the
  release tag).
- A minimal reproduction (code sample, request/response, or steps). Redact any
  real credentials — **never send real IDaaS client secrets, private keys, or
  tokens**. Replace them with `example.com` placeholders.
- Your assessment of severity and any suggested remediation.

## Response Timeline

We will acknowledge receipt of your report within **48 hours** and keep you
informed as we triage and remediate. Coordinated disclosure timelines are
agreed case by case; we default to publishing a CVE and a patched release once
a fix is widely available.

## Scope

This policy covers the SDK source in this repository, including the main
module and the `samples/` example module. It does **not** cover the
`logger/adapters/slog` nested module (which is not published and is intended to
be copied into consumer projects — see its README).

Vulnerabilities in the IDaaS service itself, or in unrelated Aliyun products,
must be reported through the
[Aliyun security channel](https://www.alibabacloud.com/trust-center), not here.

## Supported Versions

The SDK is in **v0.x beta**. There are no Long-Term-Support (LTS) lines yet.

| Version | Supported          | Notes |
|---------|--------------------|-------|
| `v0.x`  | ✅ Security fixes  | Current beta line; upgrade to the latest `v0.x` tag for security fixes. |
| `< v0.x` (none) | —          | No earlier published releases. |

Once `v1.0` is released, the supported-versions table will be updated to
reflect the LTS policy for the `v1.x` line. During the `v0.x` beta, the public
API may change between minor releases; consumers should pin a specific tag and
upgrade deliberately.

## Security-Related Design Notes

- HTTP clients disable TLS renegotiation and never disable certificate
  verification by default.
- `secureCheckRedirect` strips the request body, `Authorization`, `Cookie`,
  and `Content-Type` headers when a redirect crosses hosts, preventing
  replay of `client_secret` / tokens to an attacker-controlled host.
- Device-flow logs never persist `user_code`; only `verification_uri` is logged
  (RFC 8628 §5.4), while `verification_uri_complete` is used solely to open the
  browser.
- Local human-credential cache files are written under `0700` directories.
- `OpenBrowser` only accepts `http`/`https` schemes.
