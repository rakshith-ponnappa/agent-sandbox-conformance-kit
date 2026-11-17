# Security Policy

## Reporting a vulnerability in this kit

Please do **not** open a public issue. Use GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
("Report a vulnerability" under the repository's **Security** tab).

Include the affected version or commit, reproduction steps and impact. You can
expect an acknowledgement within 7 days and a fix or mitigation plan within 30
days for confirmed issues.

Examples of in-scope issues:

- A check that reports `PASS` when the property is actually violated (false negative)
- Secrets or canaries leaking into reports despite redaction
- Teardown paths that can leave sandboxes running
- The `local-docker` adapter exposing secret values on the host command line

## Findings about a sandbox provider

A `FAIL` from this kit against a third-party sandbox may be a vulnerability in
**that provider**, not in this project. Report it privately to the vendor first,
using their published security contact or bug bounty programme, and allow a
reasonable remediation window (90 days is a common default) before any public
disclosure. Only test infrastructure and accounts you are authorised to use.

## Supported versions

Only the latest release on `main` receives security fixes.
