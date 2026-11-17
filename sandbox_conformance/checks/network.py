from __future__ import annotations

from ..provider import UnsupportedFeature
from .base import Check, CheckContext
from .probes import METADATA_IP, classify_dns, classify_tcp, dns_probe, tcp_probe

EGRESS_TARGETS = [("1.1.1.1", 443), ("8.8.8.8", 53), ("example.com", 443)]
DENIED_UNDER_ALLOWLIST = [("example.org", 443), ("1.1.1.1", 443)]


def _tcp(ctx: CheckContext, sandbox, host: str, port: int) -> str:
    _, out, _ = ctx.run(sandbox, tcp_probe(host, port), label=f"tcp-probe {host}:{port}")
    return classify_tcp(out)


def _require_conclusive(ctx: CheckContext, verdicts: dict[str, str]) -> None:
    if all(v == "inconclusive" for v in verdicts.values()):
        ctx.skip("probe could not run (python3 missing from the sandbox template?)")


def deny_all_egress(ctx: CheckContext) -> None:
    sandbox = ctx.create(network_policy="deny-all")
    verdicts = {f"{h}:{p}": _tcp(ctx, sandbox, h, p) for h, p in EGRESS_TARGETS}
    _require_conclusive(ctx, verdicts)
    leaked = [target for target, verdict in verdicts.items() if verdict == "connected"]
    ctx.require(not leaked, f"egress succeeded under deny-all: {leaked}")


def allowlist_honoured(ctx: CheckContext) -> None:
    host = ctx.options.get("allow_host", "example.com")
    sandbox = ctx.create(network_policy="deny-all")
    sandbox.set_network_policy("allowlist", allow=[host])
    ctx.note(f"set_network_policy('allowlist', allow=[{host!r}])")
    allowed = _tcp(ctx, sandbox, host, 443)
    denied = {f"{h}:{p}": _tcp(ctx, sandbox, h, p) for h, p in DENIED_UNDER_ALLOWLIST}
    _require_conclusive(ctx, {"allowed": allowed, **denied})
    leaked = [target for target, verdict in denied.items() if verdict == "connected"]
    ctx.require(not leaked, f"hosts outside the allowlist were reachable: {leaked}")
    ctx.require(allowed == "connected", f"allowlisted host {host}:443 was not reachable ({allowed})")


def metadata_unreachable(ctx: CheckContext) -> None:
    try:
        sandbox = ctx.create(network_policy="open")
    except UnsupportedFeature:
        sandbox = ctx.create(network_policy="deny-all")
    verdict = _tcp(ctx, sandbox, METADATA_IP, 80)
    _require_conclusive(ctx, {"metadata": verdict})
    ctx.require(
        verdict == "blocked",
        f"cloud instance metadata endpoint {METADATA_IP}:80 is reachable from the sandbox",
    )


def dns_under_deny(ctx: CheckContext) -> None:
    host = ctx.options.get("dns_host", "example.com")
    sandbox = ctx.create(network_policy="deny-all")
    _, out, _ = ctx.run(sandbox, dns_probe(host), label=f"dns-probe {host}")
    verdict = classify_dns(out)
    if verdict == "inconclusive":
        ctx.skip("probe could not run (python3 missing from the sandbox template?)")
    ctx.require(
        verdict == "unresolved",
        f"{host} resolves under deny-all; DNS may be usable as an exfiltration channel",
    )


CHECKS = [
    Check("network.deny-all-egress", "network", "deny-all blocks outbound TCP to IPs and hostnames", deny_all_egress),
    Check("network.allowlist", "network", "allowlist permits listed hosts and blocks everything else", allowlist_honoured),
    Check("network.metadata-unreachable", "network", f"Cloud metadata endpoint {METADATA_IP} is unreachable", metadata_unreachable),
    Check("network.dns-under-deny", "network", "Name resolution fails under deny-all (no DNS side channel)", dns_under_deny),
]
