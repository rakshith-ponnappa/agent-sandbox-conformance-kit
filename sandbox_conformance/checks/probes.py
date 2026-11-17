"""Probe commands run inside the sandbox.

Probes print a verdict token (CONNECTED/BLOCKED, RESOLVED/UNRESOLVED) so that a
missing interpreter is distinguishable from a blocked connection. The trailing
``# probe:...`` shell comment is ignored by real shells and lets the fake
provider recognise the probe.
"""

from __future__ import annotations

import shlex

WORKDIR = "/sandbox-conformance"
METADATA_IP = "169.254.169.254"


def tcp_probe(host: str, port: int, timeout: float = 3.0) -> str:
    script = (
        "import socket\n"
        "try:\n"
        f"    socket.create_connection(({host!r}, {int(port)}), timeout={float(timeout)}).close()\n"
        "    print('CONNECTED')\n"
        "except Exception as exc:\n"
        "    print('BLOCKED:' + type(exc).__name__)\n"
    )
    return f"python3 -c {shlex.quote(script)} # probe:tcp {host} {int(port)}"


def dns_probe(host: str) -> str:
    script = (
        "import socket\n"
        "try:\n"
        f"    socket.getaddrinfo({host!r}, 443)\n"
        "    print('RESOLVED')\n"
        "except Exception as exc:\n"
        "    print('UNRESOLVED:' + type(exc).__name__)\n"
    )
    return f"python3 -c {shlex.quote(script)} # probe:dns {host}"


PS_PROBE = (
    "(ps auxww 2>/dev/null || for p in /proc/[0-9]*; do "
    "tr '\\0' ' ' < \"$p/cmdline\" 2>/dev/null; echo; done) # probe:ps"
)

GIT_CLONE_PROBE = (
    "command -v git >/dev/null 2>&1 || exit 127; "
    f"d={WORKDIR}/git; rm -rf \"$d\" && mkdir -p \"$d/src\" && cd \"$d/src\" && git init -q && "
    "git -c user.email=conformance@example.invalid -c user.name=conformance "
    "commit -q --allow-empty -m init && git clone -q \"$d/src\" \"$d/dst\" && echo CLONED "
    "# probe:git-clone"
)


def classify_tcp(stdout: str) -> str:
    if "CONNECTED" in stdout:
        return "connected"
    if "BLOCKED:" in stdout:
        return "blocked"
    return "inconclusive"


def classify_dns(stdout: str) -> str:
    if "UNRESOLVED:" in stdout:
        return "unresolved"
    if "RESOLVED" in stdout:
        return "resolved"
    return "inconclusive"
