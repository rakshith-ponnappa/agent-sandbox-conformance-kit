from __future__ import annotations

import hashlib

from .base import Check, CheckContext
from .probes import WORKDIR


def _first_difference(a: bytes, b: bytes) -> int:
    for index, (x, y) in enumerate(zip(a, b)):
        if x != y:
            return index
    return min(len(a), len(b))


def text_roundtrip(ctx: CheckContext) -> None:
    sandbox = ctx.create()
    path = f"{WORKDIR}/text.txt"
    payload = "conformance \u2713 \u00fcn\u00efc\u00f6d\u00e9\nline two\n".encode("utf-8")
    sandbox.write_file(path, payload)
    ctx.note(f"wrote {len(payload)} bytes to {path}")
    got = sandbox.read_file(path)
    ctx.require(got == payload, f"read_file returned {got!r}, expected {payload!r}")
    code, out, _ = ctx.run(sandbox, f"cat {path}")
    ctx.require(code == 0 and out.encode("utf-8") == payload, "file written via write_file() is not visible to processes")


def binary_roundtrip(ctx: CheckContext) -> None:
    sandbox = ctx.create()
    path = f"{WORKDIR}/blob.bin"
    payload = bytes(range(256)) * 64 + b"\x00\r\n\x1a\xff\xfe"
    sandbox.write_file(path, payload)
    got = sandbox.read_file(path)
    ctx.note(
        f"sha256 sent={hashlib.sha256(payload).hexdigest()} received={hashlib.sha256(got).hexdigest()} "
        f"len sent={len(payload)} received={len(got)}"
    )
    ctx.require(got == payload, f"binary payload corrupted; first difference at byte {_first_difference(got, payload)}")


CHECKS = [
    Check("filesystem.text-roundtrip", "filesystem", "write_file/read_file round-trip for UTF-8 text", text_roundtrip),
    Check("filesystem.binary-roundtrip", "filesystem", "write_file/read_file is binary safe (all 256 byte values)", binary_roundtrip),
]
