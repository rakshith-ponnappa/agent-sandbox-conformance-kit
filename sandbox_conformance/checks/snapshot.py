from __future__ import annotations

from .base import Check, CheckContext
from .probes import WORKDIR


def restore_integrity(ctx: CheckContext) -> None:
    sandbox = ctx.create()
    kept, added = f"{WORKDIR}/snap-kept.txt", f"{WORKDIR}/snap-added.txt"
    sandbox.write_file(kept, b"version-1\n")
    snapshot_id = sandbox.snapshot()
    ctx.note(f"snapshot {snapshot_id}")
    sandbox.write_file(kept, b"version-2\n")
    sandbox.write_file(added, b"created after snapshot\n")
    sandbox.restore(snapshot_id)
    got = sandbox.read_file(kept)
    ctx.require(got == b"version-1\n", f"restore() did not roll back file contents: {got!r}")
    code, _, _ = ctx.run(sandbox, f"test -e {added}")
    ctx.require(code != 0, "file created after the snapshot survived restore()")


CHECKS = [
    Check("snapshot.restore-integrity", "snapshot", "restore() rolls back modified and newly created files", restore_integrity),
]
