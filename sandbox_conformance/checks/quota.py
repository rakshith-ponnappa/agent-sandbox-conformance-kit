from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from .base import Check, CheckContext


def parallel_teardown(ctx: CheckContext) -> None:
    count = int(ctx.options.get("parallel", 4))
    list_active = getattr(ctx.provider, "list_active", None)
    before = set(list_active()) if list_active else set()
    created, refused = [], []
    try:
        with ThreadPoolExecutor(max_workers=count) as pool:
            futures = [pool.submit(ctx.create) for _ in range(count)]
            for future in as_completed(futures):
                try:
                    created.append(future.result())
                except Exception as exc:
                    refused.append(f"{type(exc).__name__}: {exc}")
        ctx.note(f"requested {count} parallel sandboxes: created {len(created)}, refused {len(refused)}")
        for reason in refused:
            ctx.note(f"create refused: {reason}")
        ctx.require(created, "no sandbox could be created")
        for sandbox in created:
            code, out, _ = ctx.run(sandbox, "echo quota-ok")
            ctx.require(code == 0 and "quota-ok" in out, f"sandbox {sandbox.id} did not run a command")
    finally:
        errors = ctx.cleanup()
    ctx.require(not errors, f"teardown failed: {errors}")
    if list_active:
        leftovers = sorted(set(list_active()) - before)
        ctx.require(not leftovers, f"sandboxes still active after parallel teardown: {leftovers}")


CHECKS = [
    Check(
        "quota.parallel-teardown",
        "quota",
        "N parallel creates succeed or are cleanly refused, and all are torn down",
        parallel_teardown,
    ),
]
