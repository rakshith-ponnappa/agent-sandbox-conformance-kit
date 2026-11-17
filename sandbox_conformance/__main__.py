"""CLI: ``python -m sandbox_conformance {run,list}``."""

from __future__ import annotations

import argparse
import signal
import sys
from pathlib import Path
from typing import Sequence

from . import __version__
from .checks import ALL_CHECKS, CATEGORIES
from .providers import PROFILES, PROVIDER_NAMES, FakeProvider, LocalDockerProvider
from .runner import ICONS, CheckResult, render_json, render_markdown, run_checks, select_checks


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m sandbox_conformance",
        description="Black-box conformance, network-policy and quota-edge tests for AI agent code sandboxes.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="run checks against a provider")
    run.add_argument("--provider", required=True, choices=PROVIDER_NAMES)
    run.add_argument(
        "--only",
        action="append",
        metavar="CATEGORY",
        help=f"restrict to a category (repeatable or comma-separated): {', '.join(CATEGORIES)}",
    )
    run.add_argument("--json", type=Path, metavar="PATH", help="write the JSON report here")
    run.add_argument("--md", type=Path, metavar="PATH", help="write the Markdown report here")
    run.add_argument("--image", default=None, help="container image for local-docker (default python:3.12-slim)")
    run.add_argument("--fake-profile", default="conformant", choices=sorted(PROFILES))
    run.add_argument("--parallel", type=int, default=4, help="sandboxes for the quota check (default 4)")
    run.add_argument("--allow-host", default="example.com", help="host used by the allowlist check")

    sub.add_parser("list", help="print the check catalogue")
    return parser


def _build_provider(args: argparse.Namespace):
    if args.provider == "fake":
        return FakeProvider(profile=args.fake_profile)
    return LocalDockerProvider(image=args.image) if args.image else LocalDockerProvider()


def _print_result(result: CheckResult) -> None:
    detail = f" - {result.message}" if result.message else ""
    print(f"{ICONS[result.status]} {result.status.value:<5} {result.id}{detail}", flush=True)


def _cmd_list() -> int:
    width = max(len(check.id) for check in ALL_CHECKS) + 2
    print(f"{'CHECK':<{width}}{'CATEGORY':<12}DESCRIPTION")
    for check in ALL_CHECKS:
        print(f"{check.id:<{width}}{check.category:<12}{check.description}")
    return 0


def _cmd_run(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    categories = [c.strip() for item in (args.only or []) for c in item.split(",") if c.strip()]
    try:
        checks = select_checks(categories)
    except ValueError as exc:
        parser.error(str(exc))
    provider = _build_provider(args)
    options = {"parallel": args.parallel, "allow_host": args.allow_host}

    def _terminate(signum, _frame):
        raise SystemExit(128 + signum)

    previous = signal.signal(signal.SIGTERM, _terminate)
    try:
        report = run_checks(provider, checks, options=options, on_result=_print_result)
    finally:
        signal.signal(signal.SIGTERM, previous)

    if args.json:
        args.json.write_text(render_json(report), encoding="utf-8")
    if args.md:
        args.md.write_text(render_markdown(report), encoding="utf-8")
    summary = report.summary()
    print(f"\n{report.provider}: " + ", ".join(f"{k}={v}" for k, v in summary.items()))
    return 0 if report.ok else 1


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "list":
        return _cmd_list()
    return _cmd_run(args, parser)


if __name__ == "__main__":
    sys.exit(main())
