from __future__ import annotations

import argparse
import sys

import httpx
import yaml

from .auth import LoginError
from .config import ALL_STAGES, expand_env, load_config, parse_header
from .models import SEVERITIES
from .runner import STAGE_FUNCS, failed, run_pipeline


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sprat", description="Test any REST API from its Swagger/OpenAPI spec")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="run the selected test stages")
    r.add_argument("spec", nargs="?", help="Swagger/OpenAPI URL or file (or set `spec:` in --config)")
    r.add_argument("--config", help="YAML config file")
    r.add_argument("--base-url", help="API base URL (default: taken from the spec)")
    r.add_argument("-H", "--header", action="append", default=[], help="'Name: value' for user A (repeatable)")
    r.add_argument("--header-b", action="append", default=[], help="'Name: value' for user B, used for BOLA tests")
    r.add_argument("--stages", help=f"comma list from: {','.join(ALL_STAGES)}")
    r.add_argument("--max-examples", type=int)
    r.add_argument("--fail-on", choices=SEVERITIES, help="exit 1 if any finding is at/above this severity")
    r.add_argument("--out", help="output directory (default: reports)")
    r.add_argument("--no-mutating-authz", action="store_true", help="authz stage: only send GET/HEAD/OPTIONS")
    r.add_argument("--lenient-spec", action="store_true",
                   help="the Swagger isn't reliable: report mismatches with it as info (Swagger problems), "
                        "keep crashes, auth, type and security findings")
    r.add_argument("--op", action="append", default=[], metavar='"METHOD /path"',
                   help="only test this operation (repeatable), e.g. --op \"GET /orders/{id}\"")
    d = sub.add_parser("discover", help="find the Swagger/OpenAPI documents of a running app and list its APIs")
    d.add_argument("url", help="app root, Swagger UI page, or spec URL")
    d.add_argument("-H", "--header", action="append", default=[])
    u = sub.add_parser("ui", help="start the web UI")
    u.add_argument("--host", default="127.0.0.1",
                   help="bind address (default 127.0.0.1). The UI sends requests to any URL you give it; "
                        "don't expose it on a shared network without putting auth in front.")
    u.add_argument("--port", type=int, default=8787)
    u.add_argument("--data-dir", default="reports", help="where run results are stored (default: ./reports)")
    return p


def _print_event(e: dict) -> None:
    t = e["type"]
    if t == "spec_loading":
        print(f"{e['msg']}..." if e.get("msg") else f"Loading spec: {e['spec']}")
    elif t == "spec":
        print(f"  {e['version']}, {e['operations']} operations, base URL: {e['base_url'] or '(none)'}")
    elif t == "stage_start":
        print(f"[{e['stage']}] running...", flush=True)
    elif t == "stage_end":
        print(f"[{e['stage']}] {e['status']}: {e['findings']} finding(s) {e['note']}")
    elif t == "done":
        print(f"Report: {e['report']}")


def _discover(args) -> int:
    from .discover import discover, not_found_message
    from .spec import load_spec
    headers = {k: expand_env(v) for k, v in (parse_header(h) for h in args.header)}
    res = discover(args.url, headers)
    if not res["specs"]:
        print(not_found_message(res) + " Pass the spec URL directly if it lives somewhere unusual.")
        return 1
    for s in res["specs"]:
        print(f"\n{s['title'] or '(untitled)'} {s['api_version']}  [{s['spec_version']}]  {s['url']}"
              + ("  (embedded in Swagger UI page)" if s["embedded"] else ""))
        for o in load_spec(s["url"], headers).operations:
            print(f"  {o.method.upper():7} {o.path}{'  [secured]' if o.secured else ''}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd == "ui":
        from .web.app import serve
        serve(args.host, args.port, args.data_dir)
        return 0
    if args.cmd == "discover":
        return _discover(args)
    try:
        return _run(args)
    # user errors: bad header / ${VAR} / config key / --op, unreadable spec or config, spec URL unreachable
    except (LoginError, ValueError, OSError, yaml.YAMLError, httpx.HTTPError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


def _run(args) -> int:
    cfg = load_config(args.config)
    if args.spec:
        cfg.spec = args.spec
    if args.base_url:
        cfg.base_url = args.base_url
    for h in args.header:
        k, v = parse_header(h)
        cfg.headers[k] = expand_env(v)
    for h in args.header_b:
        k, v = parse_header(h)
        cfg.headers_b[k] = expand_env(v)
    if args.stages:
        cfg.stages = [s.strip() for s in args.stages.split(",")]
    if args.max_examples:
        cfg.max_examples = args.max_examples
    if args.fail_on:
        cfg.fail_on = args.fail_on
    if args.out:
        cfg.out_dir = args.out
    if args.no_mutating_authz:
        cfg.no_mutating_authz = True
    if args.lenient_spec:
        cfg.lenient_spec = True
    if args.op:
        cfg.operations = args.op
    if not cfg.spec:
        print("error: no spec given", file=sys.stderr)
        return 2
    bad = [s for s in cfg.stages if s not in STAGE_FUNCS]
    if bad:
        print(f"error: unknown stage(s): {bad}", file=sys.stderr)
        return 2

    cfg.on_progress = lambda p: print(f"  {p['msg']}") if p["stage"] == "auth" else None
    results = run_pipeline(cfg, _print_event)
    return 1 if failed(cfg, results) else 0


if __name__ == "__main__":
    sys.exit(main())
