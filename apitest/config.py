from __future__ import annotations

import os
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import yaml

ALL_STAGES = ["lint", "conformance", "types", "authz", "zap"]


@dataclass
class Config:
    spec: str = ""
    base_url: str = ""
    headers: dict[str, str] = field(default_factory=dict)  # user A
    headers_b: dict[str, str] = field(default_factory=dict)  # user B, for BOLA
    stages: list[str] = field(default_factory=lambda: list(ALL_STAGES))
    max_examples: int = 50
    fail_on: str = "high"
    out_dir: str = "reports"
    no_mutating_authz: bool = False
    # The Swagger can't be trusted: findings that only show a mismatch with it become info ("Swagger problems")
    lenient_spec: bool = False
    # Working requests per API, used instead of the Swagger's examples: {"POST /x": {"body", "path", "query"}}
    examples: dict[str, dict] = field(default_factory=dict)
    exclude_paths: list[str] = field(default_factory=list)
    bola: list[dict] = field(default_factory=list)
    timeout: float = 15.0
    types_max_fields: int = 60  # per operation, for the wrong-type probing stage
    operations: list[str] = field(default_factory=list)  # "GET /path" to test; empty = all
    title: str = ""  # shown in reports (the project name in the web UI)
    # Automatic login (see auth.LoginConfig); secrets inside are ${VAR} references
    login_a: dict | None = None
    login_b: dict | None = None
    variables: dict[str, str] = field(default_factory=dict, repr=False, compare=False)  # project secrets for ${NAME}
    auth_a: object | None = field(default=None, repr=False, compare=False)  # auth.TokenProvider, set by the runner
    auth_b: object | None = field(default=None, repr=False, compare=False)
    cancel: threading.Event | None = field(default=None, repr=False, compare=False)
    on_progress: Callable[[dict], None] | None = field(default=None, repr=False, compare=False)
    testlog: object | None = field(default=None, repr=False, compare=False)  # testlog.TestLog, set by the runner
    zap_image: str = "ghcr.io/zaproxy/zaproxy:stable"
    zap_threads: int = 0         # parallel requests to the API; 0 = sized from Docker's CPUs
    zap_rule_minutes: int = 2    # per active-scan rule, so all ~20 rules get a turn on big APIs; 0 = no limit
    zap_max_minutes: int = 50    # whole active scan; ZAP then reports what it found so far; 0 = no limit


ENV_REF = re.compile(r"\$\{(\w+)\}")


def expand_env(value: str, variables: dict[str, str] | None = None) -> str:
    """Replace ${NAME} with the project's secret of that name (web UI), else the environment
    variable (CLI/CI). Keeps passwords and tokens out of project and config files."""
    def sub(m):
        name = m.group(1)
        if variables and name in variables:
            return variables[name]
        if name in os.environ:
            return os.environ[name]
        raise ValueError(f"{name} has no value. Set it under the project's Settings → Test users "
                         f"(Secrets), or as an environment variable")
    return ENV_REF.sub(sub, value)


def parse_header(h: str) -> tuple[str, str]:
    name, _, value = (s.strip() for s in h.partition(":"))
    if not name or not value:
        raise ValueError(f"Header must look like 'Name: value', got {h!r}")
    return name, value


def load_config(path: str | None) -> Config:
    if not path:
        return Config()
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{path}: the config must be a YAML mapping of keys (spec:, base_url:, ...), "
                         f"not a {type(data).__name__}")
    cfg = Config()
    for k, v in data.items():
        if not hasattr(cfg, k) or k in ("cancel", "on_progress", "testlog", "auth_a", "auth_b", "variables"):
            raise ValueError(f"Unknown config key: {k}")
        setattr(cfg, k, v)
    cfg.headers = {k: expand_env(str(v)) for k, v in (cfg.headers or {}).items()}
    cfg.headers_b = {k: expand_env(str(v)) for k, v in (cfg.headers_b or {}).items()}
    return cfg
