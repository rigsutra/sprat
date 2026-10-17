"""DAST via the OWASP ZAP API scan, run in Docker."""
from __future__ import annotations

import json
import re
import shlex
import shutil
import socket
import subprocess
import time
import uuid
from pathlib import Path
from urllib.parse import urlparse, urlunparse

import httpx

from ..models import Finding, StageResult
from ..auth import LoginError, current_headers
from ..proc import Cancelled, progress, run_cmd
from ..testlog import OpMatcher, log_of

RISK = {"3": "high", "2": "medium", "1": "low", "0": "info"}
ZAP_PORT = 8090      # ZAP's proxy/API port inside the container
RENEW_AHEAD = 90     # seconds before expiry to log in again and hand ZAP the new token
RENEW_EVERY = 15     # seconds between token checks during the scan
SNAPSHOT_EVERY = 120  # seconds between saved partial reports during the scan


def _docker_ok() -> bool:
    if not shutil.which("docker"):
        return False
    return subprocess.run(["docker", "info"], capture_output=True).returncode == 0


def _docker_resources() -> tuple[int, int]:
    """CPUs and memory (MB) Docker can give a container; (0, 0) if it doesn't say."""
    try:
        p = subprocess.run(["docker", "info", "--format", "{{.NCPU}} {{.MemTotal}}"], capture_output=True,
                           text=True, timeout=30)
        cpus, mem = p.stdout.split()
        return int(cpus), int(mem) // 2**20
    except (OSError, subprocess.SubprocessError, ValueError):
        return 0, 0


def _sizing(cfg) -> tuple[int, int]:
    """ZAP's parallel requests and Java heap (MB, 0 = ZAP's default of 1/4 of memory), from what Docker has.
    Requests mostly wait on the API, so several threads per CPU, capped so a small API isn't flooded."""
    cpus, mem = _docker_resources()
    threads = cfg.zap_threads if cfg.zap_threads > 0 else min(max(cpus * 4, 8), 48) if cpus else 16
    return threads, mem // 2 if mem >= 2048 else 0


def _for_container(url: str) -> str:
    u = urlparse(url)
    if u.hostname in ("localhost", "127.0.0.1", "::1"):
        userinfo = u.netloc.rpartition("@")[0]
        netloc = (userinfo + "@" if userinfo else "") + "host.docker.internal" + (f":{u.port}" if u.port else "")
        return urlunparse(u._replace(netloc=netloc))
    return url


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _TokenRenewer:
    """ZAP sends the login token through replacer rules set at start. A scan can outlast the token, so
    during the scan this logs in again before expiry and swaps the rules through ZAP's API (its port is
    published on 127.0.0.1 only; zap-api-scan.py runs ZAP with the API key disabled)."""

    def __init__(self, cfg, port: int, headers: dict[str, str]):
        # ZAP answers API calls for http://zap/ sent through it as a proxy; a direct call to the
        # published port would be forwarded, as the port differs from the one ZAP listens on
        self.cfg, self.proxy, self.api = cfg, f"http://127.0.0.1:{port}", "http://zap/JSON/replacer/action/"
        self.sent = dict(headers)
        self.rule = {k: f"h{i}" for i, k in enumerate(headers)}  # header -> replacer rule now in ZAP
        self.stale: list[str] = []  # replaced rules still to remove from ZAP
        self.gen, self.next_check, self.warned = 0, 0.0, False

    def tick(self) -> None:
        now = time.time()
        if now < self.next_check:
            return
        self.next_check = now + RENEW_EVERY
        try:
            self.cfg.auth_a.ensure_valid_for(RENEW_AHEAD)
            want = current_headers(self.cfg)
        except LoginError as e:
            self._warn(f"Couldn't renew the token for ZAP ({e}); later requests may get 401.")
            return
        changed = {k: v for k, v in want.items() if self.sent.get(k) != v}
        if not changed and not self.stale:
            return
        try:
            with httpx.Client(proxy=self.proxy, timeout=5) as c:
                for k, v in changed.items():
                    # New rule first, old one removed after, so no request goes out without the header
                    self.gen += 1
                    new = f"h{list(want).index(k)}r{self.gen}"
                    c.get(self.api + "addRule/", params={
                        "description": new, "enabled": "true", "matchType": "REQ_HEADER", "matchRegex": "false",
                        "matchString": k, "replacement": v, "initiators": ""}).raise_for_status()
                    if k in self.rule:
                        self.stale.append(self.rule[k])
                    self.rule[k], self.sent[k] = new, v
                while self.stale:
                    c.get(self.api + "removeRule/", params={"description": self.stale[0]}).raise_for_status()
                    self.stale.pop(0)
        except httpx.HTTPError:
            # ZAP still starting (API not up yet) or busy: try again shortly
            self.next_check = now + 2
            return
        if changed:
            progress(self.cfg, "zap", "Gave ZAP a renewed login token")

    def _warn(self, msg: str) -> None:
        if not self.warned:
            self.warned = True
            progress(self.cfg, "zap", msg, level="warn")


class _Snapshot:
    """zap-api-scan.py writes its report only when the whole scan ends. Save ZAP's alerts so far every
    few minutes, and once more on stop or timeout, so a stopped or killed run keeps what ZAP found."""

    def __init__(self, port: int, out: Path):
        self.proxy, self.out = f"http://127.0.0.1:{port}", out
        self.path = out / "zap-partial.json"
        self.next = time.time() + SNAPSHOT_EVERY

    def tick(self) -> None:
        if time.time() >= self.next:
            self.save()
            self.next = time.time() + SNAPSHOT_EVERY

    def save(self, html: bool = False) -> None:
        """Same API calls zap-api-scan.py makes for zap.json / zap.html. Best effort: ZAP may not be up."""
        files = [("jsonreport", self.path)] + ([("htmlreport", self.out / "zap-partial.html")] if html else [])
        try:
            with httpx.Client(proxy=self.proxy, timeout=30) as c:
                for report, path in files:
                    r = c.get(f"http://zap/OTHER/core/other/{report}/")
                    r.raise_for_status()
                    if report == "jsonreport":
                        json.loads(r.text)
                    tmp = path.with_name(path.name + ".tmp")
                    tmp.write_text(r.text, encoding="utf-8")
                    tmp.replace(path)
        except (httpx.HTTPError, ValueError, OSError):
            pass


# Lines from zap-api-scan.py's debug log (-d, written to stderr), in the order they appear
PROGRESS_LINES = [
    (re.compile(r"\bStarting ZAP\b"), lambda m: ("ZAP is starting up (usually 1–3 minutes)", None)),
    (re.compile(r"Set max pscan alerts"), lambda m: ("ZAP is up; importing the API definition", None)),
    (re.compile(r"Number of Imported URLs: (\d+)"), lambda m: (f"Imported {m[1]} URLs from the spec", None)),
    (re.compile(r"Spider progress %: (\d+)"), lambda m: ("Crawling", int(m[1]))),
    (re.compile(r"Active Scan progress %: (\d+)"), lambda m: ("Active scan: attacking the APIs", int(m[1]))),
    (re.compile(r"Active Scan complete"), lambda m: ("Active scan complete", 100)),
    (re.compile(r"Records to scan"), lambda m: ("Passive scan: analysing responses", None)),
    (re.compile(r"Passive scanning complete"), lambda m: ("Passive scan complete; writing the report", None)),
    (re.compile(r"Total of (\d+) URLs"), lambda m: (f"Finished: {m[1]} URLs checked", None)),
]


def _live(cfg, lines: list[str]) -> None:
    for line in lines:
        for rx, fmt in PROGRESS_LINES:
            m = rx.search(line)
            if m:
                msg, pct = fmt(m)
                progress(cfg, "zap", msg + (f" {pct}%" if pct is not None else ""), done=pct,
                         total=100 if pct is not None else None)
                break


def run(spec, cfg, out: Path) -> StageResult:
    res = StageResult("zap")
    if not _docker_ok():
        res.status, res.note = "skipped", "Docker not available or daemon not running"
        return res
    base = cfg.base_url or spec.base_url
    (out / "spec.json").write_text(spec.text, encoding="utf-8")
    threads, heap = _sizing(cfg)
    zap_opts = ["-config", f"scanner.threadPerHost={threads}",
                "-config", f"scanner.maxRuleDurationInMins={max(0, cfg.zap_rule_minutes)}",
                "-config", f"scanner.maxScanDurationInMins={max(0, cfg.zap_max_minutes)}"]
    headers = current_headers(cfg)
    for i, (k, v) in enumerate(headers.items()):
        for opt in (f"description=h{i}", "enabled=true", "matchtype=REQ_HEADER", f"matchstr={k}", "regex=false",
                    f"replacement={v}"):
            zap_opts += ["-config", f"replacer.full_list({i}).{opt}"]
    if heap:
        zap_opts.append(f"-Xmx{heap}m")  # zap.sh uses it in place of its default heap
    name = f"apitest-zap-{uuid.uuid4().hex[:8]}"
    cmd = ["docker", "run", "--rm", "--name", name, "--add-host", "host.docker.internal:host-gateway",
           "-v", f"{out.resolve()}:/zap/wrk:rw"]
    # ZAP's API, published to this machine only: renews the login token mid-scan and saves partial reports
    port = _free_port()
    renewer = _TokenRenewer(cfg, port, headers) if cfg.auth_a is not None else None
    snap = _Snapshot(port, out)
    cmd += ["-p", f"127.0.0.1:{port}:{ZAP_PORT}", cfg.zap_image, "zap-api-scan.py",
            "-t", "spec.json", "-f", "openapi", "-O", _for_container(base),
            "-J", "zap.json", "-r", "zap.html", "-I", "-d",  # -d: debug output includes scan progress %
            "-P", str(ZAP_PORT), "-z", shlex.join(zap_opts)]  # ZAP shlex-splits -z, so values with spaces must be quoted
    progress(cfg, "zap", f"Starting the OWASP ZAP container ({threads} parallel requests"
                         + (f", {heap / 1024:.1f} GB memory)" if heap else ")"))
    # Killing the docker client doesn't stop the container, so remove it by name on cancel and timeout
    def stop():
        progress(cfg, "zap", "Saving what ZAP found so far")
        snap.save(html=True)
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)

    # Startup, spider, passive scan and the report come on top of the active scan's own limit
    timeout = (cfg.zap_max_minutes + 30) * 60 if cfg.zap_max_minutes > 0 else 24 * 3600
    stopped = ""
    try:
        p = run_cmd(cmd, cancel=cfg.cancel, timeout=timeout, on_cancel=stop,
                    on_tick=lambda lines: (_live(cfg, lines), renewer and renewer.tick(), snap.tick()))
    except Cancelled:
        if not snap.path.exists():
            raise
        stopped, status = "Stopped by user", "cancelled"
    except subprocess.TimeoutExpired:
        stop()
        if not snap.path.exists():
            raise
        stopped, status = f"Timed out after {timeout // 60} min", "error"
    if stopped:
        zf, log = snap.path, ""
    else:
        zf, log = out / "zap.json", p.stdout + "\n" + p.stderr
        (out / "zap.log").write_text(log, encoding="utf-8")
        if not zf.exists():
            res.status, res.note = "error", (p.stderr or p.stdout)[-600:]
            return res
    tl = log_of(cfg)
    match = OpMatcher(spec.operations, _for_container(base))
    for site in json.loads(zf.read_text(encoding="utf-8")).get("site", []):
        for a in site.get("alerts", []):
            inst = a.get("instances", [])
            where = f"{inst[0].get('method', '')} {inst[0].get('uri', '')}" if inst else ""
            sev = RISK.get(str(a.get("riskcode")), "info")
            res.findings.append(Finding("zap", sev, a.get("name", "ZAP alert"), where,
                                        f"{len(inst)} instance(s). {a.get('desc', '')[:300]}"))
            if not tl:
                continue
            for i in inst:
                method, uri = i.get("method", ""), i.get("uri", "")
                tl.add("zap", f"Security check: {a.get('name', 'alert')}", operation=match(method, uri),
                       expected=_strip_html(a.get("solution", ""))[:400] or "No issue",
                       verdict="info" if sev == "info" else "fail",
                       explanation=f"ZAP rated this {sev} risk. {_strip_html(a.get('desc', ''))[:300]}"
                                   + (f" Parameter: {i.get('param')}." if i.get("param") else "")
                                   + (f" Attack sent: {i.get('attack')}." if i.get("attack") else ""),
                       request={"method": method, "url": uri},
                       details={"risk": sev, "confidence": a.get("confidence"), "param": i.get("param"),
                                "attack": i.get("attack"), "evidence": i.get("evidence"),
                                "otherinfo": i.get("otherinfo"), "cwe": a.get("cweid"), "wasc": a.get("wascid"),
                                "description": _strip_html(a.get("desc", ""))[:1500],
                                "reference": _strip_html(a.get("reference", ""))[:600]})
    if tl:
        imported = re.search(r"Total of (\d+) URLs", log)
        tl.add("zap", "ZAP scan summary", verdict="info",
               details={"message": f"ZAP checked {imported[1] if imported else 'an unknown number of'} URLs. "
                                   "Only requests that raised an alert are listed individually; ZAP's API scan "
                                   "doesn't export every request it sends. Its full HTML report is zap.html."})
    if stopped:
        res.status = status
        res.note = (f"{stopped}: partial results, only the alerts ZAP raised before it stopped. "
                    "Its HTML report so far is zap-partial.html.")
    return res


def _strip_html(s: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", s or "")).strip()
