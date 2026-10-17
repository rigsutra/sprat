"""Automatic login: get a token from a login API, use it, and get a new one 30 s before it expires.

The login request (URL, headers, body) may reference environment variables as ${VAR}; that's where
passwords live. Nothing secret is stored by sprat.

    login = LoginConfig(url="https://auth.example.com/api/auth/login",
                        body='{"email": "qa@example.com", "password": "${QA_PASSWORD}"}',
                        token_path="data.accessToken", token_type="bearer")
    provider = TokenProvider(login)
    provider.headers()  # {"Authorization": "Bearer eyJ..."}, refreshed automatically
"""
from __future__ import annotations

import base64
import json
import re
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from urllib.parse import parse_qsl, quote_plus, urlsplit

import httpx

from .config import ENV_REF, expand_env

REFRESH_MARGIN = 30  # seconds before expiry to get a new token
DEFAULT_LIFETIME = 10 * 60  # when the expiry can't be determined
SECRET_KEY = re.compile(r"pass|pwd|secret|token|api[-_]?key|credential", re.I)
MAX_REDIRECTS = 10


def _http(method: str, url: str, timeout: float, **kw) -> httpx.Response:
    """Follows redirects on the login API's own host only. A redirect elsewhere is returned unfollowed:
    the request holds the password (307/308 re-send the body) and custom secret headers."""
    from .discover import client_for, same_site  # IPv4 for localhost (avoids a ~2 s IPv6 delay on Windows)
    with client_for(url, timeout=timeout, follow_redirects=False) as c:
        r = c.request(method, url, **kw)
        for _ in range(MAX_REDIRECTS):
            nxt = r.next_request
            if nxt is None or not same_site(url, nxt.url):
                return r
            r = c.send(nxt)
        if r.next_request is not None and same_site(url, r.next_request.url):
            raise httpx.TooManyRedirects("Exceeded maximum allowed redirects.", request=r.next_request)
        return r


class LoginError(Exception):
    """Login failed; the message is meant for people."""


@dataclass
class LoginConfig:
    url: str
    method: str = "POST"
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""                 # usually JSON; may contain ${VAR}
    body_type: str = "json"        # json | form | raw
    token_path: str = "accessToken"  # where the token is in the response, e.g. data.accessToken
    token_type: str = "bearer"     # bearer | header | cookie
    header_name: str = "Authorization"  # for token_type=header (e.g. X-API-Key)
    cookie_name: str = ""          # for token_type=cookie
    expiry: str = "jwt"            # jwt | field | fixed
    expiry_path: str = ""          # for expiry=field, e.g. data.expiresIn (seconds) or an absolute time
    fixed_minutes: int = 15        # for expiry=fixed
    timeout: float = 20.0

    @classmethod
    def from_dict(cls, d: dict) -> "LoginConfig":
        known = {k: v for k, v in (d or {}).items() if k in cls.__dataclass_fields__}
        return cls(**known)

    def to_dict(self) -> dict:
        return asdict(self)


def literal_secrets(cfg: LoginConfig) -> list[str]:
    """Names of fields that look like secrets but hold a literal value instead of ${VAR}."""
    bad = []
    try:
        body = json.loads(cfg.body) if cfg.body.strip().startswith("{") else {}
    except ValueError:
        body = {}

    def walk(o, path=""):
        if isinstance(o, dict):
            for k, v in o.items():
                p = f"{path}.{k}" if path else k
                if isinstance(v, (dict, list)):
                    walk(v, p)
                elif SECRET_KEY.search(k) and isinstance(v, str) and v and not ENV_REF.search(v):
                    bad.append(f"body field `{p}`")
        elif isinstance(o, list):
            for i, v in enumerate(o):
                walk(v, f"{path}[{i}]")
    walk(body)
    if cfg.body_type == "form" or not body:
        for m in re.finditer(r"(?:^|&)([^=&]*)=([^&]*)", cfg.body):
            if SECRET_KEY.search(m[1]) and m[2] and not ENV_REF.search(m[2]):
                bad.append(f"form field `{m[1]}`")
    for k, v in cfg.headers.items():
        if (SECRET_KEY.search(k) or k.lower() == "authorization") and v and not ENV_REF.search(v):
            bad.append(f"header `{k}`")
    u = urlsplit(cfg.url)
    if u.password and not ENV_REF.search(u.password):
        bad.append("password in the URL")
    for k, v in parse_qsl(u.query):
        if SECRET_KEY.search(k) and v and not ENV_REF.search(v):
            bad.append(f"URL parameter `{k}`")
    return bad


def get_path(obj, path: str):
    """Follow 'data.accessToken' / 'items[0].token' / 'data["a.b"]' through parsed JSON. Raises KeyError."""
    cur = obj
    for part in re.findall(r'\["(?:[^"\\]|\\.)*"\]|\[\d+\]|[^.\[\]]+', path.strip()):
        if part.startswith('["'):
            part = json.loads(part[1:-1])
        elif part.startswith("["):
            cur = cur[int(part[1:-1])]
            continue
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            raise KeyError(part)
    return cur


def _key_path(prefix: str, k) -> str:
    k = str(k)
    if not k or k != k.strip() or re.search(r"[.\[\]]", k):  # not expressible as .key: quote it
        return f"{prefix}[{json.dumps(k, ensure_ascii=False)}]"
    return f"{prefix}.{k}" if prefix else k


def leaf_paths(obj, prefix="") -> list[tuple[str, object]]:
    """Every scalar field in a JSON document with its path (for the 'pick the token' UI)."""
    out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out += leaf_paths(v, _key_path(prefix, k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:20]):
            out += leaf_paths(v, f"{prefix}[{i}]")
    else:
        out.append((prefix, obj))
    return out


def jwt_claims(token: str) -> dict | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        pad = "=" * (-len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(parts[1] + pad))
    except (ValueError, json.JSONDecodeError):
        return None
    return claims if isinstance(claims, dict) else None


def _to_epoch(value, now: float) -> float | None:
    """Expiry field: seconds-from-now, epoch seconds/ms, or an ISO date."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if value > 1e12:
            return value / 1000.0
        if value > 1e9:
            return float(value)
        return now + float(value)
    if isinstance(value, str):
        s = value.strip()
        if s.isascii() and s.isdigit():  # isdigit() alone accepts '²', which int() rejects
            return _to_epoch(int(s), now)
        try:
            d = datetime.fromisoformat(s.replace("Z", "+00:00"))
            # naive = UTC: local time would go through the OS's mktime, which fails outside its range on Windows
            return (d if d.tzinfo else d.replace(tzinfo=timezone.utc)).timestamp()
        except (ValueError, OverflowError, OSError):
            return None
    return None


class TokenProvider:
    """Thread-safe: stages call headers() before each request; it logs in again when needed."""

    def __init__(self, login: LoginConfig, label: str = "user A", margin: int = REFRESH_MARGIN,
                 variables: dict[str, str] | None = None):
        self.cfg, self.label, self.margin = login, label, margin
        self.variables = variables or {}  # the project's secrets, for ${NAME} in the login request
        self.token: str | None = None
        self.expires_at: float = 0.0
        self.expiry_source = ""
        self.logins = 0
        self.on_login = None  # callback(provider) after each successful login
        self._lock = threading.Lock()

    # ---------- public ----------
    def headers(self) -> dict[str, str]:
        tok = self.current_token()
        t = self.cfg.token_type
        if t == "bearer":
            return {"Authorization": f"Bearer {tok}"}
        if t == "header":
            return {self.cfg.header_name or "Authorization": tok}
        if t == "cookie":
            return {"Cookie": f"{self.cfg.cookie_name or 'token'}={tok}"}
        raise LoginError(f"Unknown token type {t!r}")

    def current_token(self) -> str:
        with self._lock:
            if not self.token or time.time() >= self.expires_at - self.margin:
                self._login()
            return self.token

    def ensure_valid_for(self, seconds: float) -> None:
        """Log in again now if the token would expire within `seconds` (for tools that can't refresh, like ZAP)."""
        with self._lock:
            if not self.token or self.expires_at - time.time() < seconds:
                self._login()

    def status(self) -> dict:
        return {"label": self.label, "logged_in": bool(self.token), "expires_at": self.expires_at,
                "expiry_source": self.expiry_source, "logins": self.logins}

    # ---------- internals ----------
    def resolved(self) -> dict:
        """The login config with ${NAME}s filled in (for the Schemathesis subprocess). Contains secrets."""
        d = self.cfg.to_dict()
        d["url"] = self._x(d["url"])
        d["headers"] = {k: self._x(v) for k, v in d["headers"].items()}
        if d["body"]:
            t = d["body_type"]
            d["body"] = (json.dumps(self._json_body()) if t == "json" else self._form_body() if t == "form"
                         else self._x(d["body"]))
        return d

    def _x(self, s: str) -> str:
        try:
            return expand_env(s, self.variables)
        except ValueError as e:
            raise LoginError(f"{self.label}: {e}.") from None

    def _mask(self, text: str) -> str:
        """Hide the ${NAME} values of the login request in text from the login API (some echo them back)."""
        c = self.cfg
        for name in set(ENV_REF.findall(" ".join([c.url, c.body, *c.headers.values()]))):
            v = self._x("${%s}" % name)
            for form in sorted({v, json.dumps(v)[1:-1], quote_plus(v)}, key=len, reverse=True):
                if len(form) >= 3:
                    text = text.replace(form, "***")
        return text

    def _json_body(self):
        """Parse first, then fill ${NAME}s inside strings, so a password containing quotes or
        backslashes can't break the JSON."""
        try:
            doc = json.loads(self.cfg.body)
        except ValueError:
            raise LoginError(f"{self.label}: the login body isn't valid JSON.") from None

        def walk(o):
            if isinstance(o, str):
                return self._x(o)
            if isinstance(o, list):
                return [walk(v) for v in o]
            if isinstance(o, dict):
                return {self._x(k): walk(v) for k, v in o.items()}
            return o
        return walk(doc)

    def _form_body(self) -> str:
        """URL-encode each ${NAME} value, so a password containing & = + % can't break the form. The
        literal parts are sent as written."""
        return ENV_REF.sub(lambda m: quote_plus(self._x(m[0])), self.cfg.body)

    def _login(self) -> None:
        c = self.cfg
        url = self._x(c.url)
        headers = {k: self._x(v) for k, v in c.headers.items()}
        kw: dict = {"headers": headers}
        if c.body:
            if c.body_type == "json":
                kw["json"] = self._json_body()
            elif c.body_type == "form":
                kw["content"] = self._form_body().encode()
                kw["headers"] = {"Content-Type": "application/x-www-form-urlencoded", **headers}
            else:
                kw["content"] = self._x(c.body).encode()
        try:
            r = _http(c.method.upper(), url, timeout=c.timeout, **kw)
        except httpx.HTTPError as e:
            raise LoginError(f"{self.label}: couldn't reach the login API ({e}).") from None
        nxt = getattr(r, "next_request", None)
        if nxt is not None:
            raise LoginError(f"{self.label}: the login API redirected to {nxt.url.host}. sprat doesn't "
                             "follow a login to another host, so the password isn't sent there; "
                             "use the final login URL instead.")
        if not 200 <= r.status_code < 300:
            said = ""
            m = re.search(r'"(?:message|detail|error|title)"\s*:\s*"([^"]{2,160})"', r.text)
            if m:
                said = f": {self._mask(m[1])}"
            raise LoginError(f"{self.label}: login failed with HTTP {r.status_code}{said}. "
                             "Check the login URL, the body and the credential environment variables.")
        try:
            doc = r.json()
        except ValueError:
            raise LoginError(f"{self.label}: the login API didn't return JSON.") from None
        try:
            token = get_path(doc, c.token_path)
        except (KeyError, IndexError, TypeError):
            fields = ", ".join(p for p, v in leaf_paths(doc) if isinstance(v, str) and len(v) > 20)[:300]
            raise LoginError(f"{self.label}: logged in, but there's no `{c.token_path}` in the response. "
                             f"Fields that look like tokens: {fields or 'none'}.") from None
        if not isinstance(token, str) or not token:
            raise LoginError(f"{self.label}: `{c.token_path}` in the login response is empty or not text.")
        now = time.time()
        exp, src = self._expiry(doc, token, now)
        self.token, self.expires_at, self.expiry_source = token, exp, src
        self.logins += 1
        if self.on_login:
            try:
                self.on_login(self)
            except Exception:  # a UI callback must never break a login
                pass

    def _expiry(self, doc, token: str, now: float) -> tuple[float, str]:
        c = self.cfg
        if c.expiry == "fixed":
            return now + max(1, c.fixed_minutes) * 60, f"fixed {c.fixed_minutes} min"
        if c.expiry == "field" and c.expiry_path:
            try:
                exp = _to_epoch(get_path(doc, c.expiry_path), now)
            except (KeyError, IndexError, TypeError):
                exp = None
            if exp:
                return exp, f"response field `{c.expiry_path}`"
        claims = jwt_claims(token)
        if claims and isinstance(claims.get("exp"), (int, float)):
            return float(claims["exp"]), "JWT exp claim"
        return now + DEFAULT_LIFETIME, f"unknown (assumed {DEFAULT_LIFETIME // 60} min)"


def make_providers(cfg) -> None:
    """Create TokenProviders for cfg.login_a / login_b (unless already set) and log in once."""
    for user, label in (("a", "user A"), ("b", "user B")):
        login = getattr(cfg, f"login_{user}")
        if login and getattr(cfg, f"auth_{user}") is None:
            setattr(cfg, f"auth_{user}", TokenProvider(LoginConfig.from_dict(login), label,
                                                       variables=getattr(cfg, "variables", None)))
        p = getattr(cfg, f"auth_{user}")
        if p is not None and not p.token:
            p.current_token()


def has_user(cfg, user: str = "a") -> bool:
    return bool((cfg.headers if user == "a" else cfg.headers_b) or getattr(cfg, f"login_{user}", None)
                or getattr(cfg, f"auth_{user}", None))


def current_headers(cfg, user: str = "a") -> dict[str, str]:
    """Headers for user A/B: the static ones from the config plus a fresh login token if configured."""
    static = dict(cfg.headers if user == "a" else cfg.headers_b)
    provider = getattr(cfg, "auth_a" if user == "a" else "auth_b", None)
    if provider is not None:
        static.update(provider.headers())
    return static
