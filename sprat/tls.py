"""Which certificate authorities sprat trusts for HTTPS.

Python ships its own CA list (certifi) and ignores the operating system's. That breaks on
machines where HTTPS is re-signed by something the OS trusts but certifi doesn't: antivirus
web shields (Norton, Avast, Kaspersky...), corporate TLS inspection, an internal company CA.
Browsers and curl work there, sprat would fail with CERTIFICATE_VERIFY_FAILED.

So sprat trusts certifi's list plus the Windows certificate store, plus an optional
extra bundle from SPRAT_CA_BUNDLE. Verification is never switched off.

The combined list is also written to a PEM file for the subprocesses: Schemathesis
(--tls-verify) and Node/Spectral (NODE_EXTRA_CA_CERTS).
"""
from __future__ import annotations

import functools
import hashlib
import os
import ssl
import sys
import tempfile
from pathlib import Path

import certifi

SERVER_AUTH = "1.3.6.1.5.5.7.3.1"


def _windows_pems() -> list[str]:
    if sys.platform != "win32":
        return []
    pems = []
    for store in ("ROOT", "CA"):
        try:
            entries = ssl.enum_certificates(store)
        except OSError:
            continue
        for der, encoding, trust in entries:
            if encoding == "x509_asn" and (trust is True or SERVER_AUTH in trust):
                pems.append(ssl.DER_cert_to_PEM_cert(der))
    return pems


@functools.lru_cache(maxsize=1)
def ca_bundle() -> str:
    """Path of a PEM file with every CA sprat trusts."""
    parts = [Path(certifi.where()).read_text(encoding="ascii")]
    extra = os.environ.get("SPRAT_CA_BUNDLE", "").strip()
    if extra:
        parts.append(Path(extra).read_text(encoding="ascii"))
    parts += _windows_pems()
    text = "\n".join(p.strip() for p in parts) + "\n"
    digest = hashlib.sha256(text.encode()).hexdigest()[:16]
    path = Path(tempfile.gettempdir()) / f"sprat-ca-{digest}.pem"
    if not path.exists():
        tmp = path.with_suffix(f".{os.getpid()}.tmp")
        tmp.write_text(text, encoding="ascii")
        os.replace(tmp, path)
    return str(path)


@functools.lru_cache(maxsize=1)
def ssl_context() -> ssl.SSLContext:
    return ssl.create_default_context(cafile=ca_bundle())


def explain(exc: BaseException) -> str:
    """Plain-language reason for a connection error."""
    msg = str(exc)
    if "CERTIFICATE_VERIFY_FAILED" in msg:
        reason = msg.split("] ")[-1].split(" (_ssl")[0]
        text = f"The server's HTTPS certificate was rejected ({reason})."
        if "issuer" in reason or "self-signed" in reason or "self signed" in reason:
            text += (" If an antivirus or company proxy inspects HTTPS, or the server uses an internal CA, "
                     "export that root certificate as PEM and set SPRAT_CA_BUNDLE to the file.")
        return text
    return f"{type(exc).__name__}: {msg}" if msg else type(exc).__name__
