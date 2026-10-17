"""Trusted CAs (sprat.tls): bundle building, Windows store filtering, explain(), and TLS handshakes with
certificates generated in tmp_path. Handshakes run through memory BIOs, so antivirus web shields that re-sign
even loopback HTTPS can't interfere; the two real-socket tests skip when that happens."""
import datetime as dt
import hashlib
import http.server
import ipaddress
import socket
import ssl
import sys
import tempfile
import threading
from pathlib import Path

import certifi
import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from sprat import tls
from sprat.discover import client_for

REAL_WINDOWS_PEMS = tls._windows_pems


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    """Bundle files go to tmp_path, not the system temp dir; caches don't leak between tests; the (slow,
    machine-specific) Windows store is left out unless a test asks for it."""
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    monkeypatch.delenv("SPRAT_CA_BUNDLE", raising=False)
    monkeypatch.setattr(tls, "_windows_pems", lambda: [])
    tls.ca_bundle.cache_clear()
    tls.ssl_context.cache_clear()
    yield
    tls.ca_bundle.cache_clear()
    tls.ssl_context.cache_clear()


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_cert(cn, signer=None, ca=False, sans=("localhost",), ips=("127.0.0.1",), days=(-1, 30)):
    """Return (cert, key). signer=(cert, key) or None for self-signed."""
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc)
    issuer_cert, issuer_key = signer or (None, key)
    b = (x509.CertificateBuilder().subject_name(_name(cn))
         .issuer_name(issuer_cert.subject if issuer_cert else _name(cn))
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now + dt.timedelta(days=days[0])).not_valid_after(now + dt.timedelta(days=days[1]))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
                        critical=False))  # Python 3.13+ verifies with X509_STRICT, which wants SKI/AKI
    if ca:
        b = b.add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                          content_commitment=False, key_encipherment=False, data_encipherment=False,
                                          key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
    else:
        alt = [x509.DNSName(s) for s in sans] + [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]
        if alt:
            b = b.add_extension(x509.SubjectAlternativeName(alt), critical=False)
        b = b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    return b.sign(issuer_key, hashes.SHA256()), key


def pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def write_pair(tmp_path, name, cert, key, chain=()):
    c, k = tmp_path / f"{name}.crt", tmp_path / f"{name}.key"
    c.write_text(pem(cert) + "".join(pem(x) for x in chain), encoding="ascii")
    k.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()))
    return str(c), str(k)


@pytest.fixture(scope="module")
def pki():
    ca = make_cert("sprat Test Root CA", ca=True)
    leaf = make_cert("localhost", signer=ca)
    return {"ca": ca, "leaf": leaf}


def _server_ctx(tmp_path, cert, key, chain=()):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(*write_pair(tmp_path, f"srv-{cert.serial_number}", cert, key, chain))
    return ctx


def mem_handshake(server_ctx, hostname="localhost", client_ctx=None):
    """TLS handshake through memory BIOs with sprat's client context."""
    client_ctx = client_ctx or tls.ssl_context()
    c_in, c_out, s_in, s_out = (ssl.MemoryBIO() for _ in range(4))
    client = client_ctx.wrap_bio(c_in, c_out, server_hostname=hostname)
    server = server_ctx.wrap_bio(s_in, s_out, server_side=True)
    for _ in range(20):
        done = 0
        for side in (client, server):
            try:
                side.do_handshake()
                done += 1
            except ssl.SSLWantReadError:
                pass
        s_in.write(c_out.read())
        c_in.write(s_out.read())
        if done == 2:
            return client.version()
    raise AssertionError("handshake didn't finish")


def _trust(tmp_path, monkeypatch, cert):
    extra = tmp_path / "root.pem"
    extra.write_text(pem(cert), encoding="ascii")
    monkeypatch.setenv("SPRAT_CA_BUNDLE", str(extra))


class TLSServer:
    """HTTPS server on 127.0.0.1 serving a tiny OpenAPI document."""

    def __init__(self, certfile, keyfile):
        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = b'{"openapi": "3.0.0", "info": {"title": "tls", "version": "1"}, "paths": {"/x": {"get": {}}}}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        class S(http.server.ThreadingHTTPServer):
            def handle_error(self, request, client_address):  # failed handshakes are expected here
                pass
        sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sctx.load_cert_chain(certfile, keyfile)
        self.httpd = S(("127.0.0.1", 0), H)
        self.httpd.socket = sctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def serve(tmp_path):
    servers = []

    def start(cert, key):
        s = TLSServer(*write_pair(tmp_path, f"sock{len(servers)}", cert, key))
        servers.append(s)
        return s
    yield start
    for s in servers:
        s.close()


def _skip_if_intercepted(port, expected):
    """Antivirus web shields (Norton, Avast...) re-sign even loopback TLS; then the server's own
    certificate never reaches the client and end-to-end checks can't be made."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw, \
            ctx.wrap_socket(raw, server_hostname="localhost") as s:
        der = s.getpeercert(binary_form=True)
    if der != expected.public_bytes(serialization.Encoding.DER):
        seen = x509.load_der_x509_certificate(der).issuer.rfc4514_string()
        pytest.skip(f"TLS to 127.0.0.1 is intercepted on this machine (issuer {seen})")


# ---------- _windows_pems ----------

def test_windows_pems_empty_off_windows(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    assert REAL_WINDOWS_PEMS() == []


def test_windows_pems_filters_by_encoding_and_trust(monkeypatch, pki):
    der = pki["ca"][0].public_bytes(serialization.Encoding.DER)
    other = make_cert("other root", ca=True)[0].public_bytes(serialization.Encoding.DER)
    calls = []

    def enum(store):
        calls.append(store)
        if store == "CA":
            raise OSError("access denied")
        return [(der, "x509_asn", True),
                (other, "x509_asn", {tls.SERVER_AUTH, "1.3.6.1.5.5.7.3.2"}),
                (der, "x509_asn", {"1.3.6.1.5.5.7.3.3"}),     # code signing only
                (der, "x509_asn", set()),
                (der, "pkcs_7_asn", True)]
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(ssl, "enum_certificates", enum, raising=False)
    out = REAL_WINDOWS_PEMS()
    assert calls == ["ROOT", "CA"]
    assert out == [ssl.DER_cert_to_PEM_cert(der), ssl.DER_cert_to_PEM_cert(other)]


@pytest.mark.skipif(sys.platform != "win32", reason="real Windows certificate store")
def test_windows_pems_real_store_are_valid_pem():
    pems = REAL_WINDOWS_PEMS()
    assert pems and all(p.startswith("-----BEGIN CERTIFICATE-----") for p in pems)


@pytest.mark.skipif(sys.platform != "win32", reason="real Windows certificate store")
def test_bundle_with_real_windows_store_has_more_than_certifi(monkeypatch):
    monkeypatch.setattr(tls, "_windows_pems", REAL_WINDOWS_PEMS)
    text = Path(tls.ca_bundle()).read_text(encoding="ascii")
    assert text.count("BEGIN CERTIFICATE") > Path(certifi.where()).read_text(encoding="ascii").count("BEGIN CERT")


# ---------- ca_bundle ----------

def test_bundle_layout_and_location(tmp_path, monkeypatch, pki):
    monkeypatch.setattr(tls, "_windows_pems", lambda: [pem(pki["ca"][0])])
    path = Path(tls.ca_bundle())
    text = path.read_text(encoding="ascii")
    assert path.parent == tmp_path and path.name == f"sprat-ca-{hashlib.sha256(text.encode()).hexdigest()[:16]}.pem"
    assert text.startswith(Path(certifi.where()).read_text(encoding="ascii").strip())
    assert text.endswith(pem(pki["ca"][0]).strip() + "\n")
    assert list(tmp_path.glob("*.tmp")) == []


def test_bundle_includes_extra_ca_file(tmp_path, monkeypatch, pki):
    extra = tmp_path / "corp.pem"
    extra.write_text("\n\n" + pem(pki["ca"][0]) + "\n\n", encoding="ascii")
    monkeypatch.setenv("SPRAT_CA_BUNDLE", f"  {extra}  ")
    text = Path(tls.ca_bundle()).read_text(encoding="ascii")
    certifi_count = Path(certifi.where()).read_text(encoding="ascii").count("BEGIN CERTIFICATE")
    assert text.count("BEGIN CERTIFICATE") == certifi_count + 1 and pem(pki["ca"][0]).strip() in text


def test_blank_extra_is_ignored(monkeypatch):
    monkeypatch.setenv("SPRAT_CA_BUNDLE", "   ")
    text = Path(tls.ca_bundle()).read_text(encoding="ascii")
    assert text == Path(certifi.where()).read_text(encoding="ascii").strip() + "\n"


def test_missing_extra_file_raises(tmp_path, monkeypatch):
    monkeypatch.setenv("SPRAT_CA_BUNDLE", str(tmp_path / "nope.pem"))
    with pytest.raises(FileNotFoundError):
        tls.ca_bundle()


def test_extra_bundle_pointing_at_a_directory_raises(tmp_path, monkeypatch):
    monkeypatch.setenv("SPRAT_CA_BUNDLE", str(tmp_path))
    with pytest.raises(OSError):
        tls.ca_bundle()


def test_bundle_is_cached_and_content_addressed(tmp_path, monkeypatch, pki):
    first = tls.ca_bundle()
    assert tls.ca_bundle() is first
    Path(first).write_text("sentinel", encoding="ascii")  # existing file with the same digest is not rewritten
    tls.ca_bundle.cache_clear()
    assert tls.ca_bundle() == first and Path(first).read_text() == "sentinel"
    _trust(tmp_path, monkeypatch, pki["ca"][0])
    tls.ca_bundle.cache_clear()
    second = tls.ca_bundle()
    assert second != first and len(list(tmp_path.glob("sprat-ca-*.pem"))) == 2


# ---------- ssl_context ----------

def test_context_verifies_and_trusts_extra_ca(tmp_path, monkeypatch, pki):
    _trust(tmp_path, monkeypatch, pki["ca"][0])
    ctx = tls.ssl_context()
    assert ctx is tls.ssl_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname
    subjects = [dict(x[0] for x in c["subject"]).get("commonName") for c in ctx.get_ca_certs()]
    assert "sprat Test Root CA" in subjects


def test_garbage_between_certificates_is_tolerated(tmp_path, monkeypatch, pki):
    extra = tmp_path / "messy.pem"
    extra.write_text("# exported by some tool\nBag Attributes: none\n" + pem(pki["ca"][0]) + "trailing junk\n",
                     encoding="ascii")
    monkeypatch.setenv("SPRAT_CA_BUNDLE", str(extra))
    assert tls.ssl_context().cert_store_stats()["x509_ca"] > 1


# ---------- handshakes (in memory) ----------

def test_private_ca_rejected_by_default_and_explained(tmp_path, pki):
    with pytest.raises(ssl.SSLCertVerificationError) as ei:
        mem_handshake(_server_ctx(tmp_path, *pki["leaf"]))
    assert tls.explain(ei.value) == (
        "The server's HTTPS certificate was rejected (certificate verify failed: unable to get local issuer "
        "certificate). If an antivirus or company proxy inspects HTTPS, or the server uses an internal CA, "
        "export that root certificate as PEM and set SPRAT_CA_BUNDLE to the file.")


def test_private_ca_trusted_via_sprat_ca_bundle(tmp_path, monkeypatch, pki):
    _trust(tmp_path, monkeypatch, pki["ca"][0])
    assert mem_handshake(_server_ctx(tmp_path, *pki["leaf"])).startswith("TLSv1.")


def test_intermediate_chain_sent_by_server(tmp_path, monkeypatch, pki):
    inter = make_cert("sprat Intermediate", signer=pki["ca"], ca=True)
    leaf = make_cert("localhost", signer=inter)
    _trust(tmp_path, monkeypatch, pki["ca"][0])
    assert mem_handshake(_server_ctx(tmp_path, *leaf, chain=[inter[0]]))
    with pytest.raises(ssl.SSLCertVerificationError, match="issuer"):  # chain missing on the server
        mem_handshake(_server_ctx(tmp_path, *leaf))


def test_self_signed_server_explained(tmp_path):
    with pytest.raises(ssl.SSLCertVerificationError) as ei:
        mem_handshake(_server_ctx(tmp_path, *make_cert("localhost")))
    msg = tls.explain(ei.value)
    assert ("self-signed" in msg or "self signed" in msg) and "SPRAT_CA_BUNDLE" in msg


def test_expired_certificate_explained_without_ca_advice(tmp_path, monkeypatch, pki):
    _trust(tmp_path, monkeypatch, pki["ca"][0])
    with pytest.raises(ssl.SSLCertVerificationError) as ei:
        mem_handshake(_server_ctx(tmp_path, *make_cert("localhost", signer=pki["ca"], days=(-30, -1))))
    msg = tls.explain(ei.value)
    assert "expired" in msg and "SPRAT_CA_BUNDLE" not in msg


def test_not_yet_valid_certificate(tmp_path, monkeypatch, pki):
    _trust(tmp_path, monkeypatch, pki["ca"][0])
    with pytest.raises(ssl.SSLCertVerificationError) as ei:
        mem_handshake(_server_ctx(tmp_path, *make_cert("localhost", signer=pki["ca"], days=(5, 30))))
    assert "not yet valid" in tls.explain(ei.value)


@pytest.mark.parametrize("hostname,ok", [("localhost", True), ("127.0.0.1", True), ("api.other.test", False),
                                         ("sub.localhost", False)])
def test_hostname_checking(tmp_path, monkeypatch, pki, hostname, ok):
    _trust(tmp_path, monkeypatch, pki["ca"][0])
    if ok:
        assert mem_handshake(_server_ctx(tmp_path, *pki["leaf"]), hostname=hostname)
        return
    with pytest.raises(ssl.SSLCertVerificationError) as ei:
        mem_handshake(_server_ctx(tmp_path, *pki["leaf"]), hostname=hostname)
    msg = tls.explain(ei.value)
    assert "rejected" in msg and "mismatch" in msg.lower() and "SPRAT_CA_BUNDLE" not in msg


# ---------- client_for ----------

def test_client_for_localhost_https_end_to_end(serve, pki, tmp_path, monkeypatch):
    """discover.client_for -> IPv4-bound transport + sprat's CA bundle, against a real HTTPS server."""
    srv = serve(*pki["leaf"])
    _skip_if_intercepted(srv.port, pki["leaf"][0])
    _trust(tmp_path, monkeypatch, pki["ca"][0])
    with client_for(f"https://localhost:{srv.port}/", timeout=5) as c:
        r = c.get(f"https://localhost:{srv.port}/openapi.json")
    assert r.status_code == 200 and r.json()["openapi"] == "3.0.0"


def test_httpx_error_through_client_for_is_explained(serve, pki):
    srv = serve(*pki["leaf"])
    _skip_if_intercepted(srv.port, pki["leaf"][0])
    with client_for(f"https://localhost:{srv.port}/", timeout=5) as c:
        with pytest.raises(httpx.ConnectError) as ei:
            c.get(f"https://localhost:{srv.port}/")
    assert "SPRAT_CA_BUNDLE" in tls.explain(ei.value)


def test_client_for_transport_choice():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    with client_for("https://api.example.test", verify=ctx) as c:
        assert c._transport._pool._local_address is None
    for url in ("http://localhost:8000/x", "https://LOCALHOST/", "http://localhost"):
        with client_for(url, verify=ctx) as c:  # IPv4 for localhost; hostnames are case-insensitive
            assert c._transport._pool._local_address == "0.0.0.0" and c._transport._pool._ssl_context is ctx
    with client_for("http://127.0.0.1:8000", verify=ctx) as c:
        assert c._transport._pool._local_address is None


def test_client_for_defaults_to_sprat_context(monkeypatch):
    sentinel = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    import sprat.discover as d
    monkeypatch.setattr(d, "ssl_context", lambda: sentinel)
    with client_for("https://localhost/") as c:
        assert c._transport._pool._ssl_context is sentinel
    with client_for("https://api.example.test/", timeout=3, headers={"X": "1"}) as c:
        assert c.timeout.connect == 3 and c.headers["X"] == "1"


# ---------- explain ----------

@pytest.mark.parametrize("reason,advice", [
    ("unable to get local issuer certificate", True),
    ("self-signed certificate", True),
    ("self signed certificate in certificate chain", True),
    ("self-signed certificate in certificate chain", True),
    ("unable to get issuer certificate", True),
    ("certificate has expired", False),
    ("Hostname mismatch, certificate is not valid for 'x'.", False),
    ("certificate is not yet valid", False),
])
def test_explain_verify_failures(reason, advice):
    e = ssl.SSLCertVerificationError(f"[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: {reason} (_ssl.c:1028)")
    msg = tls.explain(e)
    assert msg.startswith(f"The server's HTTPS certificate was rejected (certificate verify failed: {reason}).")
    assert ("SPRAT_CA_BUNDLE" in msg) is advice


def test_explain_wrapped_in_httpx_error():
    e = httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate "
                           "(_ssl.c:1000)")
    assert "self-signed certificate" in tls.explain(e) and "SPRAT_CA_BUNDLE" in tls.explain(e)


@pytest.mark.parametrize("exc,expected", [
    (httpx.ConnectError("[Errno 111] Connection refused"), "ConnectError: [Errno 111] Connection refused"),
    (httpx.ReadTimeout("timed out"), "ReadTimeout: timed out"),
    (ConnectionResetError(), "ConnectionResetError"),
    (httpx.ConnectError(""), "ConnectError"),
    (ValueError("CERTIFICATE_VERIFY_FAILED"), "The server's HTTPS certificate was rejected (CERTIFICATE_VERIFY_FAILED)."),
])
def test_explain_other_errors(exc, expected):
    assert tls.explain(exc) == expected
