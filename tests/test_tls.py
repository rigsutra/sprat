import ssl
import sys

import certifi
import pytest

from sprat import tls
from sprat.discover import not_found_message


def test_bundle_has_certifi_and_windows_roots():
    text = open(tls.ca_bundle(), encoding="ascii").read()
    certifi_count = open(certifi.where(), encoding="ascii").read().count("BEGIN CERTIFICATE")
    if sys.platform == "win32":
        assert text.count("BEGIN CERTIFICATE") > certifi_count
    else:
        assert text.count("BEGIN CERTIFICATE") >= certifi_count
    assert tls.ssl_context().verify_mode == ssl.CERT_REQUIRED


def test_explain_untrusted_issuer_gives_advice():
    e = ssl.SSLCertVerificationError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: "
                                     "unable to get local issuer certificate (_ssl.c:1028)")
    msg = tls.explain(e)
    assert "unable to get local issuer certificate" in msg and "SPRAT_CA_BUNDLE" in msg
    expired = tls.explain(ssl.SSLCertVerificationError(
        "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: certificate has expired (_ssl.c:1028)"))
    assert "expired" in expired and "SPRAT_CA_BUNDLE" not in expired


@pytest.mark.parametrize("res,start", [
    ({"tried": 3, "errors": 3, "error": "boom"}, "Couldn't connect to the server"),
    ({"tried": 3, "errors": 1, "error": "boom"}, "No Swagger/OpenAPI document found"),
    ({"tried": 3, "errors": 0, "error": ""}, "No Swagger/OpenAPI document found"),
])
def test_not_found_message(res, start):
    assert not_found_message({"specs": [], **res}).startswith(start)
