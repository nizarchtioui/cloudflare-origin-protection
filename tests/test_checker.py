"""Tests for check_origin_lockdown.py.

Covers certificate parsing, verdict logic, and end-to-end runs of the CLI against
small in-process origins on 127.0.0.1: plain HTTP always, TLS when the `openssl`
command is available to mint a throwaway certificate.
"""

import base64
import errno
import importlib.util
import ipaddress
import json
import os
import random
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "skills", "cloudflare-origin-protection", "scripts", "check_origin_lockdown.py")

sys.dont_write_bytecode = True  # keep __pycache__ out of the skill folder
_spec = importlib.util.spec_from_file_location("check_origin_lockdown", SCRIPT)
chk = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(chk)

SITE = "example.test"
PAGE = b"<html><head><title>Example Shop</title></head><body>real site</body></html>"

# Public test certificates (no private keys).
SAN_ONLY_CERT = base64.b64decode(  # empty subject, SAN www.example.test, issued by "Test Issuing CA"
    "MIIBMTCB2KADAgECAggBAgMEBQYHCDAKBggqhkjOPQQDAjAaMRgwFgYDVQQDEw9UZXN0IElzc3VpbmcgQ0EwHhcNMjYxMDI1Mj"
    "EzMDM2WhcNMjYxMTE1MjEzMDM2WjAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEM3BdFR0Tc1oHA6kXK5SLul0j9YbO4iFc"
    "dkkisCQNKPf/TgA0sUECeuDWHpRuUfmLtnwZYQHuKY5pZmDLOGj5/6MiMCAwHgYDVR0RAQH/BBQwEoIQd3d3LmV4YW1wbGUudG"
    "VzdDAKBggqhkjOPQQDAgNIADBFAiB3oZmi1FEOGPDLIYXkSOaQSxeiveNJRN/2f/zKW+Tc6AIhAL8ZDySiA1TPzC2LGqPrJIre"
    "cF7tMppXrzMHMscyC6iJ")
WILDCARD_BMP_CERT = base64.b64decode(  # subject CN *.xyz.ai as BMPString, SAN *.xyz.ai + xyz.ai
    "MIIBTDCB86ADAgECAggBAgMEBQYHCDAKBggqhkjOPQQDAjAaMRgwFgYDVQQDEw9UZXN0IElzc3VpbmcgQ0EwHhcNMjYxMDI1Mj"
    "EzMDM2WhcNMjYxMTE1MjEzMDM2WjAbMRkwFwYDVQQDHhAAKgAuAHgAeQB6AC4AYQBpMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD"
    "QgAEWHptdvte4jW1XQPHhUU2Uc1YqH9UBM5PsMex0AEU3mhZIhp+ebCz0eQbSNkrF/2h2E+OOvRLlI1lnXpY/yGWdaMiMCAwHg"
    "YDVR0RAQH/BBQwEoIIKi54eXouYWmCBnh5ei5haTAKBggqhkjOPQQDAgNIADBFAiEAx2XwrZV+6OwqWMEWsNSNmqOk4qVSTXD9"
    "L4W3jv5P9a0CIGy45GKhO9tVn/JhoOYSDeb7RXmkgosV1zCqa6XA4FLu")
SITE_CERT = base64.b64decode(  # self-signed CN example.test, SAN example.test + www.example.test
    "MIIBUDCB96ADAgECAgh39czwuTo34jAKBggqhkjOPQQDAjAXMRUwEwYDVQQDEwxleGFtcGxlLnRlc3QwHhcNMjYxMDI1MjA1Mj"
    "A0WhcNMjYxMTI1MjA1MjA0WjAXMRUwEwYDVQQDEwxleGFtcGxlLnRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATougAh"
    "I8Fd4pJrf2UmIaqj9Qyy4cfkoK1pa0Bvwu6sNWgBmH6xG0mPwTxYd0BcdtiEAOFaX7n5DuTPHCYyzT/coy0wKzApBgNVHREEIj"
    "AgggxleGFtcGxlLnRlc3SCEHd3dy5leGFtcGxlLnRlc3QwCgYIKoZIzj0EAwIDSAAwRQIhAKwUQ2wTiDeFc/TsX5Q1m6TM+S9h"
    "t+VnB4GCOhBrdsXoAiAPBSfOyf/X1DqPCKmvgTw3oknalkX2PetyvhTFNTy6jA==")


# --------------------------------------------------------------------------- #
# A tiny origin simulator
# --------------------------------------------------------------------------- #

def respond(status, body=b"", headers=()):
    lines = ["HTTP/1.1 %s" % status, "Content-Length: %d" % len(body), "Connection: close"] + list(headers)
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


def behaviour(mode, path, host, conn):
    """Bytes to send for a request, or None to close without answering."""
    if mode == "site":
        return respond("200 OK", PAGE)
    if mode == "upgrade":
        return respond("301 Moved Permanently", headers=["Location: https://%s%s" % (SITE, path)])
    if mode == "app-redirect":
        if path == "/":
            return respond("302 Found", headers=["Location: https://%s/login" % SITE])
        return respond("200 OK", b"<title>Sign in</title>")
    if mode == "relative":
        if path == "/":
            return respond("302 Found", headers=["Location: /dashboard"])
        return respond("200 OK", b"<title>Dashboard</title>")
    if mode == "auth403":
        return respond("403 Forbidden", b"origin auth")
    if mode == "app403":
        return respond("200 OK", b"User-agent: *") if path == "/robots.txt" else respond("403 Forbidden")
    if mode == "app401":
        return respond("401 Unauthorized", headers=['WWW-Authenticate: Bearer realm="api"'])
    if mode == "close":
        return None
    if mode == "redirect-then-403":
        if host == SITE:
            return respond("301 Moved Permanently", headers=["Location: http://www.%s/" % SITE])
        return respond("403 Forbidden", b"origin auth")
    if mode == "nginx-mtls":
        if conn.getpeercert() is None:
            body = (b"<html><head><title>400 No required SSL certificate was sent</title></head><body>"
                    b"<center>No required SSL certificate was sent</center></body></html>")
            return respond("400 Bad Request", body)
        return respond("200 OK", PAGE)
    raise ValueError(mode)


def read_request(conn):
    conn.settimeout(5)
    data = b""
    while b"\r\n\r\n" not in data and len(data) < 65536:
        chunk = conn.recv(4096)
        if not chunk:
            break
        data += chunk
    lines = data.decode("latin-1").split("\r\n")
    parts = lines[0].split(" ")
    path = parts[1] if len(parts) > 1 else "/"
    host = ""
    for line in lines[1:]:
        if line.lower().startswith("host:"):
            host = line.split(":", 1)[1].strip().split(":")[0]
    return path, host


class Origin(object):
    def __init__(self, mode, tls_ctx=None):
        self.mode, self.tls_ctx = mode, tls_ctx
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                raw, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(raw,), daemon=True).start()

    def _handle(self, raw):
        conn = raw
        try:
            if self.tls_ctx is not None:
                conn = self.tls_ctx.wrap_socket(raw, server_side=True)
            path, host = read_request(conn)
            reply = behaviour(self.mode, path, host, conn)
            if reply:
                conn.sendall(reply)
        except (OSError, ssl.SSLError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def close(self):
        self.sock.close()


def run_checker(*args):
    cmd = [sys.executable, "-I", SCRIPT, "--no-vantage-check"] + list(args)
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                          timeout=120)
    return proc.returncode, proc.stdout, proc.stderr


def audit(port, scheme):
    code, out, err = run_checker("--host", SITE, "--ip", "127.0.0.1", "--ports", "%d/%s" % (port, scheme),
                                 "--timeout", "3", "--json")
    return code, json.loads(out)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# --------------------------------------------------------------------------- #
# Unit tests
# --------------------------------------------------------------------------- #

class CertificateNames(unittest.TestCase):
    def test_san_only_certificate_does_not_report_issuer_cn(self):
        self.assertEqual(chk.cert_names(SAN_ONLY_CERT), ["www.example.test"])

    def test_bmpstring_common_name_is_decoded(self):
        self.assertEqual(chk.cert_names(WILDCARD_BMP_CERT), ["*.xyz.ai", "xyz.ai"])

    def test_self_signed_site_certificate(self):
        self.assertEqual(chk.cert_names(SITE_CERT), ["example.test", "www.example.test"])

    def test_parser_survives_corrupted_and_truncated_input(self):
        rng = random.Random(7)
        for _ in range(1000):
            blob = bytearray(SITE_CERT)
            for _ in range(rng.randint(1, 8)):
                blob[rng.randrange(len(blob))] = rng.randrange(256)
            chk.cert_names(bytes(blob[:rng.randint(0, len(blob))]))  # must not raise


class DomainMatching(unittest.TestCase):
    def test_reveals(self):
        self.assertTrue(chk.names_reveal(["*.xyz.ai"], "app.xyz.ai"))
        self.assertTrue(chk.names_reveal(["www.example.com"], "example.com"))
        self.assertTrue(chk.names_reveal(["api.shop.example.com"], "shop.example.com"))
        self.assertTrue(chk.names_reveal(["example.co.uk"], "app.example.co.uk"))

    def test_does_not_reveal(self):
        self.assertFalse(chk.names_reveal(["other.co.uk"], "app.example.co.uk"))
        self.assertFalse(chk.names_reveal(["example.net"], "example.com"))
        self.assertFalse(chk.names_reveal(["placeholder.invalid"], "example.com"))


class Verdicts(unittest.TestCase):
    def test_untested_never_turns_into_a_pass(self):
        L, R, E, U = chk.LOCKED, chk.REACHABLE, chk.EXPOSED, chk.UNTESTED
        self.assertEqual(chk.combine([L, U]), U)
        self.assertEqual(chk.combine([U, U]), U)
        self.assertEqual(chk.combine([E, U]), E)
        self.assertEqual(chk.combine([R, L]), R)
        self.assertEqual(chk.combine([L, L]), L)

    def test_ipv6_unavailable_locally_is_untested(self):
        real = socket.socket

        def no_ipv6(family=socket.AF_INET, *args, **kwargs):
            if family == socket.AF_INET6:
                raise OSError(errno.EAFNOSUPPORT, "Address family not supported by protocol")
            return real(family, *args, **kwargs)

        chk.socket.socket = no_ipv6
        try:
            probe = chk.Probe(ipaddress.ip_address("2001:db8::10"), 443, "https", "bypass", SITE, "/")
            chk.run_probe(probe, 2.0)
        finally:
            chk.socket.socket = real
        self.assertEqual(probe.outcome, chk.UNTESTED)


class Parsing(unittest.TestCase):
    def test_ports_and_schemes(self):
        self.assertEqual(chk.parse_ports("443,80"), [(443, "https"), (80, "http")])
        self.assertEqual(chk.parse_ports("9443"), [(9443, "https")])
        self.assertEqual(chk.parse_ports("9000"), [(9000, "http")])
        self.assertEqual(chk.parse_ports("8443/http"), [(8443, "http")])
        for bad in ("0", "70000", "80/ftp", "x"):
            with self.assertRaises(Exception):
                chk.parse_ports(bad)

    def test_redirect_targets(self):
        self.assertEqual(chk.redirect_target("/dash?x=1", "https", SITE, "/"), ("https", SITE, "/dash?x=1"))
        self.assertIsNone(chk.redirect_target("javascript:alert(1)", "https", SITE, "/"))
        target = chk.redirect_target("https://evil.test\r\nX: y/", "https", SITE, "/")
        self.assertTrue(target is None or not any(c in target[1] + target[2] for c in "\r\n "))


# --------------------------------------------------------------------------- #
# End-to-end: the CLI against simulated origins
# --------------------------------------------------------------------------- #

class PlainHttpOrigins(unittest.TestCase):
    CASES = [
        ("site", "EXPOSED"),
        ("upgrade", "REACHABLE"),
        ("app-redirect", "EXPOSED"),
        ("relative", "EXPOSED"),
        ("auth403", "REACHABLE"),
        ("app403", "EXPOSED"),
        ("app401", "EXPOSED"),
        ("close", "REACHABLE"),
        ("redirect-then-403", "REACHABLE"),
    ]
    EXIT = {"LOCKED": 0, "EXPOSED": 1, "REACHABLE": 3, "UNTESTED": 4}

    def test_verdicts(self):
        for mode, expected in self.CASES:
            with self.subTest(mode=mode):
                origin = Origin(mode)
                try:
                    code, result = audit(origin.port, "http")
                finally:
                    origin.close()
                self.assertEqual(result["overall"], expected, json.dumps(result["probes"], indent=1))
                self.assertEqual(code, self.EXIT[expected])

    def test_bare_ip_redirect_to_the_site_is_a_leak(self):
        origin = Origin("upgrade")
        try:
            _, result = audit(origin.port, "http")
        finally:
            origin.close()
        self.assertTrue(any("redirects bare-IP requests" in leak for leak in result["leaks"]), result["leaks"])

    def test_closed_port_is_locked(self):
        code, result = audit(free_port(), "http")
        self.assertEqual((code, result["overall"]), (0, "LOCKED"))


class Guards(unittest.TestCase):
    def test_refused_inputs(self):
        for args in (["--host", SITE, "--ip", "104.16.0.1"],
                     ["--host", "example.test\r\nX-Evil: 1", "--ip", "127.0.0.1"],
                     ["--host", SITE, "--ip", "127.0.0.1", "--timeout", "0"],
                     ["--host", SITE, "--ip", "127.0.0.1", "--path", "no-slash"],
                     ["--host", SITE] + sum((["--ip", "203.0.113.%d" % i] for i in range(1, 6)), [])):
            with self.subTest(args=args):
                code, _, _ = run_checker(*args)
                self.assertEqual(code, 2)


#: Optional throwaway certificate for example.test, for machines without openssl.
GIVEN_CERT = os.environ.get("CFOP_TEST_CERT"), os.environ.get("CFOP_TEST_KEY")


@unittest.skipUnless(shutil.which("openssl") or all(GIVEN_CERT),
                     "needs the openssl command, or CFOP_TEST_CERT and CFOP_TEST_KEY")
class TlsOrigins(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        if all(GIVEN_CERT):
            cls.cert, cls.key = GIVEN_CERT
            return
        cls.cert, cls.key = os.path.join(cls.tmp, "cert.pem"), os.path.join(cls.tmp, "key.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                        "-keyout", cls.key, "-out", cls.cert, "-subj", "/CN=%s" % SITE,
                        "-addext", "subjectAltName=DNS:%s,DNS:www.%s" % (SITE, SITE)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def context(self, verify=ssl.CERT_NONE):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.cert, self.key)
        if verify != ssl.CERT_NONE:
            ctx.verify_mode = verify
            ctx.load_verify_locations(self.cert)
        return ctx

    def run_origin(self, mode, verify=ssl.CERT_NONE):
        origin = Origin(mode, self.context(verify))
        try:
            return audit(origin.port, "https")
        finally:
            origin.close()

    def test_site_over_tls_is_exposed_and_certificate_leaks(self):
        _, result = self.run_origin("site")
        self.assertEqual(result["overall"], "EXPOSED")
        self.assertTrue(any("certificate naming" in leak for leak in result["leaks"]), result["leaks"])

    def test_mandatory_client_certificate_is_reachable_not_locked(self):
        _, result = self.run_origin("site", verify=ssl.CERT_REQUIRED)
        self.assertEqual(result["overall"], "REACHABLE")

    def test_nginx_style_mtls_rejection_is_reachable(self):
        _, result = self.run_origin("nginx-mtls", verify=ssl.CERT_OPTIONAL)
        self.assertEqual(result["overall"], "REACHABLE")
        self.assertIn("nginx mTLS", result["probes"][0]["detail"])


if __name__ == "__main__":
    unittest.main()
