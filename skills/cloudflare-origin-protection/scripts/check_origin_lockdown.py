#!/usr/bin/env python3
"""Self-audit: can MY origin still be reached directly, bypassing Cloudflare?

Point this at an origin server YOU operate. For every IP and port you give it, it
connects straight to the origin (not through Cloudflare), the way someone who
knows the IP would, and classifies what came back:

  LOCKED     the port refused or silently dropped the connection: the network
             allowlist is doing its job from this vantage point.
  REACHABLE  the port accepted a connection but served no site content (mTLS,
             secret-header 403, HTTPS redirect, closed without a response...).
             Origin auth may be stopping the app, but the network allowlist is
             missing or incomplete, so direct floods still land on the origin.
  EXPOSED    the origin served your site or app directly (including a login
             page or an API error): edge controls (WAF, rate limits, bot
             checks, DDoS shielding) can be bypassed.
  UNTESTED   this machine could not test it (no route, IPv6 unavailable, local
             firewall). Not a pass: re-test from a network that can.

Two probes run per port: a "bypass" probe that presents your hostname (SNI and
Host), and a "scanner" probe that connects to the bare IP with no hostname, the
way internet-wide scanners do. The scanner probe reports which names the
default TLS certificate carries and where a bare-IP redirect points, because
that is how scanners tie a leaked IP back to your site.

This verifies infrastructure you control. It is not a discovery tool: it probes
at most 4 IPs you supply, on at most 16 ports.

Run it from a network OUTSIDE Cloudflare's ranges and not from the origin itself;
it warns you if either is the case, since the firewall would let you through.

Usage:
    python -I check_origin_lockdown.py --host example.com --ip 203.0.113.10
    python -I check_origin_lockdown.py --host example.com --ip 203.0.113.10 --ip 2001:db8::10
    python -I check_origin_lockdown.py --host example.com --ip 203.0.113.10 --ports 443,80,8443
    python -I check_origin_lockdown.py --host example.com --ip 203.0.113.10 --ports 9443/https
    python -I check_origin_lockdown.py --host example.com --ip 203.0.113.10 --path /robots.txt
    python -I check_origin_lockdown.py --host example.com --ip 203.0.113.10 --json

Exit status: 0 LOCKED, 1 EXPOSED, 3 REACHABLE, 4 UNTESTED, 2 usage or internal error.
Stdlib only, Python 3.6+.
"""

import argparse
import concurrent.futures
import errno
import ipaddress
import json
import re
import socket
import ssl
import sys
import urllib.parse
import urllib.request
import warnings

USER_AGENT = "origin-lockdown-selftest/2"
CF_TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace"

# Ports Cloudflare proxies; used to pick http/https when a port has no suffix.
HTTPS_PORTS = {443, 2053, 2083, 2087, 2096, 8443}
HTTP_PORTS = {80, 8080, 8880, 2052, 2082, 2086, 2095}
MAX_PORTS = 16
MAX_IPS = 4
MAX_REDIRECTS = 3

# Cloudflare's published ranges (snapshot 2026-10-26), used only for sanity
# warnings: is the target, or this machine, actually a Cloudflare address?
CF_RANGES = [ipaddress.ip_network(c) for c in (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
    "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
)]

LOCKED, REACHABLE, EXPOSED, UNTESTED = "LOCKED", "REACHABLE", "EXPOSED", "UNTESTED"
SEVERITY = {UNTESTED: 0, LOCKED: 1, REACHABLE: 2, EXPOSED: 3}
EXIT_CODES = {LOCKED: 0, EXPOSED: 1, REACHABLE: 3, UNTESTED: 4}

HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")
TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)


def _errnos(*names_and_numbers):
    out = set()
    for item in names_and_numbers:
        value = getattr(errno, item, None) if isinstance(item, str) else item
        if value is not None:
            out.add(value)
    return out


# "This machine cannot test that": no route, family unsupported, local policy.
LOCAL_FAILURE = _errnos("ENETUNREACH", "EADDRNOTAVAIL", "EAFNOSUPPORT", "EPERM", "EACCES",
                        10051, 10049, 10047, 10013)


def in_cloudflare(ip):
    return any(ip.version == net.version and ip in net for net in CF_RANGES)


def endpoint(ip, port):
    return "[%s]:%d" % (ip, port) if ip.version == 6 else "%s:%d" % (ip, port)


# --------------------------------------------------------------------------- #
# Certificate names (small DER walker; avoids third-party libraries)
# --------------------------------------------------------------------------- #

CN_OID = b"\x55\x04\x03"   # 2.5.4.3 commonName
SAN_OID = b"\x55\x1d\x11"  # 2.5.29.17 subjectAltName


def _tlv(der, i):
    """Return (tag, value_start, value_end) of the DER element starting at i."""
    tag, length = der[i], der[i + 1]
    i += 2
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(der[i:i + n], "big")
        i += n
    return tag, i, i + length


def _children(der, start, end):
    i = start
    while i < end:
        tag, vs, ve = _tlv(der, i)
        yield tag, vs, ve
        i = ve


def cert_names(der):
    """Subject CN plus SAN dNSNames of a DER certificate (best effort, lowercase)."""
    names = []
    try:
        _, cert_s, cert_e = _tlv(der, 0)
        _, tbs_s, tbs_e = _tlv(der, cert_s)
        fields = list(_children(der, tbs_s, tbs_e))
        if fields and fields[0][0] == 0xA0:  # explicit [0] version
            fields = fields[1:]
        # serial, signature, issuer, validity, subject, subjectPublicKeyInfo, extensions...
        _, subj_s, subj_e = fields[4]
        for _, rdn_s, rdn_e in _children(der, subj_s, subj_e):
            for _, atv_s, atv_e in _children(der, rdn_s, rdn_e):
                parts = list(_children(der, atv_s, atv_e))
                if len(parts) == 2 and der[parts[0][1]:parts[0][2]] == CN_OID:
                    tag, v_s, v_e = parts[1]
                    codec = {0x1E: "utf-16-be", 0x1C: "utf-32-be"}.get(tag, "utf-8")  # BMP/Universal
                    names.append(der[v_s:v_e].decode(codec, "replace").lower())
        for tag, ext_s, _ in fields[6:]:
            if tag != 0xA3:  # explicit [3] extensions
                continue
            _, list_s, list_e = _tlv(der, ext_s)
            for _, x_s, x_e in _children(der, list_s, list_e):
                ext = list(_children(der, x_s, x_e))
                if der[ext[0][1]:ext[0][2]] != SAN_OID:
                    continue
                _, gn_s, gn_e = _tlv(der, ext[-1][1])  # OCTET STRING wraps GeneralNames
                for t, n_s, n_e in _children(der, gn_s, gn_e):
                    if t == 0x82:  # [2] dNSName
                        names.append(der[n_s:n_e].decode("ascii", "replace").lower())
    except (IndexError, ValueError):
        pass
    seen = []
    for name in names:
        if name not in seen:
            seen.append(name)
    return seen


def base_domain(host):
    """Rough registrable domain (example.com, example.co.uk) without a suffix list."""
    labels = host.split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and len(labels[-2]) <= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def names_reveal(names, host):
    """Does any of these DNS names point at the user's site?"""
    labels = host.split(".")
    parents = {".".join(labels[i:]) for i in range(len(labels) - 1)}  # host and its parents
    base = base_domain(host)
    for name in names:
        name = (name or "").lower().rstrip(".")
        name = name[2:] if name.startswith("*.") else name
        if not name:
            continue
        if name in parents or name.endswith("." + host) or name == base or name.endswith("." + base):
            return True
    return False


# --------------------------------------------------------------------------- #
# Probing
# --------------------------------------------------------------------------- #

class Fetch(object):
    """One direct connection: either a transport outcome or an HTTP response."""

    def __init__(self):
        self.outcome = None  # set when no HTTP response was obtained
        self.detail = ""
        self.cert_der = None
        self.status, self.headers, self.body = None, {}, b""


class Probe(object):
    def __init__(self, ip, port, scheme, kind, host, path):
        self.ip, self.port, self.scheme, self.kind, self.path = ip, port, scheme, kind, path
        self.site = host  # the user's hostname, whatever this probe sends
        literal = "[%s]" % ip if ip.version == 6 else str(ip)
        self.sni = host if kind == "bypass" else None
        self.host_header = host if kind == "bypass" else literal
        self.outcome, self.detail = UNTESTED, ""
        self.status, self.title, self.location, self.cert_names = None, None, None, []
        self.cloudflare_edge = False
        self.leak = None

    def as_dict(self):
        keys = ("port", "scheme", "kind", "host_header", "path", "outcome", "detail", "status",
                "title", "location", "cert_names", "cloudflare_edge", "leak")
        out = {k: getattr(self, k) for k in keys}
        out["ip"] = str(self.ip)
        return out


def tls_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # Reachability probe against a raw IP: certificate validation must never hide
    # the real question (did the origin answer?), and neither may a legacy TLS
    # setup that an attacker's lenient client would still talk to.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.options |= getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0x4)
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        try:
            ctx.minimum_version = ssl.TLSVersion.TLSv1
        except (AttributeError, ValueError):
            pass
    return ctx


def tls_error_text(exc):
    up = str(exc).upper()
    if "CERTIFICATE_REQUIRED" in up or "CERTIFICATE REQUIRED" in up:
        return "TLS alert certificate_required: the origin demands a client certificate (mTLS)"
    if "HANDSHAKE_FAILURE" in up or "HANDSHAKE FAILURE" in up:
        return "TLS handshake_failure alert (a mandatory client certificate, or no shared cipher/protocol)"
    if "UNRECOGNIZED_NAME" in up or "UNRECOGNIZED NAME" in up:
        return "TLS handshake rejected for this name (e.g. nginx ssl_reject_handshake)"
    if "WRONG_VERSION_NUMBER" in up or "WRONG VERSION NUMBER" in up:
        return "port does not speak TLS (try PORT/http)"
    return "TLS error: %s" % exc


def is_local_failure(exc):
    return exc.errno in LOCAL_FAILURE or getattr(exc, "winerror", None) in LOCAL_FAILURE


def read_response(sock, timeout):
    """Read up to 64 KiB of the HTTP response; stop shortly after the headers."""
    data = b""
    sock.settimeout(timeout)
    while len(data) < 65536:
        try:
            chunk = sock.recv(8192)
        except socket.timeout:
            if data:
                break
            raise
        if not chunk:
            break
        data += chunk
        if b"\r\n\r\n" in data:
            sock.settimeout(min(timeout, 1.5))  # headers are in; body is a bonus
    return data


def fetch(ip, port, scheme, sni, host_header, path, timeout):
    """Make one direct request; never raises."""
    f = Fetch()
    family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
    try:
        raw = socket.socket(family, socket.SOCK_STREAM)
    except OSError as exc:
        f.outcome, f.detail = UNTESTED, "this machine cannot open IPv%d sockets (%s)" % (ip.version, exc)
        return f
    raw.settimeout(timeout)
    try:
        raw.connect((str(ip), port))
    except socket.timeout:
        raw.close()
        f.outcome, f.detail = LOCKED, "TCP connect timed out (packets dropped)"
        return f
    except ConnectionRefusedError:
        raw.close()
        f.outcome, f.detail = LOCKED, "TCP connection refused"
        return f
    except OSError as exc:
        raw.close()
        if is_local_failure(exc):
            f.outcome, f.detail = UNTESTED, "inconclusive from this machine (%s)" % exc
        else:
            f.outcome, f.detail = LOCKED, "TCP connect rejected: %s (firewall reject or routing)" % exc
        return f

    # From here on the TCP port is open: the best the result can be is REACHABLE.
    sock = raw
    try:
        if scheme == "https":
            try:
                sock = tls_context().wrap_socket(raw, server_hostname=sni)
            except socket.timeout:
                f.outcome, f.detail = REACHABLE, "TCP open, TLS handshake timed out"
                return f
            except ssl.SSLError as exc:
                f.outcome, f.detail = REACHABLE, "TCP open; " + tls_error_text(exc)
                return f
            except OSError as exc:
                f.outcome, f.detail = REACHABLE, "TCP open, TLS handshake reset: %s" % exc
                return f
            f.cert_der = sock.getpeercert(binary_form=True)

        request = ("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\n"
                   "Connection: close\r\n\r\n" % (path, host_header, USER_AGENT))
        try:
            sock.sendall(request.encode("ascii"))
            data = read_response(sock, timeout)
        except socket.timeout:
            f.outcome, f.detail = REACHABLE, "connection open but no HTTP response (timeout)"
            return f
        except ssl.SSLError as exc:
            f.outcome, f.detail = REACHABLE, tls_error_text(exc)
            return f
        except OSError as exc:
            f.outcome = REACHABLE
            f.detail = ("connection reset after the TLS handshake, typical of mandatory client "
                        "certificates (mTLS) or a connection filter: %s" % exc)
            return f
    finally:
        try:
            sock.close()
        except OSError:
            pass

    if not data:
        f.outcome, f.detail = REACHABLE, "connection closed with no response (e.g. nginx return 444)"
        return f
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode("latin-1", "replace").split("\r\n")
    match = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})", lines[0])
    if not match:
        f.outcome, f.detail = REACHABLE, "non-HTTP reply: %r" % lines[0][:60]
        return f
    f.status, f.body = int(match.group(1)), body
    for line in lines[1:]:
        key, sep, value = line.partition(":")
        if sep:
            f.headers[key.strip().lower()] = value.strip()
    return f


def redirect_target(location, scheme, host, path):
    """Resolve a Location header; return (scheme, host, path) or None if unusable."""
    base = "%s://%s%s" % (scheme, host, path)
    parts = urllib.parse.urlsplit(urllib.parse.urljoin(base, location))
    target_host = (parts.hostname or "").lower()
    if parts.scheme not in ("http", "https") or not HOSTNAME_RE.match(target_host):
        return None
    target_path = parts.path or "/"
    if parts.query:
        target_path += "?" + parts.query
    target_path = urllib.parse.quote(target_path, safe="/%?=&:+,;@!$'()*~-._")
    return parts.scheme, target_host, target_path


def apply_http(probe, f):
    probe.status = f.status
    title = TITLE_RE.search(f.body)
    if title:
        probe.title = re.sub(r"\s+", " ", title.group(1).decode("utf-8", "replace")).strip()[:80]
    probe.location = f.headers.get("location")
    if "cf-ray" in f.headers or f.headers.get("server", "").lower() == "cloudflare":
        probe.cloudflare_edge = True


def classify(probe, f, host, timeout):
    """Decide the outcome of an HTTP response (following in-app redirects)."""
    apply_http(probe, f)
    status = f.status
    if probe.cloudflare_edge:
        return REACHABLE, "HTTP %d from a Cloudflare edge (CF-RAY/Server header): not your origin" % status
    if status == 400 and b"no required ssl certificate" in f.body.lower():
        return REACHABLE, "HTTP 400 'No required SSL certificate was sent': nginx mTLS is enforced"

    if probe.kind == "scanner":
        if 200 <= status < 300:
            return EXPOSED, "HTTP %d: the bare IP serves content (fingerprintable by scanners)" % status
        if 300 <= status < 400:
            target = probe.location or ""
            parsed = redirect_target(target, probe.scheme, "invalid.invalid", "/") if target else None
            if parsed and names_reveal([parsed[1]], host):
                probe.leak = ("%s redirects bare-IP requests to %s: scanners record Location headers, "
                              "so this ties the IP to your site. Make the default server return 444 "
                              "instead." % (endpoint(probe.ip, probe.port), target[:80]))
            return REACHABLE, "HTTP %d redirect to %s" % (status, target[:80] or "(no Location)")
        return REACHABLE, "HTTP %d for a bare-IP request (default server answers)" % status

    # bypass probe: the request carried your hostname
    if status in (403, 407) and probe.path != "/robots.txt":
        again = fetch(probe.ip, probe.port, probe.scheme, probe.sni, probe.host_header, "/robots.txt", timeout)
        if again.status is not None and 200 <= again.status < 300:
            return EXPOSED, ("HTTP %d at %s but /robots.txt is served directly: the 403 comes from the "
                             "app, not from origin auth" % (status, probe.path))
    if 300 <= status < 400:
        return follow(probe, f, host, timeout)
    return classify_final(f)


def classify_final(f):
    """Outcome of a non-redirect response to a request that carried your hostname."""
    status = f.status
    if status == 400 and b"no required ssl certificate" in f.body.lower():
        return REACHABLE, "HTTP 400 'No required SSL certificate was sent': nginx mTLS is enforced"
    if status == 401:
        return EXPOSED, "HTTP 401: the app's own login answered directly; edge controls are bypassable"
    if status in (403, 407):
        return REACHABLE, ("HTTP %d: rejected before the app (consistent with a secret-header or "
                           "origin-auth rule; confirm it is yours)" % status)
    if status == 421:
        return REACHABLE, "HTTP 421 Misdirected Request: refused for this Host"
    if 200 <= status < 300:
        return EXPOSED, "HTTP %d: the origin served your hostname directly" % status
    return EXPOSED, "HTTP %d: the origin app answered for your hostname directly" % status


def follow(probe, f, host, timeout):
    """A redirect on the bypass probe is benign only as a pure upgrade to HTTPS; else follow it."""
    scheme, cur_host, path, current = probe.scheme, probe.host_header, probe.path, f
    for hop in range(MAX_REDIRECTS + 1):
        location = current.headers.get("location", "")
        target = redirect_target(location, scheme, cur_host, path) if location else None
        if target is None:
            return EXPOSED, "HTTP %d redirect inside the origin app (%s)" % (
                current.status, location[:80] or "no Location")
        t_scheme, t_host, t_path = target
        if hop == 0 and probe.scheme == "http" and t_scheme == "https" and t_path == probe.path \
                and names_reveal([t_host], host):
            return REACHABLE, "HTTP %d redirect to https://%s%s (no content on this port)" % (
                current.status, t_host, t_path)
        if t_scheme != probe.scheme or not names_reveal([t_host], host):
            return EXPOSED, "HTTP %d: the origin app answered directly with a redirect to %s" % (
                current.status, location[:80])
        if hop == MAX_REDIRECTS:
            break
        scheme, cur_host, path = t_scheme, t_host, t_path
        current = fetch(probe.ip, probe.port, scheme, t_host, t_host, t_path, timeout)
        if current.status is None:
            outcome = EXPOSED if current.outcome == EXPOSED else REACHABLE
            return outcome, "redirected to %s, then: %s" % (t_path, current.detail)
        if not 300 <= current.status < 400:
            outcome, detail = classify_final(current)
            title = TITLE_RE.search(current.body)
            label = (' "%s"' % title.group(1).decode("utf-8", "replace").strip()[:60]) if title else ""
            return outcome, "redirected to %s: %s%s" % (t_path, detail, label)
    return EXPOSED, "redirect chain inside the origin app"


def run_probe(probe, timeout):
    try:
        f = fetch(probe.ip, probe.port, probe.scheme, probe.sni, probe.host_header, probe.path, timeout)
        if f.cert_der:
            probe.cert_names = cert_names(f.cert_der)
        if f.status is None:
            probe.outcome, probe.detail = f.outcome, f.detail
        else:
            probe.outcome, probe.detail = classify(probe, f, probe.site, timeout)
    except Exception as exc:  # noqa: BLE001 - one bad probe must not crash the audit
        probe.outcome, probe.detail = UNTESTED, "internal error: %r" % exc
    return probe


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def parse_ports(spec):
    ports = []
    for item in spec.split(","):
        item = item.strip().lower()
        if not item:
            continue
        number, _, scheme = item.partition("/")
        if not number.isdigit() or not 0 < int(number) < 65536:
            raise argparse.ArgumentTypeError("invalid port %r" % item)
        port = int(number)
        if not scheme:
            scheme = "https" if port in HTTPS_PORTS or (port not in HTTP_PORTS and number.endswith("443")) else "http"
        if scheme not in ("http", "https"):
            raise argparse.ArgumentTypeError("port scheme must be /http or /https: %r" % item)
        if (port, scheme) not in ports:
            ports.append((port, scheme))
    if not ports or len(ports) > MAX_PORTS:
        raise argparse.ArgumentTypeError("give between 1 and %d ports" % MAX_PORTS)
    return ports


def parse_host(value):
    host = value.strip().lower().rstrip(".")
    if not HOSTNAME_RE.match(host):
        raise argparse.ArgumentTypeError("not a valid hostname: %r (use punycode for IDNs)" % value)
    return host


def parse_ip(value):
    try:
        return ipaddress.ip_address(value.strip().strip("[]"))
    except ValueError:
        raise argparse.ArgumentTypeError("not an IP address: %r" % value)


def parse_path(value):
    if not value.startswith("/") or "#" in value or not all(32 < ord(c) < 127 for c in value):
        raise argparse.ArgumentTypeError("path must start with / and be printable ASCII without spaces: %r"
                                         % value)
    return value


def positive(value):
    try:
        number = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError("not a number: %r" % value)
    if not number > 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return number


def vantage_point(timeout):
    """This machine's public IP as Cloudflare sees it, or None."""
    req = urllib.request.Request(CF_TRACE_URL, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(4096).decode("ascii", "replace")
    except Exception:  # noqa: BLE001 - optional sanity check only
        return None
    for line in body.splitlines():
        if line.startswith("ip="):
            try:
                return ipaddress.ip_address(line[3:].strip())
            except ValueError:
                return None
    return None


def combine(outcomes):
    """Worst tested outcome; UNTESTED parts keep an otherwise clean result from passing."""
    outcomes = list(outcomes)
    tested = [o for o in outcomes if o != UNTESTED]
    if not tested:
        return UNTESTED
    result = max(tested, key=SEVERITY.get)
    if result == LOCKED and len(tested) < len(outcomes):
        return UNTESTED
    return result


ADVICE = {
    EXPOSED: ("The origin can be used directly, bypassing Cloudflare. Apply the network allowlist and "
              "origin authentication (references/hardening-playbook.md), then re-run this check."),
    REACHABLE: ("Ports accept direct connections from this vantage point. Origin auth may be stopping the "
                "app, but without the network allowlist the origin still absorbs direct floods. If you are "
                "outside Cloudflare's ranges, add or fix the allowlist (Layer 1)."),
    LOCKED: ("No direct access from here. Also confirm every DNS record, Docker-published ports, and that "
             "origin auth rejects requests from an allowed address (references/verification.md)."),
    UNTESTED: ("Not everything could be tested from this machine (see UNTESTED rows). That is not a pass: "
               "re-run from a network that can reach those addresses (usually one with IPv6)."),
}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", required=True, type=parse_host, help="your public hostname, e.g. example.com")
    ap.add_argument("--ip", required=True, action="append", type=parse_ip,
                    help="an origin IP you operate (repeat for IPv4 and IPv6; at most %d)" % MAX_IPS)
    ap.add_argument("--ports", default="443,80", type=parse_ports,
                    help="ports to test, optionally PORT/http or PORT/https (default: 443,80)")
    ap.add_argument("--path", default="/", type=parse_path,
                    help="path to request (default /); use a known public URL to sharpen the verdict")
    ap.add_argument("--timeout", type=positive, default=8.0, help="seconds per connection step (default 8)")
    ap.add_argument("--json", action="store_true", help="print machine-readable results")
    ap.add_argument("--no-vantage-check", action="store_true",
                    help="skip asking cloudflare.com/cdn-cgi/trace for this machine's public IP")
    args = ap.parse_args()

    targets = []
    for ip in args.ip:
        if ip in targets:
            continue
        if in_cloudflare(ip):
            ap.error("%s is a Cloudflare edge address, not your origin. Pass the origin server's own IP "
                     "(from your hosting provider, not from DNS)." % ip)
        targets.append(ip)
    if len(targets) > MAX_IPS:
        ap.error("at most %d origin IPs per run: this is a self-audit of your own origin, not a scanner"
                 % MAX_IPS)

    warnings_out = []
    vantage = None if args.no_vantage_check else vantage_point(min(args.timeout, 8.0))
    if vantage is not None and in_cloudflare(vantage):
        warnings_out.append(
            "This machine's public IP %s is inside Cloudflare's ranges (WARP, a Worker, or a Cloudflare-hosted "
            "runner). A correct allowlist admits you, so these results are NOT meaningful: test from a "
            "non-Cloudflare network." % vantage)
    if vantage is not None and vantage in targets:
        warnings_out.append(
            "You are running this on the origin itself (%s). Local traffic skips the firewall path an attacker "
            "uses: run it from another network." % vantage)
    for ip in targets:
        if not ip.is_global:
            warnings_out.append("%s is not a public address: results only describe your local network path." % ip)

    probes = [Probe(ip, port, scheme, kind, args.host, args.path)
              for ip in targets for port, scheme in args.ports for kind in ("bypass", "scanner")]
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(probes))) as pool:
        list(pool.map(lambda p: run_probe(p, args.timeout), probes))

    per_ip = {ip: combine(p.outcome for p in probes if p.ip == ip) for ip in targets}
    overall = combine(per_ip.values())

    leaks = []
    for p in probes:
        if p.kind == "scanner" and p.cert_names and p.outcome != LOCKED and names_reveal(p.cert_names, args.host):
            leaks.append("%s presents a certificate naming %s to clients that send no hostname: scanners that "
                         "index certificates per IP can link this IP to your site. Make the default server "
                         "reject unknown names (ssl_reject_handshake)."
                         % (endpoint(p.ip, p.port), ", ".join(p.cert_names[:4])))
        if p.leak:
            leaks.append(p.leak)
        edge = ("%s answered with Cloudflare edge headers: this address is proxied by Cloudflare, so it is "
                "not a direct path to your origin." % endpoint(p.ip, p.port))
        if p.cloudflare_edge and edge not in warnings_out:
            warnings_out.append(edge)

    if args.json:
        print(json.dumps({
            "host": args.host,
            "path": args.path,
            "vantage_ip": str(vantage) if vantage else None,
            "overall": overall,
            "per_ip": {str(ip): v for ip, v in per_ip.items()},
            "warnings": warnings_out,
            "leaks": leaks,
            "probes": [p.as_dict() for p in probes],
        }, indent=2))
        return EXIT_CODES[overall]

    print("Self-audit of direct access to the origin of %s (path %s)" % (args.host, args.path))
    print("Vantage point: %s" % (vantage if vantage else "unknown (check skipped or unavailable)"))
    for w in warnings_out:
        print("WARNING: " + w)
    for ip in targets:
        print("\n%s" % ip)
        for p in (p for p in probes if p.ip == ip):
            if p.kind == "bypass":
                label, how = "%d/%s" % (p.port, p.scheme), "bypass  (Host %s)" % p.host_header
            else:
                label, how = "", "scanner (bare IP%s)" % (", no SNI" if p.scheme == "https" else "")
            extra = ' title="%s"' % p.title if p.title else ""
            if p.cert_names and p.kind == "scanner":
                extra += " cert=%s" % ",".join(p.cert_names[:4])
            print("  %-10s %-34s %-9s %s%s" % (label, how, p.outcome, p.detail, extra))
        print("  verdict: %s" % per_ip[ip])
    for leak in leaks:
        print("\nLEAK: " + leak)
    print("\nOVERALL: %s - %s" % (overall, ADVICE[overall]))
    return EXIT_CODES[overall]


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(2)
    except Exception as exc:  # noqa: BLE001 - never let a crash read as a verdict
        sys.stderr.write("internal error: %r\n" % exc)
        sys.exit(2)
