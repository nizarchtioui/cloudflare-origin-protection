#!/usr/bin/env python3
"""Generate origin rules that admit web traffic ONLY from Cloudflare.

Fetches Cloudflare's published IP ranges (API first, plain-text lists second),
validates every entry, and prints a ready-to-apply allowlist for the chosen
backend. Built to be re-run on a schedule: the nftables output replaces its own
table atomically, and the iptables and Windows outputs build the new rules
before removing the old ones, so a refresh never opens a gap, stacks
duplicates, or keeps ranges Cloudflare has retired.

This is a defensive tool for an origin server YOU operate: it narrows who may
reach the web ports down to Cloudflare's edge, so direct-to-origin connections
are dropped.

Formats:
  nftables  Recommended on Linux. One self-contained table that drops
            non-Cloudflare traffic to the web ports at prerouting, before
            Docker/Kubernetes DNAT, so published container ports are covered.
            Every other port and rule (ufw, firewalld, Docker) is left alone.
  iptables  The same policy for iptables/ip6tables (mangle PREROUTING).
  ufw       ufw allow rules. One-time setup only; ufw does NOT see Docker ports.
  aws       JSON for: aws ec2 authorize-security-group-ingress --ip-permissions file://FILE
  gcp       gcloud commands (one rule per IP family; GCP cannot mix them).
  windows   PowerShell for Windows Defender Firewall (allow Cloudflare, block the rest).
  nginx     set_real_ip_from list, real_ip_header, and a $from_cloudflare geo map.
  apache    mod_remoteip RemoteIPTrustedProxy list.
  caddy     global trusted_proxies / client_ip_headers / protocols options.
  cidr      one CIDR per line.
  json      Cloudflare's ranges plus source and etag (accepted back by --ranges-file).

Scope (nftables, iptables): by default the drops apply to traffic arriving on
every interface except loopback, so Docker bridges, Kubernetes pods, VPNs and
private networks lose access to the web ports too. On such hosts pass
--public-iface with the internet-facing interface(s) (see `ip route show default`).

Usage:
    python -I generate_cf_firewall_rules.py --format nftables --public-iface eth0 > cf-origin.nft
    python -I generate_cf_firewall_rules.py --format nftables --ports 443 --deny-ports 80
    python -I generate_cf_firewall_rules.py --format nftables --also-allow 10.0.1.0/24
    python -I generate_cf_firewall_rules.py --format iptables --require-live > cf-origin.sh
    python -I generate_cf_firewall_rules.py --format aws --ports 443 > cf-sg.json
    python -I generate_cf_firewall_rules.py --format nginx > /etc/nginx/conf.d/cloudflare.conf
    python -I generate_cf_firewall_rules.py --format json > cf-ranges.json
    python -I generate_cf_firewall_rules.py --format nftables --ranges-file cf-ranges.json

Exit status: 0 ok, 1 ranges unavailable, invalid or suspicious, 2 usage error.
Stdlib only, Python 3.6+.
"""

import argparse
import datetime
import ipaddress
import json
import re
import sys
import urllib.request

CF_API_URL = "https://api.cloudflare.com/client/v4/ips"
CF_V4_URL = "https://www.cloudflare.com/ips-v4/"
CF_V6_URL = "https://www.cloudflare.com/ips-v6/"
# www.cloudflare.com answers 403 to Python's default User-Agent, so always send one.
USER_AGENT = "cf-origin-protection/2 (firewall allowlist refresh)"

# Bundled fallback, and the baseline for spotting suspicious changes: Cloudflare's
# published ranges as fetched on SNAPSHOT_DATE.
SNAPSHOT_DATE = "2026-10-26"
SNAPSHOT_V4 = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]
SNAPSHOT_V6 = [
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
    "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
]

# A poisoned or garbled list must never widen the allowlist: refuse anything
# broader than these prefixes, and anything that is not a public CIDR.
MIN_PREFIX = {4: 8, 6: 16}
# --also-allow may go broader than MIN_PREFIX only inside private or link-local
# space (e.g. fc00::/7). Listed explicitly: ipaddress's is_private differs across
# Python versions, and some versions count 0.0.0.0/0 as private.
PRIVATE_SPACE = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16",
    "fc00::/7", "fe80::/10")]
MAX_RANGES = 200
MAX_PORTS = 15  # iptables multiport limit
ADMIN_PORTS = {22: "SSH", 3389: "RDP", 5985: "WinRM", 5986: "WinRM"}
IFACE_RE = re.compile(r"^[A-Za-z0-9_.:@-]{1,15}$")
ETAG_RE = re.compile(r"^[0-9A-Za-z._-]{1,128}$")

NFT_TABLE = "cf_origin"
IPT_CHAIN = "CF_ORIGIN"
WIN_GROUP = "Cloudflare origin lockdown"
AWS_RULE_QUOTA = 60  # default inbound rules per security group, per IP family


# --------------------------------------------------------------------------- #
# Ranges: fetch, validate, compare
# --------------------------------------------------------------------------- #

def to_networks(entries, version, label):
    """Validate Cloudflare CIDR strings for one IP family; return them collapsed and sorted."""
    nets = []
    for entry in entries:
        text = str(entry).split("#", 1)[0].strip()
        if not text:
            continue
        try:
            net = ipaddress.ip_network(text)
        except ValueError:
            raise ValueError("%s: %r is not a valid CIDR" % (label, text[:60]))
        if net.version != version:
            raise ValueError("%s: %s is not an IPv%d range" % (label, net, version))
        if net.prefixlen < MIN_PREFIX[version]:
            raise ValueError("%s: refusing implausibly broad range %s" % (label, net))
        if not net.is_global:
            raise ValueError("%s: %s is not a public range" % (label, net))
        nets.append(net)
    if len(nets) > MAX_RANGES:
        raise ValueError("%s: %d ranges is implausible" % (label, len(nets)))
    return sorted(ipaddress.collapse_addresses(nets))


def both_families(v4, v6, label):
    if not v4 or not v6:
        raise ValueError("%s: missing IPv4 or IPv6 ranges" % label)
    return v4, v6


def http_get(url, timeout):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read(1000000).decode("utf-8", "replace")


def fetch_live(timeout):
    """Return (v4, v6, source, etag) from Cloudflare, or raise RuntimeError."""
    problems = []
    try:
        doc = json.loads(http_get(CF_API_URL, timeout))
        if not doc.get("success"):
            raise ValueError("API answered success=false")
        result = doc.get("result") or {}
        v4, v6 = both_families(to_networks(result.get("ipv4_cidrs", []), 4, "API ipv4_cidrs"),
                               to_networks(result.get("ipv6_cidrs", []), 6, "API ipv6_cidrs"), CF_API_URL)
        return v4, v6, CF_API_URL, result.get("etag")
    except Exception as exc:  # noqa: BLE001 - any failure falls through to the next source
        problems.append("%s: %s" % (CF_API_URL, exc))
    try:
        v4, v6 = both_families(to_networks(http_get(CF_V4_URL, timeout).splitlines(), 4, CF_V4_URL),
                               to_networks(http_get(CF_V6_URL, timeout).splitlines(), 6, CF_V6_URL),
                               "www.cloudflare.com lists")
        return v4, v6, "%s + %s" % (CF_V4_URL, CF_V6_URL), None
    except Exception as exc:  # noqa: BLE001
        problems.append("www.cloudflare.com lists: %s" % exc)
    raise RuntimeError("; ".join(problems))


def load_ranges_file(path):
    """Read ranges from this script's json output, Cloudflare's API JSON, or a CIDR list."""
    with open(path, encoding="utf-8-sig") as fh:  # tolerate a BOM from Windows editors
        text = fh.read()
    etag = None
    if text.lstrip().startswith("{"):
        doc = json.loads(text)
        doc = doc.get("result", doc)
        v4_entries, v6_entries, etag = doc.get("ipv4_cidrs", []), doc.get("ipv6_cidrs", []), doc.get("etag")
    else:
        lines = [line.split("#", 1)[0].strip() for line in text.splitlines()]
        v4_entries = [line for line in lines if line and ":" not in line]
        v6_entries = [line for line in lines if ":" in line]
    v4, v6 = both_families(to_networks(v4_entries, 4, path), to_networks(v6_entries, 6, path), path)
    return v4, v6, "file %s" % path, etag


def snapshot():
    return to_networks(SNAPSHOT_V4, 4, "snapshot"), to_networks(SNAPSHOT_V6, 6, "snapshot")


def report_changes(v4, v6):
    """Tell the operator (stderr) when Cloudflare's list moved since the snapshot."""
    old = set().union(*snapshot())
    new = set(v4) | set(v6)
    added, removed = sorted(new - old, key=str), sorted(old - new, key=str)
    if not added and not removed:
        sys.stderr.write("[info] ranges match the bundled snapshot of %s\n" % SNAPSHOT_DATE)
        return
    sys.stderr.write(
        "[notice] Cloudflare's ranges differ from the bundled snapshot of %s:\n"
        "         added:   %s\n         removed: %s\n"
        "         If you did not expect a change, compare with https://www.cloudflare.com/ips/ "
        "before applying.\n" % (SNAPSHOT_DATE, ", ".join(map(str, added)) or "-",
                                ", ".join(map(str, removed)) or "-"))


def check_changes(v4, v6):
    """Raise ValueError if the list moved suspiciously far from the snapshot."""
    problems = []
    for version, now, before in ((4, v4, snapshot()[0]), (6, v6, snapshot()[1])):
        kept = len(set(now) & set(before))
        if kept * 2 < len(before):
            problems.append("only %d of %d known IPv%d ranges remain" % (kept, len(before), version))
        grown = sum(n.num_addresses for n in now)
        known = sum(n.num_addresses for n in before)
        if grown > 2 * known:
            problems.append("IPv%d address space is %.1fx the known size" % (version, float(grown) / known))
    if problems:
        raise ValueError("suspicious change (%s); review https://www.cloudflare.com/ips/ and re-run "
                         "with --accept-changes if it is genuine" % "; ".join(problems))


def complement(nets, version):
    """CIDRs covering every address NOT in nets (for block-everyone-else rules)."""
    space = [ipaddress.ip_network("0.0.0.0/0" if version == 4 else "::/0")]
    for net in nets:
        remaining = []
        for block in space:
            if not block.overlaps(net):
                remaining.append(block)
            elif block.prefixlen < net.prefixlen:
                remaining.extend(block.address_exclude(net))
            # else: the block lies inside net and is excluded entirely
        space = remaining
    out = []
    for block in sorted(ipaddress.collapse_addresses(space)):
        # Firewall UIs tend to reject /0, so state the whole space as two halves.
        out.extend(block.subnets(prefixlen_diff=1) if block.prefixlen == 0 else [block])
    return out


def printable(text, limit=200):
    """Make text safe for a comment line in a generated file: no newlines or controls."""
    return "".join(c if c.isprintable() else "?" for c in str(text))[:limit]


# --------------------------------------------------------------------------- #
# Emitters
# --------------------------------------------------------------------------- #

class Ruleset(object):
    def __init__(self, v4, v6, extra4, extra6, args, source, etag):
        self.cf4, self.cf6_all = v4, v6
        self.cf6 = v6 if not args.no_v6 else []
        self.extra4, self.extra6 = extra4, extra6
        self.allow4 = sorted(ipaddress.collapse_addresses(self.cf4 + extra4))
        self.allow6 = sorted(ipaddress.collapse_addresses(self.cf6 + extra6))
        self.ports, self.deny_ports = args.ports, args.deny_ports
        self.ifaces = [i for n, i in enumerate(args.public_iface) if i not in args.public_iface[:n]]
        self.udp_drop = not args.no_udp_drop
        self.generated = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.source = printable(source)
        self.etag = etag if isinstance(etag, str) and ETAG_RE.match(etag) else None
        self.banner = "Generated %s from %s%s: %d IPv4 + %d IPv6 Cloudflare ranges%s%s" % (
            self.generated, self.source, " (etag %s)" % self.etag if self.etag else "", len(self.cf4),
            len(self.cf6), "" if self.cf6 else " (IPv6 not admitted)",
            ", plus --also-allow %s" % ", ".join(map(str, extra4 + extra6)) if extra4 or extra6 else "")

    def scope_lines(self):
        if self.ifaces:
            return ["# Scope: only traffic arriving on %s (--public-iface); other interfaces are"
                    % ", ".join(self.ifaces),
                    "# untouched."]
        return ["# Scope: every interface except loopback. Traffic from Docker bridges,",
                "# Kubernetes pods (kube-proxy IPVS binds every ClusterIP to the host), VPNs and",
                "# private networks to these ports is dropped too unless it comes from an",
                "# allowed range. On such hosts regenerate with --public-iface <interface>."]


def port_list(ports, sep=","):
    return sep.join(str(p) for p in ports)


def nft_ports(ports):
    return "{ %s }" % port_list(ports, ", ")


def nft_set(name, kind, nets):
    lines = ["\tset %s {" % name, "\t\ttype %s" % kind, "\t\tflags interval"]
    if nets:
        lines += ["\t\telements = {", ",\n".join("\t\t\t%s" % n for n in nets), "\t\t}"]
    return lines + ["\t}"]


def emit_nftables(rs):
    ports = nft_ports(rs.ports)
    scope = 'iifname { %s } ' % ", ".join('"%s"' % i for i in rs.ifaces) if rs.ifaces else ""
    out = [
        "#!/usr/sbin/nft -f",
        "# " + rs.banner,
        "#",
        "# Cloudflare-only web ingress. Traffic to TCP %s is dropped unless it comes from" % port_list(rs.ports),
        "# the allowed ranges; every other port is left to your existing firewall.",
    ] + rs.scope_lines() + [
        "# Atomic and self-contained: loading this replaces only table inet %s and never" % NFT_TABLE,
        "# touches your other rules (ufw, firewalld, Docker). Hooked at prerouting priority",
        "# -150, before Docker/Kubernetes DNAT (-100), so published container ports are",
        "# covered as well as host services.",
        "#   check:  nft -c -f FILE      load:  nft -f FILE      remove:  nft delete table inet %s" % NFT_TABLE,
        "table inet %s" % NFT_TABLE,
        "delete table inet %s" % NFT_TABLE,
        "table inet %s {" % NFT_TABLE,
    ]
    out += nft_set("cf_v4", "ipv4_addr", rs.allow4)
    out += nft_set("cf_v6", "ipv6_addr", rs.allow6)
    out += [
        "\tchain prerouting {",
        "\t\ttype filter hook prerouting priority -150; policy accept;",
        '\t\tiif "lo" accept',
        "\t\tfib daddr type != local accept",
    ]
    if rs.deny_ports:
        out += ["\t\t# Ports nothing should reach, not even Cloudflare:",
                "\t\t%stcp dport %s counter drop" % (scope, nft_ports(rs.deny_ports)),
                "\t\t%sudp dport %s counter drop" % (scope, nft_ports(rs.deny_ports))]
    out += [
        "\t\ttcp dport %s ip saddr @cf_v4 accept" % ports,
        "\t\ttcp dport %s ip6 saddr @cf_v6 accept" % ports,
        "\t\t%stcp dport %s counter drop" % (scope, ports),
    ]
    if rs.udp_drop:
        out += ["\t\t# Cloudflare never connects to origins over UDP (no HTTP/3 to origin), so QUIC",
                "\t\t# on these ports is only a path around the edge. (VPN on UDP 443? --no-udp-drop)",
                "\t\t%sudp dport %s counter drop" % (scope, ports)]
    out += ["\t}", "}"]
    return "\n".join(out)


def sh_continued(command, items):
    return " \\\n".join([command] + ["\t%s" % item for item in items])


def emit_iptables(rs):
    ports = port_list(rs.ports)
    matches = (["-i %s -m addrtype --dst-type LOCAL" % i for i in rs.ifaces] if rs.ifaces
               else ["! -i lo -m addrtype --dst-type LOCAL"])
    tag = "-m comment --comment $TAG"
    hooks = []
    for match in matches:
        hooks.append("\t$IPT -I PREROUTING 1 %s -p tcp -m multiport --dports %s %s -j $NEW" % (match, ports, tag))
        if rs.udp_drop:
            hooks.append("\t$IPT -I PREROUTING 1 %s -p udp -m multiport --dports %s %s -j DROP"
                         % (match, ports, tag))
        if rs.deny_ports:
            hooks += ["\t$IPT -I PREROUTING 1 %s -p %s -m multiport --dports %s %s -j DROP"
                      % (match, proto, port_list(rs.deny_ports), tag) for proto in ("tcp", "udp")]
    out = [
        "#!/bin/sh",
        "# " + rs.banner,
        "#",
        "# Cloudflare-only web ingress for iptables/ip6tables (legacy or nf_tables backend).",
        "# Traffic to TCP %s is dropped unless it comes from the allowed ranges%s;" % (
            ports, "; UDP on those ports (QUIC) is dropped for everyone" if rs.udp_drop else ""),
        "# other ports are left to your firewall.",
    ] + rs.scope_lines() + [
        "# Runs in mangle PREROUTING, before Docker's DNAT, so published container ports are",
        "# covered too. Each run builds a fresh chain, switches the tagged hooks to it, then",
        "# deletes the previous chain and hooks, so a refresh never leaves a gap and a failed",
        "# run keeps the old rules. Persist with netfilter-persistent save, or run at boot.",
        "#   sh FILE          apply or refresh",
        "#   sh FILE remove   take out everything this script added",
        "set -e",
        "TAG=cf-origin-lockdown",
        "NEW=%s_$$" % IPT_CHAIN,
        "",
        "old_hooks() {  # this script's PREROUTING rules, rewritten as delete commands",
        "\t$IPT -S PREROUTING | grep -e \"$TAG\" | sed 's/^-A /-D /'",
        "}",
        "",
        "old_chains() {  # this script's chains, from earlier runs",
        "\t$IPT -S | sed -n 's/^-N \\(%s[A-Za-z0-9_]*\\)$/\\1/p'" % IPT_CHAIN,
        "}",
        "",
        "drop_hooks() {  # drop_hooks <delete commands from old_hooks>",
        "\tprintf '%s\\n' \"$1\" | while read -r rule; do",
        "\t\tif [ -n \"$rule\" ]; then eval \"$IPT $rule\"; fi",
        "\tdone",
        "}",
        "",
        "drop_chains() {  # drop_chains <chain>...  (unhooked leftovers: failing here is harmless)",
        "\tfor chain in \"$@\"; do",
        "\t\t$IPT -F \"$chain\" && $IPT -X \"$chain\" || echo \"warning: could not remove chain $chain\" >&2",
        "\tdone",
        "}",
        "",
        "apply() {  # apply <iptables|ip6tables> <allowed cidr>...",
        "\tIPT=\"$1 -w -t mangle\"; shift",
        "\tstale_hooks=$(old_hooks)",
        "\tstale_chains=$(old_chains)",
        "\t$IPT -N $NEW",
        "\tfor cidr in \"$@\"; do $IPT -A $NEW -s \"$cidr\" -j RETURN; done",
        "\t$IPT -A $NEW -j DROP",
    ] + hooks + [
        "\tdrop_hooks \"$stale_hooks\"  # the new hooks are already in place: no gap",
        "\tdrop_chains $stale_chains",
        "}",
        "",
        "remove() {  # remove <iptables|ip6tables>",
        "\tIPT=\"$1 -w -t mangle\"",
        "\tdrop_hooks \"$(old_hooks)\"",
        "\tchains=$(old_chains)",
        "\tdrop_chains $chains",
        "}",
        "",
        "case \"${1:-apply}\" in",
        "apply)",
        "\t" + sh_continued("apply iptables", [str(n) for n in rs.allow4]).replace("\n", "\n\t"),
        "\tif [ -e /proc/net/if_inet6 ]; then",
        "\t\tif ! command -v ip6tables >/dev/null 2>&1; then",
        "\t\t\techo \"ERROR: IPv6 is enabled but ip6tables is missing: IPv6 web ports are NOT filtered\" >&2",
        "\t\t\texit 1",
        "\t\tfi",
        "\t\t" + sh_continued("apply ip6tables", [str(n) for n in rs.allow6]).replace("\n", "\n\t\t"),
        "\tfi",
        "\t;;",
        "remove)",
        "\tremove iptables",
        "\tif [ -e /proc/net/if_inet6 ] && command -v ip6tables >/dev/null 2>&1; then remove ip6tables; fi",
        "\t;;",
        "*)",
        "\techo \"usage: $0 [apply|remove]\" >&2",
        "\texit 2",
        "\t;;",
        "esac",
    ]
    return "\n".join(out)


def emit_ufw(rs):
    ports = port_list(rs.ports)
    out = [
        "# " + rs.banner,
        "#",
        "# ufw allow rules for Cloudflare. Fine for a one-time setup, but know the limits:",
        "#  - ufw does NOT filter Docker-published ports (Docker's own iptables rules bypass",
        "#    it). Use --format nftables instead, or publish containers on 127.0.0.1 only.",
        "#  - IPv6 is filtered only when IPV6=yes in /etc/default/ufw.",
        "#  - Re-running adds new ranges but never removes retired ones. For scheduled",
        "#    refreshes use --format nftables.",
        "#  - Afterwards delete every broader allow on these ports ('Nginx Full', 'Apache Full',",
        "#    '80', '443', '80/tcp' from Anywhere):  ufw status numbered;  ufw delete N",
        "#  - Keep your SSH rule and `ufw default deny incoming`.",
    ]
    out += ["ufw allow proto tcp from %s to any port %s comment 'Cloudflare origin'" % (n, ports)
            for n in rs.allow4 + rs.allow6]
    if rs.deny_ports:
        out.append("# Also delete any allow rule for port(s) %s: nothing should be served there."
                   % port_list(rs.deny_ports))
    return "\n".join(out)


def emit_aws(rs):
    def ranges(nets, extras, key):
        return [{key: str(n), "Description": "also-allow" if n in extras else "Cloudflare"} for n in nets]

    perms = []
    for port in rs.ports:
        perm = {"IpProtocol": "tcp", "FromPort": port, "ToPort": port}
        if rs.allow4:
            perm["IpRanges"] = ranges(rs.allow4, rs.extra4, "CidrIp")
        if rs.allow6:
            perm["Ipv6Ranges"] = ranges(rs.allow6, rs.extra6, "CidrIpv6")
        perms.append(perm)
    sys.stderr.write(
        "# %s\n# Apply once:  aws ec2 authorize-security-group-ingress --group-id sg-XXXX "
        "--ip-permissions file://cf-sg.json\n# Then revoke every 0.0.0.0/0 and ::/0 rule on port(s) %s "
        "in every security group attached to the origin. Re-applying fails as a duplicate and never "
        "removes retired ranges: for scheduled refreshes use a customer-managed prefix list "
        "(see references/hardening-playbook.md).\n" % (rs.banner, port_list(rs.ports)))
    for family, count in (("IPv4", len(rs.ports) * len(rs.allow4)), ("IPv6", len(rs.ports) * len(rs.allow6))):
        if count > AWS_RULE_QUOTA:
            sys.stderr.write("[warn] %d %s rules exceed the default quota of %d inbound rules per security "
                             "group; use a managed prefix list or request a quota increase.\n"
                             % (count, family, AWS_RULE_QUOTA))
    return json.dumps(perms, indent=2)


def emit_gcp(rs):
    rules = ",".join("tcp:%d" % p for p in rs.ports)
    out = [
        "# " + rs.banner,
        "#",
        "# Google Cloud VPC firewall. One rule per IP family: a rule cannot mix IPv4 and IPv6.",
        "# Replace NETWORK, put the cf-origin network tag on the origin VMs, then delete every",
        "# rule that admits 0.0.0.0/0 or ::/0 on these ports (default-allow-http/https, the",
        "# http-server/https-server tags). Refresh later with: gcloud compute firewall-rules",
        "# update cf-origin-v4 --source-ranges=...",
    ]
    for name, nets in (("cf-origin-v4", rs.allow4), ("cf-origin-v6", rs.allow6)):
        if nets:
            out.append("gcloud compute firewall-rules create %s --network=NETWORK --direction=INGRESS "
                       "--action=ALLOW --rules=%s --source-ranges=%s --target-tags=cf-origin"
                       % (name, rules, ",".join(map(str, nets))))
    return "\n".join(out)


def ps_array(name, nets):
    return ["$%s = @(" % name] + ["\t'%s'" % n for n in nets] + [")"]


def emit_windows(rs):
    ports = port_list(rs.ports)
    allowed = rs.allow4 + rs.allow6
    others = complement(rs.allow4, 4) + complement(rs.allow6, 6)
    out = [
        "# " + rs.banner,
        "#",
        "# Windows Defender Firewall; run in an elevated PowerShell. Windows ORs allow rules",
        "# together, so an allow rule alone would not stop an older 'allow 80/443 from Any'",
        "# rule (such as IIS's World Wide Web Services rules). A block rule always wins over",
        "# allow rules, so this also blocks the web ports for every address outside the",
        "# allowed ranges. That includes anything else on TCP %s of this server, such as" % ports,
        "# RD Gateway or an SSTP VPN: move those off the origin first, or you lose them.",
        "# Re-running builds a new generation of rules first and removes the previous one",
        "# only after every new rule exists, so a failure keeps the old rules.",
        "$ErrorActionPreference = 'Stop'",
        "$Group = '%s'" % WIN_GROUP,
        "$Gen = 'CFOrigin-' + (Get-Date -Format 'yyyyMMddHHmmss')",
    ]
    out += ps_array("Allowed", allowed) + ps_array("EveryoneElse", others)
    rule = ("New-NetFirewallRule -Name \"$Gen-%s\" -Group $Group -Direction Inbound -DisplayName '%s' "
            "-Action %s -Protocol %s -LocalPort %s%s | Out-Null")
    out += [
        rule % ("allow-tcp", "Cloudflare origin: allow TCP %s from Cloudflare" % ports, "Allow", "TCP", ports,
                " -RemoteAddress $Allowed"),
        rule % ("block-tcp", "Cloudflare origin: block TCP %s from everyone else" % ports, "Block", "TCP", ports,
                " -RemoteAddress $EveryoneElse"),
    ]
    if rs.udp_drop:
        out.append(rule % ("block-udp", "Cloudflare origin: block UDP %s (QUIC; Cloudflare never uses it)" % ports,
                           "Block", "UDP", ports, ""))
    if rs.deny_ports:
        deny = port_list(rs.deny_ports)
        out += [rule % ("deny-%s" % proto.lower(), "Cloudflare origin: block %s %s for everyone" % (proto, deny),
                        "Block", proto, deny, "") for proto in ("TCP", "UDP")]
    out += [
        "Get-NetFirewallRule -Group $Group | Where-Object { $_.Name -notlike \"$Gen-*\" } | Remove-NetFirewallRule",
        "Get-NetFirewallRule -Group $Group | Format-Table Name, DisplayName, Action, Enabled -AutoSize",
    ]
    return "\n".join(out)


def emit_nginx(rs):
    out = [
        "# " + rs.banner,
        "#",
        "# nginx: include inside http {} (for example as /etc/nginx/conf.d/cloudflare.conf),",
        "# then run nginx -t and reload. Regenerate whenever the ranges change.",
        "",
        "# 1) Real visitor IP. Trust CF-Connecting-IP only when the TCP peer is Cloudflare, so",
        "#    direct callers cannot spoof it; logs and limit_req then see the real visitor.",
    ]
    out += ["set_real_ip_from %s;" % n for n in rs.cf4 + rs.cf6]
    out += [
        "real_ip_header CF-Connecting-IP;",
        "",
        "# 2) $from_cloudflare is 1 when the TCP peer is an allowed range. An app-layer",
        "#    backstop for hosts whose firewall you cannot change; in each public server {}:",
        "#        if ($from_cloudflare = 0) { return 444; }",
        "geo $realip_remote_addr $from_cloudflare {",
        "\tdefault 0;",
    ]
    out += ["\t%s 1;" % n for n in rs.allow4 + rs.allow6]
    out.append("}")
    return "\n".join(out)


def emit_apache(rs):
    out = [
        "# " + rs.banner,
        "#",
        "# Apache 2.4 mod_remoteip (a2enmod remoteip): restore the visitor IP from",
        "# CF-Connecting-IP, trusted only from Cloudflare peers. Log it with %a.",
        "RemoteIPHeader CF-Connecting-IP",
    ]
    out += ["RemoteIPTrustedProxy %s" % n for n in rs.cf4 + rs.cf6]
    return "\n".join(out)


def emit_caddy(rs):
    return "\n".join([
        "# " + rs.banner,
        "#",
        "# Caddy: merge into the global options block at the top of your Caddyfile.",
        "# trusted_proxies needs Caddy 2.6.3+ and client_ip_headers 2.7+ (check `caddy version`).",
        "{",
        "\tservers {",
        "\t\ttrusted_proxies static %s" % " ".join(str(n) for n in rs.cf4 + rs.cf6),
        "\t\tclient_ip_headers CF-Connecting-IP",
        "\t\t# Cloudflare reaches origins over TCP only, but Caddy serves HTTP/3 on UDP 443",
        "\t\t# by default, which a TCP-only firewall rule leaves open. Turn it off:",
        "\t\tprotocols h1 h2",
        "\t}",
        "}",
    ])


def emit_cidr(rs):
    sys.stderr.write("# %s\n" % rs.banner)
    return "\n".join(str(n) for n in rs.allow4 + rs.allow6)


def emit_json(rs):
    # Always both families and no extras, so --ranges-file can read it back as is.
    return json.dumps({
        "generated": rs.generated,
        "source": rs.source,
        "etag": rs.etag,
        "ipv4_cidrs": [str(n) for n in rs.cf4],
        "ipv6_cidrs": [str(n) for n in rs.cf6_all],
    }, indent=2)


EMITTERS = {
    "nftables": emit_nftables,
    "iptables": emit_iptables,
    "ufw": emit_ufw,
    "aws": emit_aws,
    "gcp": emit_gcp,
    "windows": emit_windows,
    "nginx": emit_nginx,
    "apache": emit_apache,
    "caddy": emit_caddy,
    "cidr": emit_cidr,
    "json": emit_json,
}


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def parse_ports(spec):
    ports = []
    for item in spec.split(","):
        item = item.strip()
        if not item:
            continue
        if not item.isdigit() or not 0 < int(item) < 65536:
            raise argparse.ArgumentTypeError("invalid port %r" % item)
        port = int(item)
        if port in ADMIN_PORTS:
            raise argparse.ArgumentTypeError(
                "port %d is %s, an admin port: this tool only restricts web ports, and limiting %s to "
                "Cloudflare would lock you out" % (port, ADMIN_PORTS[port], ADMIN_PORTS[port]))
        if port not in ports:
            ports.append(port)
    if len(ports) > MAX_PORTS:
        raise argparse.ArgumentTypeError("at most %d ports" % MAX_PORTS)
    return sorted(ports)


def parse_extra(value):
    try:
        net = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        raise argparse.ArgumentTypeError("not a CIDR or IP: %r" % value)
    inside_private = any(net.version == p.version and net.network_address in p and net.broadcast_address in p
                         for p in PRIVATE_SPACE)
    if net.prefixlen < MIN_PREFIX[net.version] and not inside_private:
        raise argparse.ArgumentTypeError("refusing a public range as broad as %s" % net)
    return net


def parse_iface(value):
    if not IFACE_RE.match(value) or value in (".", "..", "lo"):
        raise argparse.ArgumentTypeError("not a usable interface name: %r" % value)
    return value


def positive(value):
    try:
        number = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError("not a number: %r" % value)
    if not number > 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return number


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--format", choices=sorted(EMITTERS), default="nftables",
                    help="output backend (default: nftables)")
    ap.add_argument("--ports", type=parse_ports, default="80,443",
                    help="web ports Cloudflare may reach (default: 80,443)")
    ap.add_argument("--deny-ports", type=parse_ports, default="",
                    help="ports to drop for everyone, Cloudflare included, e.g. 80 once the edge "
                         "redirects all HTTP to HTTPS (firewall formats only)")
    ap.add_argument("--also-allow", type=parse_extra, action="append", default=[], metavar="CIDR",
                    help="extra trusted source, e.g. your load balancer subnet (repeatable)")
    ap.add_argument("--public-iface", type=parse_iface, action="append", default=[], metavar="IFACE",
                    help="only filter traffic arriving on this internet-facing interface (repeatable; "
                         "nftables/iptables). Strongly recommended with Docker, Kubernetes or a VPN")
    ap.add_argument("--no-udp-drop", action="store_true",
                    help="do not drop UDP on the web ports (only if a VPN must use UDP 443 and no web "
                         "server listens there)")
    ap.add_argument("--no-v6", action="store_true",
                    help="do not admit Cloudflare over IPv6 (IPv6 web traffic is then dropped)")
    ap.add_argument("--require-live", action="store_true",
                    help="fail instead of falling back to the bundled snapshot (use in timers)")
    ap.add_argument("--accept-changes", action="store_true",
                    help="accept a range list that moved far from the bundled snapshot")
    ap.add_argument("--ranges-file", metavar="PATH",
                    help="use a vetted local copy (json from this script, Cloudflare API JSON, "
                         "or one CIDR per line) instead of fetching")
    ap.add_argument("--timeout", type=positive, default=15.0, help="fetch timeout in seconds")
    args = ap.parse_args()

    if not args.ports:
        ap.error("--ports must name at least one port")
    if set(args.ports) & set(args.deny_ports):
        ap.error("a port cannot be in both --ports and --deny-ports")

    try:
        if args.ranges_file:
            v4, v6, source, etag = load_ranges_file(args.ranges_file)
        else:
            v4, v6, source, etag = fetch_live(args.timeout)
        report_changes(v4, v6)
        if not args.accept_changes:
            check_changes(v4, v6)
    except Exception as exc:  # noqa: BLE001
        if args.require_live or args.ranges_file:
            sys.stderr.write("[error] no usable Cloudflare ranges: %s\n" % printable(exc, 1000))
            return 1
        sys.stderr.write("[warn] could not use live ranges (%s); using the bundled snapshot of %s. Verify "
                         "it against https://www.cloudflare.com/ips/ before relying on it.\n"
                         % (printable(exc, 1000), SNAPSHOT_DATE))
        v4, v6 = snapshot()
        source, etag = "BUNDLED SNAPSHOT of %s (live ranges unavailable)" % SNAPSHOT_DATE, None

    if args.format in ("nftables", "iptables") and not args.public_iface:
        sys.stderr.write("[warn] no --public-iface: the rules apply to every non-loopback interface. On hosts "
                         "with Docker, Kubernetes, a VPN or private networking, pass --public-iface "
                         "(see `ip route show default`).\n")

    extra4 = [n for n in args.also_allow if n.version == 4]
    extra6 = [n for n in args.also_allow if n.version == 6]
    rs = Ruleset(v4, v6, extra4, extra6, args, source, etag)
    print(EMITTERS[args.format](rs))
    return 0


if __name__ == "__main__":
    sys.exit(main())
