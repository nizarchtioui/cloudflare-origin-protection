# Scripts

Both scripts are stdlib-only Python 3.6+ and self-contained, so you can copy
one file to a server. Run them with `python3 -I script.py ...`. The `-I` flag
isolates the interpreter so it ignores the current directory, environment and
user site-packages, which is a good habit for any security utility.

## check_origin_lockdown.py: is my origin still directly reachable?

A self-audit for an origin **you operate**. For every IP and port you give it,
it connects straight to the origin, bypassing Cloudflare, with two probes:

- **bypass:** presents your hostname (SNI and Host), as someone who knows the
  IP would. Redirects that stay inside your site are followed (up to 3 hops) on
  the same direct connection. A 403 is cross-checked against `/robots.txt`, so
  an app's own 403 or login redirect is not mistaken for origin auth.
- **scanner:** connects to the bare IP with no hostname, as internet-wide
  scanners do. It reports the default certificate's names, whether the bare IP
  serves content, and whether it redirects to your hostname. Each of those
  leaks the link between IP and site.

```bash
python3 -I check_origin_lockdown.py --host example.com --ip 203.0.113.10
python3 -I check_origin_lockdown.py --host example.com --ip 203.0.113.10 --ip 2001:db8::10
python3 -I check_origin_lockdown.py --host example.com --ip 203.0.113.10 --ports 443,80,8443,9443/https
python3 -I check_origin_lockdown.py --host example.com --ip 203.0.113.10 --path /robots.txt --json
```

| Verdict | Exit | Meaning |
|---|---|---|
| LOCKED | 0 | Refused or dropped: the allowlist works from here. |
| EXPOSED | 1 | The app answered directly: a page, an API error, a 401, or a redirect into the app. Also when the bare IP serves content. |
| REACHABLE | 3 | TCP accepted but no content (mTLS, origin-auth 403, a pure HTTPS redirect, 444): origin auth may hold, but the network allowlist is missing. |
| UNTESTED | 4 | This machine could not test it: no route, IPv6 disabled, or a local firewall. A clean run with any UNTESTED part is UNTESTED overall, never LOCKED. |

Exit status 2 means a usage or internal error. It never collides with a
verdict.

Safety and accuracy features:

- It refuses targets inside Cloudflare's ranges (that is not your origin), and
  accepts at most 4 IPs and 16 ports per run: it is a self-audit, not a
  scanner.
- It warns when the machine running it is inside Cloudflare's ranges or is the
  origin itself; disable that lookup with `--no-vantage-check`.
- It recognises nginx's mTLS rejection (`400 No required SSL certificate was
  sent`), Apache's handshake rejection and TLS `certificate_required` alerts.
- It uses a deliberately lenient TLS client (old protocol versions, any
  cipher), so a legacy origin cannot look "rejected" while an attacker's
  client would still get through.
- Ports are tested with the right protocol: Cloudflare's HTTPS ports over TLS,
  HTTP ports in plain text, overridable as `PORT/http` or `PORT/https`.

## generate_cf_firewall_rules.py: allow only Cloudflare

Fetches Cloudflare's ranges from the API (falling back to the www lists) and
validates every entry before printing ready-to-apply rules. It refuses:

- non-CIDRs, private ranges, and prefixes broader than /8 (IPv4) or /16 (IPv6)
- lists missing an IP family
- lists that moved suspiciously far from the bundled snapshot: more than half
  of the known ranges gone, or more than double the address space. Override
  with `--accept-changes` after review.

This means a captive portal, a truncated response or a poisoned list is
rejected rather than applied. Banner text such as the etag and source is
sanitised, so a ranges file cannot inject commands into the generated
scripts. Range changes are reported on stderr.

```bash
python3 -I generate_cf_firewall_rules.py --format nftables --public-iface eth0 > cf-origin.nft   # recommended
python3 -I generate_cf_firewall_rules.py --format nftables --public-iface eth0 --ports 443 --deny-ports 80
python3 -I generate_cf_firewall_rules.py --format iptables --public-iface eth0 > cf-origin.sh   # sh cf-origin.sh [remove]
python3 -I generate_cf_firewall_rules.py --format ufw                                         # one-time, no Docker
python3 -I generate_cf_firewall_rules.py --format aws --ports 443 > cf-sg.json                # one-time setup
python3 -I generate_cf_firewall_rules.py --format gcp
python3 -I generate_cf_firewall_rules.py --format windows > cf-origin.ps1
python3 -I generate_cf_firewall_rules.py --format nginx > /etc/nginx/conf.d/cloudflare.conf
python3 -I generate_cf_firewall_rules.py --format apache
python3 -I generate_cf_firewall_rules.py --format caddy
python3 -I generate_cf_firewall_rules.py --format cidr
python3 -I generate_cf_firewall_rules.py --format json > cf-ranges.json                       # vetted copy
python3 -I generate_cf_firewall_rules.py --format nftables --ranges-file cf-ranges.json
```

| Option | Effect |
|---|---|
| `--ports 80,443` | Web ports Cloudflare may reach (default 80,443). SSH/RDP/WinRM ports are refused. |
| `--deny-ports 80` | Drop these for everyone, Cloudflare included. Use it only once Always Use HTTPS is on, and not with HTTP-01 certificate renewal on the origin. |
| `--public-iface IFACE` | Filter only traffic arriving on this internet-facing interface (repeatable). Strongly recommended on hosts with Docker, Kubernetes, a VPN or private networking; without it they also lose access to the web ports. |
| `--also-allow CIDR` | Extra trusted source: load balancer, health checker, VPC range, or a temporary test IP. Repeatable. |
| `--no-udp-drop` | Keep UDP on the web ports open, for a VPN on UDP 443. Disable HTTP/3 on the web server then. |
| `--no-v6` | Do not admit Cloudflare over IPv6; IPv6 web traffic is then dropped. |
| `--require-live` | Exit 1 instead of using the bundled snapshot. Use it in timers so a fetch failure keeps the last good rules. |
| `--accept-changes` | Accept a range list that moved far from the snapshot, after you have reviewed it. |
| `--ranges-file PATH` | Use a vetted local copy: this script's json, Cloudflare's API JSON, or one CIDR per line. |

What the firewall outputs do:

- **nftables:** one table, `inet cf_origin`, replaced atomically on each load.
  It hooks prerouting at priority -150, before Docker/Kubernetes DNAT, and
  touches only the listed ports. TCP from outside the allowed ranges and UDP
  (QUIC) on those ports are dropped, and every other rule on the host is left
  alone. Roll back with `nft delete table inet cf_origin`.
- **iptables:** the same policy in mangle PREROUTING. Each run builds a fresh
  chain and moves its tagged hooks to it before deleting the old one, so there
  is no gap and a failed run keeps the old rules. It errors out if IPv6 is on
  but `ip6tables` is missing. `sh cf-origin.sh remove` undoes it.
- **ufw:** allow rules only. It does not cover Docker-published ports, needs
  `IPV6=yes`, and never removes retired ranges.
- **windows:** an allow rule for Cloudflare plus a block rule for every other
  address (block beats allow), and a UDP block. A new rule generation is
  created before the old one is removed. It also blocks RD Gateway or SSTP on
  the same ports, so move those first.
- **aws:** JSON for a one-time `authorize-security-group-ingress`. For
  refreshes use a customer-managed prefix list (see the playbook).

Schedule the refresh (see the systemd units in
`../references/hardening-playbook.md`), because Cloudflare's ranges change.
Check what else listens on the web ports before applying, and keep an admin
path open before applying any default-deny policy elsewhere.
