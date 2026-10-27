<div align="center">

# Cloudflare Origin Protection

### Stop attackers from going around Cloudflare.

An Agent Skill for Claude, plus two zero-dependency tools, that find, close and
**prove closed** every path to your origin server that skips Cloudflare.

[![CI](https://github.com/nizarchtioui/cloudflare-origin-protection/actions/workflows/ci.yml/badge.svg)](https://github.com/nizarchtioui/cloudflare-origin-protection/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Python 3.6+](https://img.shields.io/badge/python-3.6%2B-blue.svg)
![Dependencies: none](https://img.shields.io/badge/dependencies-none-brightgreen.svg)

**Founder and maintainer: Nizar Chtioui**

</div>

---

## Project status

> **New.** First released on 2026-10-27; the current version is v2.0.1. It has
> automated tests and CI, but **no independent security review yet**.
>
> - Read the generated rules before applying them.
> - Try them on a non-production host first.
> - Report problems as described in [SECURITY.md](SECURITY.md).
>
> Reviews are very welcome.

## The problem in 30 seconds

Cloudflare protects the traffic that passes through Cloudflare. If your origin
server still accepts connections from the internet, anyone who learns its IP
address can connect to it directly. Your WAF rules, rate limits, bot
protection and DDoS mitigation never see those requests.

Origin IPs leak in many ways:

- old DNS records
- a single DNS-only subdomain
- an SPF record
- the headers of a password-reset email
- the certificate your server shows to the internet-wide scanners that index
  every IPv4 address

Hiding the address doesn't work. What works:

1. Make direct connections **fail**.
2. Require proof that each request came through **your** Cloudflare zone.
3. **Verify** both from outside, continuously.

This project does all three.

**Read [Why this matters now](docs/why-now.md)** for the full case.

## What's inside

| Component | What it does |
|---|---|
| **Agent Skill** ([`skills/cloudflare-origin-protection`](skills/cloudflare-origin-protection/SKILL.md)) | Gives Claude a complete **audit → harden → verify** workflow. Playbooks cover nftables, iptables, ufw, AWS, GCP, Azure, Windows/IIS, nginx, Apache, Caddy, Docker, Kubernetes, load balancers, PaaS, and incident response. |
| **[`check_origin_lockdown.py`](skills/cloudflare-origin-protection/scripts/check_origin_lockdown.py)** | Self-audit. It connects to *your* origin directly, the way an attacker would, and reports **LOCKED / REACHABLE / EXPOSED / UNTESTED** per address and port. It also shows what internet scanners see on the bare IP. |
| **[`generate_cf_firewall_rules.py`](skills/cloudflare-origin-protection/scripts/generate_cf_firewall_rules.py)** | Turns Cloudflare's live, validated IP ranges into ready-to-apply rules for nftables, iptables, ufw, AWS, GCP and Windows, plus nginx/Apache/Caddy real-visitor-IP config. |

## See it in action

Example output: an origin that looks protected but is not.

```text
$ python3 -I check_origin_lockdown.py --host example.com --ip 203.0.113.10
Self-audit of direct access to the origin of example.com (path /)
Vantage point: 198.51.100.7

203.0.113.10
  443/https  bypass  (Host example.com)         EXPOSED   redirected to /login: HTTP 200: the origin served your hostname directly "Sign in"
             scanner (bare IP, no SNI)          REACHABLE HTTP 302 redirect to https://example.com/login cert=example.com,www.example.com
  80/http    bypass  (Host example.com)         REACHABLE HTTP 301 redirect to https://example.com/ (no content on this port)
             scanner (bare IP)                  REACHABLE HTTP 301 redirect to https://example.com/
  verdict: EXPOSED

LEAK: 203.0.113.10:443 presents a certificate naming example.com, www.example.com to clients that send no hostname: scanners that index certificates per IP can link this IP to your site. Make the default server reject unknown names (ssl_reject_handshake).

LEAK: 203.0.113.10:80 redirects bare-IP requests to https://example.com/: scanners record Location headers, so this ties the IP to your site. Make the default server return 444 instead.

OVERALL: EXPOSED - The origin can be used directly, bypassing Cloudflare. Apply the network allowlist and origin authentication (references/hardening-playbook.md), then re-run this check.
```

The home page redirects to `/login`, so a naive check that only fetches `/`
would call this origin safe. This checker follows the redirect and finds the
login page served directly.

## Quick start

Every command below is pinned to the **v2.0.1** release. You get exactly the
tested code even if `main` moves on, and the release page lists SHA-256
checksums of the scripts.

**1. Audit (two minutes).** Run it from your laptop or any network outside
Cloudflare, never on the origin itself.

```bash
curl -fsSLO https://raw.githubusercontent.com/nizarchtioui/cloudflare-origin-protection/v2.0.1/skills/cloudflare-origin-protection/scripts/check_origin_lockdown.py
python3 -I check_origin_lockdown.py --host example.com --ip <origin IPv4> --ip <origin IPv6>
```

**2. Harden.** Allow only Cloudflare on the web ports, scoped to the
internet-facing interface:

```bash
curl -fsSLO https://raw.githubusercontent.com/nizarchtioui/cloudflare-origin-protection/v2.0.1/skills/cloudflare-origin-protection/scripts/generate_cf_firewall_rules.py
ip route show default                       # shows the public interface, e.g. "dev eth0"
python3 -I generate_cf_firewall_rules.py --format nftables --public-iface eth0 --ports 443 --deny-ports 80 > cf-origin.nft
sudo nft -c -f cf-origin.nft && sudo nft -f cf-origin.nft
```

Then add origin authentication: Authenticated Origin Pulls with **your own**
certificate, or a secret header. Both are covered in the
[hardening playbook](skills/cloudflare-origin-protection/references/hardening-playbook.md).

**3. Verify.** Re-run the checker. Every row should say **LOCKED**. Put it in
CI or a monitor; the exit codes are made for that.

## Install the skill

**Claude Code, as a plugin.** Pick a scope when prompted. The `#v2.0.1` pins
the plugin to this release. To move to a later one, add the marketplace again
with that release's tag.

```text
/plugin marketplace add nizarchtioui/cloudflare-origin-protection#v2.0.1
/plugin install cloudflare-origin-protection@origin-protection
```

**Claude Code, as a personal skill:**

```bash
git clone --branch v2.0.1 --depth 1 https://github.com/nizarchtioui/cloudflare-origin-protection
cp -r cloudflare-origin-protection/skills/cloudflare-origin-protection ~/.claude/skills/
```

Choose one of the two Claude Code methods. If both are installed, the skill
appears twice.

**Claude apps (claude.ai, desktop):**

1. Turn on **Code execution and file creation**. The skill's tools need it.
2. Download
   [`cloudflare-origin-protection.zip`](https://github.com/nizarchtioui/cloudflare-origin-protection/releases/download/v2.0.1/cloudflare-origin-protection.zip)
   from the v2.0.1 release. The zip contains the skill folder; upload it as is,
   without unzipping.
3. Upload it as a custom skill
   ([how](https://support.claude.com/en/articles/12512198-how-to-create-custom-skills)),
   then turn it on.

## Just ask Claude

Once the skill is installed, describe the situation in plain words:

> "Our origin IP leaked and we're being hammered directly. Help."
>
> "Check whether 203.0.113.10 still serves example.com without going through Cloudflare."
>
> "Lock this Docker host down so only Cloudflare can reach ports 80 and 443."
>
> "Set up Authenticated Origin Pulls with our own certificate on nginx."
>
> "Generate AWS security group rules for Cloudflare and keep them up to date."

The skill walks Claude through the right controls for your stack. Claude
explains each one, generates the rules, shows you how to roll them back, and
verifies the result. It never applies firewall changes behind your back.

## The traps this catches that most guides miss

| Trap | What actually happens | What the skill does |
|---|---|---|
| **"Allow only Cloudflare's IPs"** | Those ranges are shared by **every** Cloudflare customer. An attacker can point their own zone at your IP. | Adds origin authentication bound to *your* zone. |
| **Global Authenticated Origin Pulls** | Cloudflare's provided certificate is shared across accounts, so it proves "Cloudflare", not "you". | Uses AOP with **your own** certificate, zone-level or per-hostname. |
| **mTLS on 443 only** | Full and Full (strict) forward plain-HTTP visits as plain HTTP, and there are no client certificates on port 80. | Makes port 80 redirect-only, or drops it once the edge redirects all HTTP. |
| **Docker + ufw** | Published container ports are DNATed before ufw ever sees them. | Filters at prerouting, before DNAT. |
| **HTTP/3 (UDP 443)** | Cloudflare never uses it to reach origins, but some servers enable it by default. TCP-only rules leave it open. | Drops UDP on the web ports and turns HTTP/3 off at the origin. |
| **IPv6** | The IPv4 address is locked; the IPv6 address is wide open. | Locks down both families and tests both. UNTESTED never counts as a pass. |
| **PaaS and load-balancer hostnames** | `*.herokuapp.com`, `*.elb.amazonaws.com` and similar serve your app around Cloudflare. | Gives platform-specific restrictions. |
| **Over-broad host rules** | Naive rules also cut off containers, pods, VPN users, and Kubernetes ClusterIPs (IPVS). | Scopes the rules with `--public-iface`. |
| **Stale ranges** | `www.cloudflare.com` rejects script user agents, so many "auto-refresh" scripts silently never refresh. | Uses the Cloudflare API, validates the result, and refreshes fail-safe. |

## Defense in layers

| Layer | Control | Why |
|---|---|---|
| 0 | **Cloudflare Tunnel** | No inbound ports at all, and the tunnel's DNS target only works inside your account. The strongest option. |
| 1 | **Network allowlist**, at the cloud firewall *and* the host | The baseline: direct connections fail. |
| 2 | **Origin authentication**: AOP with your own certificate, a secret header, Access JWT, or dedicated egress IPs | Closes the shared-IP-range gap. |
| 3 | **Full (strict) TLS** with an Origin CA certificate, and Always Use HTTPS | Encrypted, verified edge-to-origin traffic; a prerequisite for mTLS. |
| 4 | **App layer**: real visitor IP, a default server that rejects unknown names, no IPs in errors | Logs and rate limits keep working; scanners learn nothing. |
| 5 | **Hygiene and monitoring**: IP rotation, mail relay, scheduled range refresh, external re-audits | Keeps it closed. |

## Tool reference

<details>
<summary><b>check_origin_lockdown.py</b>: verdicts, exit codes, options</summary>

| Verdict | Exit | Meaning |
|---|---|---|
| LOCKED | 0 | Refused or dropped: the allowlist works from this vantage point. |
| EXPOSED | 1 | The app answered directly: a page, an API error, a 401, or a redirect into the app. Also when the bare IP serves content. |
| REACHABLE | 3 | The port accepts connections but serves no content (mTLS, origin-auth 403, an HTTPS redirect, or 444). The network allowlist is missing. |
| UNTESTED | 4 | This machine could not test it (no route, IPv6 disabled, local firewall). Not a pass. |

Exit code 2 means a usage or internal error.

| Option | Purpose |
|---|---|
| `--host` | Your public hostname. |
| `--ip` | An origin address you operate. Repeat it for IPv4 and IPv6, at most 4. |
| `--ports` | Ports to test, e.g. `443,80,8443` or `9443/https`. |
| `--path` | Path to request, e.g. a known public URL such as `/robots.txt`. |
| `--json` | Machine-readable output. |
| `--timeout` | Seconds per connection step. |
| `--no-vantage-check` | Skip the one request to `cloudflare.com/cdn-cgi/trace` that checks you are testing from outside Cloudflare. |

</details>

<details>
<summary><b>generate_cf_firewall_rules.py</b>: formats, options, safety</summary>

**Formats:** `nftables` (recommended), `iptables`, `ufw`, `aws`, `gcp`,
`windows`, `nginx`, `apache`, `caddy`, `cidr`, `json`.

| Option | Purpose |
|---|---|
| `--ports` / `--deny-ports` | Web ports Cloudflare may reach, and ports to drop for everyone (e.g. `80`). |
| `--public-iface` | Filter only internet traffic. Use it on hosts with Docker, Kubernetes or a VPN. |
| `--also-allow` | Extra trusted sources: a load balancer, health checks, a VPC range. |
| `--no-udp-drop` | Keep UDP open on the web ports (for a VPN on UDP 443). |
| `--no-v6` | Do not admit Cloudflare over IPv6. |
| `--allow-snapshot` | If the live list can't be fetched or looks wrong, use the bundled, dated list instead of failing. Off by default. |
| `--ranges-file` | Use a vetted local copy of the ranges. |
| `--accept-changes` | Accept a range list that changed a lot, after review. |

**Safety:**

- **It fails closed.** If the live list can't be fetched or looks suspicious,
  it prints an error, writes no rules and exits with status 1. A scheduled
  refresh then keeps your last good rules.
- It refuses non-CIDRs, private or over-broad ranges, lists missing an IP
  family, and suspicious changes (more than half the known ranges gone, or more
  than double the address space).
- It refuses SSH/RDP/WinRM ports.
- It sanitises banner text, so nothing can be injected into generated
  scripts.
- The nftables output reloads atomically. The iptables and Windows outputs
  build the new rules before removing the old ones.
- The iptables script never runs rule text as shell code. Any rule bearing
  its tag that it didn't write itself is skipped with a warning.

</details>

## Design safeguards

These are design choices, not an outside audit. See
[Project status](#project-status) above.

- **Zero dependencies.** Single-file Python 3.6+ scripts, made to run with
  `python3 -I` on old servers.
- **Never acts behind your back.** The generator prints rules and the commands
  to roll them back; you apply them.
- **Defensive by design.** The checker probes only addresses you supply (at
  most 4), refuses Cloudflare's own addresses, and is not a scanner.
- **Tested.** 30+ automated tests run against simulated origins: TLS, mTLS,
  redirects, 401/403 tricks, IPv6 edge cases, poisoned range lists. On every
  push, CI loads the generated nftables and iptables rules on a real Linux
  runner, then refreshes and removes them.

## Repository layout

```text
.
├── skills/cloudflare-origin-protection/   # the Agent Skill
│   ├── SKILL.md
│   ├── references/                        # playbooks, read on demand
│   │   ├── exposure-vectors.md
│   │   ├── hardening-playbook.md
│   │   ├── platforms.md
│   │   ├── verification.md
│   │   └── incident-response.md
│   └── scripts/                           # standalone tools
│       ├── check_origin_lockdown.py
│       └── generate_cf_firewall_rules.py
├── .claude-plugin/                        # Claude Code plugin + marketplace manifests
├── docs/why-now.md
├── tests/                                 # python -m unittest discover -s tests -v
└── .github/workflows/ci.yml
```

## Contributing and security

Contributions are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md). Please
report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © 2026 Nizar Chtioui.

## Founder

**Nizar Chtioui** founded this project and maintains it.

---

<sub>This is an independent open-source project. It is not affiliated with,
endorsed by or sponsored by Cloudflare, Inc. "Cloudflare" is a trademark of
Cloudflare, Inc. Use these tools only on systems you own or are authorized to
test.</sub>
