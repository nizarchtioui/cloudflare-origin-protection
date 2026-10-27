---
name: cloudflare-origin-protection
description: >-
  Lock down an origin server behind Cloudflare (or any CDN, WAF or reverse
  proxy) so nobody can bypass the edge by connecting to the origin directly.
  Use whenever the user mentions protecting or hiding an origin behind
  Cloudflare; a leaked, exposed or "found" origin IP; attackers bypassing
  Cloudflare, a WAF or DDoS protection; floods or scraping that hit the server
  directly; allowlisting Cloudflare IPs in a firewall, security group, ufw,
  nftables, iptables, Docker or Windows Firewall; Authenticated Origin Pulls
  or mTLS; Cloudflare Tunnel; real visitor IPs (CF-Connecting-IP); origin
  leaks via DNS history, SPF/MX records, certificates, internet scanners,
  email headers or webhooks; or auditing whether an origin is still directly
  reachable. Use it even when Cloudflare is not named but a proxied app's
  backend, load balancer or PaaS hostname can still be reached directly.
---

# Cloudflare Origin Protection

## The problem in one paragraph

With Cloudflare (or any CDN/WAF/reverse proxy) in front of an app, DNS sends
visitors to Cloudflare's edge, and Cloudflare forwards each request to the
origin. The edge supplies the WAF, DDoS mitigation, rate limiting, bot
management and caching. But **Cloudflare is a proxy, not a network boundary.**
If the origin still accepts connections from the whole internet, anyone who
learns its address can connect directly and skip every edge control at once.
This skill makes the origin **refuse anything that did not come through your
own Cloudflare zone**, so a known IP is useless.

## The mental model

> **Assume the origin IP is public. Make direct traffic fail; do not rely on
> hiding the address.**

Origin IPs leak through too many channels (old DNS answers, one grey-cloud
record, an SPF record, a mail header, a certificate that internet scanners
indexed) for secrecy to be the control. The control is **a network allowlist
plus origin authentication bound to your account**, or no inbound path at all
(Tunnel).

Secrecy still matters for one thing: **volumetric floods**. A host firewall
drops packets only after they have crossed the origin's link, so a flood aimed
at a known IP can still saturate it. Filter as far upstream as possible (cloud
firewall or security group), rotate an IP that has leaked, and prefer Tunnel,
which needs no public inbound address at all.

## First, establish the situation

Ask or infer these before recommending anything. They change which controls
apply:

1. **What Cloudflare connects to:** a VM or bare metal, a Docker host,
   Kubernetes, a load balancer, a PaaS app (Heroku, Render, Fly, Vercel, App
   Service...), or object storage. The allowlist belongs on the **first hop
   Cloudflare connects to**. Platforms are covered in `references/platforms.md`.
2. **SSL/TLS mode and plan:** Off / Flexible / Full / Full (strict) / Strict
   (SSL-only origin pull, Enterprise); Free / Pro / Business / Enterprise.
3. **IPv6:** does the origin have a public IPv6 address?
4. **What else shares the IP:** mail, SSH, panels, databases, game servers.
5. **Is it under attack right now?** If yes, go to
   `references/incident-response.md` first; the full workflow can follow.

## Workflow: audit, harden, verify

Read each reference when you reach its stage, not all up front.

### 1. Audit: how exposed is the origin today?

- Run `scripts/check_origin_lockdown.py --host <hostname> --ip <origin IP>`
  (add `--ip` for IPv6) from a machine **outside** Cloudflare and **not** on
  the origin. Per port it reports LOCKED, REACHABLE, EXPOSED or UNTESTED.
  It also shows what an internet scanner sees on the bare IP, including
  whether the default TLS certificate names the user's domain.
- Walk `references/exposure-vectors.md` to find how the IP leaked (or will),
  so a rotated IP does not leak the same way.

### 2. Harden: make direct traffic fail

Full configurations are in `references/hardening-playbook.md`.

| Layer | What it does | Use when |
|---|---|---|
| **0. Cloudflare Tunnel** | The origin dials out to Cloudflare; no inbound web ports; the app listens on localhost. A tunnel's DNS target only works inside your own account. | Strongest. Prefer for new or sensitive apps; replaces layers 1–2 for HTTP. |
| **1. Network allowlist** | Web ports accept only Cloudflare's ranges, at the cloud firewall **and** on the host. The generator's nftables output also covers Docker-published ports and drops UDP/443. Scope it with `--public-iface` on hosts with Docker, Kubernetes or a VPN. | Always, unless Tunnel removes the ports. The baseline. |
| **2. Origin authentication** | Proves a request came from **your** zone: Authenticated Origin Pulls with **your own** certificate (zone-level or per-hostname), or a secret header set by a Request Header Transform Rule. Alternatives: Access JWT validation for admin apps, or Dedicated CDN Egress IPs (formerly Aegis, Enterprise). | Always alongside layer 1, because the ranges are shared by every Cloudflare customer. |
| **3. Edge-to-origin TLS** | Full (strict) with an Origin CA certificate. The HTTP listener serves only a redirect, or is dropped once the edge redirects all HTTP. | Always; a prerequisite for mTLS. |
| **4. App layer** | Restore the real visitor IP from CF-Connecting-IP (trusted only from Cloudflare peers). The default server rejects unknown names (`ssl_reject_handshake`, `444`). No internal IPs in errors. | Always; without the real IP, logs and rate limits break. |
| **5. Hygiene and monitoring** | Rotate a leaked IP; send mail through a relay; proxy every record; refresh ranges on a schedule; alert on non-Cloudflare peers. | Ongoing. |

`scripts/generate_cf_firewall_rules.py` turns Cloudflare's live, validated
ranges into ready-to-apply output: `nftables` (recommended on Linux),
`iptables`, `ufw`, `aws`, `gcp`, `windows`, plus `nginx`/`apache`/`caddy`
real-IP config, `cidr` and `json`.

### 3. Verify: prove it holds

Follow `references/verification.md`:

- Re-run the checker from outside; every port should be LOCKED.
- Temporarily allow your test IP (`--also-allow`) to confirm origin auth
  rejects a request that arrives from an "allowed" address.
- Test IPv6 from an IPv6-capable network (UNTESTED is not a pass).
- Check Docker-published ports, UDP/443, every DNS record, and the scheduled
  refresh.

## Caveats that separate a real fix from a false sense of security

1. **Cloudflare's ranges are shared.** An IP allowlist admits every Cloudflare
   customer: an attacker can point their own zone at your origin IP and arrive
   "from Cloudflare". Close this with authentication bound to your account
   (AOP with your own certificate, a secret header, Tunnel, or dedicated
   egress IPs). **Global AOP**, which uses Cloudflare's own certificate, does
   not close it: that certificate is shared across all accounts and only proves
   the request crossed Cloudflare's network.
2. **mTLS only covers TLS.** In Full and Full (strict) modes, Cloudflare
   reaches the origin with the visitor's scheme. A plain-HTTP visit reaches the
   origin's HTTP listener with no client certificate, from your zone or anyone
   else's. Make port 80 return only a redirect, or drop it at the firewall
   (`--deny-ports 80`) once Always Use HTTPS redirects all HTTP at the edge.
3. **IPv6 is the classic gap.** Lock the IPv6 address down exactly like IPv4.
   The checker reports UNTESTED when your network has no IPv6 route; that is
   not a pass.
4. **Docker bypasses ufw.** Published container ports are DNATed before
   ufw's INPUT rules ever see them. Use the generator's `nftables` or
   `iptables` output (it filters at prerouting, before DNAT), publish on
   127.0.0.1, or filter at the cloud firewall. Pass `--public-iface` so that
   only internet traffic is filtered. Unscoped, the rules also cut containers,
   pods and VPN users off from the host's web ports. On Kubernetes nodes with
   kube-proxy in IPVS mode they would cut off every ClusterIP on 80/443,
   including the API server.
5. **UDP/443 (HTTP/3).** Cloudflare never connects to origins over QUIC, but
   some servers (Caddy by default) serve HTTP/3 on UDP 443. A TCP-only
   allowlist leaves that open. The generator drops it; also disable HTTP/3 at
   the origin.
6. **The origin may be a hostname, not an IP.** PaaS default domains, load
   balancer DNS names and bucket endpoints are public routes around the edge.
   Restrict them at the platform (`references/platforms.md`).
7. **The ranges change.** Refresh on a schedule. A failed or suspicious fetch
   exits with an error and writes no rules, so the last good rules stay in
   place; `--allow-snapshot` opts into the bundled, dated list instead. The
   nftables output swaps atomically. `www.cloudflare.com` rejects scripts with
   default user agents (HTTP 403), so the generator uses the API and sends its
   own user agent.

## Scripts

Both are stdlib-only Python 3.6+; run them with `python3 -I`. Details are in
`scripts/README.md`.

```bash
python3 -I scripts/check_origin_lockdown.py --host example.com --ip 203.0.113.10 --ip 2001:db8::10
python3 -I scripts/generate_cf_firewall_rules.py --format nftables --public-iface eth0 --ports 443 --deny-ports 80 > cf-origin.nft
```

## Working rules for the assistant

- **Probe only infrastructure the user operates.** Run the checker only
  against IPs the user confirms are theirs. It is not a discovery tool, and
  this skill never helps find someone else's origin.
- **Show, explain, then let the user apply.** Generate firewall rules and
  configs, explain each part, and give a rollback (`nft delete table inet
  cf_origin`, `sh cf-origin.sh remove`). Do not apply firewall changes on a
  remote host yourself unless the user explicitly asks and confirms they have
  console or out-of-band access.
- **Never lock the user out.** The generated rules touch only the web ports,
  and they refuse SSH/RDP/WinRM ports, but those web ports can carry more than
  the website. Before applying, check what else listens there: `ss -tulpn`, or
  `Get-NetTCPConnection -State Listen` on Windows. Things to look for:
  - a VPN on UDP 443 (use `--no-udp-drop`)
  - RD Gateway or an SSTP VPN on TCP 443 (move them first)
  - internal users of the web ports, such as containers, pods, VPN clients
    or load-balancer health checks (use `--public-iface` or `--also-allow`)

  Any broader default-deny change needs a live admin session and an allowed
  admin path (VPN, your IP, or SSH through Tunnel or Access) first.
- **Treat secrets as credentials.** AOP keys, tunnel tokens and secret-header
  values never go into tickets, chat logs or repositories.

## Tone and scope

This is defensive hardening for infrastructure the user operates. Explain the
*why* behind each control, because a rule the user understands is one they
keep correct. When discussing how origin IPs get discovered, stay at the level
needed to decide what to close: the goal is a locked-down origin, not a
reconnaissance playbook.
