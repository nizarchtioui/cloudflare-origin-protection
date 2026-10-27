# Changelog

## 2.0.0 (2026-10-26)

A ground-up hardening release. Upgrade from 1.x: its checker can report
"locked down" for origins that are still reachable.

### Fixed

- **The range refresh never actually refreshed.** `www.cloudflare.com` answers
  HTTP 403 to Python's default User-Agent, so the generator always fell back to
  its built-in list. It now uses the Cloudflare API first and sends its own
  User-Agent.
- **Wrong verdicts from the self-audit:**
  - Open ports guarded only by mTLS were reported as locked, and mTLS
    rejections as exposed.
  - Plain HTTP was never tested.
  - A Cloudflare edge IP passed by mistake was reported as an exposed origin.
  - A machine with no IPv6 route got "locked down" for an IPv6 address.
- **nftables output:** `--no-v6` produced invalid syntax. The ruleset was
  default-drop with the SSH rule commented out (a lockout risk) and dropped
  ICMPv6.
- **Docs:** they said Authenticated Origin Pulls stops other Cloudflare
  accounts. Only AOP with **your own** certificate does: global AOP's
  certificate is shared across accounts.

### Added

- **Checker:**
  - Verdicts: LOCKED / REACHABLE / EXPOSED / UNTESTED.
  - A "scanner view" of the bare IP that flags default-certificate and redirect
    leaks.
  - In-app redirects are followed, and an app's own 401/403 is detected.
  - IPv4 and IPv6 in one run; `--path`, `--json`, and a vantage-point check.
- **Generator:**
  - 11 formats: nftables, iptables, ufw, AWS, GCP, Windows, nginx, Apache,
    Caddy, cidr, json.
  - Rules hook in before Docker/Kubernetes DNAT, and UDP/443 (QUIC) is
    dropped.
  - New options: `--public-iface`, `--deny-ports`, `--also-allow`,
    `--no-udp-drop`.
  - Input validation and a guard against suspicious range changes
    (`--accept-changes`).
  - Fail-safe refresh for iptables and Windows; admin ports are refused.
- **References:**
  - `platforms.md`: Docker, Kubernetes, load balancers, PaaS, object storage,
    Windows/IIS, Caddy and Traefik.
  - `incident-response.md`: what to do when the origin IP has leaked.
- **Packaging and tests:**
  - A test suite with simulated origins.
  - CI that loads the generated nftables and iptables rules on Linux.
  - Claude Code plugin and marketplace manifests.

## 1.0.0

- Initial skill: an audit → harden → verify workflow, a Cloudflare IP allowlist
  generator, and a basic origin self-check.
