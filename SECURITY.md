# Security policy

## Reporting a vulnerability

Report security problems **privately**. Use the **Report a vulnerability**
button on this repository's **Security** tab. Please do not open a public
issue for a vulnerability.

Include:

- the affected file and version
- steps to reproduce
- what an attacker could achieve

The maintainer will acknowledge the report, keep you updated, and credit you
in the release notes unless you prefer otherwise.

## Supported versions

| Version | Supported |
|---|---|
| 2.x | Yes |
| 1.x | No: upgrade, because 1.x gives false "locked down" results |

## Responsible use

This project is for infrastructure **you own or are explicitly authorized to
test**.

- `check_origin_lockdown.py` probes only the addresses you pass, at most 4 per
  run on at most 16 ports. It refuses Cloudflare's own addresses. It is a
  self-audit, not a scanner, and must not be used to find or confirm other
  people's origin servers.
- `generate_cf_firewall_rules.py` prints rules; it never applies them. Review
  generated rules, keep an admin path open, and test on a non-production host
  first.

## What the tools send over the network

- **Checker:** plain `GET` requests to the IPs and ports you name, with the
  User-Agent `origin-lockdown-selftest/2`. It also makes one request to
  `https://www.cloudflare.com/cdn-cgi/trace` to learn the public IP of the
  machine running it; disable that with `--no-vantage-check`.
- **Generator:** requests to `api.cloudflare.com` and `www.cloudflare.com`
  to fetch Cloudflare's published IP ranges. None at all with `--ranges-file`.
- **Neither tool** collects telemetry, stores credentials, or needs an API
  token.
