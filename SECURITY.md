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
| 2.0.1 and later | Yes |
| 2.0.0 | Upgrade. When a fetch fails, its generator falls back to the bundled range list with only a warning and exits 0. Its iptables script runs rule text through `eval`. |
| 1.x | No: upgrade, because 1.x gives false "locked down" results |

## Project status

This project is new. It was first released on 2026-10-27 and has not had an
independent security review. Reviews of the scripts and of the generated rules
are very welcome; report findings privately as described above.

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
