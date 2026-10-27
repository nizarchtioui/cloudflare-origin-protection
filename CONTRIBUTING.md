# Contributing

Thanks for helping make origin servers harder to reach around Cloudflare.

By taking part you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

- **Bugs and feature ideas:** open an issue using one of the forms.
- **Vulnerabilities:** report them privately, as described in
  [SECURITY.md](SECURITY.md), never in an issue.
- **Changes:** open a pull request; its template lists the checks.

Never post real origin IP addresses, hostnames, certificates or secrets
anywhere in this repository. Use placeholders such as `203.0.113.10` and
`example.com`.

## Ground rules

- **Defensive scope only.** No features for finding or confirming origin servers
  you don't operate: no range sweeps, no DNS-history or certificate-search
  lookups, and no lifting the checker's IP and port limits.
- **Standard library only.** The scripts must run as single files on old
  servers, with Python 3.6 or newer and no `pip install`.
- **Every behaviour change comes with a test.** Every claim about Cloudflare,
  a web server or a cloud provider comes with a link to its documentation.
- **Fail safe.** A refresh that cannot complete must leave the previous rules in
  place, and a probe that cannot test something must say UNTESTED, never
  LOCKED.

## Run the tests

```bash
python -m unittest discover -s tests -v
```

The TLS tests need the `openssl` command. On machines without it, point
`CFOP_TEST_CERT` and `CFOP_TEST_KEY` at a throwaway certificate and key for
`example.test`.

CI also loads the generated nftables and iptables rules on a Linux runner
(see `.github/workflows/ci.yml`). Use a throwaway VM if you reproduce that
locally.

## Pull requests

1. Describe the problem, the fix, and how you verified it.
2. Update `CHANGELOG.md`.
3. Keep `SKILL.md` short: it is loaded on every use, so detail belongs in
   `references/`.
