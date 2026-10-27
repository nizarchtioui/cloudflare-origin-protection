# Verification: prove the lockdown holds

Hardening you cannot verify is hardening you cannot trust. Run these checks
after applying the playbook and again whenever the infrastructure changes. All
checks target infrastructure the user operates.

## Ground rules for a meaningful test

- **Vantage point:** test from a network **outside** Cloudflare's ranges and
  **not** from the origin itself. The checker asks
  `cloudflare.com/cdn-cgi/trace` for your public IP and warns if either is
  true. A Cloudflare WARP connection or a Worker counts as "inside" when its
  egress is in Cloudflare's ranges.
- **Address families:** test IPv4 and IPv6 separately, each from a network that
  actually has that family. UNTESTED (no route) is **not** a pass.
- **Right target:** use the origin's own address from the hosting provider,
  never what DNS returns (that is Cloudflare). The checker refuses Cloudflare
  addresses.

## 1. Direct access is refused (network allowlist)

```bash
python3 -I check_origin_lockdown.py --host example.com --ip 203.0.113.10 --ip 2001:db8::10
# extra ports, or an explicit scheme:
python3 -I check_origin_lockdown.py --host example.com --ip 203.0.113.10 --ports 443,80,8443,8080
# a known public URL sharpens the verdict when / is a redirect or a 403:
python3 -I check_origin_lockdown.py --host example.com --ip 203.0.113.10 --path /robots.txt
```

| Verdict | Meaning | Next step |
|---|---|---|
| **LOCKED** | Refused or silently dropped. | Good. Continue with the checks below. |
| **REACHABLE** | TCP accepted, but no site content. Examples: mTLS rejection; a 403 on `/` *and* `/robots.txt`; a pure HTTP→HTTPS redirect; a connection closed without a response. | Origin auth or redirects are working, but the **network allowlist is missing**, so direct floods still land. Fix layer 1. |
| **EXPOSED** | The app answered directly. That includes a page, an API error, a 401 login challenge, a redirect into the app (to `/login`, an SSO provider...), or a 403 on `/` while `/robots.txt` is served. Also when the bare IP serves content. | Fix layers 1 and 2 now. |
| **UNTESTED** | This machine could not test it: no route, IPv6 disabled locally, or a local firewall. | Re-test from a network that can. |

The overall verdict is the worst tested result. If some addresses or ports
were UNTESTED, a clean result becomes UNTESTED rather than LOCKED. Exit status:
0 LOCKED, 1 EXPOSED, 3 REACHABLE, 4 UNTESTED, 2 usage or internal error. Use
it in CI or monitoring (`--json` for machine-readable output).

Without the script, the equivalent manual probes are:

```bash
curl -v --connect-timeout 10 --resolve example.com:443:203.0.113.10 https://example.com/
curl -v --connect-timeout 10 http://203.0.113.10/ -H 'Host: example.com'
curl -v -6 --connect-timeout 10 --resolve 'example.com:443:[2001:db8::10]' https://example.com/
```

## 2. Origin authentication rejects "allowed" addresses

The allowlist must not be the only thing standing. Simulate a request that
arrives from an allowed range but is not from your zone:

1. Temporarily add your test IP. Use **exactly the production flags plus
   `--also-allow`**, so the test does not reopen anything else (port 80, for
   example): `generate_cf_firewall_rules.py --format nftables --public-iface
   eth0 --ports 443 --deny-ports 80 --also-allow <your IP>/32 > t.nft && nft -f
   t.nft`.
2. Run the checker. Expected result: **REACHABLE** with
   `TLS alert certificate_required`, `HTTP 400 'No required SSL certificate was
   sent'`, or `HTTP 403` (on both `/` and `/robots.txt`). **EXPOSED means origin
   auth is not enforced.**
3. Re-apply the normal table. Confirm the checker shows LOCKED again.

Also confirm port 80 cannot be used to skip mTLS: it must be LOCKED (with
`--deny-ports 80`) or show only `redirect to https://<host>/`, never content.

## 3. Scanner view: the bare IP gives nothing away

The checker's `scanner` rows show what internet-wide scanners record:

- No `LEAK` line. The default certificate must not name your domain (use
  `ssl_reject_handshake on;`), and a bare-IP request must not redirect to your
  hostname: scanners record `Location` headers too.
- Bare-IP HTTP(S) returns nothing (`444` or a refused handshake), not the site
  and not a redirect.

## 4. The ports you forgot

- **Docker:** run `docker ps --format '{{.Names}} {{.Ports}}'` and test every
  published port with `--ports`.
- **UDP/443 (HTTP/3):** on the origin, `ss -ulpn | grep -E ':(443|80)\b'`
  shows any QUIC listener; it must be disabled or dropped
  (`nft list chain inet cf_origin prerouting` shows the UDP drop counter).
  From outside, `curl --http3-only` (if your curl supports it) must fail.
- **Everything else listening:** on the origin, run `ss -tulpn`. Only the web
  server (and SSH restricted to admin sources) should be bound to public
  addresses. Databases, admin panels and metrics should listen on localhost or
  a private network. A VPN on UDP 443 needs `--no-udp-drop`. RD Gateway or SSTP
  on TCP 443 must move off the origin.
- **Internal users still work:** from a container, a pod, a VPN client and the
  load balancer's health check, call the web ports that should stay reachable
  internally. If they fail, regenerate with `--public-iface` (or add
  `--also-allow` for internal sources that arrive on the public interface).
- **Provider firewall:** no `0.0.0.0/0` or `::/0` rule on web ports. On AWS,
  this lists every security group with a world-open ingress rule, so you can
  review its ports:

  ```bash
  aws ec2 describe-security-groups --query \
    "SecurityGroups[?IpPermissions[?IpRanges[?CidrIp=='0.0.0.0/0'] || Ipv6Ranges[?CidrIpv6=='::/0']]].[GroupId,GroupName]"
  ```

## 5. DNS and leak channels are closed

- Export the zone's records and confirm none is DNS-only while pointing at the
  origin or its subnet (A **and** AAAA).
- `dig +short TXT example.com` shows no origin IP in SPF.
  `dig +short MX example.com` shows no mail host on the origin.
- A transactional email's raw headers contain no origin IP.

## 6. Cloudflare settings match the plan

- SSL/TLS mode is **Full (strict)**, and Always Use HTTPS is on (required
  before `--deny-ports 80`).
- AOP uses **your** certificate (zone-level or per-hostname), not only global
  AOP, or the secret-header transform rule is active for every protected
  hostname.
- Every hostname that serves the app is proxied (orange cloud).

## 7. It stays true

- The refresh timer ran recently: `systemctl list-timers cf-origin-refresh.timer`
  and `journalctl -u cf-origin-refresh`. Range changes are logged there.
- Drop counters and the non-Cloudflare access log are monitored.
- The checker runs from outside on a schedule and alerts on a non-zero exit.

---

### Verification summary

- [ ] Checker: every IPv4 and IPv6 address and port is LOCKED from outside Cloudflare
- [ ] With a temporary `--also-allow`, the origin still refuses (mTLS/403), and port 80 serves no content
- [ ] No certificate leak; bare-IP requests get nothing
- [ ] Docker-published ports and UDP/443 covered; only intended services listen
- [ ] No provider-firewall rule admits 0.0.0.0/0 or ::/0 on web ports
- [ ] No DNS-only record, SPF, MX or mail header exposes the origin
- [ ] Full (strict), Always Use HTTPS, AOP with your certificate (or a secret header)
- [ ] Range refresh scheduled; drops and non-Cloudflare requests monitored
