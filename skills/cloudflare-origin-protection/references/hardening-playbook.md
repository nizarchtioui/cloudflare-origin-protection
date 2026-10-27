# Hardening playbook: make direct-to-origin traffic fail

Contents: [Choose controls](#choose-your-controls) ·
[Layer 0 Tunnel](#layer-0-cloudflare-tunnel-strongest) ·
[Layer 1 Allowlist](#layer-1-network-allowlist) ·
[Layer 2 Origin auth](#layer-2-origin-authentication) ·
[Layer 3 TLS](#layer-3-edge-to-origin-tls) ·
[Layer 4 App](#layer-4-application-layer) ·
[Layer 5 Hygiene](#layer-5-hygiene-and-monitoring)

Layer 1 is the minimum bar and layer 2 closes the gap it leaves. Layer 0
(Tunnel) can replace both for HTTP. Explain the *why* of each control so the
user keeps it correct.

The sources of truth for Cloudflare's ranges are
`https://api.cloudflare.com/client/v4/ips` (JSON with an etag), and
`https://www.cloudflare.com/ips-v4/` and `/ips-v6/`. The www lists answer
HTTP 403 to default script user agents; `scripts/generate_cf_firewall_rules.py`
handles both sources and validates every entry. If neither source gives a
usable list, it exits with an error and writes no rules, unless you pass
`--allow-snapshot` to use its bundled, dated list.

---

## Choose your controls

| Cloudflare connects to... | Do this |
|---|---|
| A VM or bare-metal server | Tunnel. Or: provider-firewall allowlist, the nftables table on the host, AOP with your certificate (or a secret header), and Full (strict). |
| A Docker host | As above. Use the `nftables`/`iptables` output with `--public-iface`, which also covers published ports, or publish on `127.0.0.1` behind a host proxy. ufw alone does **not** protect containers. |
| A load balancer (ALB, NLB, cloud LB) | Allowlist on the **load balancer's** firewall or security group. Servers accept traffic only from the load balancer. Origin auth at the LB or the servers. |
| Kubernetes | `cloudflared` in the cluster with no public LoadBalancer, or `loadBalancerSourceRanges` on the ingress Service. See `platforms.md`. |
| A PaaS app or object storage | Platform-level restrictions plus a secret header or mTLS check in the app. See `platforms.md`. |
| Shared hosting (no firewall access) | Secret header plus the nginx/Apache backstop below; ask the host for a Cloudflare-only firewall. |
| Windows / IIS | `--format windows` (allow Cloudflare, block everyone else), plus AOP or a secret header. |

---

## Layer 0: Cloudflare Tunnel (strongest)

`cloudflared` on the origin opens **outbound** connections to Cloudflare, so the
origin needs no inbound web ports. The DNS target (`<UUID>.cfargotunnel.com`)
only proxies for DNS records **in the same Cloudflare account**. Knowing the
UUID does not let another account route traffic to it, so the shared-range
problem disappears.

**Remotely managed (simplest).** Create a tunnel in the Cloudflare dashboard
and copy the install command it generates. That command has the shape
`sudo cloudflared service install <TOKEN>`. Then add a public hostname that
maps `app.example.com` to `http://localhost:8080`.

**Locally managed:**

```bash
cloudflared tunnel login
cloudflared tunnel create my-app
cloudflared tunnel route dns my-app app.example.com
# ~/.cloudflared/config.yml
#   tunnel: <TUNNEL-UUID>
#   credentials-file: /home/<user>/.cloudflared/<TUNNEL-UUID>.json
#   ingress:
#     - hostname: app.example.com
#       service: http://localhost:8080
#     - service: http_status:404
sudo cloudflared --config /home/<user>/.cloudflared/config.yml service install
sudo systemctl start cloudflared
```

Then finish the job:

- Bind the app to `127.0.0.1` so it is not listening on public interfaces at all.
- Close inbound 80/443 at the provider firewall and on the host. The tunnel
  needs only outbound connections.
- Keep SSH reachable only from your IP or VPN, or carry it over Tunnel and
  Cloudflare Access too.
- Treat the tunnel token and credentials file as secrets: anyone holding them
  can run a connector for your tunnel. Restrict them with `chmod 600`, keep
  them out of repositories, and rotate them if exposed.
- Run two connectors (replicas) for availability, and keep `cloudflared`
  updated.

---

## Layer 1: Network allowlist

Admit the web ports **only** from Cloudflare's ranges, IPv4 **and** IPv6,
first at the provider and then on the host.

### 1a. At the provider (do this first)

The provider filters before traffic reaches the VM, so this cannot be bypassed
by Docker and it absorbs more of a flood than the host can.

- **AWS security group:** run `generate_cf_firewall_rules.py --format aws
  --ports 443 > cf-sg.json`, then
  `aws ec2 authorize-security-group-ingress --group-id sg-... --ip-permissions file://cf-sg.json`.
  Revoke every `0.0.0.0/0` and `::/0` rule on those ports in **every**
  security group attached to the instance or load balancer. The default quota
  is 60 inbound rules per group per IP family; the script warns before you
  hit it. That JSON is for a one-time setup: re-applying fails as a duplicate
  and never removes retired ranges. For scheduled refreshes, point the rule at
  a customer-managed prefix list (one per IP family; it counts its max
  entries against the quota) and update the list:

  ```bash
  aws ec2 create-managed-prefix-list --prefix-list-name cloudflare-v4 --address-family IPv4 --max-entries 25 \
    --entries $(python3 -I generate_cf_firewall_rules.py --format cidr | grep -v : | sed 's/^/Cidr=/')
  aws ec2 authorize-security-group-ingress --group-id sg-... --ip-permissions \
    'IpProtocol=tcp,FromPort=443,ToPort=443,PrefixListIds=[{PrefixListId=pl-...}]'
  # refresh: apply the difference the generator reports on stderr
  aws ec2 modify-managed-prefix-list --prefix-list-id pl-... --current-version <n> \
    --add-entries Cidr=<added range> --remove-entries Cidr=<removed range>
  ```
- **Google Cloud:** `--format gcp` gives one rule per IP family, because a
  rule cannot mix IPv4 and IPv6. Remove `default-allow-http`/`https` and the
  `http-server`/`https-server` network tags.
- **Azure NSG, Hetzner, DigitalOcean, Linode, OVH and others:** use
  `--format cidr` as the source list. One rule per IP family is the safe
  shape. Delete the "any source" rules for 80/443.

### 1b. On the host: nftables (recommended)

```bash
ip route show default; ss -tulpn                     # find the public interface; see what uses 80/443
python3 -I generate_cf_firewall_rules.py --format nftables --public-iface eth0 \
    --ports 443 --deny-ports 80 > cf-origin.nft
nft -c -f cf-origin.nft && nft -f cf-origin.nft      # check, then load
nft list table inet cf_origin                         # inspect (counters show drops)
nft delete table inet cf_origin                       # roll back
```

Why this shape works, and where it bites:

- **Self-contained.** One table, `inet cf_origin`, replaced atomically on each
  load. It never edits ufw, firewalld or Docker rules, and any of them can
  coexist with it. In nftables a `drop` in any base chain is final, so other
  tables' `accept` rules cannot undo it.
- **Only the web ports.** It drops traffic to the listed ports from outside the
  allowed sets, with `policy accept` for everything else. SSH, ICMP/ICMPv6
  (IPv6 neighbour discovery), DHCP and every other port are untouched, and the
  generator refuses SSH/RDP/WinRM ports.
- **Scope it to the internet (`--public-iface`).** Unscoped, it filters
  traffic arriving on every interface except loopback, so other users of the
  web ports are cut off too. That includes containers calling the host on
  `172.17.0.1:443` (for example `cloudflared` in Docker in front of a host
  nginx), pods, VPN clients (WireGuard, Tailscale), and load-balancer health
  checks from the VPC. On Kubernetes nodes with kube-proxy in **IPVS** mode
  every ClusterIP is a local address, so unscoped rules would cut off every
  80/443 Service, including the API server. With `--public-iface eth0` only
  traffic arriving on that interface is filtered. Use `--also-allow` for
  internal sources that arrive on the public interface (VPC load balancers).
- **Before DNAT.** The chain hooks prerouting at priority -150, ahead of
  Docker's and Kubernetes' DNAT (-100), so published container ports are
  filtered on their original port. `fib daddr type != local accept` limits it
  to traffic addressed to this host, so container egress and routed traffic
  pass.
- **UDP dropped on the web ports.** Cloudflare never uses QUIC to origins, so
  UDP there is only a bypass path. If a VPN must use UDP 443 (WireGuard,
  OpenVPN), pass `--no-udp-drop` and make sure no web server listens on UDP
  443 (disable HTTP/3).
- **`--deny-ports 80`.** Drops port 80 for everyone, Cloudflare included. Use
  it only once **Always Use HTTPS** is on: Full and Full (strict) forward a
  plain-HTTP visit as plain HTTP, and without the edge redirect those visits
  would fail. It also breaks Let's Encrypt **HTTP-01** renewals on the origin,
  so use a Cloudflare Origin CA certificate or DNS-01 validation instead.
- **`--also-allow CIDR`.** For a load balancer, health checker or test IP that
  must reach the ports. Private ranges such as `10.0.0.0/8` or `fc00::/7` are
  accepted; broad public ranges are refused.

**Persist it and keep it current.** Load the last good file at boot, refresh
daily, and fail safe:

```ini
# /etc/systemd/system/cf-origin-firewall.service: load the last good table at boot
[Unit]
Description=Cloudflare-only origin firewall (last good rules)
Wants=network-pre.target
Before=network-pre.target shutdown.target
Conflicts=shutdown.target
DefaultDependencies=no

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /etc/cf-origin/cf-origin.nft

[Install]
WantedBy=sysinit.target
```

```sh
#!/bin/sh
# /usr/local/sbin/cf-origin-refresh: regenerate; keep the last good table on any failure
# (a failed or suspicious fetch exits 1 and writes nothing, so set -e stops here)
set -eu
dir=/etc/cf-origin
python3 -I /usr/local/lib/cf-origin/generate_cf_firewall_rules.py --format nftables \
    --public-iface eth0 --ports 443 --deny-ports 80 > "$dir/cf-origin.nft.new"
nft -c -f "$dir/cf-origin.nft.new"
mv "$dir/cf-origin.nft.new" "$dir/cf-origin.nft"
nft -f "$dir/cf-origin.nft"
# Optional: keep nginx's real-IP list in step
# python3 -I /usr/local/lib/cf-origin/generate_cf_firewall_rules.py --format nginx \
#     > /etc/nginx/conf.d/cloudflare.conf.new && mv /etc/nginx/conf.d/cloudflare.conf.new \
#     /etc/nginx/conf.d/cloudflare.conf && nginx -t && systemctl reload nginx
```

```ini
# /etc/systemd/system/cf-origin-refresh.service
[Unit]
Description=Refresh the Cloudflare-only origin firewall
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/cf-origin-refresh

# /etc/systemd/system/cf-origin-refresh.timer
[Unit]
Description=Daily refresh of the Cloudflare-only origin firewall

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
```

Enable both with `systemctl enable --now cf-origin-firewall.service
cf-origin-refresh.timer`. Read range changes in `journalctl -u
cf-origin-refresh`; the generator reports additions and removals against
its snapshot. It refuses a list that changed suspiciously (more than half the
known ranges gone, or more than double the address space). The last good
table then stays in place until a human reviews the change and re-runs with
`--accept-changes`. If you also run `nftables.service` with a
`flush ruleset` config, `include` the file from `/etc/nftables.conf`
instead, or a restart of that service will drop the table.

### 1c. Other host firewalls

- **iptables / ip6tables:** `--format iptables --public-iface eth0 >
  cf-origin.sh`, then `sh cf-origin.sh` to apply or refresh and
  `sh cf-origin.sh remove` to undo. It applies the same policy in mangle
  PREROUTING, before Docker's DNAT. Each run builds a fresh chain, moves its
  tagged hooks to it, and only then deletes the old chain, so a refresh never
  opens a gap and a failed run keeps the old rules. If IPv6 is enabled but
  `ip6tables` is missing, it stops with an error instead of leaving IPv6 open.
  Persist with `netfilter-persistent save` or run it at boot.
- **ufw:** `--format ufw` suits a one-time setup on hosts without Docker.
  `IPV6=yes` must be set in `/etc/default/ufw`. Delete every broader allow on
  the web ports afterwards (`ufw status numbered`, `ufw delete N`). Re-runs
  never remove retired ranges.
- **Windows:** `--format windows` creates an allow rule for Cloudflare and a
  **block** rule for every other address. Block rules beat allow rules, so
  older "allow 80/443 from Any" rules (IIS's defaults) stop mattering. It also
  blocks UDP on those ports. The block also hits anything else on the same
  ports, such as **RD Gateway or an SSTP VPN on TCP 443**: move those off the
  origin first. Re-running creates the new rule generation before removing the
  old one, so a failure keeps the previous rules.

> **Keep your own access.** The generated host rules touch only the web
> ports, but check what else uses them before applying: a VPN on UDP 443, RD
> Gateway/SSTP on TCP 443, and containers, pods or VPN users reaching the
> host's web ports (use `--public-iface`). Any broader default-deny change
> needs an open admin session and an admin path that stays allowed (your IP,
> a VPN, or SSH through Tunnel or Access) before you apply it.

---

## Layer 2: Origin authentication

The allowlist admits **every** Cloudflare customer. Someone can create their
own zone, point a proxied record at your origin IP, and arrive from
Cloudflare's addresses with any Host header they like. Origin authentication
proves the request came from **your** zone.

### 2a. Authenticated Origin Pulls (mTLS) with your own certificate

Cloudflare presents a client certificate on its TLS connection to the origin,
and the origin refuses connections without the expected one. There are three
modes, and the most specific wins (per-hostname, then zone-level, then
global):

| Mode | Certificate | Proves |
|---|---|---|
| Global AOP | Cloudflare's own, **shared across all accounts** | Only "came through Cloudflare". Does **not** stop another zone. |
| Zone-level AOP | **Yours**, uploaded for the zone | Came through **your** zone. |
| Per-hostname AOP | **Yours**, per hostname | Came through **your** zone for that hostname. |

AOP works only when Cloudflare talks TLS to the origin (Full or Full (strict)).

**1. Create a private CA and a client certificate.** Only your origin trusts
the CA. Keep `aop-ca.key` offline.

```bash
openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
  -subj "/CN=example.com origin-pull CA" -keyout aop-ca.key -out aop-ca.pem
openssl req -newkey rsa:2048 -nodes -subj "/CN=cloudflare-origin-pull.example.com" \
  -keyout aop-client.key -out aop-client.csr
printf 'extendedKeyUsage=clientAuth\n' > aop-client.ext
openssl x509 -req -sha256 -days 825 -in aop-client.csr -CA aop-ca.pem -CAkey aop-ca.key \
  -CAcreateserial -extfile aop-client.ext -out aop-client.pem
```

**2. Upload `aop-client.pem` and `aop-client.key` to Cloudflare and enable
it.** Use the dashboard (SSL/TLS, then Origin Server, then Authenticated
Origin Pulls) or the API:

- zone-level: `POST /zones/{zone_id}/origin_tls_client_auth` with the
  certificate and private key, then `PUT
  /zones/{zone_id}/origin_tls_client_auth/settings` with
  `{"enabled": true}`
- per-hostname: `POST /zones/{zone_id}/origin_tls_client_auth/hostnames/certificates`,
  then `PUT /zones/{zone_id}/origin_tls_client_auth/hostnames` to bind
  `hostname` + `cert_id` with `enabled: true`

**3. Make the origin require a certificate from *your* CA.** Do not trust
Cloudflare's shared origin-pull CA here.

```nginx
server {
  listen 443 ssl;
  listen [::]:443 ssl;
  server_name example.com www.example.com;
  ssl_certificate         /etc/ssl/origin/example.com.pem;   # Cloudflare Origin CA cert
  ssl_certificate_key     /etc/ssl/origin/example.com.key;
  ssl_client_certificate  /etc/ssl/origin/aop-ca.pem;        # YOUR CA, not Cloudflare's shared one
  ssl_verify_client       on;
  # ...
}
```

```apache
<VirtualHost *:443>
  ServerName example.com
  SSLEngine on
  SSLCertificateFile    /etc/ssl/origin/example.com.pem
  SSLCertificateKeyFile /etc/ssl/origin/example.com.key
  SSLCACertificateFile  /etc/ssl/origin/aop-ca.pem
  SSLVerifyClient require
  SSLVerifyDepth  1
</VirtualHost>
```

nginx completes the handshake and answers `400 No required SSL certificate
was sent` (internally 496). Apache aborts the handshake. The checker
recognises both as "mTLS enforced".

**4. Close the plain-HTTP side door.** mTLS cannot apply to plain HTTP, and Full
or Full (strict) forward a plain-HTTP visit to the origin as plain HTTP. So port
80 must never serve the app. Either keep it as a bare redirect:

```nginx
server {                      # port 80: redirect only, never content
  listen 80;
  listen [::]:80;
  server_name example.com www.example.com;
  return 301 https://$host$request_uri;
}
```

or turn on **Always Use HTTPS** at the edge and drop port 80 entirely
(`--deny-ports 80`).

**5. Renew** the client certificate before it expires: upload the new one,
switch to it, then retire the old one. Re-issue it if a key may have leaked.

### 2b. Secret header (any plan, quickest)

A Request Header Transform Rule (available on the Free plan) can set a static
header on every request Cloudflare sends to the origin, and the origin rejects
requests without it. A "set static" rule overwrites any value a client sends,
so visitors cannot supply it. Header names starting with `cf-` cannot be set:
use something like `X-Origin-Verify`.

1. Generate a value: `openssl rand -hex 32`.
2. Cloudflare: Rules → Transform Rules → Request Header Transform Rules,
   *Set static* `X-Origin-Verify` = value, applied to all incoming requests
   (or the protected hostnames).
3. Origin (nginx). This accepts the current and the previous value while you
   rotate:

```nginx
# http {}
map $http_x_origin_verify $origin_verified {
  default 0;
  "CURRENT-LONG-RANDOM-VALUE" 1;
  # "PREVIOUS-VALUE"          1;   # only during a rotation
}
# each Cloudflare-fronted server {}
if ($origin_verified = 0) { return 403; }
proxy_set_header X-Origin-Verify "";   # do not hand the secret to the app, its logs or error trackers
# nginx gotcha: a location {} with its own proxy_set_header lines inherits none
# from server {}, so repeat the line in such locations.
```

The secret is a bearer credential. Anything that echoes request headers
(debug pages, error trackers, request logs) can leak it, so strip it before
the app, rotate it on any suspicion, and prefer AOP where you can.

### 2c. Cloudflare Access JWT (admin and internal apps)

Put admin panels and internal tools behind Cloudflare Access. Every request
then carries a `Cf-Access-Jwt-Assertion` header. Validate it at the origin
against your team's keys at
`https://<team>.cloudflareaccess.com/cdn-cgi/access/certs`, checking the
application's AUD tag, and reject requests that lack a valid token. Only your
Access applications can mint it.

### 2d. Dedicated CDN Egress IPs (formerly Aegis, Enterprise)

Cloudflare connects to the origin from IPs reserved for your account, so the
allowlist can name only those instead of all of Cloudflare. This closes the
shared-range problem at the network layer. Ask your account team.

---

## Layer 3: Edge-to-origin TLS

- Set SSL/TLS mode to **Full (strict)** and install a **Cloudflare Origin CA**
  certificate at the origin. It is free, long-lived, and not publicly trusted
  or CT-logged. Flexible sends visitor traffic to the origin in plaintext and
  rules out AOP. Full (non-strict) does not validate the origin certificate.
- Turn on **Always Use HTTPS** so plain-HTTP visits are redirected at the edge
  and never forwarded to the origin as HTTP.
- On Enterprise, **Strict (SSL-Only Origin Pull)** always connects to the
  origin over TLS, whatever scheme the visitor used.

---

## Layer 4: Application layer

### Restore the real visitor IP (do not skip)

Behind a proxy, every request appears to come from Cloudflare. Logs, rate
limits, abuse rules and geo logic all break unless the origin restores the
visitor IP from `CF-Connecting-IP`, **trusting it only when the TCP peer is a
Cloudflare range**. Otherwise a direct caller can spoof it.

- nginx: `--format nginx > /etc/nginx/conf.d/cloudflare.conf`, which gives
  `set_real_ip_from` per range plus `real_ip_header CF-Connecting-IP;`.
- Apache: `--format apache`, for `mod_remoteip` with `RemoteIPTrustedProxy`.
- Caddy: `--format caddy`, which gives `trusted_proxies`, `client_ip_headers`,
  and `protocols h1 h2` to turn off HTTP/3.
- Frameworks: configure trusted proxies so the app reads the forwarded IP only
  from Cloudflare (or from your own proxy, which itself trusts only
  Cloudflare).

Refresh these lists with the firewall, on the same schedule.

### The default server answers nothing

```nginx
# Requests for unknown names, or the bare IP, get nothing: no certificate, no page.
server {
  listen 443 ssl default_server;
  listen [::]:443 ssl default_server;
  ssl_reject_handshake on;          # nginx >= 1.19.4; no certificate needed
}
server {
  listen 80 default_server;
  listen [::]:80 default_server;
  return 444;                       # close without a response
}
```

On older nginx, give the default server a self-signed placeholder certificate
for a meaningless name and `return 444;`. Never use the real site's
certificate there: scanners record it per IP.

### App-layer backstop when you cannot touch the firewall

`--format nginx` also defines `$from_cloudflare` (1 when the TCP peer is an
allowed range). In each public server block:

```nginx
if ($from_cloudflare = 0) { return 444; }
```

This does not stop floods, because the connection still lands, but it stops
the app from serving direct visitors.

### Strip identifying output

Remove version banners (`server_tokens off;`, `ServerTokens Prod`), drop
`X-Powered-By`/`X-Backend-Server`, build redirects from the public hostname,
and never print internal IPs in errors or status pages.

---

## Layer 5: Hygiene and monitoring

- **Rotate a leaked origin IP.** Bring up the new address with the allowlist
  already in place, switch the proxied DNS record, then retire the old one.
  First close the leak that exposed it (`exposure-vectors.md`).
- **Mail through a relay**, outbound fetches through a different egress IP,
  every record proxied, and non-web services on other hosts.
- **Detect bypass attempts:**
  - nftables counters: `nft list chain inet cf_origin prerouting`. Rising
    drop counters mean someone is hitting the origin directly.
  - nginx: log requests whose TCP peer is not Cloudflare. They should not
    exist once the firewall is right.

    ```nginx
    map $from_cloudflare $not_cloudflare { 0 1; default 0; }
    log_format peer '$realip_remote_addr -> $host "$request" $status cf-ray=$http_cf_ray';
    access_log /var/log/nginx/non-cloudflare.log peer if=$not_cloudflare;
    ```

  - Requests from Cloudflare Workers carry a `CF-Worker` header naming the
    zone that owns the Worker. A value that is not your zone means another
    account's Worker is calling your origin; alert on it.
- **Re-audit from outside on a schedule.** Run `check_origin_lockdown.py`
  from CI or a monitoring host outside Cloudflare. Exit status is 0 for
  LOCKED, 1 for EXPOSED, 3 for REACHABLE and 4 for UNTESTED, so any non-zero
  result can page someone. Run it from a runner with IPv6 if the origin has
  IPv6; otherwise it reports UNTESTED.
