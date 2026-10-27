# Exposure vectors: how an origin address gets out, and what to close

Audit each channel for **your own** zone and servers. For every channel the fix
is to close the leak, stop relying on secrecy, or usually both. The real
protection is still the allowlist plus origin authentication
(`hardening-playbook.md`). This list shrinks the attack surface, explains how
an IP leaked, and stops a **rotated** IP from leaking the same way.

## 1. DNS records, past and present

- **History.** Before Cloudflare, the A/AAAA records pointed straight at the
  origin. Passive-DNS datasets keep those answers indefinitely.
  *Close:* after enabling Cloudflare, move the origin to a new IP that has
  never been published, then rely on the allowlist, not on secrecy.
- **Grey-cloud (DNS-only) records.** Only proxied (orange-cloud) records hide
  the origin. `mail`, `ftp`, `cpanel`, `webmail`, `direct`, `origin`, `dev`,
  `staging` and `vpn` are the usual DNS-only offenders, and one record on the
  same host leaks the whole site.
  *Audit:* export every record in the zone (dashboard or API). Flag every
  DNS-only record and anything that resolves into the origin's IP or subnet.
  *Close:* proxy whatever can be proxied. Move what cannot (mail, SSH, game
  servers) to **separate hosts with different IPs**.
- **TXT/SPF and MX.** `v=spf1 ip4:203.0.113.10 ...` publishes the sending
  server's IP. An MX host that resolves to the web server does the same.
  *Close:* send mail through a provider or relay and reference its SPF include.
  The web origin must never appear in SPF or MX.
- **Reverse DNS (PTR).** A PTR record such as `203.0.113.10 -> web.example.com`
  ties the IP to the domain. *Close:* set a neutral PTR at the hosting
  provider.
- **AAAA.** Every point above applies to IPv6 too, which is often forgotten
  until it leaks.

## 2. Certificates

- **Certificate Transparency.** Every publicly trusted certificate is logged.
  A certificate issued for `origin.example.com` or `direct.example.com` names
  hosts that then resolve to the origin.
  *Close:* terminate public TLS at Cloudflare. Use a **Cloudflare Origin CA**
  certificate at the origin; it is not publicly trusted and not CT-logged.
  Never put origin-only hostnames in public DNS.
- **The certificate served on the bare IP.** Internet-wide scanners connect to
  every IPv4 address on 443 without a hostname and record the certificate the
  server presents by default. If that certificate names `example.com`, even an
  Origin CA one, the IP is linked to the site in their datasets.
  *Audit:* the checker's `scanner` probe prints the default certificate's
  names and flags a `LEAK` when they name your domain.
  *Close:* the default server must refuse unknown or absent SNI (nginx
  `ssl_reject_handshake on;`, 1.19.4+), plus the allowlist so scanners cannot
  connect at all.

## 3. What the bare IP serves

Scanners also store the HTTP response per IP: page title, body hash, favicon
hash, headers. If the origin answers a bare-IP request with the real site, it
can be matched to the public site without any DNS.

- *Audit:* the checker's `scanner` probe (Host = the IP, no SNI).
- *Close:* the default vhost returns nothing (`return 444;`) for unknown Host
  values, and the allowlist stops the connection in the first place.

## 4. Mail and other outbound traffic from the origin

Anything the origin sends to an address an attacker controls carries its IP:

- **Email** (password reset, signup, notifications) sent by the app server
  puts the IP in `Received:` headers. Anyone can trigger such a mail.
- **Outbound fetches an attacker can direct**: webhooks, "import from URL",
  avatar or link-preview fetchers, oEmbed, XML-RPC pingbacks (WordPress),
  PDF and image renderers.
- *Audit:* send yourself a transactional mail and read the raw headers. Point
  each URL-fetching feature at a request logger you control and see which IP
  arrives.
- *Close:* send mail through a dedicated relay or provider. Route outbound
  fetches through an egress proxy or NAT with a **different** IP, and disable
  pingbacks. Fetchers must also block internal and metadata addresses
  (SSRF).

## 5. The application talking about itself

- Debug pages, `phpinfo()`, status and health endpoints, stack traces, and
  verbose errors that print `SERVER_ADDR` or internal hostnames.
- Headers such as `X-Backend-Server`, `X-Served-By`, `Via` and `Server`, and
  absolute redirects built from the server's own IP (`Location:
  http://203.0.113.10/...`).
- *Close:* switch off debug output in production, strip identifying headers,
  build redirects from the configured public hostname, and lock status
  endpoints behind auth or Cloudflare Access.

## 6. Code, configuration and clients

- IPs or origin hostnames in public repositories (including git history),
  CI/CD configs, Terraform state, `.env` files, client-side JavaScript,
  mobile or desktop app binaries, API docs and Postman collections.
- *Close:* reference the public hostname only. Move origin addresses into
  private config, and rotate any IP that was ever committed publicly.

## 7. Platform hostnames: the origin is not always an IP

When the origin is a managed service, the bypass is its **default hostname**:
`*.herokuapp.com`, `*.onrender.com`, `*.fly.dev`, `*.vercel.app`,
`*.netlify.app`, `*.azurewebsites.net`, `*.appspot.com`,
`*.elb.amazonaws.com`, bucket and storage endpoints. They are publicly
resolvable and serve the same app. See `platforms.md` for per-platform
restrictions.

## 8. Co-located services

Anything else listening on the same IP, such as an SSH banner, mail, a
database or admin panel, a monitoring agent or a game server, can be
fingerprinted and tied back to the site.

- *Audit:* on the origin, list listening sockets (`ss -tulpn`) and the
  provider firewall's open ports.
- *Close:* bind internal services to localhost or a private network/VPN, and
  move public non-web services to other hosts. Only Cloudflare-fronted web
  ports should face the internet, and only from Cloudflare.

## 9. Internet-scan and hosting datasets

Any IP that ever served your content may already be catalogued. There is
nothing to unpublish. That is why the control must be the allowlist plus
origin authentication. You can look up **your own** origin IP in such datasets
to see what they recorded and confirm a fix (for example, that the
certificate stopped being served).

---

### Audit checklist

- [ ] Origin IP never appeared in public DNS (rotate if it did)
- [ ] No DNS-only record resolves to the origin or its subnet (A and AAAA)
- [ ] SPF, MX and PTR do not reference the origin
- [ ] Mail and outbound fetches leave from a different IP
- [ ] Origin certificate is Origin CA or otherwise not tied to origin-only names
- [ ] Bare-IP TLS presents no certificate for your domain (`ssl_reject_handshake`)
- [ ] Bare-IP HTTP serves nothing (`444`)
- [ ] No IP or internal names in errors, headers, redirects or debug endpoints
- [ ] No origin addresses in public code, configs or client apps
- [ ] PaaS, load-balancer and bucket hostnames are restricted
- [ ] Only web ports face the internet, and only from Cloudflare
