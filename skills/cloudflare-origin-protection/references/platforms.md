# Platform notes: where the bypass hides on common stacks

The allowlist and origin authentication from `hardening-playbook.md` always
apply. This file covers the places where they quietly fail to: container
networking, load balancers, managed platforms, and servers with surprising
defaults.

## Docker

**Why ufw does not protect containers.** `docker run -p 443:443` (or
`ports:` in Compose) makes Docker DNAT the port in the nat table's PREROUTING
chain. The traffic then goes through FORWARD, not INPUT, and ufw's rules live
on INPUT. A host that shows "443 allowed only from Cloudflare" in
`ufw status` can still serve a container to the whole internet.

Fixes, best first:

1. **Filter before DNAT.** The generator's `nftables` output (prerouting,
   priority -150) and its `iptables` output (mangle PREROUTING) both see the
   original destination port, so published ports are covered. This works with
   Docker's iptables backend and with the nftables backend added in Docker 29.
   Generate it with `--public-iface <internet interface>`. Without it,
   containers that call the host's own web ports (`172.17.0.1:443`,
   `host.docker.internal`, or `cloudflared` in a container in front of a host
   nginx) are dropped too, and so is container-to-container traffic that goes
   through the host's public IP.
2. **Publish only on loopback.** Use `-p 127.0.0.1:8080:80`, and let a host
   proxy (nginx, Caddy, `cloudflared`) be the only thing on the public
   interface.
3. **Use Docker's own hook.** With the iptables backend, user filtering goes in
   the `DOCKER-USER` chain. Match the original destination with
   `-m conntrack --ctorigdst <host IP> --ctorigdstport 443`, because packets
   arrive there already DNATed. The experimental nftables backend in Docker
   29 has **no** `DOCKER-USER` chain; it uses your own table with a base chain
   ordered around Docker's. Option 1 avoids both details.
4. **Filter at the cloud firewall.** It is applied before the VM and Docker
   cannot bypass it.

Check with `docker ps --format '{{.Names}} {{.Ports}}'`. Anything shown as
`0.0.0.0:...` or `[::]:...` is public unless the steps above cover it.

## Kubernetes

- **Best:** run `cloudflared` as a Deployment inside the cluster (two
  replicas) pointing at the ingress or service by its cluster DNS name. No
  public LoadBalancer or NodePort is needed at all.
- **With a public ingress LoadBalancer:** set
  `spec.loadBalancerSourceRanges` on the ingress controller's Service to
  Cloudflare's ranges (`--format cidr`), so the cloud load balancer enforces
  it. Add origin authentication (secret header or mTLS) at the ingress.
- **NodePorts** (30000-32767) on node public IPs bypass the load balancer
  entirely. Block them at the cloud firewall, or avoid public node IPs.
- **Do not load the generator's host table on nodes unscoped.** With
  kube-proxy in IPVS mode, every ClusterIP is bound to a local interface. The
  table would then drop pod traffic to every Service on 80/443, including the
  API server at `10.96.0.1:443`, and the cluster fails. If you need a host
  table for hostPort/hostNetwork ingress pods, generate it with
  `--public-iface` set to the node's internet interface. eBPF dataplanes (for
  example Cilium's kube-proxy replacement) may translate traffic before
  netfilter sees it, so enforce the allowlist at the cloud firewall or load
  balancer there.
- To preserve the client IP through the load balancer
  (`externalTrafficPolicy: Local`), remember that Cloudflare's IP is the
  "client". Read the visitor from `CF-Connecting-IP`, trusted only from
  Cloudflare's ranges.

## Load balancers between Cloudflare and the servers

Cloudflare connects to the load balancer, so the **load balancer** is the
origin.

- Allowlist Cloudflare on the load balancer's security group or firewall
  (`--format aws` / `gcp` / `cidr`), and remove `0.0.0.0/0` and `::/0`.
- Let the servers accept only the load balancer: reference its security group,
  or use `--also-allow <LB subnet>` with the nftables table.
- The load balancer's own DNS name (`*.elb.amazonaws.com` and similar) is a
  public bypass route until its security group is restricted.
- Put origin authentication where TLS terminates. If the load balancer
  terminates TLS, AOP must be checked there (or switch to a secret header the
  servers verify).

## Managed platforms (PaaS)

The platform's default hostname serves your app to anyone, bypassing
Cloudflare. Work through this list:

1. **Remove or disable the default hostname** where the platform allows it,
   or restrict access at the platform. App Service and Container Apps have
   access restrictions; some platforms have IP rules; others have none.
2. **Authenticate Cloudflare in the app.** Require the secret header from
   `hardening-playbook.md` (2b) in middleware and reject anything without it.
   It is often the only control a PaaS leaves you.
3. **Check outbound mail and fetches.** PaaS apps often send mail directly or
   fetch URLs; see `exposure-vectors.md`.

Platforms that put their own CDN in front of your app (Vercel, Netlify) add
another proxy layer. Make sure Cloudflare-specific trust (CF-Connecting-IP)
is not taken from the wrong hop.

## Object storage origins

- **S3 behind Cloudflare:** a bucket policy that allows reads only when
  `aws:SourceIp` is in Cloudflare's ranges, and blocks public access
  otherwise. The bucket endpoint itself stays resolvable, so the policy is the
  control. If the content can move, Cloudflare R2 behind a custom domain
  removes the problem.
- **Other providers:** use the equivalent IP condition, or signed URLs with
  the signing done at the edge (a Worker).

## Web server specifics

- **Caddy** serves HTTP/3 on UDP 443 by default. Cloudflare never uses it to
  reach origins, so it is pure bypass surface. Use `--format caddy`
  (`protocols h1 h2`, `trusted_proxies`, `client_ip_headers`), and keep the
  firewall's UDP drop.
- **nginx:** HTTP/3 needs `listen 443 quic`. Make sure nobody added it to an
  origin. Use `ssl_reject_handshake on;` for the default server (1.19.4+).
- **Traefik:** HTTP/3 is opt-in per entry point. Set
  `forwardedHeaders.trustedIPs` / `proxyProtocol.trustedIPs` to Cloudflare's
  ranges only.
- **IIS / Windows Server:** `--format windows` for the firewall. IIS's built-in
  "World Wide Web Services" allow rules admit everyone, which is why the
  generated script adds a block rule for all non-Cloudflare addresses. For the
  visitor IP, log the `CF-Connecting-IP` request header as a custom logging
  field.
- **Shared hosting / cPanel:** you usually cannot change the firewall. Use the
  secret header, enforce it in `.htaccess` or app middleware, enable
  `mod_remoteip` with `--format apache`, and ask the host whether they offer a
  Cloudflare-only firewall option.

## Admin access that does not reopen the hole

- SSH, RDP and panels must not rely on the web allowlist. Restrict them to
  your IP or VPN, or carry them over Cloudflare Tunnel with Access in front.
- Hosting-provider web consoles and serial consoles are the break-glass path.
  Confirm they work **before** changing firewalls.
