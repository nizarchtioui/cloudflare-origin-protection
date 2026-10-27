# Incident response: "they found our origin and are hitting it directly"

Order matters. Stop the bleeding upstream first, then close the hole for good,
then fix the leak so a new address stays private. Confirm the user operates
the infrastructure, and that they have console or out-of-band access before
any firewall change.

## 0. Confirm it really is direct-to-origin (minutes)

Signs:

- The origin is overloaded, but Cloudflare's analytics show no matching spike.
- Origin logs show TCP peers outside Cloudflare's ranges (`$realip_remote_addr`
  in nginx), or requests without a `CF-Ray` header.
- Edge controls such as Under Attack mode, WAF rules and rate limits have no
  effect. They cannot: this traffic never passes through Cloudflare.

If the traffic **does** come from Cloudflare's ranges with your Host header and
no valid AOP certificate or secret header, someone is using **their own
Cloudflare zone** against your origin. Step 2 is the fix for that.

## 1. Block at the provider edge (minutes)

- Restrict the cloud firewall or security group to Cloudflare's ranges on the
  web ports (`--format aws` / `gcp` / `cidr`), and delete the `0.0.0.0/0` and
  `::/0` rules. This filters before the VM.
- Then load the host table, scoped to the internet-facing interface so
  containers, pods and VPN users keep working:
  `generate_cf_firewall_rules.py --format nftables --public-iface eth0 > cf.nft && nft -c -f cf.nft && nft -f cf.nft`.
  Before applying, check `ss -tulpn` for a VPN on UDP 443 (`--no-udp-drop`).
- On bare metal with no provider firewall, ask the host or upstream for an ACL
  or scrubbing. A host firewall cannot absorb a flood that saturates the link.

## 2. Require proof of *your* zone (minutes to an hour)

- **Fastest:** the secret header. One Request Header Transform Rule plus one
  nginx `map`/`if` (playbook 2b).
- **Durable:** AOP with your own certificate, zone-level or per-hostname
  (playbook 2a), and port 80 reduced to a redirect or dropped.

## 3. If the link is still saturated: move

Packets aimed at a known IP still arrive, whatever the host does with them.

- **Option A, Tunnel:** stand up `cloudflared` and point the hostname at the
  tunnel. The origin then needs no public inbound address, so you can drop or
  change the old IP.
- **Option B, new IP:** bring up the new address with the allowlist and origin
  auth **already applied**, verify with the checker, switch the proxied DNS
  record, then release the old IP. Never put the new IP in DNS-only records,
  SPF, mail headers, code, or tickets.

## 4. Find and close the leak (same day)

Walk `exposure-vectors.md`, or a rotated IP will leak the same way. The usual
culprits: a DNS-only record on the same host, mail sent from the origin
(headers, SPF), historical DNS, the real certificate served on the bare IP, a
webhook or URL fetcher, or an IP committed to a public repository.

## 5. Verify and keep watching

- From outside, the checker shows LOCKED for every address and port, IPv4 and
  IPv6.
- The `--also-allow` test shows origin auth refusing (`verification.md` §2).
- Leave monitoring in place: drop counters, a non-Cloudflare access log,
  `CF-Worker` values that are not your zone, and the scheduled range refresh
  with `--require-live`.

## Afterwards

Write down what leaked the address and which control was missing, then move
the origin to the strongest pattern it can take. That is Tunnel; failing that,
the provider allowlist plus the host table plus AOP with your certificate.
