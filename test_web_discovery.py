#!/usr/bin/env python3
"""Focused tests for adaptive web discovery planning."""

from __future__ import annotations

import argparse
import io
import sqlite3
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import web_discovery


SAMPLE = (
    "HTTP/1.1 200 OK\r\n"
    "Server: envoy\r\n"
    "Content-Type: text/html\r\n"
    "Location: https://api.example.com/v1\r\n\r\n"
    "<title>Envoy</title> envoy x-envoy-test"
)


class DiscoveryTests(unittest.TestCase):
    def test_parse_ports_supports_ranges_and_comments(self) -> None:
        self.assertEqual(web_discovery.parse_ports("80,443\n8000-8002 # app ports"), {80, 443, 8000, 8001, 8002})
        self.assertEqual(web_discovery.compact_ports({80, 443, 8000, 8001, 8002}), "80,443,8000-8002")

    def test_nmap_discovery_command(self) -> None:
        args = argparse.Namespace(
            nmap_scan_type="connect", nmap_min_rate=500, nmap_max_retries=2,
            nmap_host_timeout="10m", nmap_version_detection=True,
            nmap_min_hostgroup=4096, nmap_timing="4", nmap_default_scripts=True,
            nmap_host_discovery=False, nmap_extra_args="--version-intensity 5",
        )
        command = web_discovery.nmap_discovery_command(
            "10.0.0.0/24", "80,443,8000-8002", Path("/tmp/network"), args,
        )
        self.assertIn("-sT", command)
        self.assertIn("-sV", command)
        self.assertIn("-sC", command)
        self.assertIn("--min-hostgroup", command)
        self.assertIn("-Pn", command)
        self.assertIn("--version-intensity", command)
        self.assertEqual(command[-1], "10.0.0.0/24")
        args.nmap_extra_args = "-oA forbidden"
        with self.assertRaisesRegex(ValueError, "tool-managed"):
            web_discovery.nmap_discovery_command("10.0.0.0/24", "80", Path("/tmp/network"), args)

    def test_staged_nmap_command_and_safe_nse_profile(self) -> None:
        args = argparse.Namespace(
            nmap_scan_type="connect", nmap_min_rate=500, nmap_max_retries=2,
            nmap_host_timeout="10m", nmap_version_detection=True, nmap_min_hostgroup=None,
            nmap_timing="4", nmap_default_scripts=True, nmap_host_discovery=False,
            nmap_extra_args="", nmap_stages="staged", nse_profile="safe",
            nmap_output_format="xml", nmap_output_all_name=None,
        )
        discovery = web_discovery.nmap_discovery_command("10.0.0.0/24", "80,443", Path("/tmp/discovery"), args)
        enrichment = web_discovery.nmap_discovery_command(
            "source", "80,443", Path("/tmp/enriched"), args, enrichment=True, target_file=Path("/tmp/targets"),
        )
        self.assertNotIn("-sV", discovery)
        self.assertNotIn("--script", discovery)
        self.assertIn("-sV", enrichment)
        self.assertIn("--script", enrichment)
        self.assertIn("http-title,http-headers,ssl-cert", enrichment)

    def test_nmap_discovery_stops_when_all_workers_fail(self) -> None:
        root = Path(tempfile.mkdtemp())
        networks = root / "networks.txt"
        ports = root / "ports.txt"
        networks.write_text("10.0.0.0/30\n", encoding="utf-8")
        ports.write_text("80,443\n", encoding="utf-8")
        args = argparse.Namespace(
            network_file=[networks], ports_file=[ports], dry_run=False, color="never",
            nmap_workers=1, nmap_scan_type="connect", nmap_min_rate=500,
            nmap_max_retries=2, nmap_host_timeout="10m", nmap_min_hostgroup=None,
            nmap_timing="4", nmap_version_detection=True, nmap_default_scripts=False,
            nmap_host_discovery=False, nmap_extra_args="", nmap_output_format="all",
            nmap_output_all_name="prod-scan", nmap_output_name="scan", require_syn=False,
        )
        failed = SimpleNamespace(returncode=1, stdout="", stderr="TCP/IP fingerprinting requires root privileges.\nQUITTING!\n")
        with patch.object(web_discovery.shutil, "which", return_value="/usr/bin/nmap"), patch.object(web_discovery.subprocess, "run", return_value=failed):
            with self.assertRaisesRegex(ValueError, "all Nmap discovery workers failed"):
                web_discovery.run_nmap_discovery(args, root / "run")
        self.assertTrue((root / "run" / "nmap-discovery.json").is_file())

    def test_syn_scan_falls_back_to_connect_scan(self) -> None:
        args = argparse.Namespace(nmap_scan_type="syn")
        with patch.object(web_discovery.os, "geteuid", return_value=1000):
            available, reason = web_discovery.syn_scan_available(args)
        self.assertFalse(available)
        self.assertIn("not root", reason)

    def test_nmap_discovery_resume_reuses_existing_xml(self) -> None:
        root = Path(tempfile.mkdtemp())
        networks = root / "networks.txt"
        ports = root / "ports.txt"
        run_dir = root / "run"
        output_dir = run_dir / "nmap-discovery"
        output_dir.mkdir(parents=True)
        networks.write_text("10.0.0.0/30\n", encoding="utf-8")
        ports.write_text("80\n", encoding="utf-8")
        (output_dir / "prod-scan-0001.xml").write_text('<?xml version="1.0"?><nmaprun/>', encoding="utf-8")
        args = argparse.Namespace(
            network_file=[networks], ports_file=[ports], dry_run=False, color="never",
            nmap_workers=1, nmap_scan_type="connect", nmap_min_rate=500,
            nmap_max_retries=2, nmap_host_timeout="10m", nmap_min_hostgroup=None,
            nmap_timing="4", nmap_version_detection=True, nmap_default_scripts=False,
            nmap_host_discovery=False, nmap_extra_args="", nmap_output_format="all",
            nmap_output_all_name="prod-scan", nmap_output_name="scan", resume=run_dir,
            require_syn=False,
        )
        with patch.object(web_discovery.shutil, "which", return_value="/usr/bin/nmap"), patch.object(web_discovery.subprocess, "run") as run:
            outputs, results = web_discovery.run_nmap_discovery(args, run_dir)
        run.assert_not_called()
        self.assertEqual(outputs, [output_dir / "prod-scan-0001.xml"])
        self.assertTrue(results[0]["resumed"])

    def test_native_nmap_cli_flags(self) -> None:
        args = web_discovery.parser().parse_args([
            "-iL", "networks.txt", "-ports", "ports.txt", "-sS", "-sC", "-sV", "-Pn",
            "-T4", "--min-hostgroup", "4096", "--min-rate", "1000",
            "--max-retries", "3", "--host-timeout", "5m",
            "-oA", "prod-scan",
        ])
        self.assertEqual(args.nmap_scan_type, "syn")
        self.assertTrue(args.nmap_default_scripts)
        self.assertTrue(args.nmap_version_detection)
        self.assertFalse(args.nmap_host_discovery)
        self.assertEqual(args.nmap_timing, "4")
        self.assertEqual(args.nmap_min_hostgroup, 4096)
        self.assertEqual(args.nmap_min_rate, 1000)
        self.assertEqual(args.nmap_max_retries, 3)
        self.assertEqual(args.nmap_host_timeout, "5m")
        self.assertEqual(args.nmap_output_all_name, "prod-scan")

    def test_network_file_services_and_endpoint_limit(self) -> None:
        root = Path(tempfile.mkdtemp())
        networks = root / "networks.txt"
        ports = root / "ports.txt"
        networks.write_text("10.0.0.0/30\n# comment\n10.0.0.9\n", encoding="utf-8")
        ports.write_text("80,443\n4318\n", encoding="utf-8")
        args = argparse.Namespace(
            network_file=[networks], ports_file=[ports], max_network_endpoints=9,
        )
        services = web_discovery.network_file_services(args)
        self.assertEqual(len(services), 9)
        self.assertTrue(all(item["explicit_web_probe"] for item in services))
        target_args = argparse.Namespace(http_ports="80,4318", https_ports="443", nmap_all_open_ports=False)
        targets = web_discovery.gnmap_targets(services, target_args)
        self.assertIn("http://10.0.0.1", targets)
        self.assertIn("https://10.0.0.1", targets)
        self.assertNotIn("https://10.0.0.1:4318", targets)
        with self.assertRaisesRegex(ValueError, "max-network-endpoints"):
            web_discovery.network_file_services(argparse.Namespace(
                network_file=[networks], ports_file=[ports], max_network_endpoints=8,
            ))

    def test_console_color_modes(self) -> None:
        colored = io.StringIO()
        web_discovery.console("OK", "finished", "always", colored)
        self.assertIn("\033[32m", colored.getvalue())
        self.assertIn("[OK] finished", colored.getvalue().replace("\033[32m", "").replace("\033[0m", ""))

        plain = io.StringIO()
        web_discovery.console("ERROR", "failed", "never", plain)
        self.assertEqual(plain.getvalue(), "[ERROR] failed\n")

    def test_scan_profiles_preserve_explicit_options(self) -> None:
        args = web_discovery.parser().parse_args([
            "-iL", "networks.txt", "-ports", "ports.txt",
            "--scan-profile", "balanced", "--min-rate", "900", "--profile", "api",
        ])
        web_discovery.apply_scan_profile(args, [
            "-iL", "networks.txt", "-ports", "ports.txt",
            "--scan-profile", "balanced", "--min-rate", "900", "--profile", "api",
        ])
        self.assertEqual(args.nmap_min_rate, 900)
        self.assertEqual(args.profile, "api")
        self.assertEqual(args.nmap_workers, 8)
        self.assertEqual(args.host_concurrency, 20)

    def test_preflight_summary_estimates_network_work(self) -> None:
        root = Path(tempfile.mkdtemp())
        networks = root / "networks.txt"
        ports = root / "ports.txt"
        networks.write_text("10.0.0.0/30\n10.0.0.9\n", encoding="utf-8")
        ports.write_text("80,443\n", encoding="utf-8")
        args = argparse.Namespace(
            scan_profile="balanced", network_discovery="nmap", network_file=[networks],
            ports_file=[ports], nmap_workers=4, nmap_min_rate=500,
        )
        summary = web_discovery.preflight_summary(args)
        self.assertEqual(summary["estimated_hosts"], 3)
        self.assertEqual(summary["estimated_tcp_probes"], 6)
        self.assertEqual(summary["aggregate_min_rate"], 2000)
        self.assertEqual(summary["per_worker_min_rate"], 500)
        self.assertIsNone(summary["nmap_min_hostgroup"])
        self.assertEqual(summary["largest_worker_target_hosts"], 2)

    def test_scope_policy(self) -> None:
        policy = {
            "domains": {"include": ["*.example.com"], "exclude": ["billing.example.com"]},
            "cidrs": {"include": ["10.0.0.0/8"], "exclude": []},
        }
        self.assertEqual(web_discovery.scope_decision("api.example.com", policy)[0], "authorized")
        self.assertEqual(web_discovery.scope_decision("billing.example.com", policy)[0], "blocked")
        self.assertEqual(web_discovery.scope_decision("outside.test", policy)[0], "candidate")
        self.assertEqual(web_discovery.scope_decision("10.1.2.3", policy)[0], "authorized")

    def test_fingerprint_candidates_actions_and_wildcard(self) -> None:
        args = argparse.Namespace(fingerprint_probes="basic", technology=[], timeout=1)
        policy = {
            "domains": {"include": ["*.example.com"], "exclude": []},
            "cidrs": {"include": [], "exclude": []},
        }
        metadata = {
            "envoy": {
                "risk": "medium",
                "automatic_actions": ["Collect evidence."],
                "follow_up": ["Review admin exposure."],
                "protocols": ["http"],
            }
        }
        probe = {"url": "https://app.example.com", "status": 200, "response_sample": SAMPLE, "returncode": 0, "error": ""}
        tls = {"openssl": {"certificate": "X509v3 Subject Alternative Name: DNS:api.example.com, DNS:outside.test"}}
        with patch.object(web_discovery, "curl_probe", return_value=probe), patch.object(web_discovery, "tls_fingerprint", return_value=tls):
            fingerprint = web_discovery.fingerprint_target(
                "https://app.example.com", args, {"envoy": ("envoy", "x-envoy-")},
                {"envoy": ("Review admin exposure.",)}, policy, metadata,
            )
        self.assertTrue(fingerprint["wildcard_response"])
        self.assertEqual(fingerprint["technologies"]["envoy"]["confidence"], "high")
        self.assertTrue(any(item["host"] == "api.example.com" and item["state"] == "authorized" for item in fingerprint["candidates"]))
        self.assertTrue(any(action["type"] == "stop" for action in fingerprint["actions"]))

    def test_playbooks_persistence_and_reports(self) -> None:
        args = argparse.Namespace(playbooks=[], technology=[])
        paths, signatures, follow_up, explicit_only, metadata = web_discovery.load_catalog(args)
        self.assertIn("kubernetes", paths)
        self.assertIn("cloud-metadata-proxy", explicit_only)
        self.assertEqual(len(paths), len(metadata))
        fingerprint = {
            "target": "https://example.test", "reachable": True, "server": "test",
            "powered_by": None, "response_aliases": [], "technologies": {},
            "candidates": [], "actions": [], "probes": [],
        }
        run_dir = Path(tempfile.mkdtemp())
        findings = web_discovery.derive_findings([fingerprint], [], [])
        web_discovery.persist_state(run_dir, [fingerprint], [], [], findings, [])
        web_discovery.write_reports(run_dir, [fingerprint], [], [], findings, [])
        with sqlite3.connect(run_dir / "discovery.sqlite3") as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM targets").fetchone()[0], 1)
        self.assertTrue((run_dir / "report.md").is_file())
        self.assertTrue((run_dir / "report.html").is_file())
        self.assertTrue((run_dir / "findings.json").is_file())

    def test_gnmap_ingestion(self) -> None:
        source = Path(tempfile.mkdtemp()) / "scan.gnmap"
        source.write_text(
            "Host: 10.0.0.10 (app.example.com) Ports: "
            "22/open/tcp//ssh//OpenSSH 9.0/, 443/open/tcp//ssl|http//nginx/, "
            "3000/open/tcp//http//Grafana/, 5432/open/tcp//postgresql//PostgreSQL/\n",
            encoding="utf-8",
        )
        services = web_discovery.parse_gnmap(source)
        args = argparse.Namespace(
            http_ports="80,3000,8080", https_ports="443,8443", nmap_all_open_ports=False
        )
        targets = web_discovery.gnmap_targets(services, args)
        self.assertEqual(len(services), 4)
        self.assertIn("https://app.example.com", targets)
        self.assertIn("http://app.example.com:3000", targets)
        self.assertNotIn("http://app.example.com:5432", targets)
        findings = web_discovery.derive_findings([], [], services)
        self.assertTrue(any(item["severity"] == "high" and "postgresql" in item["technology"] for item in findings))

    def test_nmap_normal_ingestion(self) -> None:
        source = Path(tempfile.mkdtemp()) / "scan.nmap"
        source.write_text(
            "Nmap scan report for app.example.com (10.0.0.10)\n"
            "PORT     STATE SERVICE  VERSION\n"
            "22/tcp   open  ssh      OpenSSH 9.0\n"
            "443/tcp  open  ssl/http nginx 1.25\n"
            "3000/tcp open  http     Grafana\n"
            "\nNmap scan report for 10.0.0.11\n"
            "PORT     STATE SERVICE VERSION\n"
            "8080/tcp open  http    Jetty\n",
            encoding="utf-8",
        )
        services = web_discovery.parse_nmap(source)
        args = argparse.Namespace(
            http_ports="80,3000,8080", https_ports="443,8443", nmap_all_open_ports=False
        )
        targets = web_discovery.gnmap_targets(services, args)
        self.assertEqual(len(services), 4)
        self.assertIn("https://app.example.com", targets)
        self.assertIn("http://app.example.com:3000", targets)
        self.assertIn("http://10.0.0.11:8080", targets)

    def test_nmap_xml_ingestion(self) -> None:
        source = Path(tempfile.mkdtemp()) / "scan.xml"
        source.write_text(
            '<?xml version="1.0"?><nmaprun><host><address addr="10.0.0.12" addrtype="ipv4"/>'
            '<hostnames><hostname name="api.example.com"/></hostnames><ports>'
            '<port protocol="tcp" portid="8443"><state state="open"/>'
            '<service name="https" product="Envoy" version="1.30" extrainfo="proxy"/></port>'
            '<port protocol="tcp" portid="6379"><state state="open"/>'
            '<service name="redis" product="Redis" version="7"/></port>'
            '</ports></host></nmaprun>',
            encoding="utf-8",
        )
        services, warnings = web_discovery.parse_nmap_xml_detailed(source)
        self.assertEqual(len(services), 2)
        self.assertFalse(warnings)
        self.assertEqual(services[0]["version"], "Envoy 1.30 proxy")
        args = argparse.Namespace(http_ports="80", https_ports="8443", nmap_all_open_ports=False)
        self.assertIn("https://api.example.com:8443", web_discovery.gnmap_targets(services, args))

    def test_ip_fallback_targets_only_for_unreachable_hostnames(self) -> None:
        services = [
            {"address": "10.0.0.12", "hostname": "api.example.com", "port": 8443},
            {"address": "2001:db8::12", "hostname": "v6.example.com", "port": 443},
        ]
        fingerprints = [
            {"target": "https://api.example.com:8443", "reachable": False},
            {"target": "https://v6.example.com", "reachable": False},
            {"target": "https://healthy.example.com", "reachable": True},
        ]
        fallbacks = web_discovery.ip_fallback_targets(fingerprints, services, [])
        self.assertIn("https://10.0.0.12:8443", fallbacks)
        self.assertIn("https://[2001:db8::12]", fallbacks)
        self.assertEqual(len(fallbacks), 2)

    def test_failed_fingerprint_is_reportable(self) -> None:
        fingerprint = web_discovery.failed_fingerprint(
            "https://10.0.0.12:8443",
            UnicodeDecodeError("utf-8", b"\x80", 0, 1, "invalid"),
            {},
        )
        self.assertFalse(fingerprint["reachable"])
        self.assertIn("UnicodeDecodeError", fingerprint["error"])
        self.assertTrue(any(action["type"] == "stop" for action in fingerprint["actions"]))

    def test_reachability_summary_distinguishes_tcp_from_http(self) -> None:
        fingerprint = {
            "probes": [{"status": None, "error": "curl: (52) Empty reply from server"}],
            "transport": {"reachable": True, "error": None},
        }
        self.assertEqual(
            web_discovery.reachability_summary(fingerprint),
            "http=no tcp=yes reason=curl: (52) Empty reply from server",
        )
        fingerprint["probes"] = [{"status": 405, "error": ""}]
        self.assertEqual(web_discovery.reachability_summary(fingerprint), "http=yes statuses=405")

    def test_adaptive_scanner_jobs_and_operational_artifacts(self) -> None:
        root = Path(tempfile.mkdtemp())
        wordlists = [root / "quick.txt", root / "deep.txt"]
        for path in wordlists:
            path.write_text("health\n", encoding="utf-8")
        base = {
            "reachable": True, "wildcard_response": False,
            "probes": [{"status": 404, "url": "http://example.test", "analysis": {"rate_limited": False}}],
        }
        fingerprints = [
            {**base, "target": "http://plain.test", "technologies": {}},
            {**base, "target": "http://grafana.test", "technologies": {"grafana": {}}},
        ]
        args = argparse.Namespace(max_enumeration_targets=10, enumeration_strategy="adaptive")
        targets, jobs = web_discovery.scanner_jobs(root, fingerprints, wordlists, "json", args)
        self.assertEqual(len(targets), 2)
        self.assertEqual(len(jobs), 3)
        findings = [{"id": "F-1", "severity": "info", "title": "Test", "target": "http://plain.test", "evidence": "ok"}]
        coverage, comparison = web_discovery.write_operational_artifacts(root, {}, [], fingerprints, [], findings, None)
        self.assertIsNone(comparison)
        self.assertEqual(coverage["web_targets_fingerprinted"], 2)
        self.assertTrue((root / "findings.sarif").is_file())
        self.assertTrue((root / "protocol-follow-up.json").is_file())

    def test_port_intelligence(self) -> None:
        args = argparse.Namespace(playbooks=[], technology=[])
        _, _, _, _, metadata = web_discovery.load_catalog(args)
        intelligence = web_discovery.build_port_intelligence(metadata)
        self.assertTrue(any(item["technology"] == "opentelemetry" for item in intelligence["exact"][4317]))
        self.assertTrue(any(item["technology"] == "kubernetes" for item in intelligence["ranges"]))
        services = [{"address": "10.0.0.5", "hostname": None, "port": 3100, "protocol": "tcp", "service": "unknown", "version": None}]
        web_discovery.enrich_services_with_port_intelligence(services, intelligence)
        self.assertTrue(any(item["technology"] == "loki" for item in services[0]["port_hints"]))
        target_args = argparse.Namespace(http_ports="", https_ports="", nmap_all_open_ports=False)
        self.assertIn("http://10.0.0.5:3100", web_discovery.gnmap_targets(services, target_args, intelligence))
        mixed = [
            {"address": "10.0.0.6", "hostname": None, "port": 4317, "protocol": "tcp", "service": "unknown", "version": None},
            {"address": "10.0.0.6", "hostname": None, "port": 4318, "protocol": "tcp", "service": "unknown", "version": None},
            {"address": "10.0.0.6", "hostname": None, "port": 19391, "protocol": "tcp", "service": "unknown", "version": None},
            {"address": "10.0.0.6", "hostname": None, "port": 30000, "protocol": "tcp", "service": "unknown", "version": None},
        ]
        web_discovery.enrich_services_with_port_intelligence(mixed, intelligence)
        targets = web_discovery.gnmap_targets(mixed, target_args, intelligence)
        self.assertIn("http://10.0.0.6:4318", targets)
        self.assertNotIn("http://10.0.0.6:4317", targets)
        self.assertNotIn("http://10.0.0.6:19391", targets)
        self.assertNotIn("http://10.0.0.6:30000", targets)

    def test_weird_gnmap_ingestion_and_warnings(self) -> None:
        source = Path(tempfile.mkdtemp()) / "weird.gnmap"
        source.write_text(
            "Host: 2001:db8::1 () Status: Up\n"
            "Host: 2001:db8::1 () Ports: 443/open/tcp//ssl|http//nginx, reverse/proxy/, "
            "53/open|filtered/udp//domain//DNS/, broken\n"
            "Host: 10.0.0.1 Ports: 8080/open/tcp//http//Jetty/\n"
            "Host: malformed record\n",
            encoding="utf-8",
        )
        services, warnings = web_discovery.parse_gnmap_detailed(source)
        self.assertEqual(len(services), 3)
        self.assertTrue(any(item["address"] == "2001:db8::1" and item["port"] == 443 for item in services))
        self.assertTrue(any(item["state"] == "open" for item in services))
        self.assertTrue(any(item["reason"] == "ambiguous trailing data" for item in warnings))
        self.assertTrue(any(item["reason"] == "unrecognized host record" for item in warnings))
        duplicate = web_discovery.deduplicate_services(services + services)
        self.assertEqual(len(duplicate), len(services))
        args = argparse.Namespace(http_ports="80", https_ports="443", nmap_all_open_ports=False)
        self.assertIn("https://[2001:db8::1]", web_discovery.gnmap_targets(services, args))


if __name__ == "__main__":
    unittest.main()
