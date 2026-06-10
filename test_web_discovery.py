#!/usr/bin/env python3
"""Focused tests for adaptive web discovery planning."""

from __future__ import annotations

import argparse
import io
import sqlite3
import tempfile
import unittest
from pathlib import Path
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
    def test_console_color_modes(self) -> None:
        colored = io.StringIO()
        web_discovery.console("OK", "finished", "always", colored)
        self.assertIn("\033[32m", colored.getvalue())
        self.assertIn("[OK] finished", colored.getvalue().replace("\033[32m", "").replace("\033[0m", ""))

        plain = io.StringIO()
        web_discovery.console("ERROR", "failed", "never", plain)
        self.assertEqual(plain.getvalue(), "[ERROR] failed\n")

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
