#!/usr/bin/env python3
"""Run authorized multi-target web content discovery with ffuf or gobuster."""

from __future__ import annotations

import argparse
import concurrent.futures
import fnmatch
import hashlib
import html
import ipaddress
import json
import os
import re
import shlex
import shutil
import socket
import sqlite3
import ssl
import subprocess
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse


SECLISTS_CANDIDATES = (
    "/usr/share/seclists/Discovery/Web-Content",
    "/usr/local/share/seclists/Discovery/Web-Content",
    "/opt/homebrew/share/seclists/Discovery/Web-Content",
    "~/SecLists/Discovery/Web-Content",
    "~/seclists/Discovery/Web-Content",
)

PROFILES = {
    "quick": ("common.txt",),
    "default": ("common.txt", "raft-small-directories.txt", "raft-small-files.txt"),
    "deep": (
        "DirBuster-2007_directory-list-2.3-medium.txt",
        "raft-medium-directories.txt",
        "raft-medium-files.txt",
        "Common-DB-Backups.txt",
    ),
    "api": (
        "api/api-endpoints.txt",
        "api/api-seen-in-wild.txt",
        "api/objects.txt",
        "graphql.txt",
    ),
}

TECH_PATHS = {
    "generic-api": (
        "api", "api/v1", "api/v2", "openapi.json", "openapi.yaml", "swagger.json",
        "swagger-ui", "swagger-ui/index.html", "api-docs", "v2/api-docs", "v3/api-docs",
        "graphql", "graphiql", "health", "healthz", "ready", "readyz", "live", "livez",
        "metrics", "status", ".well-known/openid-configuration",
    ),
    "kubernetes": (
        "api", "api/v1", "apis", "apis/apps/v1", "apis/batch/v1", "healthz", "livez",
        "readyz", "metrics", "version", "openapi/v2", "openapi/v3",
    ),
    "grafana": (
        "api/health", "api/frontend/settings", "api/datasources", "api/search",
        "api/admin/stats", "login", "public/build/manifest.json",
    ),
    "prometheus": (
        "-/healthy", "-/ready", "api/v1/status/buildinfo", "api/v1/status/config",
        "api/v1/targets", "api/v1/rules", "api/v1/alerts", "metrics",
    ),
    "loki": (
        "ready", "metrics", "config", "services", "loki/api/v1/status/buildinfo",
        "loki/api/v1/labels", "loki/api/v1/series",
    ),
    "opentelemetry": (
        "v1/traces", "v1/metrics", "v1/logs", "metrics", "debug/tracez",
        "debug/pipelinez", "debug/extensionz", "debug/featurez",
    ),
    "grpc": ("grpc.health.v1.Health/Check",),
    "jaeger": ("api/services", "api/traces", "search", "dependencies"),
    "tempo": ("ready", "metrics", "api/status/buildinfo", "api/search", "api/echo"),
    "alertmanager": ("-/healthy", "-/ready", "api/v2/status", "api/v2/alerts", "metrics"),
    "mimir": ("ready", "metrics", "config", "services", "api/v1/status/buildinfo", "prometheus/api/v1/status/buildinfo"),
    "thanos": ("-/healthy", "-/ready", "api/v1/status", "api/v1/stores", "api/v1/query", "metrics"),
    "pyroscope": ("-/healthy", "api/v1/label", "api/v1/render", "metrics"),
    "zipkin": ("api/v2/services", "api/v2/spans", "api/v2/traces", "zipkin"),
    "etcd": ("health", "version", "metrics", "v2/keys", "v3/kv/range"),
    "consul": ("v1/status/leader", "v1/status/peers", "v1/catalog/services", "v1/agent/self", "v1/health/state/any"),
    "vault": ("v1/sys/health", "v1/sys/seal-status", "v1/sys/mounts", "v1/sys/auth"),
    "envoy": ("ready", "server_info", "stats", "stats/prometheus", "clusters", "listeners", "config_dump"),
    "istio": ("healthz/ready", "stats/prometheus", "config_dump", "clusters", "listeners", "server_info"),
    "linkerd": ("ready", "metrics", "proxy-log-level", "tap"),
    "consul-connect": ("ready", "metrics", "clusters", "config_dump"),
    "traefik": ("ping", "api/rawdata", "api/http/routers", "api/http/services", "dashboard/"),
    "nginx": ("nginx_status", "status", "stub_status"),
    "haproxy": ("haproxy?stats", "stats", "metrics"),
    "kong": ("status", "status/ready", "metrics", "routes", "services", "plugins"),
    "apache-apisix": ("apisix/status", "apisix/admin/routes", "apisix/admin/services", "metrics"),
    "container-runtime": ("metrics", "debug/pprof", "debug/pprof/goroutine", "version"),
    "docker-registry": ("v2/", "v2/_catalog"),
    "harbor": ("api/v2.0/health", "api/v2.0/projects", "api/v2.0/systeminfo", "service/token"),
    "argocd": ("api/version", "api/v1/applications", "api/v1/clusters", "auth/login"),
    "flux": ("metrics", "healthz", "readyz"),
    "jenkins": ("login", "api/json", "computer/api/json", "manage", "script"),
    "gitlab": ("-/health", "-/readiness", "-/metrics", "api/v4/version", "api/v4/projects"),
    "rabbitmq": ("api/overview", "api/health/checks/alarms", "api/nodes", "api/queues", "metrics"),
    "kafka-rest": ("topics", "brokers", "v3/clusters"),
    "redis": ("metrics",),
    "postgres-exporter": ("metrics",),
    "mongodb": ("metrics", "serverStatus"),
    "minio": ("minio/health/live", "minio/health/ready", "minio/v2/metrics/cluster"),
    "keycloak": ("realms/master", "realms/master/.well-known/openid-configuration", "admin/master/console/"),
    "dex": (".well-known/openid-configuration", "auth", "keys", "healthz"),
    "oauth-proxy": ("oauth2/sign_in", "oauth2/auth", "ping", "ready"),
    "feature-flags": ("health", "ready", "metrics", "api/admin/projects", "api/client/features"),
    "cloud-metadata-proxy": ("latest/meta-data/", "metadata/instance", "computeMetadata/v1/"),
    "sidecar": ("health", "ready", "metrics", "stats", "config_dump", "debug/pprof"),
    "elasticsearch": ("_cluster/health", "_cluster/state", "_cat", "_cat/indices", "_nodes", "_nodes/http"),
    "spring": (
        "actuator", "actuator/health", "actuator/info", "actuator/metrics",
        "actuator/prometheus", "actuator/env", "actuator/mappings",
    ),
}

FINGERPRINT_PROBES = (
    "", "robots.txt", ".well-known/openid-configuration", "openapi.json", "swagger.json",
    "graphql", "health", "healthz", "ready", "readyz", "metrics", "version",
    "api/health", "-/healthy", "loki/api/v1/status/buildinfo", "actuator/health",
)

SIGNATURES = {
    "kubernetes": ("kubernetes", "audit-id", "x-kubernetes-pf-", "apis/apps/v1"),
    "grafana": ("grafana", "grafana_session", "x-grafana"),
    "prometheus": ("prometheus", "prometheus_build_info", "promhttp_metric_handler"),
    "loki": ("loki", "loki_build_info", "x-scope-orgid"),
    "opentelemetry": ("opentelemetry", "otel", "application/x-protobuf"),
    "grpc": ("grpc-status", "grpc-message", "application/grpc"),
    "jaeger": ("jaeger", "jaeger-query"),
    "tempo": ("tempo", "tempo_build_info"),
    "alertmanager": ("alertmanager", "alertmanager_build_info"),
    "mimir": ("mimir", "cortex_build_info"),
    "thanos": ("thanos", "thanos_build_info"),
    "pyroscope": ("pyroscope", "pyroscope_build_info"),
    "zipkin": ("zipkin", "zipkin-server"),
    "etcd": ("etcd", "etcdserver"),
    "consul": ("consul", "x-consul-"),
    "vault": ("x-vault-", "vault"),
    "envoy": ("envoy", "x-envoy-"),
    "istio": ("istio", "istio-proxy"),
    "linkerd": ("linkerd", "l5d-"),
    "consul-connect": ("consul connect", "consul-dataplane"),
    "traefik": ("traefik",),
    "nginx": ("server: nginx",),
    "haproxy": ("haproxy",),
    "kong": ("server: kong", "x-kong-"),
    "apache-apisix": ("apisix",),
    "container-runtime": ("containerd", "cri-o", "dockerd"),
    "docker-registry": ("docker-distribution-api-version",),
    "harbor": ("harbor",),
    "argocd": ("argocd", "argo cd"),
    "flux": ("fluxcd", "gotk_"),
    "jenkins": ("x-jenkins", "jenkins"),
    "gitlab": ("gitlab", "_gitlab_session"),
    "rabbitmq": ("rabbitmq", "rabbitmq_management"),
    "kafka-rest": ("kafka", "kafka-rest"),
    "redis": ("redis", "redis_exporter"),
    "postgres-exporter": ("pg_up", "postgres_exporter"),
    "mongodb": ("mongodb", "mongodb_up"),
    "minio": ("minio", "x-minio-"),
    "keycloak": ("keycloak", "kc_session"),
    "dex": ("dex", "dex-session"),
    "oauth-proxy": ("oauth2_proxy", "oauth2-proxy"),
    "feature-flags": ("unleash", "flagsmith"),
    "cloud-metadata-proxy": ("metadata-flavor", "meta-data"),
    "sidecar": ("sidecar", "proxy-sidecar"),
    "elasticsearch": ("x-elastic-product", "cluster_name", "you know, for search"),
    "spring": ("whitelabel error page", "spring", "actuator"),
}

FOLLOW_UP = {
    "kubernetes": ("Validate identity and RBAC with approved credentials; inspect API discovery and exposed OpenAPI.",),
    "grpc": ("Use grpcurl for authorized health and reflection checks; HTTP fuzzing cannot enumerate native gRPC.",),
    "opentelemetry": ("Validate OTLP/HTTP and OTLP/gRPC separately with a non-sensitive test signal.",),
    "envoy": ("Review whether the Envoy admin interface is exposed; inspect config_dump only when explicitly authorized.",),
    "istio": ("Identify proxy sidecars and ingress gateways; review mesh auth policies and exposed proxy admin routes.",),
    "linkerd": ("Validate Linkerd proxy/admin exposure and mTLS identity boundaries.",),
    "consul-connect": ("Review sidecar proxy admin exposure and Consul intentions using approved credentials.",),
    "cloud-metadata-proxy": ("Treat metadata-looking routes as high risk; do not attempt credential retrieval.",),
    "vault": ("Review health, seal state, auth methods, and ACLs without attempting secret access.",),
    "etcd": ("Determine whether client certificate authentication is required; avoid key enumeration without approval.",),
    "docker-registry": ("Review anonymous catalog and pull permissions; do not push or mutate images.",),
    "jenkins": ("Review anonymous read/admin access; do not invoke jobs, script console, or builds.",),
    "sidecar": ("Identify the sidecar owner and protocol; review local admin, metrics, and identity boundaries.",),
}

EXPLICIT_ONLY_TECHNOLOGIES = {"cloud-metadata-proxy"}
BUNDLED_PLAYBOOKS = Path(__file__).with_name("web_discovery_playbooks")
DEFAULT_HTTP_PORTS = {80, 3000, 5000, 8000, 8001, 8080, 8081, 8082, 8088, 8888, 9000, 9090, 9093, 9180, 9200, 9411}
DEFAULT_HTTPS_PORTS = {443, 2379, 4191, 5556, 6443, 8200, 8443, 8444, 10250, 15021}

ANSI = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "cyan": "\033[36m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "red": "\033[31m",
    "blue": "\033[34m",
    "dim": "\033[2m",
}
LEVEL_STYLES = {
    "INFO": ("blue",),
    "PHASE": ("bold", "cyan"),
    "PROGRESS": ("cyan",),
    "OK": ("green",),
    "WARN": ("yellow",),
    "ERROR": ("bold", "red"),
    "RUN": ("dim",),
}


@dataclass(frozen=True)
class Job:
    target: str
    wordlist: Path
    output: Path


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Orchestrate authorized directory, file, and API discovery across multiple web targets.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("-u", "--url", action="append", help="Target URL; repeat for multiple targets")
    p.add_argument("-i", "--input", action="append", type=Path, help="File containing one target URL per line; repeatable")
    p.add_argument("--gnmap", action="append", type=Path, help="Nmap grepable output file; repeatable")
    p.add_argument("--nmap", action="append", type=Path, help="Nmap normal output file; repeatable")
    p.add_argument("--nmap-xml", action="append", type=Path, help="Nmap XML output file; repeatable and preferred")
    p.add_argument("--http-ports", default=",".join(map(str, sorted(DEFAULT_HTTP_PORTS))), help="Additional comma-separated HTTP ports")
    p.add_argument("--https-ports", default=",".join(map(str, sorted(DEFAULT_HTTPS_PORTS))), help="Additional comma-separated HTTPS ports")
    p.add_argument(
        "--nmap-all-open-ports", "--gnmap-all-open-ports",
        dest="nmap_all_open_ports", action="store_true",
        help="Treat every imported open TCP port as HTTP and HTTPS candidates",
    )
    p.add_argument("--mode", choices=("smart", "fingerprint", "enumerate"), default="smart")
    p.add_argument("--tool", choices=("auto", "ffuf", "gobuster"), default="auto")
    p.add_argument("--profile", choices=tuple(PROFILES), default="default")
    p.add_argument("-w", "--wordlist", action="append", type=Path, help="Custom wordlist; repeatable")
    p.add_argument("--seclists", type=Path, help="Path to SecLists/Discovery/Web-Content")
    p.add_argument("-t", "--threads", type=positive_int, default=40, help="Threads used by each scanner process")
    p.add_argument("--host-concurrency", type=positive_int, default=2, help="Scanner processes run concurrently")
    p.add_argument("--rate", type=positive_int, help="Maximum requests/sec per scanner where supported")
    p.add_argument("-x", "--extensions", default="", help="Comma-separated file extensions")
    p.add_argument("-H", "--header", action="append", default=[], help="HTTP header; repeatable")
    p.add_argument("--cookie", help="Cookie header value")
    p.add_argument("--proxy", help="HTTP proxy URL")
    p.add_argument("--status-codes", default="200,204,301,302,307,401,403,405", help="Included HTTP statuses")
    p.add_argument("--timeout", type=positive_int, default=10, help="Request timeout in seconds")
    p.add_argument("--fingerprint-probes", choices=("basic", "extensive"), default="extensive")
    p.add_argument("--scope-policy", type=Path, help="JSON scope policy controlling candidate authorization")
    p.add_argument("--expand-authorized-candidates", action="store_true", help="Fingerprint authorized discovered hostnames")
    p.add_argument("--max-candidate-expansion", type=positive_int, default=25)
    p.add_argument("--technology", action="append", default=[], help="Force-prioritize a technology; repeatable")
    p.add_argument("--playbooks", action="append", type=Path, default=[], help="Additional playbook JSON file or directory; repeatable")
    p.add_argument("--list-technologies", action="store_true", help="List loaded technology playbooks and exit")
    p.add_argument("--list-port-intelligence", action="store_true", help="List technology port hints and ranges and exit")
    p.add_argument("--validate-playbooks", action="store_true", help="Validate loaded technology playbooks and exit")
    p.add_argument("--recursion", action="store_true", help="Enable recursion (ffuf only)")
    p.add_argument("--recursion-depth", type=positive_int, default=2)
    p.add_argument("--follow-redirects", action="store_true")
    p.add_argument("--insecure", action="store_true", help="Skip TLS certificate verification")
    p.add_argument("--extra-args", default="", help="Additional backend arguments, parsed with shell quoting")
    p.add_argument("-o", "--output", type=Path, default=Path("web-discovery-results"))
    p.add_argument("--dry-run", action="store_true", help="Print commands without executing")
    p.add_argument("--color", choices=("auto", "always", "never"), default="auto", help="Console color mode")
    p.add_argument(
        "--no-color", action="store_const", const="never", dest="color",
        default=argparse.SUPPRESS, help="Disable console colors",
    )
    p.add_argument(
        "--acknowledge-authorization",
        action="store_true",
        help="Confirm you are authorized to scan every supplied target",
    )
    return p


def colors_enabled(mode: str, stream: object = sys.stdout) -> bool:
    if mode == "always":
        return True
    if mode == "never" or os.environ.get("NO_COLOR") is not None:
        return False
    return bool(getattr(stream, "isatty", lambda: False)())


def styled(text: str, styles: tuple[str, ...], mode: str, stream: object = sys.stdout) -> str:
    if not colors_enabled(mode, stream):
        return text
    return "".join(ANSI[style] for style in styles) + text + ANSI["reset"]


def console(level: str, message: str, mode: str = "auto", stream: object = sys.stdout) -> None:
    label = styled(f"[{level}]", LEVEL_STYLES.get(level, ()), mode, stream)
    print(f"{label} {message}", file=stream, flush=True)


def positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return number


def parse_ports(value: str) -> set[int]:
    ports = set()
    for item in value.split(","):
        if item.strip():
            port = int(item)
            if not 1 <= port <= 65535:
                raise ValueError(f"invalid port: {port}")
            ports.add(port)
    return ports


def gnmap_port_fragments(ports_text: str) -> list[str]:
    starts = list(re.finditer(r"(?:^|,\s*)(?=\d+\/)", ports_text))
    if not starts:
        return [ports_text.strip()] if ports_text.strip() else []
    fragments = []
    for index, match in enumerate(starts):
        start = match.end()
        end = starts[index + 1].start() if index + 1 < len(starts) else len(ports_text)
        fragments.append(ports_text[start:end].strip().rstrip(",").strip())
    return fragments


def parse_gnmap_detailed(path: Path) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    services = []
    warnings = []
    source = path.expanduser()
    for line_number, line in enumerate(source.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if not line.startswith("Host:"):
            continue
        if "Ports:" not in line:
            if "Status:" not in line:
                warnings.append({"source": str(source), "line": line_number, "reason": "unrecognized host record", "raw": line})
            continue
        match = re.match(r"Host:\s+(\S+)(?:\s+\(([^)]*)\))?.*?\bPorts:\s+(.+?)(?:\s+Ignored State:|$)", line)
        if not match:
            warnings.append({"source": str(source), "line": line_number, "reason": "unrecognized host record", "raw": line})
            continue
        address, hostname, ports_text = match.groups()
        for entry in gnmap_port_fragments(ports_text):
            if re.search(r",\s*[A-Za-z][^/]*$", entry):
                warnings.append({"source": str(source), "line": line_number, "reason": "ambiguous trailing data", "raw": entry})
            fields = entry.strip().split("/")
            if len(fields) < 3:
                warnings.append({"source": str(source), "line": line_number, "reason": "malformed port record", "raw": entry})
                continue
            if fields[1] not in {"open", "open|filtered"}:
                continue
            try:
                port = int(fields[0])
            except ValueError:
                warnings.append({"source": str(source), "line": line_number, "reason": "invalid port", "raw": entry})
                continue
            fields += [""] * (7 - len(fields))
            version = "/".join(fields[6:]).rstrip("/") or None
            services.append({
                "address": address,
                "hostname": hostname or None,
                "port": port,
                "state": fields[1],
                "protocol": fields[2],
                "owner": fields[3] or None,
                "service": fields[4] or "unknown",
                "rpc_info": fields[5] if len(fields) > 5 else None,
                "version": version,
                "source": str(source),
                "source_line": line_number,
                "raw": entry,
            })
    return services, warnings


def parse_gnmap(path: Path) -> list[dict[str, object]]:
    return parse_gnmap_detailed(path)[0]


def parse_nmap_detailed(path: Path) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    services = []
    warnings = []
    address = None
    hostname = None
    source = path.expanduser()
    for line_number, line in enumerate(source.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        host_match = re.match(r"Nmap scan report for (?:(\S+) \(([^)]+)\)|(\S+))$", line.strip())
        if host_match:
            named_host, parenthesized_address, plain_host = host_match.groups()
            if named_host:
                hostname, address = named_host, parenthesized_address
            else:
                address = plain_host
                try:
                    ipaddress.ip_address(address)
                    hostname = None
                except ValueError:
                    hostname = address
            continue
        port_match = re.match(r"^(\d+)\/(\S+)\s+open(?:\|filtered)?\s+(\S+)(?:\s+(.*))?$", line.strip())
        if not port_match or not address:
            continue
        port, protocol, service, version_text = port_match.groups()
        services.append({
            "address": address,
            "hostname": hostname,
            "port": int(port),
            "state": "open",
            "protocol": protocol,
            "owner": None,
            "service": service,
            "rpc_info": None,
            "version": version_text or None,
            "source": str(source),
            "source_line": line_number,
            "raw": line.strip(),
        })
    return services, warnings


def parse_nmap(path: Path) -> list[dict[str, object]]:
    return parse_nmap_detailed(path)[0]


def parse_nmap_xml_detailed(path: Path) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    services = []
    warnings = []
    source = path.expanduser()
    try:
        root = ET.parse(source).getroot()
    except ET.ParseError as exc:
        return [], [{"source": str(source), "line": getattr(exc, "position", (None,))[0], "reason": "invalid Nmap XML", "raw": str(exc)}]
    for host in root.findall("host"):
        addresses = host.findall("address")
        address = next((item.get("addr") for item in addresses if item.get("addrtype") in {"ipv4", "ipv6"}), None)
        hostname_node = host.find("./hostnames/hostname")
        hostname = hostname_node.get("name") if hostname_node is not None else None
        if not address:
            warnings.append({"source": str(source), "line": None, "reason": "XML host missing address", "raw": ET.tostring(host, encoding="unicode")[:1000]})
            continue
        for port_node in host.findall("./ports/port"):
            state = port_node.find("state")
            if state is None or state.get("state") not in {"open", "open|filtered"}:
                continue
            service = port_node.find("service")
            product = service.get("product") if service is not None else None
            version = service.get("version") if service is not None else None
            extra = service.get("extrainfo") if service is not None else None
            version_text = " ".join(value for value in (product, version, extra) if value) or None
            services.append({
                "address": address,
                "hostname": hostname,
                "port": int(port_node.get("portid")),
                "state": state.get("state"),
                "protocol": port_node.get("protocol"),
                "owner": None,
                "service": service.get("name") if service is not None else "unknown",
                "rpc_info": service.get("rpcnum") if service is not None else None,
                "version": version_text,
                "source": str(source),
                "source_line": None,
                "raw": ET.tostring(port_node, encoding="unicode"),
            })
    return services, warnings


def parse_nmap_xml(path: Path) -> list[dict[str, object]]:
    return parse_nmap_xml_detailed(path)[0]


def deduplicate_services(services: list[dict[str, object]]) -> list[dict[str, object]]:
    unique = {}
    for service in services:
        key = (
            service.get("address"), service.get("hostname"), service.get("port"),
            service.get("protocol"), service.get("service"),
        )
        unique.setdefault(key, service)
    return list(unique.values())


def build_port_intelligence(playbook_metadata: dict[str, dict[str, object]]) -> dict[str, object]:
    exact = {}
    ranges = []
    for technology, playbook in playbook_metadata.items():
        for hint in playbook.get("port_hints", []):
            protocol = str(hint.get("protocol", "tcp"))
            transport = hint.get("transport", "udp" if protocol == "udp" else "tcp")
            exact.setdefault(int(hint["port"]), []).append({**hint, "technology": technology, "transport": transport})
        for hint in playbook.get("port_ranges", []):
            ranges.append({**hint, "technology": technology, "transport": hint.get("transport", "tcp")})
    return {"exact": exact, "ranges": ranges}


def enrich_services_with_port_intelligence(services: list[dict[str, object]], intelligence: dict[str, object]) -> None:
    for service in services:
        port = int(service["port"])
        service_protocol = str(service.get("protocol", "tcp"))
        exact = [
            dict(hint) for hint in intelligence["exact"].get(port, [])
            if hint.get("transport") in {service_protocol, "any", "tcp-udp"}
        ]
        service_text = f"{service.get('service', '')} {service.get('version', '')}".lower()
        for hint in exact:
            technology = str(hint["technology"]).replace("-", " ")
            hint["confidence"] = "high" if technology in service_text else ("medium" if len(exact) == 1 else "low")
        ranges = [
            dict(hint) for hint in intelligence["ranges"]
            if int(hint["start"]) <= port <= int(hint["end"])
            and hint.get("transport") in {service_protocol, "any", "tcp-udp"}
        ]
        for hint in ranges:
            hint["confidence"] = "low"
        service["port_hints"] = exact + ranges


def gnmap_targets(
    services: list[dict[str, object]],
    args: argparse.Namespace,
    port_intelligence: dict[str, object] | None = None,
) -> list[str]:
    http_ports = parse_ports(args.http_ports)
    https_ports = parse_ports(args.https_ports)
    targets = []
    for item in services:
        if item["protocol"] != "tcp":
            continue
        host = item["hostname"] or item["address"]
        try:
            if ipaddress.ip_address(host).version == 6:
                host = f"[{host}]"
        except ValueError:
            pass
        port = int(item["port"])
        service = str(item["service"]).lower()
        hints = item.get("port_hints", [])
        web_hints = [hint for hint in hints if hint.get("web")]
        web_hints_supported = web_hints and (
            all(hint.get("web") for hint in hints)
            or any(hint.get("confidence") in {"high", "medium"} for hint in web_hints)
        )
        if args.nmap_all_open_ports:
            schemes = ("https", "http")
        elif web_hints_supported:
            schemes = tuple(dict.fromkeys(str(hint.get("scheme", "http")) for hint in web_hints))
        elif "ssl" in service or "https" in service or port in https_ports:
            schemes = ("https",)
        elif "http" in service or service in {"www", "http-proxy"} or port in http_ports:
            schemes = ("http",)
        else:
            continue
        for scheme in schemes:
            default_port = 443 if scheme == "https" else 80
            suffix = "" if port == default_port else f":{port}"
            targets.append(f"{scheme}://{host}{suffix}")
    return list(dict.fromkeys(targets))


def read_targets(
    args: argparse.Namespace,
    playbook_metadata: dict[str, dict[str, object]],
) -> tuple[list[str], list[dict[str, object]], list[dict[str, object]]]:
    services = []
    warnings = []
    raw = list(args.url or [])
    for input_path in args.input or []:
        raw.extend(input_path.read_text(encoding="utf-8").splitlines())
    for paths, parser_function in (
        (args.gnmap or [], parse_gnmap_detailed),
        (args.nmap or [], parse_nmap_detailed),
        (args.nmap_xml or [], parse_nmap_xml_detailed),
    ):
        for path in paths:
            parsed, issues = parser_function(path)
            services.extend(parsed)
            warnings.extend(issues)
    services = deduplicate_services(services)
    port_intelligence = build_port_intelligence(playbook_metadata)
    enrich_services_with_port_intelligence(services, port_intelligence)
    raw.extend(gnmap_targets(services, args, port_intelligence))
    targets = []
    for line in raw:
        target = line.strip()
        if not target or target.startswith("#"):
            continue
        if "://" not in target:
            target = "https://" + target
        parsed = urlparse(target)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError(f"invalid HTTP(S) target: {line!r}")
        targets.append(target.rstrip("/"))
    if not targets:
        raise ValueError("no targets supplied")
    return list(dict.fromkeys(targets)), services, warnings


def load_scope_policy(path: Path | None, targets: list[str]) -> dict[str, object]:
    if path:
        policy = json.loads(path.expanduser().read_text(encoding="utf-8"))
    else:
        policy = {}
    policy.setdefault("domains", {})
    policy.setdefault("cidrs", {})
    policy["domains"].setdefault("include", sorted({urlparse(target).hostname for target in targets}))
    policy["domains"].setdefault("exclude", [])
    policy["cidrs"].setdefault("include", [])
    policy["cidrs"].setdefault("exclude", [])
    return policy


def scope_decision(host: str, policy: dict[str, object]) -> tuple[str, str]:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address:
        excluded = any(address in ipaddress.ip_network(cidr, strict=False) for cidr in policy["cidrs"]["exclude"])
        included = any(address in ipaddress.ip_network(cidr, strict=False) for cidr in policy["cidrs"]["include"])
    else:
        excluded = any(fnmatch.fnmatch(host.lower(), pattern.lower()) for pattern in policy["domains"]["exclude"])
        included = any(fnmatch.fnmatch(host.lower(), pattern.lower()) for pattern in policy["domains"]["include"])
    if excluded:
        return "blocked", "matched exclusion"
    if included:
        return "authorized", "matched inclusion"
    return "candidate", "outside explicit scope"


def find_seclists(explicit: Path | None) -> Path:
    candidates = (str(explicit),) if explicit else SECLISTS_CANDIDATES
    for candidate in candidates:
        path = Path(candidate).expanduser()
        if path.is_dir():
            return path.resolve()
    raise FileNotFoundError(
        "SecLists Web-Content directory not found; pass --seclists /path/to/SecLists/Discovery/Web-Content"
    )


def resolve_wordlists(args: argparse.Namespace) -> list[Path]:
    if args.wordlist:
        paths = [p.expanduser().resolve() for p in args.wordlist]
    else:
        root = find_seclists(args.seclists)
        paths = [root / relative for relative in PROFILES[args.profile]]
    missing = [str(p) for p in paths if not p.is_file()]
    if missing:
        raise FileNotFoundError("wordlist(s) not found: " + ", ".join(missing))
    return paths


def playbook_files(source: Path) -> list[Path]:
    source = source.expanduser()
    if source.is_file():
        return [source]
    if source.is_dir():
        return sorted(path for path in source.rglob("*.json") if path.name not in {"schema.json", "index.json"})
    raise FileNotFoundError(f"playbook source not found: {source}")


def validate_playbook(name: str, playbook: dict[str, object], source: Path) -> None:
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", name):
        raise ValueError(f"{source}: invalid technology id {name!r}")
    for field in ("signatures", "paths", "follow_up"):
        value = playbook.get(field, [])
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise ValueError(f"{source}: {name}.{field} must be an array of strings")
    for field in ("protocols", "typical_ports", "automatic_actions", "stop_conditions"):
        if field in playbook and not isinstance(playbook[field], list):
            raise ValueError(f"{source}: {name}.{field} must be an array")
    if "explicit_only" in playbook and not isinstance(playbook["explicit_only"], bool):
        raise ValueError(f"{source}: {name}.explicit_only must be boolean")
    for field in ("port_hints", "port_ranges"):
        if field in playbook and not isinstance(playbook[field], list):
            raise ValueError(f"{source}: {name}.{field} must be an array")
    for hint in playbook.get("port_hints", []):
        if not isinstance(hint, dict) or not isinstance(hint.get("port"), int) or not 1 <= hint["port"] <= 65535:
            raise ValueError(f"{source}: {name}.port_hints contains an invalid hint")
    for hint in playbook.get("port_ranges", []):
        if not isinstance(hint, dict) or not all(isinstance(hint.get(field), int) for field in ("start", "end")):
            raise ValueError(f"{source}: {name}.port_ranges contains an invalid hint")
    if "schema_version" in playbook:
        required = {
            "schema_version", "id", "name", "category", "risk", "explicit_only",
            "protocols", "typical_ports", "signatures", "paths", "automatic_actions",
            "follow_up", "stop_conditions",
        }
        missing = sorted(required - set(playbook))
        if missing:
            raise ValueError(f"{source}: {name} missing required field(s): {', '.join(missing)}")
        if playbook["schema_version"] != 1:
            raise ValueError(f"{source}: {name}.schema_version must be 1")
        if playbook["id"] != name:
            raise ValueError(f"{source}: playbook id {playbook['id']!r} does not match {name!r}")
        if playbook["risk"] not in {"informational", "low", "medium", "high", "critical"}:
            raise ValueError(f"{source}: {name}.risk is invalid")
        ports = playbook["typical_ports"]
        if not all(isinstance(port, int) and 1 <= port <= 65535 for port in ports):
            raise ValueError(f"{source}: {name}.typical_ports contains an invalid port")


def parse_playbook_file(source: Path) -> dict[str, dict[str, object]]:
    data = json.loads(source.read_text(encoding="utf-8"))
    if "technologies" in data:
        technologies = data["technologies"]
    elif "id" in data:
        technologies = {data["id"]: data}
    else:
        raise ValueError(f"{source}: expected an individual playbook or technologies mapping")
    if not isinstance(technologies, dict):
        raise ValueError(f"{source}: technologies must be an object")
    for name, playbook in technologies.items():
        if not isinstance(playbook, dict):
            raise ValueError(f"{source}: playbook {name!r} must be an object")
        validate_playbook(name, playbook, source)
    return technologies


def load_catalog(
    args: argparse.Namespace,
) -> tuple[dict[str, tuple[str, ...]], dict[str, tuple[str, ...]], dict[str, tuple[str, ...]], set[str], dict[str, dict[str, object]]]:
    bundled_available = BUNDLED_PLAYBOOKS.is_dir()
    paths = {} if bundled_available else dict(TECH_PATHS)
    signatures = {} if bundled_available else dict(SIGNATURES)
    follow_up = {} if bundled_available else dict(FOLLOW_UP)
    explicit_only = set() if bundled_available else set(EXPLICIT_ONLY_TECHNOLOGIES)
    metadata = {}
    sources = ([BUNDLED_PLAYBOOKS] if bundled_available else []) + list(args.playbooks)
    for source in sources:
        for playbook_file in playbook_files(source):
            for name, playbook in parse_playbook_file(playbook_file).items():
                metadata[name] = {**playbook, "source": str(playbook_file)}
                paths[name] = tuple(playbook.get("paths", ()))
                signatures[name] = tuple(signature.lower() for signature in playbook.get("signatures", ()))
                follow_up[name] = tuple(playbook.get("follow_up", ()))
                if playbook.get("explicit_only"):
                    explicit_only.add(name)
                else:
                    explicit_only.discard(name)
    unknown = sorted(set(args.technology) - set(paths))
    if unknown:
        raise ValueError("unknown technology hint(s): " + ", ".join(unknown))
    return paths, signatures, follow_up, explicit_only, metadata


def curl_probe(target: str, path: str, args: argparse.Namespace) -> dict[str, object]:
    url = target + (("/" + path) if path else "")
    cmd = ["curl", "-sS", "-i", "--max-time", str(args.timeout), "--max-filesize", "65536"]
    if args.insecure:
        cmd.append("-k")
    if args.follow_redirects:
        cmd.append("-L")
    for header in args.header:
        cmd += ["-H", header]
    if args.cookie:
        cmd += ["-b", args.cookie]
    if args.proxy:
        cmd += ["-x", args.proxy]
    cmd.append(url)
    completed = subprocess.run(cmd, capture_output=True, text=True, check=False)
    response = completed.stdout[-65536:]
    statuses = re.findall(r"^HTTP/\S+\s+(\d{3})", response, re.MULTILINE)
    return {
        "url": url,
        "status": int(statuses[-1]) if statuses else None,
        "response_sample": response,
        "returncode": completed.returncode,
        "error": completed.stderr.strip(),
    }


def openssl_fingerprint(host: str, port: int, timeout: int) -> dict[str, object] | None:
    if not shutil.which("openssl"):
        return None
    try:
        handshake = subprocess.run(
            ["openssl", "s_client", "-connect", f"{host}:{port}", "-servername", host, "-alpn", "h2,http/1.1", "-showcerts"],
            input="",
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        combined = handshake.stdout + handshake.stderr
        certificate = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", combined, re.DOTALL)
        result = {"handshake": combined[-16384:], "returncode": handshake.returncode}
        if certificate:
            details = subprocess.run(
                ["openssl", "x509", "-noout", "-subject", "-issuer", "-dates", "-fingerprint", "-sha256", "-ext", "subjectAltName"],
                input=certificate.group(0),
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            result["certificate"] = details.stdout.strip()
        return result
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"error": str(exc)}


def tls_fingerprint(target: str, timeout: int) -> dict[str, object] | None:
    parsed = urlparse(target)
    if parsed.scheme != "https":
        return None
    host = parsed.hostname
    port = parsed.port or 443
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols(["h2", "http/1.1"])
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                return {
                    "protocol": tls.version(),
                    "cipher": tls.cipher(),
                    "alpn": tls.selected_alpn_protocol(),
                    "certificate": cert,
                    "openssl": openssl_fingerprint(host, port, timeout),
                }
    except OSError as exc:
        return {"error": str(exc)}


def analyze_probe(probe: dict[str, object]) -> dict[str, object]:
    sample = str(probe.get("response_sample", ""))
    header_text, _, body = sample.partition("\r\n\r\n")
    if not body:
        header_text, _, body = sample.partition("\n\n")
    title = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    content_type = re.findall(r"^content-type:\s*(.+)$", header_text, re.IGNORECASE | re.MULTILINE)
    location = re.findall(r"^location:\s*(.+)$", header_text, re.IGNORECASE | re.MULTILINE)
    auth = re.findall(r"^www-authenticate:\s*(.+)$", header_text, re.IGNORECASE | re.MULTILINE)
    rate_limited = probe.get("status") == 429 or bool(re.search(r"^retry-after:", header_text, re.IGNORECASE | re.MULTILINE))
    return {
        "sha256": hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest(),
        "body_length": len(body),
        "title": re.sub(r"\s+", " ", title.group(1)).strip() if title else None,
        "content_type": content_type[-1].strip() if content_type else None,
        "location": location[-1].strip() if location else None,
        "authentication": auth[-1].strip() if auth else None,
        "rate_limited": rate_limited,
    }


def extract_sans(tls: dict[str, object] | None) -> list[str]:
    if not tls:
        return []
    text = str((tls.get("openssl") or {}).get("certificate", ""))
    names = re.findall(r"DNS:([^,\s]+)", text)
    names += re.findall(r"IP Address:([^,\s]+)", text)
    return list(dict.fromkeys(name.rstrip(".") for name in names))


def discovered_hosts(target: str, probes: list[dict[str, object]], tls: dict[str, object] | None) -> list[dict[str, str]]:
    candidates = [{"host": host, "source": "certificate-san"} for host in extract_sans(tls) if "*" not in host]
    for probe in probes:
        sample = str(probe.get("response_sample", ""))
        for url in re.findall(r"https?://[A-Za-z0-9._:-]+", sample):
            host = urlparse(url).hostname
            if host:
                candidates.append({"host": host, "source": "response-url"})
    original = urlparse(target).hostname
    unique = {}
    for candidate in candidates:
        if candidate["host"] != original:
            unique[(candidate["host"], candidate["source"])] = candidate
    return list(unique.values())


def make_actions(
    fingerprint: dict[str, object],
    playbook_metadata: dict[str, dict[str, object]],
) -> list[dict[str, object]]:
    actions = []
    if not fingerprint.get("reachable"):
        actions.append({
            "technology": None,
            "type": "stop",
            "risk": "medium",
            "action": "Target was unreachable; verify DNS, routing, port, protocol, and assessment scope manually.",
        })
    for technology, evidence in fingerprint["technologies"].items():
        playbook = playbook_metadata.get(technology, {})
        risk = playbook.get("risk", "medium")
        for action in playbook.get("automatic_actions", []):
            actions.append({"technology": technology, "type": "automatic", "risk": risk, "action": action})
        for action in playbook.get("follow_up", []):
            actions.append({"technology": technology, "type": "manual", "risk": risk, "action": action})
        for protocol in playbook.get("protocols", []):
            if protocol not in {"http", "https"}:
                actions.append({
                    "technology": technology,
                    "type": "manual-protocol",
                    "risk": risk,
                    "action": f"Validate {protocol} using an explicitly enabled read-only protocol-aware adapter.",
                })
    if any(probe["analysis"]["rate_limited"] for probe in fingerprint["probes"]):
        actions.append({"technology": None, "type": "stop", "risk": "high", "action": "Rate limiting detected; stop or reduce request rate."})
    if fingerprint.get("wildcard_response"):
        actions.append({"technology": None, "type": "stop", "risk": "high", "action": "Likely wildcard or soft-404 behavior detected; calibrate response filters before enumeration."})
    return actions


def fingerprint_target(
    target: str,
    args: argparse.Namespace,
    signatures: dict[str, tuple[str, ...]],
    follow_up: dict[str, tuple[str, ...]],
    scope_policy: dict[str, object],
    playbook_metadata: dict[str, dict[str, object]],
) -> dict[str, object]:
    paths = FINGERPRINT_PROBES if args.fingerprint_probes == "extensive" else ("", "robots.txt", "health", "metrics")
    probes = [curl_probe(target, path, args) for path in paths]
    for probe in probes:
        probe["analysis"] = analyze_probe(probe)
    evidence_text = "\n".join(str(probe.get("response_sample", "")) for probe in probes).lower()
    technologies = {}
    for technology, technology_signatures in signatures.items():
        matches = sorted({signature for signature in technology_signatures if signature in evidence_text})
        if matches:
            technologies[technology] = {"confidence": "high" if len(matches) > 1 else "medium", "evidence": matches}
    for technology in args.technology:
        technologies.setdefault(technology, {"confidence": "operator-hint", "evidence": ["--technology"]})
    root_headers = probes[0].get("response_sample", "") if probes else ""
    server = re.findall(r"^server:\s*(.+)$", str(root_headers), re.MULTILINE | re.IGNORECASE)
    powered_by = re.findall(r"^x-powered-by:\s*(.+)$", str(root_headers), re.MULTILINE | re.IGNORECASE)
    tls = tls_fingerprint(target, args.timeout)
    successful_hashes = [
        probe["analysis"]["sha256"]
        for probe in probes[1:]
        if probe.get("status") in {200, 204, 301, 302, 307, 401, 403}
    ]
    wildcard_response = any(successful_hashes.count(value) >= 3 for value in set(successful_hashes))
    fingerprint = {
        "target": target,
        "reachable": any(probe.get("status") is not None for probe in probes),
        "server": server[-1].strip() if server else None,
        "powered_by": powered_by[-1].strip() if powered_by else None,
        "tls": tls,
        "technologies": technologies,
        "wildcard_response": wildcard_response,
        "manual_follow_up": [
            {"technology": technology, "actions": list(follow_up.get(technology, ()))}
            for technology in technologies
            if follow_up.get(technology)
        ],
        "probes": probes,
    }
    fingerprint["candidates"] = [
        {**candidate, "state": scope_decision(candidate["host"], scope_policy)[0], "reason": scope_decision(candidate["host"], scope_policy)[1]}
        for candidate in discovered_hosts(target, probes, tls)
    ]
    fingerprint["actions"] = make_actions(fingerprint, playbook_metadata)
    return fingerprint


def write_smart_wordlist(
    run_dir: Path,
    fingerprint: dict[str, object],
    technology_paths: dict[str, tuple[str, ...]],
    explicit_only: set[str],
) -> Path:
    technologies = list(fingerprint["technologies"])
    ordered = []
    fallback = [name for name in technology_paths if name not in explicit_only]
    for technology in technologies + ["generic-api"] + fallback:
        ordered.extend(technology_paths.get(technology, ()))
    words = list(dict.fromkeys(ordered))
    path = run_dir / safe_name(str(fingerprint["target"])) / "smart-infrastructure-routes.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(words) + "\n", encoding="utf-8")
    return path


def choose_tool(requested: str) -> str:
    if requested != "auto":
        if not shutil.which(requested):
            raise FileNotFoundError(f"{requested} is not installed or not on PATH")
        return requested
    for candidate in ("ffuf", "gobuster"):
        if shutil.which(candidate):
            return candidate
    raise FileNotFoundError("neither ffuf nor gobuster is installed or on PATH")


def redact_command(command: list[str]) -> list[str]:
    redacted = list(command)
    for index, value in enumerate(redacted[:-1]):
        following = redacted[index + 1]
        if value in {"-b", "-c"}:
            redacted[index + 1] = "<redacted>"
        elif value in {"-H", "--header"} and re.match(r"(?i)^(authorization|cookie|x-api-key):", following):
            name = following.split(":", 1)[0]
            redacted[index + 1] = f"{name}: <redacted>"
    return redacted


def safe_name(target: str) -> str:
    parsed = urlparse(target)
    raw = parsed.scheme + "_" + parsed.netloc + parsed.path
    return re.sub(r"[^A-Za-z0-9._-]+", "_", raw).strip("_") or "target"


def ffuf_command(job: Job, args: argparse.Namespace) -> list[str]:
    url = job.target + "/FUZZ"
    cmd = [
        "ffuf", "-u", url, "-w", str(job.wordlist), "-t", str(args.threads),
        "-timeout", str(args.timeout), "-mc", args.status_codes,
        "-of", "json", "-o", str(job.output),
    ]
    if args.extensions:
        cmd += ["-e", "," + args.extensions.lstrip(",")]
    for header in args.header:
        cmd += ["-H", header]
    if args.cookie:
        cmd += ["-b", args.cookie]
    if args.proxy:
        cmd += ["-x", args.proxy]
    if args.rate:
        cmd += ["-rate", str(args.rate)]
    if args.recursion:
        cmd += ["-recursion", "-recursion-depth", str(args.recursion_depth)]
    if args.follow_redirects:
        cmd.append("-r")
    if args.insecure:
        cmd.append("-k")
    return cmd + shlex.split(args.extra_args)


def gobuster_command(job: Job, args: argparse.Namespace) -> list[str]:
    if args.recursion:
        raise ValueError("--recursion is supported by ffuf but not gobuster")
    if args.rate:
        console("WARN", "gobuster does not support --rate; continuing without a rate limit", args.color, sys.stderr)
    cmd = [
        "gobuster", "dir", "-u", job.target, "-w", str(job.wordlist),
        "-t", str(args.threads), "--timeout", f"{args.timeout}s",
        "-s", args.status_codes, "--no-error", "-o", str(job.output),
    ]
    if args.extensions:
        cmd += ["-x", args.extensions]
    for header in args.header:
        cmd += ["-H", header]
    if args.cookie:
        cmd += ["-c", args.cookie]
    if args.proxy:
        cmd += ["--proxy", args.proxy]
    if args.follow_redirects:
        cmd.append("-r")
    if args.insecure:
        cmd.append("-k")
    return cmd + shlex.split(args.extra_args)


def run_job(job: Job, tool: str, args: argparse.Namespace) -> dict[str, object]:
    command = ffuf_command(job, args) if tool == "ffuf" else gobuster_command(job, args)
    safe_command = redact_command(command)
    console("RUN", shlex.join(safe_command), args.color)
    if args.dry_run:
        return {"target": job.target, "wordlist": str(job.wordlist), "command": safe_command, "returncode": None}
    job.output.parent.mkdir(parents=True, exist_ok=True)
    completed = subprocess.run(command, check=False)
    return {
        "target": job.target,
        "wordlist": str(job.wordlist),
        "output": str(job.output),
        "command": safe_command,
        "returncode": completed.returncode,
    }


def candidate_targets(fingerprints: list[dict[str, object]], limit: int) -> list[str]:
    targets = []
    for fingerprint in fingerprints:
        parsed = urlparse(str(fingerprint["target"]))
        port = f":{parsed.port}" if parsed.port else ""
        for candidate in fingerprint.get("candidates", []):
            if candidate["state"] == "authorized":
                host = candidate["host"]
                try:
                    if ipaddress.ip_address(host).version == 6:
                        host = f"[{host}]"
                except ValueError:
                    pass
                targets.append(f"{parsed.scheme}://{host}{port}")
    existing = {str(fingerprint["target"]) for fingerprint in fingerprints}
    return [target for target in dict.fromkeys(targets) if target not in existing][:limit]


def mark_aliases(fingerprints: list[dict[str, object]]) -> None:
    groups = {}
    for fingerprint in fingerprints:
        probes = fingerprint.get("probes", [])
        root_hash = probes[0]["analysis"]["sha256"] if probes else None
        if root_hash:
            groups.setdefault(root_hash, []).append(str(fingerprint["target"]))
    for fingerprint in fingerprints:
        probes = fingerprint.get("probes", [])
        root_hash = probes[0]["analysis"]["sha256"] if probes else None
        fingerprint["response_aliases"] = [
            target for target in groups.get(root_hash, []) if target != fingerprint["target"]
        ]


def safe_for_enumeration(fingerprint: dict[str, object]) -> bool:
    if not fingerprint.get("reachable") or fingerprint.get("wildcard_response"):
        return False
    return not any(probe["analysis"]["rate_limited"] for probe in fingerprint.get("probes", []))


def derive_findings(
    fingerprints: list[dict[str, object]],
    results: list[dict[str, object]],
    services: list[dict[str, object]] | None = None,
) -> list[dict[str, object]]:
    findings = []
    for fingerprint in fingerprints:
        target = str(fingerprint["target"])
        if not fingerprint.get("reachable"):
            findings.append({"severity": "info", "title": "Target unreachable", "target": target, "technology": None, "evidence": "No fingerprint probe returned an HTTP status.", "recommendation": "Verify routing, protocol, port, and scope."})
        if fingerprint.get("wildcard_response"):
            findings.append({"severity": "medium", "title": "Wildcard or soft-404 behavior detected", "target": target, "technology": None, "evidence": "Multiple unrelated probe paths returned identical successful responses.", "recommendation": "Calibrate scanner filters before interpreting enumeration results."})
        if any(probe["analysis"]["rate_limited"] for probe in fingerprint.get("probes", [])):
            findings.append({"severity": "medium", "title": "Rate limiting detected", "target": target, "technology": None, "evidence": "HTTP 429 or Retry-After was observed.", "recommendation": "Reduce request rate and confirm the approved testing window."})
        for technology, evidence in fingerprint.get("technologies", {}).items():
            severity = "high" if technology in {"kubernetes", "vault", "etcd", "container-runtime", "cloud-metadata-proxy"} else "info"
            findings.append({
                "severity": severity,
                "title": f"{technology} technology identified",
                "target": target,
                "technology": technology,
                "evidence": ", ".join(evidence.get("evidence", [])) or evidence.get("confidence", "detected"),
                "recommendation": "Review the technology-specific next actions and authentication boundary.",
            })
        for probe in fingerprint.get("probes", []):
            if probe.get("status") in {200, 204} and probe["url"] != target:
                findings.append({
                    "severity": "low",
                    "title": "Discovery endpoint reachable",
                    "target": probe["url"],
                    "technology": None,
                    "evidence": f"HTTP {probe['status']} content-type={probe['analysis'].get('content_type') or 'unknown'}",
                    "recommendation": "Confirm whether this route is intended to be reachable from the assessment network.",
                })
        for candidate in fingerprint.get("candidates", []):
            if candidate["state"] == "candidate":
                findings.append({"severity": "info", "title": "Out-of-scope candidate discovered", "target": candidate["host"], "technology": None, "evidence": f"{candidate['source']} from {target}", "recommendation": "Confirm authorization before scanning."})
    for result in results:
        if result.get("returncode") not in (None, 0):
            findings.append({"severity": "medium", "title": "Scanner job failed", "target": result.get("target"), "technology": None, "evidence": f"Return code {result.get('returncode')} using {result.get('wordlist')}", "recommendation": "Review scanner output and rerun only after correcting the cause."})
        output = Path(str(result.get("output", "")))
        if result.get("returncode") == 0 and output.is_file():
            findings.extend(scanner_output_findings(output, str(result.get("target"))))
    sensitive_services = {
        "etcd", "kubernetes", "redis", "mongodb", "postgresql", "mysql", "elasticsearch",
        "vault", "consul", "docker", "docker-registry", "rabbitmq", "kafka", "zookeeper", "nats",
    }
    for service in services or []:
        name = str(service.get("service") or "unknown").lower()
        for hint in service.get("port_hints", []):
            confidence = hint.get("confidence", "low")
            risk = (
                "high" if confidence == "high" and hint.get("technology") in {"kubernetes", "etcd", "vault", "container-runtime"}
                else "medium" if confidence in {"high", "medium"}
                else "info"
            )
            findings.append({
                "severity": risk,
                "title": "Technology-specific port identified",
                "target": f"{service.get('address')}:{service.get('port')}/{service.get('protocol')}",
                "technology": hint.get("technology"),
                "evidence": f"{hint.get('role')} ({hint.get('protocol')}); confidence={confidence}",
                "recommendation": "Validate the inferred role using the technology playbook and an appropriate read-only protocol check.",
            })
        if any(value in name for value in sensitive_services):
            target = f"{service.get('address')}:{service.get('port')}/{service.get('protocol')}"
            findings.append({
                "severity": "high",
                "title": "High-value infrastructure service exposed",
                "target": target,
                "technology": name,
                "evidence": f"GNMAP identified {name} {service.get('version') or ''}".strip(),
                "recommendation": "Confirm network exposure, authentication, encryption, and authorized protocol-specific review.",
            })
    for index, finding in enumerate(findings, 1):
        finding["id"] = f"WD-{index:04d}"
    return findings


def route_severity(url: str, status: int | None) -> str:
    sensitive = ("config", "admin", "debug", "metrics", "actuator", "cluster", "targets", "rules", "env", "metadata", "v2/_catalog")
    if status in {200, 204} and any(value in url.lower() for value in sensitive):
        return "medium"
    if status in {200, 204}:
        return "low"
    return "info"


def scanner_output_findings(output: Path, target: str) -> list[dict[str, object]]:
    findings = []
    try:
        if output.suffix == ".json":
            data = json.loads(output.read_text(encoding="utf-8"))
            for item in data.get("results", []):
                url = item.get("url") or f"{target}/{item.get('input', {}).get('FUZZ', '')}"
                status = item.get("status")
                findings.append({
                    "severity": route_severity(str(url), status),
                    "title": "Content discovery result",
                    "target": str(url),
                    "technology": None,
                    "evidence": f"HTTP {status}; length={item.get('length')}; words={item.get('words')}",
                    "recommendation": "Review the discovered route and confirm intended exposure.",
                })
        else:
            for line in output.read_text(encoding="utf-8", errors="replace").splitlines():
                status_match = re.search(r"\(Status:\s*(\d{3})\)", line)
                path_match = re.match(r"^(\S+)", line.strip())
                if status_match and path_match:
                    status = int(status_match.group(1))
                    url = target.rstrip("/") + "/" + path_match.group(1).lstrip("/")
                    findings.append({
                        "severity": route_severity(url, status),
                        "title": "Content discovery result",
                        "target": url,
                        "technology": None,
                        "evidence": line.strip(),
                        "recommendation": "Review the discovered route and confirm intended exposure.",
                    })
    except (OSError, ValueError, TypeError):
        return []
    return findings


def persist_state(
    run_dir: Path,
    fingerprints: list[dict[str, object]],
    results: list[dict[str, object]],
    services: list[dict[str, object]],
    findings: list[dict[str, object]],
    import_warnings: list[dict[str, object]],
) -> Path:
    database = run_dir / "discovery.sqlite3"
    connection = sqlite3.connect(database)
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS targets (
            target TEXT PRIMARY KEY, reachable INTEGER, server TEXT, powered_by TEXT,
            wildcard_response INTEGER, aliases_json TEXT, tls_json TEXT
        );
        CREATE TABLE IF NOT EXISTS technologies (
            target TEXT, technology TEXT, confidence TEXT, evidence_json TEXT,
            PRIMARY KEY (target, technology)
        );
        CREATE TABLE IF NOT EXISTS candidates (
            source_target TEXT, host TEXT, source TEXT, state TEXT, reason TEXT,
            PRIMARY KEY (source_target, host, source)
        );
        CREATE TABLE IF NOT EXISTS actions (
            target TEXT, technology TEXT, type TEXT, risk TEXT, action TEXT
        );
        CREATE TABLE IF NOT EXISTS probes (
            target TEXT, url TEXT, status INTEGER, returncode INTEGER, analysis_json TEXT,
            response_sample TEXT, error TEXT, PRIMARY KEY (target, url)
        );
        CREATE TABLE IF NOT EXISTS jobs (
            target TEXT, wordlist TEXT, output TEXT, returncode INTEGER, command_json TEXT
        );
        CREATE TABLE IF NOT EXISTS services (
            address TEXT, hostname TEXT, port INTEGER, protocol TEXT, service TEXT,
            version TEXT, source TEXT, port_hints_json TEXT
        );
        CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY, severity TEXT, title TEXT, target TEXT, technology TEXT,
            evidence TEXT, recommendation TEXT
        );
        CREATE TABLE IF NOT EXISTS import_warnings (
            source TEXT, line INTEGER, reason TEXT, raw TEXT
        );
        """
    )
    for fingerprint in fingerprints:
        target = str(fingerprint["target"])
        connection.execute(
            "INSERT OR REPLACE INTO targets VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                target, int(bool(fingerprint["reachable"])), fingerprint.get("server"),
                fingerprint.get("powered_by"), int(bool(fingerprint.get("wildcard_response"))),
                json.dumps(fingerprint.get("response_aliases", [])), json.dumps(fingerprint.get("tls")),
            ),
        )
        for technology, evidence in fingerprint["technologies"].items():
            connection.execute(
                "INSERT OR REPLACE INTO technologies VALUES (?, ?, ?, ?)",
                (target, technology, evidence.get("confidence"), json.dumps(evidence.get("evidence", []))),
            )
        for candidate in fingerprint.get("candidates", []):
            connection.execute(
                "INSERT OR REPLACE INTO candidates VALUES (?, ?, ?, ?, ?)",
                (target, candidate["host"], candidate["source"], candidate["state"], candidate["reason"]),
            )
        for action in fingerprint.get("actions", []):
            connection.execute(
                "INSERT INTO actions VALUES (?, ?, ?, ?, ?)",
                (target, action.get("technology"), action["type"], action["risk"], action["action"]),
            )
        for probe in fingerprint.get("probes", []):
            connection.execute(
                "INSERT OR REPLACE INTO probes VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    target, probe["url"], probe.get("status"), probe.get("returncode"),
                    json.dumps(probe.get("analysis", {})), probe.get("response_sample"), probe.get("error"),
                ),
            )
    for result in results:
        connection.execute(
            "INSERT INTO jobs VALUES (?, ?, ?, ?, ?)",
            (result.get("target"), result.get("wordlist"), result.get("output"), result.get("returncode"), json.dumps(result.get("command", []))),
        )
    for service in services:
        connection.execute(
            "INSERT INTO services VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                service.get("address"), service.get("hostname"), service.get("port"),
                service.get("protocol"), service.get("service"), service.get("version"),
                service.get("source"), json.dumps(service.get("port_hints", [])),
            ),
        )
    for finding in findings:
        connection.execute(
            "INSERT OR REPLACE INTO findings VALUES (?, ?, ?, ?, ?, ?, ?)",
            (finding["id"], finding["severity"], finding["title"], finding["target"], finding.get("technology"), finding["evidence"], finding["recommendation"]),
        )
    for warning in import_warnings:
        connection.execute(
            "INSERT INTO import_warnings VALUES (?, ?, ?, ?)",
            (warning.get("source"), warning.get("line"), warning.get("reason"), warning.get("raw")),
        )
    connection.commit()
    connection.close()
    return database


def write_port_catalog(run_dir: Path, playbook_metadata: dict[str, dict[str, object]]) -> None:
    intelligence = build_port_intelligence(playbook_metadata)
    entries = []
    for port, hints in sorted(intelligence["exact"].items()):
        entries.extend({"port": port, **hint} for hint in hints)
    (run_dir / "port-intelligence.json").write_text(
        json.dumps({"exact": entries, "ranges": intelligence["ranges"]}, indent=2) + "\n",
        encoding="utf-8",
    )


def write_reports(
    run_dir: Path,
    fingerprints: list[dict[str, object]],
    results: list[dict[str, object]],
    services: list[dict[str, object]],
    findings: list[dict[str, object]],
    import_warnings: list[dict[str, object]],
) -> None:
    generated = datetime.now(timezone.utc).isoformat()
    counts = {severity: sum(item["severity"] == severity for item in findings) for severity in ("critical", "high", "medium", "low", "info")}
    lines = [
        "# Adaptive discovery report", "", f"Generated: {generated}", "",
        "## Executive Summary", "",
        f"- Assets fingerprinted: `{len(fingerprints)}`",
        f"- Services imported: `{len(services)}`",
        f"- Scanner jobs: `{len(results)}`",
        f"- Findings: `{len(findings)}`",
        f"- Import warnings: `{len(import_warnings)}`",
        f"- Severity: critical `{counts['critical']}`, high `{counts['high']}`, medium `{counts['medium']}`, low `{counts['low']}`, info `{counts['info']}`",
        "",
        "## Findings", "",
    ]
    lines += [
        f"- **{item['id']} / {item['severity'].upper()} / {item['title']}** on `{item['target']}`: {item['evidence']} Recommendation: {item['recommendation']}"
        for item in findings
    ] or ["- None"]
    lines += ["", "## Assets", ""]
    for fingerprint in fingerprints:
        lines += [
            f"## {fingerprint['target']}",
            "",
            f"- Reachable: `{fingerprint['reachable']}`",
            f"- Server: `{fingerprint.get('server') or 'unknown'}`",
            f"- Technologies: `{', '.join(fingerprint['technologies']) or 'unknown'}`",
            f"- Wildcard/soft-404 behavior: `{fingerprint.get('wildcard_response', False)}`",
            f"- Response aliases: `{', '.join(fingerprint.get('response_aliases', [])) or 'none'}`",
            "",
            "### Candidates",
            "",
        ]
        candidates = fingerprint.get("candidates", [])
        lines += [f"- `{item['host']}`: **{item['state']}** via {item['source']} ({item['reason']})" for item in candidates] or ["- None"]
        lines += ["", "### Next Actions", ""]
        lines += [f"- **{item['risk']} / {item['type']}**: {item['action']}" for item in fingerprint.get("actions", [])] or ["- None"]
        lines.append("")
    lines += ["## Scanner Jobs", ""]
    lines += [f"- `{result.get('target')}` using `{result.get('wordlist')}`: return code `{result.get('returncode')}`" for result in results] or ["- None"]
    markdown = "\n".join(lines) + "\n"
    (run_dir / "report.md").write_text(markdown, encoding="utf-8")
    (run_dir / "findings.json").write_text(json.dumps(findings, indent=2) + "\n", encoding="utf-8")
    (run_dir / "services.json").write_text(json.dumps(services, indent=2) + "\n", encoding="utf-8")
    (run_dir / "import-warnings.json").write_text(json.dumps(import_warnings, indent=2) + "\n", encoding="utf-8")
    csv_lines = ["id,severity,title,target,technology,evidence,recommendation"]
    for item in findings:
        csv_lines.append(",".join(json.dumps("" if item.get(field) is None else str(item.get(field, ""))) for field in ("id", "severity", "title", "target", "technology", "evidence", "recommendation")))
    (run_dir / "findings.csv").write_text("\n".join(csv_lines) + "\n", encoding="utf-8")

    cards = "".join(f'<div class="metric {severity}"><b>{counts[severity]}</b><span>{severity.title()}</span></div>' for severity in counts)
    finding_rows = "".join(
        f'<tr data-severity="{html.escape(item["severity"])}"><td><span class="badge {html.escape(item["severity"])}">{html.escape(item["severity"].upper())}</span></td>'
        f'<td>{html.escape(item["id"])}</td><td>{html.escape(item["title"])}</td><td>{html.escape(str(item["target"]))}</td>'
        f'<td>{html.escape(item["evidence"])}</td><td>{html.escape(item["recommendation"])}</td></tr>'
        for item in findings
    ) or '<tr><td colspan="6">No findings</td></tr>'
    def format_port_hints(item: dict[str, object]) -> str:
        hints = item.get("port_hints", [])
        return "; ".join(
            "{} [{}]".format(hint.get("role"), hint.get("confidence", "low"))
            for hint in hints
        )

    service_rows = "".join(
        f'<tr><td>{html.escape(str(item.get("address") or ""))}</td><td>{html.escape(str(item.get("hostname") or ""))}</td>'
        f'<td>{item.get("port")}/{html.escape(str(item.get("protocol") or ""))}</td><td>{html.escape(str(item.get("service") or ""))}</td>'
        f'<td>{html.escape(str(item.get("version") or ""))}</td><td>{html.escape(format_port_hints(item))}</td></tr>' for item in services
    ) or '<tr><td colspan="6">No imported services</td></tr>'
    warning_rows = "".join(
        f'<tr><td>{html.escape(str(item.get("source") or ""))}</td><td>{html.escape(str(item.get("line") or ""))}</td>'
        f'<td>{html.escape(str(item.get("reason") or ""))}</td><td>{html.escape(str(item.get("raw") or ""))}</td></tr>'
        for item in import_warnings
    ) or '<tr><td colspan="4">No import warnings</td></tr>'
    asset_rows = "".join(
        f'<tr><td>{html.escape(str(item["target"]))}</td><td>{item["reachable"]}</td><td>{html.escape(str(item.get("server") or "unknown"))}</td>'
        f'<td>{html.escape(", ".join(item["technologies"]) or "unknown")}</td><td>{item.get("wildcard_response", False)}</td></tr>'
        for item in fingerprints
    ) or '<tr><td colspan="5">No fingerprinted assets</td></tr>'
    document = f"""<!doctype html><html><head><meta charset="utf-8"><title>Adaptive Discovery Report</title>
<style>
:root{{--bg:#f3f5f8;--panel:#fff;--text:#172033;--muted:#667085;--line:#d8dee9;--critical:#7f1d1d;--high:#b42318;--medium:#d97706;--low:#2563eb;--info:#667085}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:14px system-ui}}header{{background:#111827;color:white;padding:28px 34px}}main{{max-width:1500px;margin:auto;padding:24px}}h1,h2{{margin:0 0 14px}}section{{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:20px;margin-bottom:20px}}.metrics{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px}}.metric{{padding:18px;border-radius:8px;color:white;display:flex;justify-content:space-between;align-items:end}}.metric b{{font-size:30px}}.critical{{background:var(--critical)}}.high{{background:var(--high)}}.medium{{background:var(--medium)}}.low{{background:var(--low)}}.info{{background:var(--info)}}table{{width:100%;border-collapse:collapse}}th,td{{text-align:left;vertical-align:top;padding:10px;border-bottom:1px solid var(--line)}}th{{background:#f8fafc;position:sticky;top:0}}.table-wrap{{overflow:auto;max-height:620px}}.badge{{color:white;border-radius:999px;padding:4px 8px;font-size:11px}}input,select{{padding:9px;border:1px solid var(--line);border-radius:6px;margin:0 8px 12px 0}}small{{color:var(--muted)}}@media(max-width:800px){{.metrics{{grid-template-columns:1fr 1fr}}}}
</style></head><body><header><h1>Adaptive Discovery Report</h1><small>Generated {html.escape(generated)}</small></header><main>
<section><h2>Executive Summary</h2><p>{len(fingerprints)} fingerprinted assets, {len(services)} imported services, {len(import_warnings)} import warnings, {len(results)} scanner jobs, {len(findings)} findings.</p><div class="metrics">{cards}</div></section>
<section><h2>Findings</h2><input id="search" placeholder="Search findings"><select id="severity"><option value="">All severities</option>{"".join(f'<option>{s}</option>' for s in counts)}</select><div class="table-wrap"><table id="findings"><thead><tr><th>Severity</th><th>ID</th><th>Finding</th><th>Target</th><th>Evidence</th><th>Recommendation</th></tr></thead><tbody>{finding_rows}</tbody></table></div></section>
<section><h2>Assets</h2><div class="table-wrap"><table><thead><tr><th>Target</th><th>Reachable</th><th>Server</th><th>Technologies</th><th>Wildcard</th></tr></thead><tbody>{asset_rows}</tbody></table></div></section>
<section><h2>Imported Services</h2><div class="table-wrap"><table><thead><tr><th>Address</th><th>Hostname</th><th>Port</th><th>Service</th><th>Version</th><th>Port Intelligence</th></tr></thead><tbody>{service_rows}</tbody></table></div></section>
<section><h2>Import Quality</h2><div class="table-wrap"><table><thead><tr><th>Source</th><th>Line</th><th>Reason</th><th>Raw Record</th></tr></thead><tbody>{warning_rows}</tbody></table></div></section>
<section><h2>Artifacts</h2><p>See <code>manifest.json</code>, <code>fingerprints.json</code>, <code>findings.json</code>, <code>findings.csv</code>, <code>services.json</code>, <code>import-warnings.json</code>, <code>port-intelligence.json</code>, and <code>discovery.sqlite3</code>.</p></section>
</main><script>
const q=document.querySelector('#search'),s=document.querySelector('#severity'),rows=[...document.querySelectorAll('#findings tbody tr')];
function filter(){{const text=q.value.toLowerCase(),sev=s.value.toLowerCase();rows.forEach(r=>r.style.display=(!text||r.innerText.toLowerCase().includes(text))&&(!sev||r.dataset.severity===sev)?'':'none')}}
q.oninput=filter;s.onchange=filter;
</script></body></html>"""
    (run_dir / "report.html").write_text(document, encoding="utf-8")


def main() -> int:
    argument_parser = parser()
    args = argument_parser.parse_args()
    if args.list_technologies or args.list_port_intelligence or args.validate_playbooks:
        try:
            paths, signatures, follow_up, explicit_only, metadata = load_catalog(args)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            console("ERROR", str(exc), args.color, sys.stderr)
            return 2
        if args.list_technologies:
            for name in sorted(paths):
                playbook = metadata.get(name, {})
                print(
                    f"{name}\tcategory={playbook.get('category', 'legacy')}"
                    f"\trisk={playbook.get('risk', 'unspecified')}"
                    f"\texplicit_only={name in explicit_only}"
                )
        if args.list_port_intelligence:
            intelligence = build_port_intelligence(metadata)
            for port, hints in sorted(intelligence["exact"].items()):
                for hint in hints:
                    print(
                        f"{port}/{hint.get('transport', 'tcp')}\ttechnology={hint['technology']}\trole={hint.get('role')}"
                        f"\tprotocol={hint.get('protocol')}\tweb={bool(hint.get('web'))}"
                    )
            for hint in sorted(intelligence["ranges"], key=lambda item: (item["start"], item["end"])):
                print(
                    f"{hint['start']}-{hint['end']}/{hint.get('transport', 'tcp')}\ttechnology={hint['technology']}"
                    f"\trole={hint.get('role')}\tprotocol={hint.get('protocol')}\tweb={bool(hint.get('web'))}"
                )
        if args.validate_playbooks:
            print(
                f"valid playbooks={len(paths)} signatures={len(signatures)}"
                f" follow_up={len(follow_up)} explicit_only={len(explicit_only)}"
            )
        return 0
    if not args.url and not args.input and not args.gnmap and not args.nmap and not args.nmap_xml:
        argument_parser.error("at least one target source is required unless listing or validating catalog data")
    if not args.dry_run and not args.acknowledge_authorization:
        console("ERROR", "pass --acknowledge-authorization before executing scans", args.color, sys.stderr)
        return 2
    try:
        technology_paths, signatures, follow_up, explicit_only, playbook_metadata = load_catalog(args)
        targets, discovered_services, import_warnings = read_targets(args, playbook_metadata)
        scope_policy = load_scope_policy(args.scope_policy, targets)
        wordlists = resolve_wordlists(args) if args.mode != "fingerprint" else []
        tool = (
            choose_tool(args.tool)
            if args.mode != "fingerprint" and not args.dry_run
            else ("ffuf" if args.tool == "auto" else args.tool)
        )
    except (OSError, ValueError) as exc:
        console("ERROR", str(exc), args.color, sys.stderr)
        return 2

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = args.output.expanduser().resolve() / timestamp
    fingerprints = []
    console(
        "PHASE",
        "Inventory loaded",
        args.color,
    )
    console(
        "INFO",
        f"targets={len(targets)} services={len(discovered_services)}"
        f" import-warnings={len(import_warnings)} mode={args.mode} profile={args.profile}",
        args.color,
    )
    if not args.dry_run:
        console("INFO", f"results will be written to {run_dir}", args.color)
    if not args.dry_run:
        run_dir.mkdir(parents=True, exist_ok=True)
        write_port_catalog(run_dir, playbook_metadata)
    if args.mode in {"smart", "fingerprint"}:
        if args.dry_run:
            console(
                "INFO",
                f"dry run: would fingerprint {len(targets)} target(s) with {args.fingerprint_probes} probes",
                args.color,
            )
        else:
            probe_count = len(FINGERPRINT_PROBES) if args.fingerprint_probes == "extensive" else 4
            console("PHASE", "Fingerprinting targets", args.color)
            console(
                "INFO",
                f"targets={len(targets)} probes-per-target={probe_count}"
                f" concurrency={args.host_concurrency} timeout={args.timeout}s",
                args.color,
            )
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.host_concurrency) as executor:
                future_targets = {
                    executor.submit(
                        fingerprint_target,
                        target,
                        args,
                        signatures,
                        follow_up,
                        scope_policy,
                        playbook_metadata,
                    ): target
                    for target in targets
                }
                for completed_count, future in enumerate(concurrent.futures.as_completed(future_targets), 1):
                    fingerprint = future.result()
                    fingerprints.append(fingerprint)
                    technologies = ",".join(fingerprint["technologies"]) or "unknown"
                    level = "OK" if fingerprint["reachable"] else "WARN"
                    console(
                        level,
                        f"fingerprint {completed_count}/{len(future_targets)}"
                        f" | {future_targets[future]} | reachable={fingerprint['reachable']}"
                        f" technologies={technologies}",
                        args.color,
                    )
            if args.expand_authorized_candidates:
                expansions = candidate_targets(fingerprints, args.max_candidate_expansion)
                if expansions:
                    console("PHASE", f"Expanding {len(expansions)} authorized candidate(s)", args.color)
                    with concurrent.futures.ThreadPoolExecutor(max_workers=args.host_concurrency) as executor:
                        future_targets = {
                            executor.submit(
                                fingerprint_target,
                                target,
                                args,
                                signatures,
                                follow_up,
                                scope_policy,
                                playbook_metadata,
                            ): target
                            for target in expansions
                        }
                        for completed_count, future in enumerate(concurrent.futures.as_completed(future_targets), 1):
                            fingerprint = future.result()
                            fingerprints.append(fingerprint)
                            level = "OK" if fingerprint["reachable"] else "WARN"
                            console(
                                level,
                                f"candidate {completed_count}/{len(future_targets)}"
                                f" | {future_targets[future]} | reachable={fingerprint['reachable']}",
                                args.color,
                            )
                    targets = list(dict.fromkeys(targets + expansions))
            mark_aliases(fingerprints)
            run_dir.mkdir(parents=True, exist_ok=True)
            (run_dir / "fingerprints.json").write_text(json.dumps(fingerprints, indent=2) + "\n", encoding="utf-8")
    elif not args.dry_run:
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "fingerprints.json").write_text("[]\n", encoding="utf-8")
    if args.mode == "fingerprint":
        failures = 0 if args.dry_run else sum(not fingerprint["reachable"] for fingerprint in fingerprints)
        if not args.dry_run:
            findings = derive_findings(fingerprints, [], discovered_services)
            manifest = {
                "created_at": datetime.now(timezone.utc).isoformat(),
                "mode": args.mode,
                "scope_policy": scope_policy,
                "discovered_services": discovered_services,
                "import_warnings": import_warnings,
                "fingerprints": fingerprints,
                "findings": findings,
                "playbooks": playbook_metadata,
                "results": [],
            }
            (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
            persist_state(run_dir, fingerprints, [], discovered_services, findings, import_warnings)
            write_reports(run_dir, fingerprints, [], discovered_services, findings, import_warnings)
        level = "OK" if not failures else "WARN"
        console(level, f"completed targets={len(targets)} failures={failures}", args.color)
        if not args.dry_run:
            console("OK", f"HTML report: {run_dir / 'report.html'}", args.color)
        return 1 if failures else 0

    extension = "json" if tool == "ffuf" else "txt"
    enumeration_targets = (
        [str(fingerprint["target"]) for fingerprint in fingerprints if safe_for_enumeration(fingerprint)]
        if args.mode == "smart" and not args.dry_run
        else targets
    )
    jobs = [
        Job(target, wordlist, run_dir / safe_name(target) / f"{wordlist.stem}.{extension}")
        for target in enumeration_targets
        for wordlist in wordlists
    ]
    if args.mode == "smart" and not args.dry_run:
        jobs += [
            Job(
                str(fingerprint["target"]),
                write_smart_wordlist(run_dir, fingerprint, technology_paths, explicit_only),
                run_dir / safe_name(str(fingerprint["target"])) / f"smart-infrastructure-results.{extension}",
            )
            for fingerprint in fingerprints
            if safe_for_enumeration(fingerprint)
        ]
    console("PHASE", "Content enumeration", args.color)
    console(
        "INFO",
        f"tool={tool} targets={len(enumeration_targets)} wordlists={len(wordlists)}"
        f" jobs={len(jobs)} concurrency={args.host_concurrency} threads={args.threads}"
        + (f" rate={args.rate}/s" if args.rate else ""),
        args.color,
    )

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.host_concurrency) as executor:
        futures = [executor.submit(run_job, job, tool, args) for job in jobs]
        for completed_count, future in enumerate(concurrent.futures.as_completed(futures), 1):
            try:
                result = future.result()
                results.append(result)
                level = "OK" if result.get("returncode") in (None, 0) else "WARN"
                console(
                    level,
                    f"job {completed_count}/{len(futures)}"
                    f" | {result.get('target', 'unknown')} | returncode={result.get('returncode')}",
                    args.color,
                )
            except ValueError as exc:
                console("ERROR", str(exc), args.color, sys.stderr)
                results.append({"returncode": 2, "error": str(exc)})

    if not args.dry_run:
        findings = derive_findings(fingerprints, results, discovered_services)
        manifest = {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "tool": tool,
            "mode": args.mode,
            "profile": args.profile,
            "scope_policy": scope_policy,
            "discovered_services": discovered_services,
            "import_warnings": import_warnings,
            "fingerprints": fingerprints,
            "findings": findings,
            "playbooks": playbook_metadata,
            "results": results,
        }
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        persist_state(run_dir, fingerprints, results, discovered_services, findings, import_warnings)
        write_reports(run_dir, fingerprints, results, discovered_services, findings, import_warnings)
    failures = sum(result["returncode"] not in (None, 0) for result in results)
    level = "OK" if not failures else "WARN"
    console(level, f"completed jobs={len(results)} failures={failures}", args.color)
    if not args.dry_run:
        console("OK", f"HTML report: {run_dir / 'report.html'}", args.color)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
