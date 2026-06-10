#!/usr/bin/env python3
"""Generate the bundled one-file-per-technology playbook library."""

from __future__ import annotations

import json
from pathlib import Path

import web_discovery


ROOT = Path(__file__).with_name("web_discovery_playbooks")

CATEGORIES = {
    "api": {"generic-api", "grpc", "spring"},
    "kubernetes": {"kubernetes", "container-runtime"},
    "observability": {
        "grafana", "prometheus", "loki", "opentelemetry", "jaeger", "tempo",
        "alertmanager", "mimir", "thanos", "pyroscope", "zipkin", "postgres-exporter",
    },
    "sidecar-mesh": {"sidecar", "envoy", "istio", "linkerd", "consul-connect", "oauth-proxy"},
    "gateway-proxy": {"traefik", "nginx", "haproxy", "kong", "apache-apisix"},
    "infrastructure": {"etcd", "consul", "vault", "cloud-metadata-proxy"},
    "registry-storage": {"docker-registry", "harbor", "minio"},
    "delivery-gitops": {"argocd", "flux", "jenkins", "gitlab"},
    "messaging": {"rabbitmq", "kafka-rest"},
    "data": {"redis", "mongodb", "elasticsearch"},
    "identity": {"keycloak", "dex"},
    "application-platform": {"feature-flags"},
}

PORTS = {
    "generic-api": [80, 443], "grpc": [443, 50051], "kubernetes": [6443],
    "grafana": [3000], "prometheus": [9090], "loki": [3100], "opentelemetry": [4317, 4318],
    "jaeger": [16686], "tempo": [3200], "alertmanager": [9093], "mimir": [8080],
    "thanos": [10902], "pyroscope": [4040], "zipkin": [9411], "etcd": [2379, 2380],
    "consul": [8500, 8501], "vault": [8200], "envoy": [9901], "istio": [15000, 15021],
    "linkerd": [4191], "consul-connect": [19000], "traefik": [8080], "nginx": [80, 443],
    "haproxy": [8404], "kong": [8001, 8444], "apache-apisix": [9180],
    "container-runtime": [10250], "docker-registry": [5000], "harbor": [443],
    "argocd": [443], "flux": [8080], "jenkins": [8080], "gitlab": [443],
    "rabbitmq": [15672], "kafka-rest": [8082], "redis": [9121], "postgres-exporter": [9187],
    "mongodb": [9216], "minio": [9000, 9001], "keycloak": [8080, 8443], "dex": [5556],
    "oauth-proxy": [4180], "feature-flags": [4242], "cloud-metadata-proxy": [80],
    "sidecar": [15000, 15020, 15021], "elasticsearch": [9200], "spring": [8080],
}

PROTOCOLS = {
    "grpc": ["grpc", "grpc-tls"], "opentelemetry": ["http", "https", "grpc", "grpc-tls"],
    "kubernetes": ["https"], "etcd": ["https", "grpc"], "redis": ["http", "redis"],
    "rabbitmq": ["http", "https", "amqp"], "kafka-rest": ["http", "https", "kafka"],
}

HIGH_RISK = {"kubernetes", "etcd", "vault", "cloud-metadata-proxy", "container-runtime", "jenkins"}
EXPLICIT_ONLY = {"cloud-metadata-proxy"}

CATEGORY_ACTIONS = {
    "api": ["Compare discovered routes with published API documentation and authentication requirements."],
    "kubernetes": ["Record control-plane or runtime evidence and require explicit approval before credential-aware discovery."],
    "observability": ["Identify exposed telemetry labels, service names, build information, and tenant boundaries."],
    "sidecar-mesh": ["Determine whether the endpoint belongs to a workload sidecar, ingress gateway, or mesh control plane."],
    "gateway-proxy": ["Compare gateway routes, upstream clues, and administrative exposure without modifying configuration."],
    "infrastructure": ["Treat administrative and coordination-service routes as sensitive and keep checks read-only."],
    "registry-storage": ["Review anonymous listing and read permissions without uploading, deleting, or mutating artifacts."],
    "delivery-gitops": ["Review anonymous visibility and authentication boundaries without triggering jobs or synchronization."],
    "messaging": ["Review management-plane exposure without publishing, consuming, or altering messages."],
    "data": ["Review anonymous metadata and health exposure without querying application data."],
    "identity": ["Review issuer metadata, realm exposure, redirect behavior, and authentication configuration."],
    "application-platform": ["Review administrative API exposure and environment-specific authentication controls."],
}

CATEGORY_FOLLOW_UP = {
    "api": ["Review documented methods, schemas, authentication, authorization, and versioning manually."],
    "kubernetes": ["Use approved identities for RBAC and resource-discovery review; do not infer permission from endpoint reachability."],
    "observability": ["Review whether telemetry reveals internal topology, credentials, tenant data, or sensitive labels."],
    "sidecar-mesh": ["Review proxy identity, mTLS, policy, admin-port exposure, and workload ownership."],
    "gateway-proxy": ["Review administrative interfaces, route exposure, upstream leakage, and authentication policy."],
    "infrastructure": ["Review ACLs, authentication, encryption, and administrative exposure with approved credentials."],
    "registry-storage": ["Review anonymous catalog, artifact read access, token service behavior, and retention boundaries."],
    "delivery-gitops": ["Review repository, deployment, credential, and administrative visibility using approved credentials."],
    "messaging": ["Review virtual-host, topic, queue, ACL, and management-plane exposure using approved credentials."],
    "data": ["Review anonymous metadata, access controls, transport security, and administrative endpoints."],
    "identity": ["Review issuer configuration, clients, redirect URIs, realms, and administrative exposure."],
    "application-platform": ["Review tenant separation, administrative APIs, and authentication boundaries."],
}


def category_for(name: str) -> str:
    for category, names in CATEGORIES.items():
        if name in names:
            return category
    return "other"


def main() -> None:
    ROOT.mkdir(exist_ok=True)
    index = []
    for name, paths in sorted(web_discovery.TECH_PATHS.items()):
        category = category_for(name)
        path = ROOT / category / f"{name}.json"
        existing = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
        playbook = {
            "schema_version": 1,
            "id": name,
            "name": name.replace("-", " ").title(),
            "category": category,
            "description": f"Evidence and authorized read-only HTTP discovery guidance for {name}.",
            "risk": "high" if name in HIGH_RISK else "medium",
            "explicit_only": name in EXPLICIT_ONLY,
            "protocols": PROTOCOLS.get(name, ["http", "https"]),
            "typical_ports": PORTS.get(name, []),
            "port_hints": existing.get("port_hints", []),
            "port_ranges": existing.get("port_ranges", []),
            "signatures": existing.get("signatures", list(web_discovery.SIGNATURES.get(name, ()))),
            "paths": existing.get("paths", list(paths)),
            "automatic_actions": [
                "Collect bounded HTTP response evidence.",
                "Record authentication boundaries and non-success statuses.",
                "Prioritize these routes before broad wordlist enumeration.",
                *CATEGORY_ACTIONS.get(category, [])
            ],
            "follow_up": existing.get("follow_up", list(web_discovery.FOLLOW_UP.get(name, ())) + CATEGORY_FOLLOW_UP.get(category, [
                "Review discovered routes, authentication boundaries, and exposure using approved credentials.",
            ])),
            "stop_conditions": [
                "Stop on explicit scope mismatch.",
                "Stop or reduce request rate when throttling or instability is detected.",
                "Do not perform mutations, authentication bypass, or destructive actions."
            ]
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(playbook, indent=2) + "\n", encoding="utf-8")
        index.append({"id": name, "category": playbook["category"], "path": str(path.relative_to(ROOT))})
    (ROOT / "index.json").write_text(json.dumps({"schema_version": 1, "playbooks": index}, indent=2) + "\n", encoding="utf-8")
    print(f"generated {len(index)} playbooks in {ROOT}")


if __name__ == "__main__":
    main()
