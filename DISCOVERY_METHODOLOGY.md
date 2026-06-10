# Adaptive discovery methodology

## Goal

Build an evidence-driven discovery planner for authorized environments. The planner
should identify likely technologies, safely expand candidate targets, run appropriate
low-impact discovery, and produce automated and manual next actions.

No scanner can know every technology. Coverage must come from versioned technology
playbooks containing signatures, routes, protocol adapters, scope rules, stop
conditions, and manual-review guidance.

## Target states

- `authorized`: explicitly supplied or matched an approved domain/CIDR rule.
- `candidate`: discovered from certificates, redirects, DNS, content, API documents,
  telemetry labels, or service metadata.
- `blocked`: potentially relevant but outside confirmed scope.
- `unreachable`: authorized target with no successful connection.
- `completed`: all permitted playbook stages finished.

Candidate targets must never be scanned until a scope rule promotes them to
`authorized`.

## Discovery stages

1. **Normalize scope**
   - Parse URLs, hostnames, ports, CIDRs, allowed wildcard domains, and credentials.
   - Assign rate, concurrency, time-window, and protocol restrictions.

2. **Passive expansion**
   - Extract certificate subject, SANs, issuer, validity, wildcard names, and chain.
   - Extract redirects, CSP domains, CORS origins, HTML/JavaScript URLs, OpenAPI server
     entries, GraphQL links, and telemetry-referenced service names.
   - Add discoveries as candidates with provenance and scope-match results.

3. **Reachability and virtual-host comparison**
   - Resolve authorized hostnames.
   - Connect using the candidate hostname as SNI and HTTP `Host`.
   - Compare status, headers, titles, body hashes, certificates, and redirect chains.
   - Deduplicate identical virtual hosts while preserving aliases.

4. **Fingerprinting**
   - Collect HTTP/TLS/ALPN evidence and bounded response samples.
   - Detect soft-404s, wildcard responses, reverse proxies, WAFs, authentication,
     rate limiting, and protocol upgrades.
   - Record confirmed, probable, weak, and conflicting technology evidence.

5. **Technology-directed discovery**
   - Run common API, health, readiness, version, documentation, and metrics routes.
   - Prioritize detected technology playbooks.
   - Use broad SecLists only after high-signal routes.
   - Stop or reduce rate when blocking, throttling, instability, or wildcard behavior
     makes results unreliable.

6. **Protocol-specific validation**
   - HTTP/REST: `curl`, `ffuf`, or `gobuster`.
   - gRPC/OTLP: `grpcurl` or a safe telemetry test client.
   - Kubernetes: `kubectl` and API discovery with approved credentials.
   - Databases, caches, queues, and service registries: protocol-aware read-only
     adapters, only when explicitly allowed.
   - mTLS services: approved client certificates and non-mutating checks.

7. **Decision and reporting**
   - Convert every finding into evidence, risk context, automated next actions,
     manual actions, prerequisites, and stop conditions.
   - Preserve command provenance while redacting credentials.

## Technology families

- APIs: REST, OpenAPI, Swagger, GraphQL, gRPC, WebSocket, SSE, SOAP.
- Kubernetes: API server, kubelet, controllers, operators, admission webhooks,
  dashboards, registries, and GitOps.
- Sidecars and meshes: Envoy, Istio, Linkerd, Consul Connect, service proxies,
  authentication proxies, secret agents, and telemetry collectors.
- Observability: OpenTelemetry, Prometheus, Grafana, Loki, Tempo, Jaeger, Zipkin,
  Alertmanager, Mimir, Thanos, Pyroscope, exporters, and agents.
- Gateways and proxies: Nginx, HAProxy, Traefik, Kong, APISIX, ingress controllers,
  API gateways, load balancers, CDN, WAF, and reverse proxies.
- Infrastructure: Vault, Consul, etcd, container runtimes, registries, object storage,
  cloud metadata proxies, and serverless platforms.
- Data systems: SQL databases, Elasticsearch/OpenSearch, MongoDB, Redis, caches,
  search engines, and vector databases.
- Messaging and workflows: Kafka, RabbitMQ, NATS, Pulsar, workflow engines, schedulers,
  and event buses.
- Delivery and administration: Jenkins, GitLab, Argo CD, Flux, dashboards, admin
  consoles, feature flags, and identity providers.

## Certificate hostname expansion

1. Parse SAN DNS names and IP addresses from every reachable TLS service.
2. Record each SAN as a candidate with certificate fingerprint and source target.
3. Match candidates against explicit wildcard-domain and CIDR authorization rules.
4. Resolve authorized SANs and compare them against the original IP.
5. Test each permitted hostname using correct SNI and `Host`.
6. Deduplicate identical responses and prioritize distinct virtual hosts.
7. Never expand wildcard SANs through brute-force generation unless separately
   authorized.

## Playbook schema

Each playbook should eventually support:

```json
{
  "technologies": {
    "product": {
      "signatures": ["header or body evidence"],
      "paths": ["health", "metrics"],
      "ports": [443],
      "protocols": ["https"],
      "follow_up": ["Manual review instruction"],
      "automatic_actions": [],
      "manual_actions": [],
      "stop_conditions": [],
      "risk": "medium"
    }
  }
}
```

## Implementation roadmap

1. Make the bundled per-technology playbook library the only canonical catalog.
2. Add read-only protocol adapters behind explicit enable flags.
3. Add resumable runs and richer interactive reporting.
4. Add playbook tests using local fixture services and captured response samples.
