# Multi-target web content discovery

`web_discovery.py` implements a staged, authorized web and infrastructure discovery
methodology. It fingerprints targets first, infers likely technologies, then orchestrates
targeted directory, file, API, Kubernetes, and observability route discovery with
`ffuf` or `gobuster` plus wordlists from
[SecLists Web-Content](https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content).

## Requirements

- Python 3.10+
- `ffuf` or `gobuster`
- A local SecLists checkout/package

Only scan systems you own or have explicit permission to assess. Execution requires
`--acknowledge-authorization`; dry runs do not.

## Methodology

1. Normalize and validate the authorized target scope.
2. Fingerprint HTTP responses, headers, status behavior, TLS version/cipher, certificate
   metadata, and negotiated ALPN protocol.
3. Probe a bounded set of well-known discovery routes such as health, metrics, OpenAPI,
   GraphQL, Kubernetes, Grafana, Loki, Prometheus, and Spring Actuator endpoints.
4. Record evidence-based technology hypotheses with confidence levels.
5. Generate a prioritized infrastructure route list and combine it with the selected
   broad SecLists profile.
6. Run enumeration with explicit thread, process-concurrency, and rate controls.
7. Preserve fingerprints, commands, exit codes, and scanner output in a timestamped run.

Smart runs also extract certificate SAN and response-linked hostname candidates, classify
them against an explicit JSON scope policy, identify likely wildcard/soft-404 behavior,
group identical virtual-host responses, generate next actions, and persist evidence to
SQLite.

Common authorization header and cookie values are redacted from console output and
manifests. Avoid placing credentials inside `--extra-args`, which cannot be reliably
redacted.

`smart` is the default mode. `fingerprint` stops after evidence collection, while
`enumerate` skips fingerprinting and uses only SecLists or supplied wordlists.

Nmap XML, normal (`.nmap`), and grepable (`.gnmap`) outputs are first-class target sources.
The complete open-service inventory is retained, while HTTP/TLS-looking services are
automatically promoted into web discovery targets. Use `--nmap-all-open-ports` only when
explicitly authorized to attempt both HTTP and HTTPS against every imported open TCP port.
Prefer Nmap XML when available because it preserves structure without relying on
delimiter-sensitive text parsing.

Imported services are enriched using playbook port intelligence covering cloud-native
management, ingestion, metrics, profiling, replication, gossip, and native protocol
surfaces. Port-only matches remain confidence-rated hypotheses. Native gRPC and other
non-HTTP ports are reported without being sent to web scanners.

## Examples

Preview a default scan without sending requests:

```bash
python3 web_discovery.py \
  -u https://app.example.test \
  -u https://api.example.test \
  --seclists ~/SecLists/Discovery/Web-Content \
  --dry-run
```

Run against identified open web ports from GNMAP:

```bash
python3 web_discovery.py \
  --gnmap authorized-scan.gnmap \
  --mode smart \
  --scope-policy web_discovery_scope.example.json \
  --seclists ~/SecLists/Discovery/Web-Content \
  --acknowledge-authorization
```

Run against normal Nmap output:

```bash
python3 web_discovery.py \
  --nmap authorized-scan.nmap \
  --mode smart \
  --scope-policy web_discovery_scope.example.json \
  --seclists ~/SecLists/Discovery/Web-Content \
  --acknowledge-authorization
```

Preferred XML import:

```bash
python3 web_discovery.py \
  --nmap-xml authorized-scan.xml \
  --mode smart \
  --scope-policy web_discovery_scope.example.json \
  --seclists ~/SecLists/Discovery/Web-Content \
  --acknowledge-authorization
```

Run API-focused discovery with controlled concurrency:

```bash
python3 web_discovery.py \
  -i authorized-targets.txt \
  --mode smart \
  --scope-policy web_discovery_scope.example.json \
  --expand-authorized-candidates \
  --profile api \
  --tool ffuf \
  --threads 30 \
  --host-concurrency 2 \
  --rate 100 \
  -H 'Authorization: Bearer TOKEN' \
  --acknowledge-authorization
```

Use custom wordlists and extensions:

```bash
python3 web_discovery.py \
  -u https://example.test \
  -w ~/SecLists/Discovery/Web-Content/common.txt \
  -w ~/SecLists/Discovery/Web-Content/Common-DB-Backups.txt \
  -x php,asp,aspx,js,json,bak,zip \
  --tool gobuster \
  --threads 20 \
  --acknowledge-authorization
```

Profiles:

- `quick`: `common.txt`
- `default`: common plus small directory/file RAFT lists
- `deep`: medium directory/file lists plus common database backups
- `api`: API endpoints, endpoints seen in the wild, objects, and GraphQL lists

The generated smart route catalog covers common API documentation and health routes plus
Kubernetes API server, Grafana, Prometheus, Loki, OpenTelemetry HTTP, gRPC health,
Jaeger, Tempo, Alertmanager, Mimir, Thanos, Pyroscope, Zipkin, etcd, Consul, Vault,
Elasticsearch, Spring Actuator, common sidecars, Envoy, Istio, Linkerd, Consul Connect,
Traefik, Nginx, HAProxy, Kong, APISIX, registries, CI/CD systems, identity providers,
message brokers, caches, databases, and object storage conventions.

HTTP route discovery cannot fully enumerate native gRPC or OTLP/gRPC services. ALPN and
HTTP response evidence can identify likely HTTP/2 or gRPC exposure, but authorized
follow-up should use a protocol-aware tool such as `grpcurl`.

## Decision logic

- Strong product evidence prioritizes that product's routes first.
- Generic API, health, readiness, metrics, OpenAPI, and GraphQL routes are always covered.
- The remaining cloud-native catalog is retained as a bounded fallback because reverse
  proxies and gateways often remove identifying headers.
- Native-protocol follow-up is kept separate from HTTP route discovery. For example,
  gRPC reflection and health checks require `grpcurl`; Kubernetes resource enumeration
  requires an authorized identity and `kubectl`; OTLP/gRPC validation requires an
  appropriate telemetry client.
- A `401` or `403` is recorded as a useful discovery result, not treated as permission
  to bypass authentication.
- Sensitive technology families such as cloud metadata proxies require confirming
  evidence or an explicit `--technology` hint and are excluded from generic fallback.

## Extending technologies

The bundled [playbook library](web_discovery_playbooks/README.md) contains one JSON file
per technology and is loaded recursively. No static catalog can cover every product or
deployment-specific route. Add custom technology evidence, routes, and manual actions
with a JSON playbook file or directory:

```bash
python3 web_discovery.py \
  -u https://service.example.test \
  --playbooks custom-playbooks/ \
  --technology custom-platform \
  --seclists ~/SecLists/Discovery/Web-Content \
  --acknowledge-authorization
```

`--technology` is an operator hint that prioritizes a known built-in or externally
defined technology even when proxies have removed identifying evidence.

Inspect or validate the merged bundled and external playbook catalog:

```bash
python3 web_discovery.py --list-technologies
python3 web_discovery.py --list-port-intelligence
python3 web_discovery.py --validate-playbooks --playbooks custom-playbooks/
```

Use `--extra-args` for backend-specific flags. Results are separated by run, target,
and wordlist. Each completed run includes `manifest.json`, `fingerprints.json`,
`services.json`, `import-warnings.json`, `findings.json`, `findings.csv`,
`port-intelligence.json`, `discovery.sqlite3`, `report.md`, and a self-contained
Nessus-style `report.html`.

Recursive discovery is available with `ffuf`. Gobuster does not expose an equivalent
recursive directory mode, and does not support the per-process `--rate` limit.

## Console output

Operational output uses color-coded phase, progress, success, warning, error, and command
labels when stdout is connected to a terminal. Use `--color always` when running through
tools that hide TTY detection, or `--no-color` / `NO_COLOR=1` for plain log files.
