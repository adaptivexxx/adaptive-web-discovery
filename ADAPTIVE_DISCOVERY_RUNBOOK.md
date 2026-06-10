# Adaptive discovery runbook

## 1. Prepare authorization and scope

Create a JSON scope policy from `web_discovery_scope.example.json`. Include only domains
and CIDRs explicitly covered by the assessment authorization. Exclusions always win.

Validate the technology catalog:

```bash
python3 web_discovery.py --validate-playbooks
python3 web_discovery.py --list-technologies
```

## 2. Preview the plan

```bash
python3 web_discovery.py \
  -i authorized-targets.txt \
  --mode smart \
  --profile api \
  --scope-policy web_discovery_scope.example.json \
  --seclists ~/SecLists/Discovery/Web-Content \
  --threads 20 \
  --host-concurrency 2 \
  --rate 50 \
  --dry-run
```

Import open services directly from one or more Nmap XML, normal, or grepable output files:

```bash
python3 web_discovery.py \
  --gnmap perimeter.gnmap \
  --gnmap internal.gnmap \
  --nmap detailed-services.nmap \
  --nmap-xml preferred-structured-output.xml \
  --mode smart \
  --scope-policy web_discovery_scope.example.json \
  --seclists ~/SecLists/Discovery/Web-Content \
  --dry-run
```

Nmap XML is preferred because it is structured and avoids delimiter ambiguity. The
importers preserve every open service for reporting. They automatically create scan
targets only for ports identified as HTTP/TLS services or matching `--http-ports` and
`--https-ports`. `--nmap-all-open-ports` applies to imported Nmap services generally:
it attempts both HTTP and HTTPS against every open TCP port and should only be used when
explicitly authorized.

## 3. Run fingerprinting first

```bash
python3 web_discovery.py \
  -i authorized-targets.txt \
  --mode fingerprint \
  --scope-policy web_discovery_scope.example.json \
  --expand-authorized-candidates \
  --acknowledge-authorization
```

Review candidates and next actions in `report.md` or `report.html`. Certificate SANs and
response-linked hostnames outside explicit scope remain candidates and are not scanned.

## 4. Run smart enumeration

After reviewing scope and rate limits:

```bash
python3 web_discovery.py \
  -i authorized-targets.txt \
  --mode smart \
  --profile api \
  --scope-policy web_discovery_scope.example.json \
  --expand-authorized-candidates \
  --seclists ~/SecLists/Discovery/Web-Content \
  --tool ffuf \
  --threads 20 \
  --host-concurrency 2 \
  --rate 50 \
  --acknowledge-authorization
```

Unreachable, rate-limited, and wildcard/soft-404 targets are recorded but excluded from
automatic enumeration.

## 5. Review output

Every completed run contains:

- `manifest.json`: complete run configuration and output references.
- `fingerprints.json`: HTTP, TLS, technology, candidate, and action evidence.
- `discovery.sqlite3`: targets, probes, technologies, candidates, actions, and jobs.
- `findings.json` and `findings.csv`: normalized findings suitable for downstream tools.
- `services.json`: complete GNMAP-imported service inventory.
- `import-warnings.json`: line-level ambiguous or skipped Nmap/GNMAP records.
- `port-intelligence.json`: merged exact port roles and technology port ranges.
- `report.md`: portable text report.
- `report.html`: self-contained Nessus-style dashboard with severity metrics, searchable
  findings, assets, services, import-quality warnings, evidence, and recommendations.
- Per-target scanner output and generated smart route lists.

Treat protocol-aware actions such as gRPC, Kubernetes RBAC, databases, queues, and mTLS
as manual follow-up unless a separately reviewed read-only adapter is explicitly enabled.
