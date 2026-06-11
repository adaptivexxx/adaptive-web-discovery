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

## 3. Run staged network discovery

For authorized CIDR ranges, use staged discovery. The first stage finds open ports
without expensive scripts. The second stage runs version detection and the selected
read-only NSE profile only against confirmed open services.

```bash
sudo python3 -u web_discovery.py \
  -iL prod_subnets.txt \
  -ports ports.txt \
  --scan-profile aggressive \
  --nmap-stages staged \
  --nse-profile safe \
  -sS -Pn -T4 \
  --min-rate 750 \
  --min-hostgroup 256 \
  --nmap-workers 8 \
  -oA prod-extensive \
  --mode smart \
  --profile deep \
  --tool ffuf \
  --seclists ~/SecLists/Discovery/Web-Content \
  --fingerprint-probes basic \
  --host-concurrency 32 \
  --threads 20 \
  --global-rate 1600 \
  --max-open-services 100000 \
  --max-enumeration-targets 5000 \
  --max-scanner-jobs 20000 \
  --deadline-minutes 720 \
  --color always \
  --acknowledge-authorization
```

Use `-sT` without `sudo`. The tool also detects unavailable SYN privileges and
automatically falls back from `-sS` to `-sT` unless `--require-syn` is set.

## 4. Run fingerprinting first

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

## 5. Run smart enumeration

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

## 6. Review output

Every completed run contains:

- `manifest.json`: complete run configuration and output references.
- `fingerprints.json`: HTTP, TLS, technology, candidate, and action evidence.
- `discovery.sqlite3`: targets, probes, technologies, candidates, actions, and jobs.
- `findings.json` and `findings.csv`: normalized findings suitable for downstream tools.
- `findings.sarif`: normalized findings for SARIF-compatible review systems.
- `coverage.json`: counts and coverage ratios for discovery, fingerprinting, and jobs.
- `comparison.json`: service changes when `--compare-run` is supplied.
- `provenance.json`: input hashes and tool versions.
- `protocol-follow-up.json`: read-only protocol-aware follow-up recommendations.
- `virtual-host-candidates.json`: certificate and response-derived hostname candidates.
- `services.json`: complete GNMAP-imported service inventory.
- `import-warnings.json`: line-level ambiguous or skipped Nmap/GNMAP records.
- `port-intelligence.json`: merged exact port roles and technology port ranges.
- `report.md`: portable text report.
- `report.html`: self-contained Nessus-style dashboard with severity metrics, searchable
  findings, assets, services, import-quality warnings, evidence, and recommendations.
- Per-target scanner output and generated smart route lists.

Treat protocol-aware actions such as gRPC, Kubernetes RBAC, databases, queues, and mTLS
as manual follow-up unless a separately reviewed read-only adapter is explicitly enabled.
