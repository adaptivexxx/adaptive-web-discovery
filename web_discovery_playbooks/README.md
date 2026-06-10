# Technology playbook library

Each technology has one JSON playbook under its category directory. The CLI loads this
bundled directory recursively, then applies any `--playbooks` files or directories in
argument order as overrides.

## Playbook fields

- `id`: stable lowercase technology identifier used by `--technology`.
- `category`: organizational technology family.
- `signatures`: lowercase header/body evidence used for fingerprinting.
- `paths`: authorized HTTP routes prioritized during smart discovery.
- `protocols`: protocols requiring consideration or protocol-aware follow-up.
- `typical_ports`: informational defaults; the current scanner does not port-scan them.
- `port_hints`: exact port roles, protocols, and whether the port is web-capable.
- `port_ranges`: non-exact range indicators such as Kubernetes NodePort.
- `risk`: review priority context.
- `explicit_only`: excludes sensitive routes from generic fallback discovery.
- `automatic_actions`: safe automated workflow guidance.
- `follow_up`: technology-specific manual review guidance.
- `stop_conditions`: boundaries that prevent unsafe or unreliable continuation.

## Add a technology

1. Copy an existing playbook or `../web_discovery_playbooks.example.json`.
2. Use a unique lowercase `id`.
3. Add strong signatures and bounded read-only routes.
4. Set `explicit_only` for sensitive products or routes that should require evidence or
   an explicit operator hint.
5. Document protocol-aware and manual follow-up.
6. Validate it with:

```bash
python3 web_discovery.py --validate-playbooks --playbooks custom-playbooks/

python3 web_discovery.py \
  -u https://example.test \
  -w README.md \
  --playbooks web_discovery_playbooks \
  --technology your-technology \
  --dry-run
```

Inspect the complete merged catalog with:

```bash
python3 web_discovery.py --list-technologies
python3 web_discovery.py --list-port-intelligence
```

Port-only matches are hypotheses. Shared ports receive low confidence unless Nmap service
or version evidence supports a technology. Native gRPC, replication, gossip, database,
and queue ports are retained for reporting and protocol-specific follow-up but are not
automatically treated as HTTP.

Run `python3 generate_web_discovery_playbooks.py` only when intentionally rebuilding
the bundled library from the legacy constants in `web_discovery.py`. Manual playbook
improvements should eventually become the canonical source instead.
