# Installation

This guide installs the discovery orchestrator and its optional external tools. Only run
scans against systems covered by explicit authorization.

## Amazon Linux 2023

### 1. Install system packages

```bash
sudo dnf update -y
sudo dnf install -y \
  git \
  golang \
  nmap \
  openssl \
  python3 \
  python3-pip
```

Verify the base tools:

```bash
python3 --version
go version
nmap --version
openssl version
git --version
```

### 2. Configure the Go binary path

Tools installed with `go install` are normally written to `$HOME/go/bin`.

```bash
mkdir -p "$HOME/go/bin"
echo 'export PATH="$HOME/go/bin:$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
export PATH="$HOME/go/bin:$HOME/.local/bin:$PATH"
```

Verify:

```bash
go env GOPATH
echo "$PATH"
```

### 3. Install discovery tools

`ffuf` is the recommended content-discovery backend. Gobuster is optional. `grpcurl` is
useful for separately reviewed, protocol-aware gRPC follow-up.

```bash
go install github.com/ffuf/ffuf/v2@latest
go install github.com/OJ/gobuster/v3@latest
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest
```

Verify:

```bash
ffuf -V
gobuster version
grpcurl --version
```

If a command is still not found, reload the shell:

```bash
source "$HOME/.bashrc"
```

### 4. Download only the required SecLists directory

The tool requires `Discovery/Web-Content`, not the complete SecLists repository.

```bash
cd "$HOME"
git clone --depth 1 --filter=blob:none --sparse \
  https://github.com/danielmiessler/SecLists.git
cd SecLists
git sparse-checkout set Discovery/Web-Content
```

Verify:

```bash
test -f "$HOME/SecLists/Discovery/Web-Content/common.txt"
find "$HOME/SecLists/Discovery/Web-Content" -maxdepth 2 -type f | head
```

Update the lists later with:

```bash
cd "$HOME/SecLists"
git pull --ff-only
```

### 5. Obtain and install adaptive-web-discovery

Clone your repository and enter the project directory:

```bash
cd "$HOME"
git clone YOUR_GITHUB_REPOSITORY_URL adaptive-web-discovery
cd adaptive-web-discovery
```

Then run the dependency-free installer:

```bash
chmod +x install.sh
./install.sh
source "$HOME/.bashrc"
```

The installer places the command in `$HOME/.local/bin` and the application files under
`$HOME/.local/share/adaptive-web-discovery`.

Verify:

```bash
adaptive-web-discovery --help
adaptive-web-discovery --validate-playbooks
adaptive-web-discovery --list-port-intelligence | head
```

Alternatively, on systems with working Python packaging tools:

```bash
python3 -m pip install --user .
adaptive-web-discovery --help
```

### 6. Validate a scan configuration without sending traffic

```bash
adaptive-web-discovery \
  -iL prod_subnets.txt \
  -ports ports.txt \
  --scan-profile aggressive \
  --nmap-stages staged \
  --nse-profile safe \
  -sT -Pn -T4 \
  --min-rate 2000 \
  --min-hostgroup 4096 \
  --nmap-workers 8 \
  --mode fingerprint \
  --preflight-only \
  --color always \
  --acknowledge-authorization
```

Use `--dry-run` instead of `--preflight-only` to also display the generated Nmap worker
commands without executing them.

### 7. SYN scan privileges

Nmap SYN scans (`-sS`) require root or appropriate raw-socket privileges. The recommended
approach is to run the authorized network-discovery command with `sudo`:

```bash
sudo --preserve-env=PATH adaptive-web-discovery ... -sS ...
```

Use `-sT` when running without `sudo`. The tool automatically falls back from `-sS` to
`-sT` unless `--require-syn` is supplied.

### 8. Optional troubleshooting

Confirm command locations:

```bash
command -v adaptive-web-discovery
command -v ffuf
command -v gobuster
command -v grpcurl
command -v nmap
```

Confirm the SecLists path:

```bash
ls -l "$HOME/SecLists/Discovery/Web-Content/common.txt"
```

Run the bundled project tests from the source directory:

```bash
python3 -m py_compile web_discovery.py test_web_discovery.py
python3 -m unittest -v test_web_discovery.py
```

## macOS

Install dependencies with Homebrew:

```bash
brew install git go nmap openssl seclists
```

Install the optional scanners:

```bash
go install github.com/ffuf/ffuf/v2@latest
go install github.com/OJ/gobuster/v3@latest
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest
echo 'export PATH="$HOME/go/bin:$HOME/.local/bin:$PATH"' >> "$HOME/.zshrc"
source "$HOME/.zshrc"
```

Install and verify the orchestrator:

```bash
chmod +x install.sh
./install.sh
adaptive-web-discovery --validate-playbooks
```

Common Homebrew SecLists locations are:

```text
/opt/homebrew/share/seclists/Discovery/Web-Content
/usr/local/share/seclists/Discovery/Web-Content
```

## Required versus optional tools

| Tool | Requirement | Purpose |
| --- | --- | --- |
| Python 3.9+ | Required | Runs the orchestrator |
| Nmap | Required for `-iL` staged discovery | Discovers and enriches open services |
| OpenSSL | Recommended | TLS certificate and handshake fingerprinting |
| ffuf | Recommended | Content and API enumeration |
| Gobuster | Optional | Alternative content-enumeration backend |
| SecLists Web-Content | Required for broad enumeration | Directory, file, and API wordlists |
| grpcurl | Optional | Manual, protocol-aware gRPC follow-up |
