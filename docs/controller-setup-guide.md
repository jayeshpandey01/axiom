# Linux Controller VPS Setup & Axiom Provisioning Guide

This guide details the step-by-step procedure to configure a dedicated Linux VPS (or local Ubuntu WSL2 environment) as the **Axiom Controller**.

---

## 1. System Requirements & Security Baseline

* **Operating System**: Ubuntu 22.04 LTS or 24.04 LTS (x86_64)
* **Hardware**: Minimum 1 vCPU, 2 GB RAM, 25 GB SSD
* **Network / Firewall**:
  * **Inbound**: Block all public ports except SSH (or require WireGuard/Tailscale VPN).
  * **Outbound**: HTTPS (443) and SSH (22) to cloud provider API and target endpoints.

### Initial Server Hardening
```bash
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install -y ufw curl git jq rsync unzip python3 python3-pip python3-venv

# Configure basic firewall
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw enable
```

---

## 2. Install Axiom Prerequisites & CLI

### Step 2.1: Clone Axiom Classic
```bash
git clone https://github.com/pry0cc/axiom.git ~/.axiom
```

### Step 2.2: Run Axiom Configuration Wizard
```bash
# Axiom requires interactive configuration before building images
$HOME/.axiom/interact/axiom-configure
```
* When prompted, select your cloud provider (e.g., `digitalocean`).
* Enter your Cloud Provider API Token (e.g., DigitalOcean Personal Access Token with read/write permissions).
* Choose your preferred region (e.g., `nyc3`, `fra1`, `blr1`).
* Choose default droplet size (e.g., `s-1vcpu-1gb`).

### Step 2.3: Build Base Scanner Image (`axiom-build`)
Axiom uses Packer to create an immutable snapshot image pre-installed with security tools (`httpx`, `nuclei`, `nmap`, `subfinder`, `ffuf`, etc.).

```bash
# Build the base snapshot image (takes ~8-12 minutes)
$HOME/.axiom/interact/axiom-build
```

---

## 3. Verify Axiom Manually (Independent Lifecycle Test)

Before connecting the controller to our API service, verify the full manual lifecycle against an **authorized, low-impact test target**:

```bash
# 1. Create a 1-node test fleet
$HOME/.axiom/interact/axiom-fleet poc-test-01 -i 1

# 2. Verify instance is active
$HOME/.axiom/interact/axiom-ls

# 3. Run a basic DNS/HTTP probe against authorized target
echo "scanme.nmap.org" > /tmp/target.txt
$HOME/.axiom/interact/axiom-scan /tmp/target.txt -m httpx --fleet poc-test-01 -o /tmp/output.txt

# 4. View results
cat /tmp/output.txt

# 5. Immediately destroy the fleet
$HOME/.axiom/interact/axiom-rm poc-test-01 -f

# 6. Verify 0 active instances remain
$HOME/.axiom/interact/axiom-ls
```

---

## 4. Setting up the Python Controller Agent

1. Clone or copy your `Scan_tool` repository to the Controller VPS.
2. Set up the Python virtual environment:
```bash
cd /opt/scan_tool
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-controller.txt
```

3. Run the automated lifecycle test runner:
```bash
python3 -m controller.test_lifecycle
```

---

## 5. Install Additional Scanner Tools

The controller supports six scan profiles. Install the tools for each profile you intend to use:

```bash
# nmap (network-portscan) — usually pre-installed on Ubuntu
sudo apt-get install -y nmap

# masscan (fast-portscan) — requires raw socket capability
sudo apt-get install -y masscan
sudo setcap cap_net_raw+ep $(which masscan)

# ffuf (content-discovery) — installed via Go
go install github.com/ffuf/ffuf/v2@latest

# nuclei (vuln-assessment) — installed via Go
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Update nuclei templates after install
nuclei -update-templates
```

### Download SecLists wordlist for FFUF

```bash
mkdir -p ~/.axiom/wordlists
wget -qO ~/.axiom/wordlists/common.txt \
  https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt
```

Or set a custom path:
```bash
# In .env.local on the controller VPS
CONTROLLER_FFUF_WORDLIST=/path/to/your/wordlist.txt
```

> **Note:** A minimal bundled wordlist (`scripts/wordlists/common.txt`) is included in the repo for development and dry-run testing. Always use the full SecLists in production.

