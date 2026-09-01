# 100% Free Axiom Controller Setup on Windows (WSL2 + Free Trial)

This guide shows you how to turn your Windows machine into a **Linux Axiom Controller for $0**, using **Windows Subsystem for Linux (WSL2)** and a **DigitalOcean $200 free trial credit**.

---

## 1. Install Ubuntu on Windows via WSL2 (Cost: $0)

Open Windows PowerShell as **Administrator** and run:

```powershell
wsl --install -d Ubuntu-22.04
```

* Once installation finishes, restart your PC if prompted.
* Open the **Ubuntu** app from your Start menu and set up your Linux username and password.

---

## 2. Install Axiom Prerequisites inside WSL2

Inside your WSL2 Ubuntu terminal:

```bash
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install -y curl git jq rsync unzip python3 python3-pip python3-venv

# Clone Axiom
git clone https://github.com/pry0cc/axiom.git ~/.axiom
```

---

## 3. Get Your Free Cloud Credits ($0)

1. Sign up for a [DigitalOcean Free Trial](https://www.digitalocean.com/) to receive **$200 in free credits for 60 days** (or use the GitHub Student Pack).
2. In DigitalOcean dashboard:
   * Go to **API** $\to$ **Tokens** $\to$ **Generate New Token**.
   * Name: `axiom-token`, Scope: **Read & Write**.
   * Copy the token secret.

---

## 4. Configure Axiom & Build Base Image

Inside your WSL2 Ubuntu terminal:

```bash
# 1. Run interactive configuration
$HOME/.axiom/interact/axiom-configure
```
* Select `digitalocean`.
* Paste your DigitalOcean API token.
* Select your preferred region (e.g. `nyc3`, `fra1`, `blr1`).
* Select default droplet size (`s-1vcpu-1gb`).

```bash
# 2. Build the snapshot image (Takes ~8-10 minutes, uses free credits)
$HOME/.axiom/interact/axiom-build
```

---

## 5. Clone and Run the Controller Agent in WSL2

Inside WSL2:

```bash
# Navigate to your workspace (Windows files are accessible under /mnt/c/)
cd /mnt/c/Users/jayes/Downloads/Scan_tool

# Set up Linux virtual environment
python3 -m venv .venv-linux
source .venv-linux/bin/activate
pip install -r requirements-controller.txt

# Run the controller agent connecting to your local or Render API
export CONTROLLER_DRY_RUN=false
python3 -m controller.agent
```

Your controller will now automatically spawn real DigitalOcean droplets when scans are queued, run the tools (`httpx`, `nuclei`, etc.), download the findings, and immediately destroy the droplets!
