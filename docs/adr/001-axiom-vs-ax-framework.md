# ADR 001: Evaluation of Axiom Classic vs Ax Framework for Scanning Orchestration

- **Status:** Accepted
- **Date:** 2026-09-01
- **Deciders:** Engineering Team
- **Technical Context:** Authorized Scan Orchestrator Engine

---

## 1. Context and Problem Statement

The scan orchestrator requires a distributed execution engine to spin up ephemeral cloud scanner VMs, distribute target workloads across multiple nodes, execute security testing modules (such as `httpx`, `dnsx`, `nuclei`, `nmap`), collect raw scan outputs, and reliably destroy the VMs.

Two primary options exist in the ecosystem:
1. **Axiom Classic (Bash-based)**: The original, battle-tested distributed scanning toolkit.
2. **Ax Framework (Go-based)**: The newer rewrite of Axiom in Go with an interactive TUI and modular architecture.

We must decide which framework to adopt as the underlying fleet controller, and establish how our application interfaces with it.

---

## 2. Technical Comparison

| Criteria | Axiom Classic (Bash) | Ax Framework (Go) |
| :--- | :--- | :--- |
| **Language & Runtime** | Bash scripts, `jq`, `packer`, standard UNIX utilities | Compiled Go binary |
| **Stability & Ecosystem** | Highly stable, hundreds of community modules (`axiom-scan`), established `packer` provisioning templates. | Newer, actively evolving architecture; some modules and cloud provider wrappers still maturing. |
| **Headless / API Automation** | Standard CLI interface with predictable exit codes and file-based I/O (`-o`, `--fleet`). Easy to invoke via Python `subprocess`. | Designed with interactive TUI and modern CLI; programmatic headless API mode is expanding. |
| **Cloud Provider Support** | DigitalOcean, Linode, AWS, Hetzner, GCP, Azure, IBM, OCI. | DigitalOcean, Linode, AWS, Hetzner. |
| **Maintenance Status** | Maintenance mode (stable, mature). | Active development / next-generation. |

---

## 3. Decision

We will use **Axiom Classic** as the initial execution engine for Phase 1 through an **isolated Controller Service wrapper**, while designing strict abstraction boundaries (`FleetManager` and `ProfileRegistry`) so that migrating to **Ax Framework** later requires **zero changes to the FastAPI layer or the database model**.

Furthermore:
1. **No Forking Initially**: We will not fork or modify the Axiom repository. Axiom will be cloned and managed exclusively on the isolated Linux Controller VPS.
2. **Strict Subprocess & Output Isolation**: The FastAPI and Background Worker code will never invoke Axiom directly. Only the dedicated Controller Agent running on the Linux VPS will interface with Axiom CLI commands.
3. **Fixed Profile Translation**: The Controller Agent will map sanitized profile requests (`recon`, `web-discovery`) to predefined Axiom commands and module flags, preventing arbitrary CLI injection.

---

## 4. Consequences & Migration Path

### Positive Consequences
* **Immediate Reliability**: Axiom Classic's image building (`axiom-build`) and droplet teardown (`axiom-rm`) are thoroughly proven and predictable.
* **Extensible Module Ecosystem**: Built-in support for standard offensive and recon modules without requiring custom binary builds.
* **Decoupled Architecture**: If Ax Framework matures with a native gRPC/REST daemon, the Controller Agent can swap its internal implementation from bash CLI calls to Ax API calls without impacting Render services.

### Negative Consequences
* Axiom Classic requires standard Linux utilities (`bash`, `jq`, `rsync`, `packer`) on the Controller VPS.
* Subprocess execution requires robust timeout handlers and exit code parsing in Python.

---

## 5. Review Trigger
This decision will be reviewed when Ax Framework releases a stable, headless daemon mode with native JSON-RPC / REST endpoints.
