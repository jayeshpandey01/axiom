# ADR 002: Cloud Provider Selection & Cost Safeguards for Ephemeral Scanner Fleets

- **Status:** Accepted
- **Date:** 2026-09-01
- **Deciders:** Engineering Team
- **Technical Context:** Disposable Scanner VM Infrastructure

---

## 1. Context and Problem Statement

Axiom relies on a cloud provider API to provision disposable Linux VMs (droplets/instances), build base scanner images via Packer, execute distributed scans, and delete instances upon scan completion.

Key risks include:
1. **Runaway Cloud Costs**: If a scan worker crashes or loses network connectivity, provisioned VMs might remain running indefinitely.
2. **Provider API Abuse / Account Ban**: Excessive aggressive scanning or rapid provisioning can trigger security fraud flags or rate limits.
3. **Provisioning Latency**: Slow VM spin-up times can degrade scan turnaround times.

We must select a primary cloud provider for Phase 1 and define hard cost-control safeguards.

---

## 2. Provider Evaluation

| Provider | Hourly Cost (1 vCPU / 1GB RAM) | Snapshot / Build Speed | Axiom Compatibility | Notes |
| :--- | :--- | :--- | :--- | :--- |
| **DigitalOcean** | ~$0.007/hr ($4–$6/month) | Fast (~5–8 min snapshot build) | **Native / Primary** | Axiom was originally built around DigitalOcean APIs (`doctl`). Best documentation and community support. Offers $200 trial credits. |
| **Hetzner Cloud** | ~€0.006/hr (€4/month) | Very Fast | High | Extremely cost-effective, excellent European routing, supported by Axiom. |
| **Linode (Akamai)** | ~$0.0075/hr ($5/month) | Fast | High | Reliable API, $100 developer credits available. |
| **AWS (EC2)** | Variable ($0.0116/hr) | Moderate (Packer AMI) | Moderate | Broad global reach, but AMI creation and security group rules add configuration complexity. |

---

## 3. Decision

1. **Primary Provider for Phase 1 / PoC**: **DigitalOcean**
   - Use DigitalOcean as the default provider due to native Axiom tooling, fast droplet provisioning, and straightforward API token scoping.
2. **Hard Spend Caps & Quotas**:
   - Limit the cloud provider API token to a dedicated project/team space.
   - Enforce a maximum fleet size of **`MAX_FLEET_SIZE = 2`** instances during Phase 1.
   - Configure a cloud billing notification alarm at **$5.00** and **$15.00**.
3. **Multi-Layered Automatic VM Teardown (Fail-Safe Cleanup)**:
   - **Layer 1 (Python Subprocess Context Manager)**: `try ... finally: destroy_fleet(name)` in the controller runner.
   - **Layer 2 (Execution Timeout)**: Hard maximum runtime of 15 minutes (`SCAN_TIMEOUT_SEC = 900`) per scan job.
   - **Layer 3 (Controller Orphan Watchdog)**: A background timer/cron service on the Controller VPS that polls active cloud VMs and terminates any instance older than 30 minutes.

---

## 4. Consequences

### Positive Consequences
* Low development cost (leveraging free trial credits or minimal droplet charges).
* Zero risk of unmonitored runaway cloud bills due to the three-tier teardown safeguards.
* Fast iteration speed since Axiom's standard DigitalOcean provisioner is stable and well-documented.

### Negative Consequences
* Initial image build (`axiom-build`) takes 5–10 minutes on first setup.
* DigitalOcean account must be in good standing with credit card or PayPal verification to enable API token creation.
