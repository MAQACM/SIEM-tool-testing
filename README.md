# SIEM Experiment — Wazuh v4.8 vs Elastic Security v8.11

Companion toolkit for *"A Comparative Experimental Evaluation of Open-Source SIEM Systems
(Wazuh vs. Elastic Security) ... Using MITRE ATT&CK-Based Adversary Emulation"*
(Strathmore University, MIT 8105). It measures, for each SIEM, the paper's dependent
variables: detection accuracy, false-positive rate, F1-score, detection latency, CPU %,
RAM (MB) and disk-write IOPS (§10.5).

## Topology

Attacker and victims run as **local VMs on your Mac**; each SIEM runs on **one VPS at a
time**. Only log telemetry crosses the internet (agents dial out to the VPS), so no attack
traffic ever leaves your Mac.

```
Your Mac (UTM / VMware Fusion, private host-only net)        VPS (4 vCPU / 8 GB, Ubuntu 22.04)
┌──────────────────────────────────────────────┐
│  Kali  ──attacks──►  Ubuntu victim  (agent) ──┼──logs──►  ┌───────────────────────────┐
│        ──attacks──►  Windows victim (agent) ──┼──logs──►  │ Wazuh  THEN (teardown)    │
│  08_event_generator.py runs on a victim       │           │ Elastic + cAdvisor sensor │
└──────────────────────────────────────────────┘           └───────────────────────────┘
```

You run **Wazuh first, tear it down, then Elastic** on the same VPS.

## Files

| File | Runs on | Purpose |
|---|---|---|
| `01_setup_wazuh.sh` | VPS | Deploy Wazuh 4.8 stack + cAdvisor |
| `02_metrics_logger.py` | VPS | Log host CPU %, RAM MB, disk IOPS every 1 s |
| `03_wazuh_alert_extractor.py` | VPS | Export Wazuh alerts + latency → CSV |
| `04_teardown_and_reset.sh` | VPS | Full purge + RAM reset (**wipes all Docker data**) |
| `05_setup_elastic.sh` | VPS | Deploy Elastic 8.11 + Fleet + cAdvisor (advertises public IP) |
| `06_kibana_alert_extractor.py` | VPS | Export Elastic alerts + latency → CSV |
| `07_plot_metrics.py` | anywhere | Comparative CPU/RAM/IOPS timeline graphs |
| `08_event_generator.py` | **victim VM** | Synthetic EPS load (benign baseline + 50/250/1000 tiers) |
| `09_attack_runner.sh` | **Kali** | Run the §10.4 ATT&CK matrix, write ground-truth CSV |
| `10_score_detections.py` | anywhere | TP/FP/FN, accuracy, FPR, precision, recall, F1, latency |
| `agents/install_wazuh_agent_linux.sh` | Ubuntu victim | Enroll Wazuh agent + auditd + FIM |
| `agents/install_wazuh_agent_windows.ps1` | Windows victim | Enroll Wazuh agent + Sysmon |
| `agents/install_elastic_agent_linux.sh` | Ubuntu victim | Enroll Elastic Agent via Fleet |
| `agents/install_elastic_agent_windows.ps1` | Windows victim | Enroll Elastic Agent + Sysmon |
| `requirements.txt` | VPS / Mac | Python deps for `07` only (pandas, matplotlib) |

The other scripts use the Python standard library only.

---

## 0. One-time prep

**On your Mac — build 3 VMs (UTM or free VMware Fusion) on one private host-only network + NAT:**
- **Kali** (attacker) — ~4 GB RAM. Ships Hydra, sqlmap, hping3, ZAP, Metasploit.
- **Ubuntu 22.04 victim** — ~2–3 GB. Hosts a vulnerable web app (e.g. a DVWA/Log4j container) for the web + RCE vectors.
- **Windows 11 ARM victim** *(optional)* — ~6 GB. For RDP brute + Sysmon telemetry.
  Apple Silicon note: use ARM builds; Elastic Defend endpoint features may be limited on Windows ARM — verify agent health and record any gap as a limitation.

**Everywhere — sync clocks** (latency = VPS alert time − Kali attack time):
```bash
sudo timedatectl set-ntp true     # VPS, Kali, Ubuntu; keep Windows time sync on
```

**Firewall the VPS to your home IP only** (find it with `curl ifconfig.me`). Set this in your
**VPS provider's firewall panel**, not just `ufw` — Docker's published ports bypass `ufw`.
Otherwise Elasticsearch/Wazuh are exposed to the whole internet with default passwords.

---

## PHASE 1 — Wazuh

### 1.1 Deploy (VPS)
```bash
chmod +x *.sh *.py agents/*.sh
./01_setup_wazuh.sh
sudo docker ps      # wazuh.manager / .indexer / .dashboard / cadvisor should be Up
```
Open ports **1514/tcp, 1515/tcp** (agents) and **443** (dashboard) to your home IP.

### 1.2 Enroll victims
```bash
# Ubuntu victim:
sudo agents/install_wazuh_agent_linux.sh <VPS_PUBLIC_IP> ubuntu-victim
# Windows victim (admin PowerShell):
.\install_wazuh_agent_windows.ps1 -Manager <VPS_PUBLIC_IP>
```
Confirm both show **Active** on the Wazuh dashboard → Agents.

### 1.3 Condition A — idle baseline, 60 min (§10.6 step 1)
```bash
python3 02_metrics_logger.py --out wazuh_baseline_idle.csv --duration 3600
```

### 1.4 Benign baseline — 50 EPS, 60 min (§10.6 step 2)
On a victim, start the generator; on the VPS, log metrics. Note the start time for the alert extract.
```bash
# victim VM:
python3 08_event_generator.py --eps 50 --duration 3600
# VPS (same hour):
python3 02_metrics_logger.py --out wazuh_benign_50eps.csv --duration 3600
```
After it ends, export the benign alerts (every alert here is a false positive):
```bash
python3 03_wazuh_alert_extractor.py --start "$BENIGN_START_ISO" --out wazuh_benign_alerts.csv
```

### 1.5 Condition B — attacks per load tier (§10.2, §10.4)
Repeat for each tier (50 → 250 → 1000 EPS). Example for Tier 1 (lab IPs: Ubuntu
`192.168.1.67`, Windows `192.168.1.70`, Kali `192.168.1.68` — use your own).

**a) Clean up any partial/aborted run first.** `02_metrics_logger.py` and
`09_attack_runner.sh` both *append*, so stale files corrupt the new run:
```bash
# VPS:
rm -f ~/siem_exp/wazuh_tier1_attacks.csv
# Kali:
rm -f ~/Downloads/SIEM-tool-testing-ft-test/ground_truth_wazuh_tier1.csv
# Ubuntu victim: make sure no old generator is still running
sudo pkill -f 08_event_generator.py
```

**b) Start the three pieces in order.**
```bash
# VPS — start metrics + record the window start (KEEP THIS SHELL OPEN):
cd ~/siem_exp
ATTACK_START=$(date +%s); START_ISO=$(date -u +%Y-%m-%dT%H:%M:%SZ)
python3 02_metrics_logger.py --out wazuh_tier1_attacks.csv &

# Ubuntu victim — background load at the tier's EPS (stops itself after --duration):
sudo python3 08_event_generator.py --eps 50 --duration 900 &

# Kali — run the attack matrix (writes ground truth):
./09_attack_runner.sh --linux 192.168.1.67 --windows 192.168.1.70 \
    --web http://192.168.1.67:8080 --gt ground_truth_wazuh_tier1.csv
```

**c) When the matrix finishes,** stop the logger on the VPS:
```bash
kill %1          # stops 02_metrics_logger (it runs in the background, so Ctrl+C won't reach it)
```

Notes:
- `ATTACK_START`/`START_ISO` live only in that VPS shell — keep it open through 1.6.
- The generator must outlast the attacks; raise `--duration` if the matrix runs longer than 15 min.
- The generator runs in the background: stop it early with `sudo pkill -f 08_event_generator.py`, not Ctrl+C.
- If a victim has no web app on :8080, skip web vectors: add `--only sys,malware,brute,ddos`.
- Pass `--ssh-user <name>` if the victim login isn't `mark`.
- Scope: `09_attack_runner.sh` targets your **own lab VMs only**; DDoS vectors are count-bounded. Never point it at the VPS or any host you don't own.

### 1.6 Extract + score (VPS or Mac)
```bash
python3 03_wazuh_alert_extractor.py --start "$START_ISO" --attack_epoch "$ATTACK_START" \
    --out wazuh_tier1_alerts.csv

python3 10_score_detections.py \
    --ground_truth ground_truth_wazuh_tier1.csv \
    --alerts wazuh_tier1_alerts.csv \
    --benign_alerts wazuh_benign_alerts.csv \
    --benign_events 180000 \
    --label "Wazuh v4.8 - Tier 1" --out wazuh_tier1_scores.csv
```
(`--benign_events` ≈ EPS × seconds of the benign run; 50 × 3600 = 180000.)

### 1.7 Back up, then tear down
```bash
# from your Mac — copy results off FIRST:
scp YOUR_USER@<VPS_IP>:~/siem_exp/wazuh_*.csv ground_truth_wazuh_*.csv .
# on the VPS:
./04_teardown_and_reset.sh      # docker system prune -af --volumes — wipes ALL Docker data
```

---

## PHASE 2 — Elastic Security (same VPS, after teardown)

### 2.1 Deploy (VPS)
```bash
./05_setup_elastic.sh           # auto-detects public IP; or: PUBLIC_HOST=1.2.3.4 ./05_setup_elastic.sh
```
Open ports **8220** (Fleet), **9200** (ES output) and **5601** (Kibana) to your home IP.
Then in Kibana:
1. **Security → Rules → Install and enable** the prebuilt detection rules (off by default — without this, Elastic scores ~0%).
2. **Fleet → Settings** should already show `http://<VPS_IP>:8220` and `:9200` (set by `05`).

### 2.2 Enroll the SAME victims
Uninstall the Wazuh agents first, then enroll via Fleet (copy the token from **Fleet → Agents → Add agent**):
```bash
# Ubuntu victim:
sudo agents/install_elastic_agent_linux.sh <VPS_PUBLIC_IP> <ENROLLMENT_TOKEN>
# Windows victim (admin PowerShell):
.\install_elastic_agent_windows.ps1 -Vps <VPS_PUBLIC_IP> -Token <ENROLLMENT_TOKEN>
```
Add the **Custom Logs** integration pointing at `/var/log/siem_synthetic/events.log` so the EPS load is ingested.

### 2.3 Run the same protocol as Phase 1
Repeat 1.3 → 1.6 with `elastic_*` filenames and the Elastic extractor:
```bash
python3 06_kibana_alert_extractor.py --start "$START_ISO" --attack_epoch "$ATTACK_START" \
    --out elastic_tier1_alerts.csv
python3 10_score_detections.py --ground_truth ground_truth_elastic_tier1.csv \
    --alerts elastic_tier1_alerts.csv --benign_alerts elastic_benign_alerts.csv \
    --benign_events 180000 --label "Elastic v8.11 - Tier 1" --out elastic_tier1_scores.csv
```
The Elastic alerts CSV also has `Pipeline_Latency_ms` (event time → alert creation).

---

## PHASE 3 — Compare

```bash
python3 07_plot_metrics.py --wazuh wazuh_tier1_attacks.csv --elastic elastic_tier1_attacks.csv \
    --tier "Tier 1 (50 EPS)" --out comparative_tier1.png --iops --cores 4
```
`--cores 4` reports CPU as % of all 4 vCPUs (paper convention). Copy the printed summary
averages and the `*_scores.csv` figures into `experimental-data-collection-sheet.xlsx`.

---

## Mapping to the paper

| Paper requirement | Provided by |
|---|---|
| Resource metrics every 1 s (§10.5.2) | `02_metrics_logger.py` (cAdvisor; paper names Prometheus — note as a deviation) |
| Idle + benign baselines, 3 load tiers (§10.2, §10.6) | `08_event_generator.py` + run protocol |
| ATT&CK matrix T1210/T1068, T1486/T1204.002, T1110, T1505.003/T1190, T1498/T1499 (§10.4) | `09_attack_runner.sh` |
| Accuracy, FPR, precision, recall, F1, latency (§10.5.1) | `10_score_detections.py` |
| Windows/Linux endpoints w/ Sysmon, auditd, agents (§10.1.2) | `agents/` + victim VMs |
| CPU as % of 4 vCPUs (§10.5.2) | `07_plot_metrics.py --cores 4` |

**Known deviations to state in the methods section:** single VPS run sequentially (not two parallel
nodes); cAdvisor instead of Prometheus + Node Exporter; no Logstash deployed; endpoints are local VMs
shipping telemetry over WAN (realistic for a cloud-hosted SME SIEM, and equal for both platforms);
DDoS detection is host-log only unless you add a Suricata sensor on the Ubuntu victim (both SIEMs have
a built-in Suricata integration).

## Default credentials (lab only — change for anything internet-facing)
| Stack   | URL                    | User    | Password          |
|---------|------------------------|---------|-------------------|
| Wazuh   | https://VPS:443 / :9200 | admin   | SecretPassword    |
| Elastic | http://VPS:5601 / :9200 | elastic | BasePassword123!  |

## Notes
- cAdvisor CPU % is relative to one core (4 busy cores = 400%); use `--cores 4` when plotting.
- `Latency_ms` = alert time − `ATTACK_START`; `Pipeline_Latency_ms` (Elastic) = event time → alert.
- `04_teardown_and_reset.sh` runs `docker system prune -af --volumes`, wiping **all** Docker data on the host.
