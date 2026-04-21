# 🛡️ HoneyPot Network Security System

> An educational **multi-attack honeypot** platform that simulates real-world attack vectors, captures attacker behaviour, classifies threats with machine learning, and visualises results in an interactive cyber-security themed dashboard.

---

## 📸 Screenshots

> **Cybersecurity Control Center** — Dark theme with neon-green/cyan palette, real-time status indicators, and live attack feeds.

---

## 🎓 Educational Purpose

Built for a **Network Security** course to demonstrate attack detection across multiple OSI layers:

| Layer | Protocol | Attack Type | Detection Method |
|-------|----------|-------------|------------------|
| Layer 2 — Data Link | ARP | ARP Spoofing / MITM | Scapy raw packet capture |
| Layer 3 — Network | ICMP | Ping Flood, Ping of Death | ICMP packet analysis |
| Layer 3 — Network | TCP | Port Scanning | Connection pattern monitoring |
| Layer 4 — Transport | TCP | SSH Brute-Force | Honeypot session capture |
| Layer 7 — Application | DNS | DNS Tunneling, Amplification | Protocol-level analysis |

**What you will learn:**
- Network reconnaissance & attack techniques
- DoS / DDoS attack vectors
- Man-in-the-Middle (MITM) attack principles
- Intrusion Detection System (IDS) design
- Behavioural pattern matching
- Machine Learning applied to cybersecurity

---

## 🧩 Features

### 🔍 Attack Detection — 5 Honeypot Types
| Honeypot | Port | Detects |
|----------|------|---------|
| SSH Honeypot | 2222 | Password brute-force, reconnaissance |
| Port Scan Detector | — | nmap-style scans (stealth, aggressive, sweep) |
| DNS Honeypot | 53 | DNS tunnelling, amplification attacks |
| ARP Spoof Detector | — | Layer-2 MITM / gratuitous ARP |
| ICMP Detector | — | Ping flood, Ping of Death |

### 🤖 Machine Learning Pipeline
- **13 attack class labels** across all 5 attack types
- **Random Forest** classifier with behavioural feature engineering
- **Real-time prediction** during active honeypot sessions
- **Feature importance** analysis for explainability

### 📊 React Frontend (Cyber UI)
- **Control Center** — launch simulations, explore data, trigger training, open dashboard
- **Live Simulation Feed** — real-time terminal log stream with progress tracking
- **Data Explorer** — sortable/filterable attack session table with CSV export
- **Security Dashboard** — pie chart, top attacker IPs, severity table, live refresh
- **ML Training Screen** — 4-stage progress tracker with live log output

### 📈 Streamlit Dashboard
- Multi-attack visualisation with type filtering
- Severity classification (Critical / High / Medium / Low)
- Cross-attack correlation (multi-vector detection)
- Attack timeline with trend analysis

---

## 📁 Project Structure

```text
HoneyPot-Network-Security/
│
├── Frontend/                        # React + Vite cyber UI
│   ├── src/
│   │   ├── components/              # All screen components
│   │   │   ├── Header.tsx
│   │   │   ├── HomeScreen.tsx
│   │   │   ├── SimulationScreen.tsx
│   │   │   ├── TrainingScreen.tsx
│   │   │   ├── DashboardScreen.tsx
│   │   │   ├── DataExplorerScreen.tsx
│   │   │   └── PostSimulationScreen.tsx
│   │   ├── lib/api.ts               # API bridge client
│   │   └── index.css                # Cyber theme (neon green/cyan)
│   └── server/
│       ├── api.mjs                  # Express API bridge
│       └── dev.mjs                  # Dev orchestrator
│
├── honeypot/                        # Honeypot servers
│   ├── honeypot_server.py           # SSH honeypot
│   ├── portscan_detector.py         # Port scan detection
│   ├── dns_honeypot.py              # Fake DNS resolver
│   ├── arp_spoof_detector.py        # ARP spoofing detection
│   └── icmp_detector.py             # ICMP attack detection
│
├── ml/                              # Machine learning pipeline
│   ├── train_model_multi.py         # Multi-attack model training
│   ├── attack_classifier_multi.py   # Inference / classifier
│   ├── feature_extractors.py        # Feature engineering
│   └── labeling_rules.py            # Attack label definitions
│
├── dashboard/                       # Streamlit analytics dashboard
│   ├── dashboard_multi.py           # Multi-attack dashboard
│   └── control_center.py            # Alternative control dashboard
│
├── logging/
│   └── attack_logger.py             # Unified CSV logger
│
├── models/                          # Saved model artefacts (generated)
│   └── session_models.py            # Data models
│
├── data/                            # Runtime attack logs (generated)
│   └── attack_logs.csv
│
├── attack_simulator.py              # SSH attack simulator
├── attack_simulator_portscan.py     # Port scan simulator
├── attack_simulator_dns.py          # DNS attack simulator
├── attack_simulator_arp.py          # ARP spoofing simulator
├── attack_simulator_icmp.py         # ICMP attack simulator
├── run_all_simulators.py            # Run all simulators in one command
├── honeypot_manager.py              # Orchestrates all detectors/honeypots
├── config.yaml                      # Port numbers, thresholds, interfaces
└── requirements.txt
```

---

## 🚀 Quick Start

### Prerequisites

- **Python 3.10+**
- **Node.js 18+** (for the React frontend)
- **Administrator / root privileges** — required for ARP, ICMP, DNS honeypots
- **Windows**: Install [Npcap](https://nmap.org/npcap/) for Scapy packet capture
- **Linux/macOS**: `libpcap` (`sudo apt install libpcap-dev`)

---

### 1 — Install Python Dependencies

```powershell
# From repository root
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 2 — Install Frontend Dependencies

```powershell
cd Frontend
npm install
cd ..
```

---

## ▶️ Running the Full Stack

### Option A — One Command (Recommended)

```powershell
# From the Frontend directory
cd Frontend
npm run dev
```

Or from the repository root:

```powershell
npm run dev:all
```

This launches:
- **Vite dev server** → http://localhost:8080
- **API bridge** → http://localhost:8787

### Then start the Honeypot Manager (new terminal, run as Administrator)

```powershell
.\.venv\Scripts\Activate.ps1
python honeypot_manager.py
```

The **"Honeypot Active"** status pill in the header turns green once the manager is running.

---

### Option B — Run Individually

```powershell
# Terminal 1 — SSH Honeypot
python honeypot/honeypot_server.py

# Terminal 2 — Port Scan Detector
python honeypot/portscan_detector.py

# Terminal 3 — DNS Honeypot (admin required)
python honeypot/dns_honeypot.py

# Terminal 4 — ARP Detector (admin required)
python honeypot/arp_spoof_detector.py

# Terminal 5 — ICMP Detector (admin required)
python honeypot/icmp_detector.py
```

---

## 🎯 Generating Attack Traffic

### Recommended — Run All Simulators

```powershell
python run_all_simulators.py             # 3 rounds each (default)
python run_all_simulators.py --quick     # 1 round each (fast demo)
python run_all_simulators.py --rounds 5  # Custom rounds
python run_all_simulators.py --intensive # 10 rounds each
```

> The simulator auto-skips attacks that require privileges not available in the current session (e.g., ARP/ICMP without admin).

### Or run individual simulators

```powershell
python attack_simulator.py                      # SSH brute-force
python attack_simulator_portscan.py --rounds 3  # Port scanning
python attack_simulator_dns.py                  # DNS attacks
python attack_simulator_arp.py                  # ARP spoofing (admin)
python attack_simulator_icmp.py --rounds 3      # ICMP flood (admin)
```

---

## 🤖 Training the ML Model

```powershell
python ml/train_model_multi.py
```

Output saved to `models/attack_model.pkl` and `models/label_encoder.pkl`.

---

## 📊 Streamlit Dashboard

```powershell
streamlit run dashboard/dashboard_multi.py
```

Or click **"Open Streamlit"** inside the React frontend → Security Dashboard page.

---

## 🏷️ Attack Classes (13 Total)

| Category | Label | Description |
|----------|-------|-------------|
| **SSH** | `ssh_normal` | Normal SSH activity |
| | `ssh_brute_force` | High login attempts, no commands |
| | `ssh_reconnaissance` | Shell commands indicating recon |
| **Port Scan** | `portscan_stealth` | Slow, randomised scan |
| | `portscan_aggressive` | Fast sequential scanning |
| | `portscan_sweep` | Quick common-port sweep |
| **DNS** | `dns_normal` | Normal DNS queries |
| | `dns_tunneling` | Data exfiltration via DNS |
| | `dns_amplification` | DDoS amplification attempts |
| **ARP** | `arp_spoofing` | Gratuitous ARP broadcasts |
| | `arp_poisoning` | MAC/IP conflict (MITM) |
| **ICMP** | `icmp_flood` | High-rate ICMP packets |
| | `icmp_ping_of_death` | Oversized ICMP packets |

---

## ⚙️ Configuration

Edit `config.yaml` to customise:
- Honeypot port numbers
- Enable / disable individual detectors
- Detection thresholds (rate limits, packet sizes, etc.)
- Network interface selection for packet capture

---

## 📝 Logged Data Schema

All attacks are unified in `data/attack_logs.csv`:

| Field | Description |
|-------|-------------|
| `timestamp` | ISO 8601 datetime |
| `ip_address` | Attacker source IP |
| `mac_address` | Layer-2 MAC (where applicable) |
| `attack_type` | One of 5 attack categories |
| `session_duration` | Duration in seconds |
| `packet_count` | Total packets in session |
| `severity` | critical / high / medium / low |
| `detected` | Boolean — ML prediction result |

SSH extras: `login_attempts`, `successful_login`, `commands_sent`  
Port Scan extras: `ports_scanned`, `scan_type`, `scan_speed`, `syn_count`  
DNS extras: `dns_query`, `query_rate`, `tunneling_detected`, `amplification_detected`  
ARP extras: `arp_op_type`, `gratuitous_arp`, `ip_conflict`, `arp_reply_rate`  
ICMP extras: `icmp_type`, `packet_size`, `icmp_rate`, `flood_detected`, `oversized_detected`

---

## 🔧 Troubleshooting

| Issue | Fix |
|-------|-----|
| `Permission denied` | Run as Administrator (Windows) or `sudo` (Linux) |
| `Model files not found` | Run `python ml/train_model_multi.py` first |
| `Scapy import error` on Windows | Install [Npcap](https://nmap.org/npcap/) |
| `Port already in use` | Stop conflicting process or change port in `config.yaml` |
| `No data in dashboard` | Generate traffic: `python run_all_simulators.py --quick` |
| `Honeypot Active` pill stays red | Start `python honeypot_manager.py` in an admin terminal |
| `Admin Privileges` pill stays red | Restart VS Code / terminal as Administrator |

---

## 📦 Python Dependencies

```
pandas>=2.0.0
scikit-learn>=1.3.0
streamlit>=1.28.0
joblib>=1.3.0
scapy>=2.5.0
pyyaml>=6.0
paramiko>=3.0.0
```

## 🖥️ Frontend Dependencies

```
React 18 + Vite
TypeScript
TailwindCSS
Framer Motion
Recharts
React Router DOM
@tanstack/react-query
```

---

## ⚠️ Security Notice

> **This is an EDUCATIONAL project for a Network Security course.**

- ❌ Do **NOT** expose honeypot ports to the public internet
- ✅ Run only in an isolated lab / VM environment
- ⚠️ ARP and ICMP simulators can disrupt local network traffic — use on an isolated network!
- 🔒 SSH honeypot listens on port **2222** (not 22) to avoid conflicting with your system SSH

---

## 👥 Team

| Name | Role |
|------|------|
| Vinay R S | Project Lead & ML Pipeline |
| *(add teammates here)* | *(their role)* |

---

## 📜 License

This project is for **educational use only** as part of a Network Security course.  
Do not use attack simulators against systems you do not own or have explicit permission to test.
