# Advanced Deep Learning–Driven Intrusion Detection and Mitigation Framework for Botnet Attacks in 5G-Enabled Networks

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python Badge">
  <img src="https://img.shields.io/badge/TensorFlow-2.x-FF6F00?style=for-the-badge&logo=tensorflow&logoColor=white" alt="TensorFlow Badge">
  <img src="https://img.shields.io/badge/Flask-2.x-000000?style=for-the-badge&logo=flask&logoColor=white" alt="Flask Badge">
  <img src="https://img.shields.io/badge/scikit--learn-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white" alt="scikit-learn Badge">
  <img src="https://img.shields.io/badge/Scapy-Packet_Sniffer-red?style=for-the-badge" alt="Scapy Badge">
</p>

---

## 📖 Project Abstract & Introduction
With the massive scalability, ultra-low latency, and device density introduced by **5G network infrastructures**, the network attack surface has expanded exponentially. Traditional signature-based Intrusion Detection Systems (IDS) fail against zero-day exploits, fast-flux DNS configurations, and stealthy distributed botnets. 

This project implements an **Advanced Deep Learning–Driven Intrusion Detection and Mitigation Framework** designed to identify, trace, and mitigate network threats (specifically Botnets, Denial of Service (DDoS), and Port Scans) in real-time. Integrating a **Keras/TensorFlow Multi-Layer Perceptron (MLP)** model, a **Scapy-powered live network hook**, and an **interactive glassmorphic SOC (Security Operations Center) Web Dashboard**, this framework offers an end-to-end sandbox representing production-grade AI-driven cybersecurity.

---

## ⚡ Core Features

*   🔍 **Scapy-Hooked Live Packet Sniffing**: Dynamically captures raw network socket traffic, compiles packets into bidirectional network flows, and analyzes flow metrics in real time.
*   🧠 **Deep Learning Intrusion Classification**: Employs a Sequential Deep Neural Network (Dense layers + Dropout regularizations) trained on flow characteristics matching the industry-standard **CICIDS2017** benchmark dataset.
*   🖥️ **Premium Glassmorphic SOC Terminal**: An interactive HTML5/CSS3/JS Web Interface incorporating:
    *   Dynamic statistical trackers (Total Analyzed, Attacks Stopped).
    *   Live system logging terminal stream showing backend threat classification logs.
    *   Toggles to start/stop the hardware-level live network interfaces.
*   🛡️ **Autonomous Threat Mitigation Engine**: Simulates immediate firewall blocks, network isolation quarantine, and detailed digital forensic incident report generation for compromised victim hosts and remote Command & Control (C2) servers.
*   📦 **Dual-Mode File Analysis**: Supports uploading network packet captures (`.pcap`) and tabular flow sheets (`.csv`) for bulk scanning, automated attacker-victim mapping, and machine-learning threat intelligence correlation.

---

## 🏗️ System Architecture & Workflow

The framework operates via three primary layers: **Telemetry Capture**, **Deep Learning Decision Core**, and **Active Orchestration**.

```mermaid
graph TD
    A["5G Network Interface Telemetry"] -->|Raw Packets| B("Scapy Live Sniffer Engine")
    A -->|Bulk Files (.pcap / .csv)| C("Batch File Ingestion")
    B -->|Bilateral Flow Compilation| D["Data Preprocessor & Feature Scaler"]
    C -->|Extract Flow Features| D
    D -->|Standardized Tensor (8 Features)| E{"Deep Learning Neural Net"}
    E -->|Normal / BENIGN| F("Verify Connection Integrity")
    E -->|Threat Flagged| G("Active Mitigation Engine")
    G -->|Dynamic IP Blocks & Firewall Rules| H["Host Network Isolation / Log Actions"]
    G -->|Threat Alert Payload| I("Flask Glassmorphic SOC Web Dashboard")
    F -->|Telemetry Stats| I
    
    style A fill:#1a1a2e,stroke:#3b82f6,stroke-width:2px,color:#fff
    style E fill:#0f172a,stroke:#f59e0b,stroke-width:2px,color:#fff
    style G fill:#7f1d1d,stroke:#ef4444,stroke-width:2px,color:#fff
    style I fill:#052e16,stroke:#10b981,stroke-width:2px,color:#fff
```

---

## 📊 Feature Extraction & Network Metrics

The model evaluates network sessions across **8 primary traffic dimensions** to differentiate standard user behavior from malicious activities:

| Feature Dimension | Extraction Target | Technical Importance in 5G Security |
| :--- | :--- | :--- |
| **Flow Duration** | Session duration in microseconds | Detects high-speed PortScans vs. slow-polling Botnet beacons |
| **Total Fwd Packets** | Packets sent client $\rightarrow$ server | Captures bulk payload transfers or initial connection handshakes |
| **Total Bwd Packets** | Packets sent server $\rightarrow$ client | Measures response ratios; essential for identifying command responses |
| **Flow Bytes/s** | Aggregated payload throughput rate | Identifies volumetric resource exhaustion attacks (DDoS) |
| **Packet Length Mean** | Mathematical mean of packet sizes | Exposes abnormally small packets (control packets) vs. large payloads |
| **Protocol** | Layer 4 Protocol identifier (TCP/UDP/ICMP)| Maps the transport layer vector used by the attacker |
| **Source Port** | Client connection socket port | Identifies host application origins or spoofed source ports |
| **Destination Port** | Targeted service port on victim | Determines targeted services (SSH, HTTP, Database) |

---

## 📂 Project Directory Structure

```directory
Advanced_IDS_Project/
├── dataset/
│   └── CICIDS2017_sample.csv    # Synthesized realistic network flow data
├── model/
│   ├── ids_model.h5             # Serialized Deep Learning Model (TensorFlow/Keras)
│   ├── ids_model.pkl            # Fallback Neural Network (Scikit-Learn MLP)
│   ├── scaler.pkl               # Standardized feature scaler
│   ├── label_mapping.pkl        # Numerical-to-Class index mapping
│   ├── accuracy_plot.png        # Training accuracy curve
│   ├── loss_plot.png            # Model training loss curve
│   └── confusion_matrix.png     # Validation evaluation metrics
├── static/
│   ├── style.css                # Premium modern dark UI stylesheet
│   └── script.js                # Asynchronous API telemetry handlers
├── templates/
│   ├── index.html               # Abstract and dashboard entrance interface
│   ├── dashboard.html           # Live SOC telemetry, graphs, and terminals
│   ├── result.html              # Individual telemetry classification analysis
│   └── batch_result.html        # Detailed forensic report for PCAP/CSV uploads
├── app.py                       # Core Flask web server & route controllers
├── generate_data.py             # Script to generate realistic synthetic telemetry
├── preprocess.py                # Flow standardization and scaling module
├── train_model.py               # NN compiler, optimizer, and trainer
├── predict.py                   # Model loading and inference wrapper
├── live_sniffer.py              # Scapy background socket polling thread
├── mitigation.py                # Active response simulation module
├── pcap_parser.py               # Low-level Scapy raw PCAP feature extractor
└── requirements.txt             # Project library dependencies
```

---

## ⚙️ Installation & Workspace Setup

### Prerequisites
*   **Python 3.8 to 3.11** installed.
*   *For Live Sniffing*: **Npcap** (Windows) or **libpcap** (Linux/Mac) must be installed to support raw packet capture via Scapy.
    *   *Windows users*: Download Npcap from the official [Npcap website](https://npcap.com/).

### Setup Commands
1. **Navigate to the Project Directory**:
   ```bash
   cd Advanced_IDS_Project
   ```

2. **Create and Activate a Virtual Environment** (Optional but Recommended):
   ```bash
   python -m venv venv
   # Windows Activation:
   venv\Scripts\activate
   # Linux/Mac Activation:
   source venv/bin/activate
   ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

---

## 🚀 Execution & Usage Guide

Follow these sequential steps to train the Deep Learning model and launch the interactive SOC interface:

### Step 1: Synthesize Network Flow Data
Generate a local mock dataset modeling the telemetry metrics of the standard CICIDS2017 catalog:
```bash
python generate_data.py
```

### Step 2: Train the Neural Network Core
Train the model to identify anomalies. This script will pre-process the dataset, export the scaler, compile the model, and dump performance validation figures (accuracy, loss, and confusion matrix) directly in the `model/` subdirectory:
```bash
python train_model.py
```

### Step 3: Run the SOC Dashboard Application
Launch the Flask development server to view the interface locally:
```bash
python app.py
```
- Open your browser and navigate to: **`http://127.0.0.1:5000`**

### Step 4: Interact & Test Threats
- **Single Flow Simulation**: Input manual telemetry values into the dashboard to test individual classifications and read active firewalls responses.
- **Batch Upload & Forensics**: Upload a packet capture (`.pcap`) or flow registry (`.csv`) to trigger automated victim identification, top targeted port listings, and Command & Control IP tracking.
- **Live Interface Sniffing**: Toggle the Live Sniffer switch on the dashboard to trigger Scapy. The console will capture background packets circulating on your local machine, run them through the model, and print security decisions live onto the terminal screen.

---

## 🛡️ Autonomous Response Playbooks (Mitigation)

When the Deep Learning Core detects a threat, the framework automatically triggers the simulation of a corresponding security response policy:

| Detected Threat Class | Assigned Defense Strategy | Active Remediation Log Actions |
| :--- | :--- | :--- |
| **Botnet Connection** | **C2 Socket Interdiction** | Identifies target IP, terminates local sockets, and adds IP to the outbound blackhole firewall rule list. |
| **DDoS Attack** | **Volumetric Rate Limiting** | Triggers dynamic packet dropping, restricts bandwidth on the ingress interface, and logs source IPs to the quarantine zone. |
| **PortScan Anomalies** | **Host Quarantine** | Temporarily isolates the requesting host machine from accessing subnet resources and drops incoming requests. |
| **BENIGN / Normal** | **Continuous Audit** | Allows packets to pass freely and updates general dashboard network statistics. |

---

> [!TIP]
> **Reducing False Positives in Live Environments**
> To avoid false positives on background network noise (e.g. DNS lookups, multicast SSDP, or active web browsing over ports 80/443), the system incorporates a **dynamic validation filter** in the live packet sniffer module (`live_sniffer.py`) ensuring clean, high-fidelity security logs.

---
*Created as a Final Year Engineering Demonstration. Powered by Advanced Agentic AI Development.*
