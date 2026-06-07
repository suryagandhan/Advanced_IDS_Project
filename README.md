# 🛡️ Advanced Deep Learning–Driven Intrusion Detection and Mitigation Framework for Botnet Attacks in 5G-Enabled Networks

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![TensorFlow](https://img.shields.io/badge/TensorFlow-DeepLearning-orange)
![Flask](https://img.shields.io/badge/Flask-WebApp-black)
![Scapy](https://img.shields.io/badge/Scapy-Packet_Sniffer-red)
![License](https://img.shields.io/badge/License-MIT-green)

> 🎓 Final Year Engineering Project & Published Patent Application

An AI-powered Intrusion Detection and Mitigation Framework designed for detecting and responding to Botnet, DDoS, and PortScan attacks in 5G-enabled networks using Deep Learning techniques.

The framework combines network traffic analysis, machine learning-based classification, packet capture, and automated mitigation strategies to improve network security and reliability in modern high-speed communication environments.

---

# 📌 Patent Publication

This project is associated with the following published Indian Patent Application:

**Title:** Advanced Deep Learning–Driven Intrusion Detection and Mitigation Framework for Botnet Attacks in 5G-Enabled Networks Using CICIDS2017 Dataset

* **Patent Application Number:** 202541109213 A
* **Publication Date:** 28 November 2025
* **Jurisdiction:** India
* **Role:** Inventor

---

# 🚀 Features

✔ Real-time detection of Botnet attacks  
✔ Detection of DDoS traffic patterns  
✔ PortScan identification and classification  
✔ Deep Learning-based MLP classifier  
✔ Live packet monitoring using Scapy  
✔ CSV and PCAP file analysis  
✔ Flask-based SOC Dashboard  
✔ Automated mitigation simulation  
✔ REST API support  
✔ Threat logging and alert generation  

---

# 🧠 Technologies Used

* Python
* TensorFlow / Keras
* Scikit-Learn
* Flask
* Scapy
* Pandas
* NumPy
* Matplotlib
* Seaborn

---

# 🏗️ System Architecture

The proposed framework consists of three major layers:

### 1. Telemetry Capture Layer
* Live Packet Capture
* Network Flow Extraction
* PCAP Processing
* Feature Engineering

### 2. Deep Learning Decision Layer
* Data Preprocessing
* Feature Scaling
* Neural Network Classification
* Attack Prediction

### 3. Active Response Layer
* Threat Logging
* Alert Generation
* Mitigation Simulation
* Dashboard Reporting

---

## Architecture Diagram

<p align="center">
  <img src="images/system_architecture.png" width="700">
</p>

---

# 📂 Project Structure

```text
Advanced_IDS_Project
│
├── dataset/
│   └── CICIDS2017_sample.csv
│
├── model/
│   ├── ids_model.pkl
│   ├── scaler.pkl
│   ├── accuracy_plot.png
│   ├── loss_plot.png
│   └── confusion_matrix.png
│
├── static/
├── templates/
├── images/
│
├── app.py
├── generate_data.py
├── train_model.py
├── predict.py
├── live_sniffer.py
├── pcap_parser.py
├── mitigation.py
├── requirements.txt
└── README.md
```

---

# 📊 Dataset

The project utilizes network flow characteristics inspired by the CICIDS2017 dataset.

Features used:

| Feature | Description |
|---|---|
| Flow Duration | Connection duration |
| Total Fwd Packets | Forward packets |
| Total Bwd Packets | Backward packets |
| Flow Bytes/s | Throughput rate |
| Packet Length Mean | Average packet size |
| Protocol | TCP/UDP/ICMP |
| Source Port | Source endpoint |
| Destination Port | Target endpoint |

---

# ⚙️ Installation

## Clone Repository

```bash
git clone https://github.com/suryagandhan/Advanced_IDS_Project.git
cd Advanced_IDS_Project
```

## Create Virtual Environment

```bash
python -m venv .venv
```

**Windows:**
```bash
.venv\Scripts\activate
```

**Linux / Mac:**
```bash
source .venv/bin/activate
```

## Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

---

# 📁 Generate Dataset

```bash
python generate_data.py
```

Generated file:
```text
dataset/CICIDS2017_sample.csv
```

---

# 🏋️ Train the Model

Run:
```bash
python train_model.py
```

### Training Pipeline:
1. Dataset loading
2. Feature scaling
3. Model training
4. Validation
5. Model saving

Artifacts generated:
```text
model/
├── ids_model.pkl
├── scaler.pkl
├── accuracy_plot.png
├── loss_plot.png
└── confusion_matrix.png
```

---

# 🧠 Neural Network Architecture

```text
Input Layer (8 Features)
          ↓
Dense Layer (128 ReLU)
          ↓
Dropout (0.3)
          ↓
Dense Layer (64 ReLU)
          ↓
Dropout (0.3)
          ↓
Dense Layer (32 ReLU)
          ↓
Output Layer (Softmax)
```

---

# 🌐 Run Web Dashboard

Start Flask Server:
```bash
python app.py
```

Open browser:
```text
http://127.0.0.1:5000
```

### Dashboard Features:
* Manual Prediction
* File Upload Analysis
* Live Packet Monitoring
* Threat Visualization
* Mitigation Reports

---

# 🔌 REST API

## Endpoint
```http
POST /api/predict
```

## Input
```json
{
  "Flow Duration": 223400,
  "Total Fwd Packets": 4,
  "Total Backward Packets": 3,
  "Flow Bytes/s": 4200,
  "Packet Length Mean": 680,
  "Protocol": 6,
  "Source Port": 49210,
  "Destination Port": 80
}
```

## Output
```json
{
  "prediction": {
    "is_attack": true,
    "prediction": "Botnet"
  },
  "mitigation": {
    "severity": "CRITICAL",
    "action_taken": "Threat detected and mitigation policy triggered."
  }
}
```

---

# 🛡️ Threat Classification

| Attack Type | Description |
|---|---|
| Botnet | Command and Control communication |
| DDoS | Resource exhaustion attacks |
| PortScan | Network reconnaissance |
| BENIGN | Legitimate traffic |

---

# 📈 Model Performance

Example evaluation metrics:

| Metric | Score |
|---|---|
| Accuracy | 88% |
| Precision | 84% |
| Recall | 88% |
| F1 Score | 85% |

*\*Results may vary depending on dataset size, hyperparameters, and training configuration.*

---

# 🖥️ Project Demonstration

## Dashboard

<p align="center">
  <img src="images/dashboard_main.jpg" width="800">
</p>

## Detection Results

<p align="center">
  <img src="images/simulation_results.jpg" width="800">
</p>

---

# 🔒 Cybersecurity Applications

This framework can support:
* Security Operations Centers (SOC)
* Security Information and Event Management (SIEM)
* Security Orchestration Automation and Response (SOAR)
* Enterprise Network Monitoring
* 5G Network Security
* Threat Intelligence Platforms

---

# 🛡️ Mitigation Policies

| Attack | Action |
|---|---|
| Botnet | Block suspicious communication |
| DDoS | Traffic rate limiting |
| PortScan | Connection quarantine |
| BENIGN | Log and monitor |

---

# 📌 Future Enhancements

* Integration with Windows Firewall
* Integration with iptables
* Kubernetes Security Monitoring
* Real-Time Threat Intelligence Feeds
* VirusTotal Integration
* AbuseIPDB Integration
* Explainable AI (XAI)
* SIEM Integration

---

# 👨💻 Author

**S.V. Suryagandhan**

Cybersecurity Enthusiast | SOC Analyst Aspirant | Security Researcher

**LinkedIn:** [linkedin.com/in/suryagandhan](https://linkedin.com/in/suryagandhan)

---

# ⭐ Acknowledgements

* CICIDS2017 Dataset
* TensorFlow
* Flask
* Scapy
* Scikit-Learn
* Open Source Cybersecurity Community

---

# 📄 License

This project is licensed under the MIT License.

---

⭐ If you found this project useful, consider starring the repository.
