# Advanced Deep Learning–Driven Intrusion Detection and Mitigation Framework for Botnet Attacks in 5G-Enabled Networks

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![TensorFlow](https://img.shields.io/badge/Deep_Learning-TensorFlow%2FKeras-orange)
![Flask](https://img.shields.io/badge/Web-Flask-green)

A complete final year engineering project featuring an AI-driven Intrusion Detection System (IDS) for 5G-enabled networks. This framework analyzes network traffic features, classifies them using a Deep Learning architecture (trained on the CICIDS2017 dataset), and simulates automated mitigation responses.

## Project Overview

With the rapid expansion of 5G networks, addressing security vulnerabilities has become critical. This project implements a Deep Learning–driven IDS capable of detecting and classifying malicious network flows in real time. It identifies multiple attack types including Botnets, DDoS, and Port Scans, while maintaining high accuracy with nominal classification latency.

### Importance of IDS in 5G Networks
5G networks introduce massive device density, ultra-low latency, and enhanced bandwidth. These advancements Unfortunately expand the attack surface, making traditional signature-based IDSs ineffective. A Deep Learning approach can identify complex, non-linear patterns characteristic of modern zero-day exploits and coordinated botnet attacks.

### The CICIDS2017 Dataset
The model is trained on network flow statistics inspired by the CICIDS2017 dataset. Features evaluated include:
- Flow Duration
- Total Forward / Backward Packets
- Flow Byte Rate
- Packet Length Mean
- Protocol and Ports

*Note: For demonstration, a synthetic `CICIDS2017_sample.csv` generator is included to emulate this dataset locally.*

## System Architecture

```text
[Network Traffic Entry] -> [Data Preprocessing Module] -> [Feature Extraction]
                                                                |
                                                                v
[Web Dashboard Viewer] <- [Mitigation Engine] <- [Deep Learning IDS Model]
```

1. **Traffic Input**: Simulated real-time 5G network telemetry input.
2. **Preprocessing**: Null handling, standardization, and normalization.
3. **Deep Learning Model**: A Multi-Layer Perceptron (Sequential Dense Layers + Dropout) with Softmax activation for multi-class classification.
4. **Mitigation Engine**: Simulates dropping packets, rate limiting, or quarantining malicious IP addresses.
5. **Web Interface**: A Flask-powered modern UI with glassmorphism aesthetics for monitoring and manual simulation.

## Directory Structure

```
Advanced_IDS_Project/
├── dataset/
│   └── CICIDS2017_sample.csv   # The synthesized network dataset
├── model/
│   ├── ids_model.pkl           # Trained classification model
│   ├── scaler.pkl              # Feature scaler instance
│   └── ...                     # Training graphs (Accuracy, Loss, Confusion Matrix)
├── static/
│   ├── style.css               # Styling
│   └── script.js               # Frontend JavaScript
├── templates/
│   ├── index.html              # Landing Page
│   ├── dashboard.html          # Traffic Simulation Interface
│   └── result.html             # Analysis & Mitigation Output
├── generate_data.py            # Script to generate sample data
├── preprocess.py               # Data cleaning and scaling module
├── train_model.py              # Model architecture and training script
├── predict.py                  # Core inference logic
├── mitigation.py               # Active response simulation
├── app.py                      # Flask web server
└── requirements.txt            # Project dependencies
```

## Installation & Setup

1. **Clone or Navigate to the Directory**:
   ```bash
   cd Advanced_IDS_Project
   ```

2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Generate the Dataset**:
   This will synthesize a realistic network flow dataset.
   ```bash
   python generate_data.py
   ```

4. **Train the Deep Learning Model**:
   This script processes the data, builds the NN, trains it over epochs, and outputs analytical graphs in the `model/` folder.
   ```bash
   python train_model.py
   ```

5. **Launch the Web Dashboard**:
   Start the local server.
   ```bash
   python app.py
   ```
   Open your browser and navigate to `http://localhost:5000`

## Example Output

**Prediction Result:**
`Botnet Attack Detected`

**Confidence:**
`96.4%`

**Mitigation Action Taken:**
`Blocked malicious IP address at Firewall. Generated High Priority Security Alert.`

---
*Created as a Final Year Engineering Demonstration.*
