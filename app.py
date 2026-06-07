from flask import Flask, render_template, request, jsonify
import os
import random
import logging
import ipaddress
import pandas as pd
from predict import predict_traffic
from mitigation import simulate_mitigation
from pcap_parser import parse_pcap_to_dataframe
from live_sniffer import live_engine

app = Flask(__name__)
app.secret_key = 'super_secret_key_ids'

# Configure logging to file
logging.basicConfig(
    filename='log.txt',
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)

# Silence Flask/Werkzeug default access logs
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

# Global stats for dashboard
dashboard_stats = {
    'total_analyzed': 0,
    'total_attacks': 0,
    'attack_types': {}
}

def update_stats(prediction_list):
    if isinstance(prediction_list, dict):
        prediction_list = [prediction_list]
        
    dashboard_stats['total_analyzed'] += len(prediction_list)
    for p in prediction_list:
        if p['is_attack']:
            dashboard_stats['total_attacks'] += 1
            attack_type = p['prediction']
            dashboard_stats['attack_types'][attack_type] = dashboard_stats['attack_types'].get(attack_type, 0) + 1

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/detect', methods=['POST'])
def detect():
    if request.method == 'POST':
        # Get data from the form
        try:
            features = {
                'Flow Duration': float(request.form.get('flow_duration', 0)),
                'Total Fwd Packets': float(request.form.get('total_fwd_packets', 0)),
                'Total Backward Packets': float(request.form.get('total_bwd_packets', 0)),
                'Flow Bytes/s': float(request.form.get('flow_bytes', 0)),
                'Packet Length Mean': float(request.form.get('packet_length_mean', 0)),
                'Protocol': float(request.form.get('protocol', 6)),
                'Source Port': float(request.form.get('src_port', 0)),
                'Destination Port': float(request.form.get('dst_port', 0))
            }
            source_ip = request.form.get('source_ip', f"192.168.1.{random.randint(2, 254)}")
            
            logging.info("Incoming traffic detected")
            logging.info("Extracting features")
            
            # Prediction
            prediction_result = predict_traffic(features)
            update_stats(prediction_result)
            
            if prediction_result['is_attack']:
                logging.warning(f"Botnet attack detected") if 'Botnet' in prediction_result['prediction'] else logging.warning(f"{prediction_result['prediction']} attack detected")
                logging.info(f"ACTION: Blocking IP {source_ip}")
            else:
                logging.info(f"Normal traffic processed")
            
            # Mitigation Simulation
            mitigation_report = simulate_mitigation(prediction_result, source_ip=source_ip)
            
            return render_template('result.html', 
                                   result=prediction_result, 
                                   mitigation=mitigation_report,
                                   features=features,
                                   source_ip=source_ip)
            
        except Exception as e:
            logging.error(f"Error during detection: {str(e)}")
            return f"Error during detection: {str(e)}"

@app.route('/upload_batch', methods=['POST'])
def upload_batch():
    if 'file' not in request.files:
        return "No file part", 400
    file = request.files['file']
    if file.filename == '':
        return "No selected file", 400
    
    try:
        logging.info(f"Batch file upload detected ({file.filename})")
        suspicious_files = []
        if file.filename.endswith('.csv'):
            df = pd.read_csv(file)
        elif file.filename.endswith('.pcap'):
            temp_path = "temp_uploaded.pcap"
            file.save(temp_path)
            logging.info(f"Extracting features from PCAP via Scapy...")
            df, suspicious_files = parse_pcap_to_dataframe(temp_path)
            if os.path.exists(temp_path):
                os.remove(temp_path)
        else:
            return "Unsupported file format. Please upload .csv or .pcap", 400
            
        if df.empty:
            return "No valid network flows found in file", 400

        predictions = predict_traffic(df)
        update_stats(predictions)
        
        attacks_found = 0
        attack_details = {}
        internal_victims = set()
        external_attackers_counts = {}
        benign_ips_detected = set()
        targeted_ports = {}
        
        # Simulated Threat Intel Whitelist
        KNOWN_BENIGN_IPS = {
            '8.8.8.8': 'Google DNS',
            '8.8.4.4': 'Google DNS',
            '1.1.1.1': 'Cloudflare',
            '204.79.197.200': 'Microsoft',
            '31.13.64.21': 'Facebook',
            '2.16.119.157': 'CDN/Cloud',
            '23.211.200.86': 'Akamai CDN',
            '13.107.4.52': 'Microsoft'
        }
        
        def is_internal(ip_str):
            try:
                if str(ip_str).startswith('10.') or str(ip_str).startswith('192.168.'):
                    return True
                # Simple check for 172.16.x.x - 172.31.x.x
                if str(ip_str).startswith('172.'):
                    second_octet = int(str(ip_str).split('.')[1])
                    if 16 <= second_octet <= 31:
                        return True
                return ipaddress.ip_address(ip_str).is_private
            except:
                return False
        
        for i, pred in enumerate(predictions):
            src_ip = df.iloc[i].get('Source IP', f"10.0.0.{random.randint(1,250)}") if 'Source IP' in df.columns else "Unknown IP"
            dst_ip = df.iloc[i].get('Destination IP', "Unknown IP") if 'Destination IP' in df.columns else "Unknown IP"
            dst_port = df.iloc[i].get('Destination Port', 0) if 'Destination Port' in df.columns else 0
            
            if pred['is_attack']:
                # Suppress PortScan false positives for normal web browsing to Instagram/Google (443/80)
                if pred['prediction'] == 'PortScan' and dst_port in [53, 80, 443, 8080]:
                    pred['is_attack'] = False
                    pred['prediction'] = 'BENIGN'
                    continue
                    
                attacks_found += 1
                attack_type = pred['prediction']
                attack_details[attack_type] = attack_details.get(attack_type, 0) + 1
                
                # Victim/Attacker Classification
                if is_internal(src_ip):
                    internal_victims.add(src_ip)
                    if not is_internal(dst_ip) and dst_ip != "Unknown IP":
                        if dst_ip in KNOWN_BENIGN_IPS:
                            benign_ips_detected.add(f"{dst_ip} ({KNOWN_BENIGN_IPS[dst_ip]})")
                        else:
                            external_attackers_counts[dst_ip] = external_attackers_counts.get(dst_ip, 0) + 1
                else:
                    if not is_internal(src_ip) and src_ip != "Unknown IP":
                        if src_ip in KNOWN_BENIGN_IPS:
                            benign_ips_detected.add(f"{src_ip} ({KNOWN_BENIGN_IPS[src_ip]})")
                        else:
                            external_attackers_counts[src_ip] = external_attackers_counts.get(src_ip, 0) + 1
                    if is_internal(dst_ip):
                        internal_victims.add(dst_ip)
                        
                # Track targeted destination ports
                port_str = str(int(dst_port))
                targeted_ports[port_str] = targeted_ports.get(port_str, 0) + 1
                
                if i < 5:  # Log only first few to avoid spamming
                    logging.warning(f"{attack_type} attack detected involving {src_ip} and {dst_ip}")
        
        # Sort attackers by volume
        sorted_attackers = sorted(external_attackers_counts.items(), key=lambda x: x[1], reverse=True)
        primary_attacker = sorted_attackers[0][0] if sorted_attackers else None
        
        # Sort ports by frequency
        top_ports = dict(sorted(targeted_ports.items(), key=lambda item: item[1], reverse=True)[:5])
        
        # Auto-generate SOC Conclusion
        conclusion = "No active threats detected in the processed batch."
        if attacks_found > 0:
            if 'Bot' in attack_details or 'Botnet' in attack_details or "SYN Flood" in attack_details or "UDP Flood" in attack_details:
                if len(internal_victims) > 0 and primary_attacker:
                    victims_str = ', '.join(list(internal_victims)[:3])
                    conclusion = f"The PCAP reveals a potential infection where internal host(s) ({victims_str}) are communicating with a suspicious external IP ({primary_attacker}). The repeated connections and high traffic volume indicate possible Command and Control (C2) communication, suggesting malware activity and possible data exfiltration."
                else:
                    conclusion = "Volumetric or Botnet attack detected impacting network assets."
            elif 'DDoS' in attack_details or 'ICMP Flood' in attack_details:
                conclusion = "Denial of Service attack detected. High volume of malicious flows attempting to exhaust network resources and disrupt availability."
            else:
                conclusion = "Malicious network anomalies detected requiring further SOC investigation."

        logging.info(f"Batch processing complete. Analyzed {len(predictions)} flows, found {attacks_found} attacks.")
        
        return render_template('batch_result.html',
                               total_flows=len(predictions),
                               attacks_found=attacks_found,
                               attack_details=attack_details,
                               internal_victims=list(internal_victims),
                               sorted_attackers=sorted_attackers,
                               primary_attacker=primary_attacker,
                               benign_ips=list(benign_ips_detected),
                               top_ports=top_ports,
                               conclusion=conclusion,
                               suspicious_files=suspicious_files)
    except Exception as e:
        logging.error(f"Error processing file: {str(e)}")
        return f"Error processing file: {str(e)}", 500

@app.route('/get_stats')
def get_stats():
    # Return both stats and recent logs
    try:
        if os.path.exists('log.txt'):
            with open('log.txt', 'r') as f:
                lines = f.readlines()
                # Get last 50 lines to show in UI
                logs = [line.strip() for line in lines[-50:]]
        else:
            logs = ["[INFO] Log file empty or not created yet."]
    except Exception:
        logs = ["[ERROR] Unable to read log file."]
        
    return jsonify({
        'stats': dashboard_stats,
        'logs': logs
    })

# Route for API testing 
@app.route('/api/predict', methods=['POST'])
def api_predict():
    data = request.json
    prediction = predict_traffic(data)
    update_stats(prediction)
    mitigation = simulate_mitigation(prediction)
    return jsonify({
        'prediction': prediction,
        'mitigation': mitigation
    })

@app.route('/toggle_live_sniffer', methods=['POST'])
def toggle_live_sniffer():
    data = request.get_json()
    action = data.get('action')
    if action == 'start':
        live_engine.start()
        return jsonify({"message": "Live interface hooking activated."})
    elif action == 'stop':
        live_engine.stop()
        return jsonify({"message": "Live engine disconnected."})
    return jsonify({"error": "Invalid action"}), 400

if __name__ == '__main__':
    # Make sure model exists before running app
    if not os.path.exists("model/ids_model.pkl") and not os.path.exists("model/ids_model.h5"):
        print("Warning: Model files not found. Please run train_model.py first.")
    
    # Initialize log
    with open('log.txt', 'w') as f:
        f.write("[INFO] Monitoring started...\n")
        
    app.run(debug=True, port=5000)
