import datetime

def simulate_mitigation(prediction_result, source_ip="192.168.1.100"):
    """
    Simulates automated responses and mitigation actions based on IDS predictions.
    """
    mitigation_report = {
        'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'event': prediction_result['prediction'],
        'actions_taken': [],
        'status': 'Logged'
    }
    
    if prediction_result['is_attack']:
        attack_type = prediction_result['prediction']
        
        # Log the incident
        mitigation_report['actions_taken'].append(f"Logged {attack_type} intrusion attempt.")
        
        # Determine specific mitigation based on attack
        if attack_type in ['Bot', 'DDoS']:
            mitigation_report['actions_taken'].append(f"Blocked malicious IP address: {source_ip} at Firewall.")
            mitigation_report['actions_taken'].append("Generated High Priority Security Alert.")
            mitigation_report['status'] = "Mitigated - IP Blocked"
            
        elif attack_type == 'PortScan':
            mitigation_report['actions_taken'].append(f"Rate limited traffic from source IP: {source_ip}.")
            mitigation_report['actions_taken'].append("Generated Medium Priority Security Alert.")
            mitigation_report['status'] = "Mitigated - Rate Limited"
            
        else:
            mitigation_report['actions_taken'].append(f"Quarantined traffic from source IP: {source_ip}.")
            mitigation_report['status'] = "Mitigated - Quarantined"
            
    else:
        mitigation_report['actions_taken'].append("Traffic allowed cleanly.")
        mitigation_report['status'] = "Allowed"
        
    return mitigation_report

if __name__ == "__main__":
    from predict import predict_traffic
    
    sample_attack = {
        'prediction': 'Bot',
        'confidence': 96.4,
        'is_attack': True
    }
    
    print("Simulating Mitigation for Attack:")
    print(simulate_mitigation(sample_attack, "10.0.0.45"))
