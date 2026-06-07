import pandas as pd
import numpy as np
import os

def generate_sample_dataset(filepath, num_samples=5000):
    np.random.seed(42)
    
    # Feature columns based on CICIDS2017
    data = {
        'Flow Duration': np.random.randint(100, 10000000, num_samples),
        'Total Fwd Packets': np.random.randint(1, 100, num_samples),
        'Total Backward Packets': np.random.randint(0, 100, num_samples),
        'Flow Bytes/s': np.random.uniform(0, 100000, num_samples),
        'Packet Length Mean': np.random.uniform(20, 1500, num_samples),
        'Protocol': np.random.choice([6, 17, 0], num_samples), # TCP, UDP, HOPOPT
        'Source Port': np.random.randint(1024, 65535, num_samples),
        'Destination Port': np.random.choice([80, 443, 22, 21, 8080, 3389], num_samples)
    }
    
    # Generate labels
    # Normal: ~60%, Botnet: ~15%, DDoS: ~15%, PortScan: ~5%, Infiltration: ~5%
    labels = np.random.choice(
        ['BENIGN', 'Bot', 'DDoS', 'PortScan', 'Infiltration'],
        num_samples,
        p=[0.6, 0.15, 0.15, 0.05, 0.05]
    )
    
    data['Label'] = labels
    
    df = pd.DataFrame(data)
    
    # Introduce some logical correlations for attacks
    
    # Botnet: Usually high flow duration and specific ports
    botnet_mask = df['Label'] == 'Bot'
    df.loc[botnet_mask, 'Destination Port'] = np.random.choice([8080, 6667], botnet_mask.sum())
    
    # DDoS: Lots of packets, small length
    ddos_mask = df['Label'] == 'DDoS'
    df.loc[ddos_mask, 'Total Fwd Packets'] = np.random.randint(100, 1000, ddos_mask.sum())
    df.loc[ddos_mask, 'Packet Length Mean'] = np.random.uniform(20, 100, ddos_mask.sum())
    
    # PortScan: Small flow duration, very few packets
    ps_mask = df['Label'] == 'PortScan'
    df.loc[ps_mask, 'Flow Duration'] = np.random.randint(1, 100, ps_mask.sum())
    df.loc[ps_mask, 'Total Fwd Packets'] = 1
    df.loc[ps_mask, 'Total Backward Packets'] = 0
    
    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    
    df.to_csv(filepath, index=False)
    print(f"Sample dataset generated at {filepath} with {num_samples} records.")

if __name__ == "__main__":
    output_path = os.path.join("dataset", "CICIDS2017_sample.csv")
    generate_sample_dataset(output_path, num_samples=10000)
