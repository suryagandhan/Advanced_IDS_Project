from scapy.all import rdpcap, IP, TCP, UDP, ICMP, Raw
import pandas as pd
import hashlib
import re

def parse_pcap_to_dataframe(pcap_path):
    """
    Parses a packet capture (.pcap) file, aggregates packets into bidirectional 
    flows using a 5-tuple key, and extracts the 8 target features required for the IDS model.
    """
    packets = rdpcap(pcap_path)
    flows = {}
    
    for pkt in packets:
        if IP in pkt:
            ip_layer = pkt[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            proto = ip_layer.proto
            
            src_port = 0
            dst_port = 0
            tcp_flags_val = 0
            
            if TCP in pkt:
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                proto = 6
                tcp_flags_val = pkt[TCP].flags.value if hasattr(pkt[TCP].flags, 'value') else int(pkt[TCP].flags)
            elif UDP in pkt:
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
                proto = 17
            elif ICMP in pkt:
                src_port = 0
                dst_port = pkt[ICMP].type # Store ICMP type in dst_port to help heuristics
                proto = 1
            else:
                proto = ip_layer.proto
                
            # Define 5-tuple key (direction independent so we track fwd/bwd)
            # Fwd is assumed as the first packet seen in a connection
            flow_key_1 = (src_ip, dst_ip, src_port, dst_port, proto)
            flow_key_2 = (dst_ip, src_ip, dst_port, src_port, proto)
            
            length = len(pkt)
            timestamp = float(pkt.time)
            
            if flow_key_1 in flows:
                f = flows[flow_key_1]
                f['fwd_pkts'] += 1
                f['fwd_bytes'] += length
                f['total_length'] += length
                f['end_time'] = timestamp
                f['packet_lengths'].append(length)
                if Raw in pkt:
                    f['fwd_payload'] += pkt[Raw].load
                
                # Update TCP flag counts for the flow
                if tcp_flags_val > 0:
                    if tcp_flags_val & 0x02: f['syn_count'] += 1
                    if tcp_flags_val & 0x10: f['ack_count'] += 1
                    if tcp_flags_val & 0x01: f['fin_count'] += 1
                    if tcp_flags_val & 0x04: f['rst_count'] += 1
                    if tcp_flags_val & 0x08: f['psh_count'] += 1
                    if tcp_flags_val & 0x20: f['urg_count'] += 1
                    
            elif flow_key_2 in flows:
                f = flows[flow_key_2]
                f['bwd_pkts'] += 1
                f['bwd_bytes'] += length
                f['total_length'] += length
                f['end_time'] = max(f['end_time'], timestamp)
                f['packet_lengths'].append(length)
                if Raw in pkt:
                    f['bwd_payload'] += pkt[Raw].load
                
                # Update TCP flag counts for the flow (backward)
                if tcp_flags_val > 0:
                    if tcp_flags_val & 0x02: f['syn_count'] += 1
                    if tcp_flags_val & 0x10: f['ack_count'] += 1
                    if tcp_flags_val & 0x01: f['fin_count'] += 1
                    if tcp_flags_val & 0x04: f['rst_count'] += 1
                    if tcp_flags_val & 0x08: f['psh_count'] += 1
                    if tcp_flags_val & 0x20: f['urg_count'] += 1
                    
            else:
                flows[flow_key_1] = {
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'protocol': proto,
                    'fwd_pkts': 1,
                    'bwd_pkts': 0,
                    'fwd_bytes': length,
                    'bwd_bytes': 0,
                    'total_length': length,
                    'start_time': timestamp,
                    'end_time': timestamp,
                    'packet_lengths': [length],
                    'syn_count': 1 if (tcp_flags_val & 0x02) else 0,
                    'ack_count': 1 if (tcp_flags_val & 0x10) else 0,
                    'fin_count': 1 if (tcp_flags_val & 0x01) else 0,
                    'rst_count': 1 if (tcp_flags_val & 0x04) else 0,
                    'psh_count': 1 if (tcp_flags_val & 0x08) else 0,
                    'urg_count': 1 if (tcp_flags_val & 0x20) else 0,
                    'fwd_payload': pkt[Raw].load if Raw in pkt else b"",
                    'bwd_payload': b""
                }
                
    features_list = []
    suspicious_files = []
    
    for flow in flows.values():
        duration_sec = flow['end_time'] - flow['start_time']
        duration_ms = duration_sec * 1000.0
        duration_micro = duration_sec * 1000000.0  # CICIDS2017 uses microsecs
        
        # Avoid division by zero for bytes/s calculation
        duration_for_rate = duration_sec if duration_sec > 0 else 0.0001
        
        bytes_per_sec = flow['total_length'] / duration_for_rate
        avg_packet_length = sum(flow['packet_lengths']) / len(flow['packet_lengths'])
        
        features_list.append({
            'Source IP': flow['src_ip'],
            'Destination IP': flow['dst_ip'],
            'Flow Duration': duration_micro,
            'Total Fwd Packets': flow['fwd_pkts'],
            'Total Backward Packets': flow['bwd_pkts'],
            'Flow Bytes/s': bytes_per_sec,
            'Packet Length Mean': avg_packet_length,
            'Protocol': flow['protocol'],
            'Source Port': flow['src_port'],
            'Destination Port': flow['dst_port'],
            
            # Heuristic features (not used by ML directly, but checked before ML model)
            'SYN_Count': flow['syn_count'],
            'ACK_Count': flow['ack_count'],
            'FIN_Count': flow['fin_count'],
            'RST_Count': flow['rst_count'],
            'PSH_Count': flow['psh_count'],
            'URG_Count': flow['urg_count']
        })
        
        # Deep Packet Inspection (DPI) for Malicious Payloads
        is_malicious = False
        filename = "Unknown_Executable.exe"
        
        # Check FWD payload for HTTP GET specifying an explicit executable
        get_match = re.search(rb'GET\s+[^\s]*?([a-zA-Z0-9_.-]+(?:\.exe|\.dll|\.bat|\.ps1|\.sh|\.bin))', flow['fwd_payload'], re.IGNORECASE)
        if get_match:
            filename = get_match.group(1).decode('utf-8', errors='ignore')
            is_malicious = True 
            
        # Check BWD payload for precise Content-Disposition filename
        cd_match = re.search(rb'Content-Disposition:.*?filename="?([a-zA-Z0-9_.-]+(?:\.exe|\.dll|\.bat|\.ps1|\.sh|\.bin)?)"?', flow['bwd_payload'], re.IGNORECASE)
        if cd_match:
            extracted_name = cd_match.group(1).decode('utf-8', errors='ignore')
            if extracted_name.lower().endswith(('.exe', '.dll', '.bat', '.ps1', '.sh', '.bin')):
                filename = extracted_name
                is_malicious = True
                
        # Deep packet check for magic bytes (Windows Executable Payload)
        if b'MZ' in flow['bwd_payload'] and b'This program cannot be run in DOS mode' in flow['bwd_payload']:
            is_malicious = True
            
            # If it's a confirmed executable but the strict regex failed to find a clean '.exe' name
            if filename == "Unknown_Executable.exe":
                # 1. Try to extract from the raw GET URI path (e.g. GET /payload?link=1)
                general_get = re.search(rb'GET\s+([^\s]+)\s+HTTP', flow['fwd_payload'], re.IGNORECASE)
                if general_get:
                    raw_uri = general_get.group(1).decode('utf-8', errors='ignore')
                    base_target = raw_uri.split('?')[0].rstrip('/').split('/')[-1]
                    if len(base_target) > 0 and len(base_target) < 50:
                        filename = base_target if '.' in base_target else base_target + '.exe'
                # 2. Try to extract from Content-Disposition without strict extensions
                elif cd_match:
                    raw_cd = cd_match.group(1).decode('utf-8', errors='ignore')
                    if len(raw_cd) > 0:
                        filename = raw_cd if '.' in raw_cd else raw_cd + '.exe'
            
        if is_malicious:
            payload_to_hash = flow['bwd_payload'] if flow['bwd_payload'] else flow['fwd_payload']
            
            # Strip HTTP headers to get the pure file binary for accurate VirusTotal hashing
            header_end = payload_to_hash.find(b'\r\n\r\n')
            if header_end != -1:
                binary_payload = payload_to_hash[header_end + 4:]
            else:
                binary_payload = payload_to_hash
                
            file_hash = hashlib.sha256(binary_payload).hexdigest()
            suspicious_files.append({
                'filename': filename,
                'victim_ip': flow['src_ip'],
                'attacker_ip': flow['dst_ip'],
                'hash': file_hash
            })
        
    return pd.DataFrame(features_list), suspicious_files
