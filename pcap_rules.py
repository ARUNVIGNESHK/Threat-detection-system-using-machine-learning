from scapy.all import rdpcap, IP, TCP, UDP
import pandas as pd
from collections import Counter, defaultdict

def _detect_alerts(row):
    alerts = []

    # IP anomalies
    if row["src_ip"] == "0.0.0.0" or row["dst_ip"] == "255.255.255.255":
        alerts.append("Suspicious IP (Spoofing/Amplification)")

    # Port anomalies
    if row["src_port"] == 0 or row["dst_port"] == 0:
        alerts.append("Illegal Port Usage")
    if row["dst_port"] in [23, 2323, 3389, 445]:
        alerts.append("Targeting risky service ports")

    # Protocol anomalies
    if row["protocol"] not in [1, 6, 17]:
        alerts.append(f"Uncommon protocol {row['protocol']} detected")
    if row["protocol"] == 1 and row["length"] < 60:
        alerts.append("Possible ICMP flood (tiny ICMP)")

    # Length anomalies
    if row["length"] > 1500:
        alerts.append("Oversized packet (possible evasion)")
    if row["length"] < 64:
        alerts.append("Suspicious tiny packet")

    return alerts


def analyze_pcap_rules(pcap_path):
    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        return pd.DataFrame(), {"error": f"Could not read PCAP: {e}"}

    rows = []
    dst_counts = Counter()
    src_counts = Counter()
    flow_counts = Counter()

    # Step 1: Parse packets and collect basic info
    for pkt in packets:
        if IP not in pkt:
            continue

        src = pkt[IP].src
        dst = pkt[IP].dst
        proto = pkt[IP].proto
        length = int(len(pkt))

        sport = dport = 0
        if TCP in pkt:
            sport = int(pkt[TCP].sport)
            dport = int(pkt[TCP].dport)
        elif UDP in pkt:
            sport = int(pkt[UDP].sport)
            dport = int(pkt[UDP].dport)

        row = {
            "src_ip": src,
            "dst_ip": dst,
            "src_port": sport,
            "dst_port": dport,
            "protocol": proto,
            "length": length,
        }

        # Detect alerts
        alerts = _detect_alerts(row)
        row["alerts"] = "; ".join(alerts) if alerts else "None"
        row["attack_type"] = "Clean"  # default
        rows.append(row)

        # Counters for heuristics
        src_counts[src] += 1
        dst_counts[dst] += 1
        flow_counts[(src, dst, dport)] += 1

    if not rows:
        return pd.DataFrame(), {}

    df = pd.DataFrame(rows)
    summary = Counter()

    # Step 2: DDoS detection (many packets to a single dst)
    for dst, cnt in dst_counts.items():
        if cnt > 500:  # threshold
            df.loc[df["dst_ip"] == dst, "attack_type"] = "DDoS"
            summary["DDoS"] += cnt

    # Step 3: PortScan detection (one src touches many dst ports)
    ports_by_src = defaultdict(set)
    for (src, dst, dport), c in flow_counts.items():
        ports_by_src[src].add(dport)
    for src, ports in ports_by_src.items():
        if len([p for p in ports if p != 0]) > 50:  # threshold
            df.loc[df["src_ip"] == src, "attack_type"] = "PortScan"
            summary["PortScan"] += len([p for p in ports if p != 0])

    # Step 4: DoS detection (tiny ICMP)
    tiny_icmp = df[(df["protocol"] == 1) & (df["length"] < 60)]
    if not tiny_icmp.empty:
        df.loc[tiny_icmp.index, "attack_type"] = "DoS"
        summary["DoS"] += len(tiny_icmp)

    # Step 5: Malware heuristic (can be extended)
    malware_packets = df[df["alerts"].str.contains("Suspicious")]
    if not malware_packets.empty:
        df.loc[malware_packets.index, "attack_type"] = "Malware"
        summary["Malware"] += len(malware_packets)

    # Step 6: Any remaining Clean packets
    clean_count = len(df[df["attack_type"] == "Clean"])
    if clean_count:
        summary["Clean"] = clean_count

    return df, dict(summary)