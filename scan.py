import numpy as np
from scapy.all import sniff, IP, TCP

print("Scanning live network for 10 seconds... Please refresh a page in your browser!")
pkts = sniff(filter="tcp", count=20, timeout=10)
if not pkts:
    print("No TCP packets captured. Try running VS Code as Administrator.")
else:
    client = pkts[0][IP].src
    fwd = [len(p) for p in pkts if IP in p and TCP in p and p[IP].src == client]
    act = [len(p) for p in pkts if IP in p and TCP in p and p[IP].src == client and len(p[TCP].payload) > 0]
    win = next((p[TCP].window for p in pkts if IP in p and TCP in p and p[IP].src == client), 8192)
   
    print(f"Fwd Packet Length Max  : {max(fwd) if fwd else 0}")
    print(f"Avg Fwd Segment Size   : {round(np.mean(fwd), 2) if fwd else 0}")
    print(f"Fwd Packet Length Mean : {round(np.mean(fwd), 2) if fwd else 0}")
    print(f"Fwd Act Data Packets   : {len(act)}")
    print(f"Init Fwd Win Bytes     : {win}")