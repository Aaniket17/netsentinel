import numpy as np
from scapy.all import sniff, IP, TCP

print("10 seconds ke liye live network scan ho raha hai... Browser me koi page refresh karein!")
pkts = sniff(filter="tcp", count=20, timeout=10)
if not pkts:
    print("Koi TCP packet nahi mila. VS Code ko Run as Administrator karke try karein.")
else:
    client = pkts[0][IP].src
    fwd = [len(p) for p in pkts if IP in p and TCP in p and p[IP].src == client]
    act = [len(p) for p in pkts if IP in p and TCP in p and p[IP].src == client and len(p[TCP].payload) > 0]
    win = next((p[TCP].window for p in pkts if IP in p and TCP in p and p[IP].src == client), 8192)
    print("\n=== IN VALUES KO DASHBOARD ME PASTE KAREIN ===")
    print(f"Fwd Packet Length Max  : {max(fwd) if fwd else 0}")
    print(f"Avg Fwd Segment Size   : {round(np.mean(fwd), 2) if fwd else 0}")
    print(f"Fwd Packet Length Mean : {round(np.mean(fwd), 2) if fwd else 0}")
    print(f"Fwd Act Data Packets   : {len(act)}")
    print(f"Init Fwd Win Bytes     : {win}")