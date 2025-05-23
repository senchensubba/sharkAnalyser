import pyshark
import pandas as pd
import time

def analyze(filepath):
    print("\n [Network Traffic Summary]")
    print(" Preparing to scan packets...")

    try:
        cap = pyshark.FileCapture(
    filepath,
    only_summaries=True,
    display_filter="dns or http"
    )

    except Exception as e:
        print(f" Could not open the file: {e}")
        return

    start_time = time.time()
    
    try:
        print(" Preloading packets into memory...")
        cap.load_packets()
        print(f" Loaded {len(cap)} packets in {round(time.time() - start_time, 2)} seconds.")
    except Exception as e:
        print(f" Failed to load packets: {e}")
        return

    packets = []
    print(" Starting analysis...")

    for i, pkt in enumerate(cap):
        try:
            packets.append({
                'No': int(pkt.no),
                'Time': float(pkt.time),
                'Source': pkt.source,
                'Destination': pkt.destination,
                'Protocol': pkt.protocol,
                'Length': int(pkt.length),
            })

            if i % 100 == 0:
                print(f"   → Processed {i} packets...", end='\r')

        except Exception:
            continue

    cap.close()
    print(f"\n Processed {len(packets)} packets in total.")

    df = pd.DataFrame(packets)

    print(f"\n Total messages observed: {len(df)}")
    print(f" Total data transferred: {df['Length'].sum()} bytes")

    print("\n Most Common Communication Types (Protocols):")
    for protocol, count in df['Protocol'].value_counts().head(10).items():
        print(f"   → {protocol}: {count} messages")

    print("\n Devices that sent the most messages (Source IPs):")
    for ip, count in df['Source'].value_counts().head(5).items():
        print(f"   → {ip}: {count} messages sent")

    print("\n Most contacted devices or websites (Destination IPs):")
    for ip, count in df['Destination'].value_counts().head(5).items():
        print(f"   → {ip}: {count} messages received")

    print("\n Finished traffic summary.\n")
