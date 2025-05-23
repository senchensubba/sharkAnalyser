import pyshark
from collections import defaultdict
import time

def analyze(filepath):
    print("\n [Device Activity Report]")

    try:
        # Use display_filter to speed things up (adjust as needed)
        cap = pyshark.FileCapture(
            filepath,
            only_summaries=True,
            display_filter="dns or http or tcp"
        )
    except Exception as e:
        print(f" Error opening file: {e}")
        return

    start_time = time.time()

    try:
        print(" Preloading packets into memory...")
        cap.load_packets()
        print(f" Loaded {len(cap)} packets in {round(time.time() - start_time, 2)} seconds.")
    except Exception as e:
        print(f" Could not load packets: {e}")
        return

    # Dictionary to store activity data for each device (by IP)
    device_info = defaultdict(lambda: {
        'connected_to': set(),
        'used_technologies': set(),
        'total_data_sent': 0,
        'number_of_messages': 0
    })

    for i, pkt in enumerate(cap):
        try:
            src_ip = pkt.source
            dst_ip = pkt.destination
            protocol = pkt.protocol
            size = int(pkt.length)

            if src_ip:
                info = device_info[src_ip]
                info['connected_to'].add(dst_ip)
                info['used_technologies'].add(protocol)
                info['total_data_sent'] += size
                info['number_of_messages'] += 1

            if i % 100 == 0:
                print(f"   → Processed {i} packets...", end='\r')

        except Exception:
            continue

    cap.close()
    print(f"\n Processed {len(cap)} packets in total.")

    # Display results
    if not device_info:
        print(" No device activity found. Try adjusting your filter (e.g., include TCP or HTTP).")
        return

    print(f"\n Found {len(device_info)} unique devices on the network.\n")
    for device_ip, stats in device_info.items():
        print(f" Device IP Address: {device_ip}")
        print(f"   → Talked to {len(stats['connected_to'])} other devices or websites")
        print(f"   → Types of network tech used: {', '.join(stats['used_technologies'])}")
        print(f"   → Total data sent: {stats['total_data_sent']} bytes")
        print(f"   → Number of messages sent: {stats['number_of_messages']}\n")

    print(" Done. This gives you a high-level view of each device's communication behavior.\n")
