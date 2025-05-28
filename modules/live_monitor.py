import pyshark
from ip_analysis import check_black_listed_ip

def live_monitor(interface='Wi-Fi', black_listed_ips={"192.168.1.232", "192.168.1.1"}):
    print(f"Starting live monitoring on {interface}... Press Ctrl+C to stop.\n")
    capture = pyshark.LiveCapture(interface=interface)
    
    try:
        for packet in capture.sniff_continuously():
            try:
                if 'IP' in packet:
                    check_black_listed_ip(packet.ip.src, black_listed_ips)
                    check_black_listed_ip(packet.ip.dst, black_listed_ips)
                    print(f"[{packet.highest_layer}] {packet.ip.src} → {packet.ip.dst}")
            except AttributeError:
                continue
    except KeyboardInterrupt:
        print("\nMonitoring stopped by user.")

if __name__ == "__main__":
    live_monitor()
