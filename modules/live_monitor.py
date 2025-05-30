import pyshark
from ip_analysis import check_black_listed_ip
from traffic_summary import send_gmail_email

def live_monitor(interface='Wi-Fi', black_listed_ips={"192.168.1.232", "192.168.1.1"}):
    print(f"Starting live monitoring on {interface}... Press Ctrl+C to stop.\n")
    capture = pyshark.LiveCapture(interface=interface)
    
    try:
        for packet in capture.sniff_continuously():
            try:
                if 'IP' in packet:
                    check_black_listed_ip(packet.ip.src, black_listed_ips)
                    check_black_listed_ip(packet.ip.dst, black_listed_ips)
                    ip_info = f"[{packet.highest_layer}] {packet.ip.src} -> {packet.ip.dst}"
                    print(ip_info)
                    send_gmail_email(
                        subject="Network Alert: Black Listed IP",
                        body=ip_info,
                        sender="johnsmith314350@gmail.com",
                        recipient="johnsmith314350@gmail.com",  # or any recipient
                        username="johnsmith314350@gmail.com",
                        password="ohjlpjjajarmltwi"  # <-- app password here
                    )
            except AttributeError:
                continue
    except KeyboardInterrupt:
        print("\nMonitoring stopped by user.")

if __name__ == "__main__":
    live_monitor()
