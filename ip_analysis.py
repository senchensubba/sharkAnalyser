import pyshark
from traffic_summary import send_gmail_email

def get_unique_ips(filepath='captures/my_traffic.pcap'):
    try:
        cap = pyshark.FileCapture(filepath)
        ip_set = set()

        for packet in cap:
            try:
                if 'IP' in packet:
                    ip_set.add(packet.ip.src)
                    ip_set.add(packet.ip.dst)
            except AttributeError:
                continue

        cap.close()

        print("Unique IPs:")
        for ip in sorted(ip_set):
            print(ip)
        print(f"ip set {ip_set}")
        return ip_set
    except Exception as e:
        print(f"Error reading capture file: {e}")

def check_black_listed_ips(ip_set, black_listed_ips):
    try:
        for ip in ip_set:
            if ip in black_listed_ips:
                ip_info = f"ALERT - Black listed ip is on your network!: {ip}"
                print(ip_info)
                send_gmail_email(
                    subject="Network Alert: Black Listed IP",
                    body=ip_info,
                    sender="johnsmith314350@gmail.com",
                    recipient="johnsmith314350@gmail.com",  # or any recipient
                    username="johnsmith314350@gmail.com",
                    password="ohjlpjjajarmltwi"  # <-- app password here
                )

    except Exception as e:
        print(f"Error checking blacklisted IPs: {e}")
        
def check_black_listed_ip(ip, black_listed_ips):
    try:
        if ip in black_listed_ips:
            ip_info = f"ALERT - Black listed ip is on your network!: {ip}"
            print(ip_info)
            send_gmail_email(
                subject="Network Alert: Black Listed IP",
                body=ip_info,
                sender="johnsmith314350@gmail.com",
                recipient="johnsmith314350@gmail.com",  # or any recipient
                username="johnsmith314350@gmail.com",
                password="ohjlpjjajarmltwi"  # <-- app password here
            )
    except Exception as e:
        print(f"Error checking blacklisted IPs: {e}")


if __name__ == "__main__":
    ip_set = get_unique_ips('captures/my_traffic.pcap')

    black_listed_ips = {"192.168.1.232", "192.168.1.1"}
    check_black_listed_ips(ip_set, black_listed_ips)

