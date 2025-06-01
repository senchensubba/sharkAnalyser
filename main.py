from traffic_summary import analyze
from device_activity import analyze as device_analyze
from ip_analysis import get_unique_ips, check_black_listed_ips
from activity_monitoring import detect_unusual_ports, detect_frequent_dns_requests, detect_suspicious_tlds_and_geos, detect_odd_protocol_behavior, detect_encrypted_traffic_to_untrusted_hosts
import capture_tshark
import local_db

def main(filepath="captures\\output.pcap"):
    print(f"Loading file: {filepath}")

    # General network stats
    analyze(filepath)

    # Device communication behavior
    device_analyze(filepath)

    # Get and analyze IPs
    ip_set = get_unique_ips(filepath)
    black_listed_ips = {"192.168.1.232", "192.168.1.1"}
    check_black_listed_ips(ip_set, black_listed_ips)

    # New: Unusual Port Usage Detection
    detect_unusual_ports(filepath)

    # New: Frequent DNS Request Detection
    threat_domains = {"malicious.com", "stealth-c2.io", "badexample.xyz"}  # Mock threat feed
    detect_frequent_dns_requests(filepath, dns_threshold=80, threat_feed=threat_domains)

    detect_suspicious_tlds_and_geos(filepath)

    detect_odd_protocol_behavior(filepath)

    detect_encrypted_traffic_to_untrusted_hosts(filepath)

def capture_tshark_main():
    capture_tshark.start_capture()

def database_setup():
    db = local_db.LocalDB()
    db.create_table("""
    CREATE TABLE IF NOT EXISTS BLACK_LIST_IPS (
        ip TEXT PRIMARY KEY
    )""")


if __name__ == "__main__":
    # Captures tshark data, commnet out to not collect data
    # capture_tshark_main()

    main("sample_data/test123.pcapng")


