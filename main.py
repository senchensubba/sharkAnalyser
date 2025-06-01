from modules import traffic_summary, device_activity, capture_tshark, local_db, ip_analysis

def main(filepath="captures\\output.pcap"):
    print(f"Loading file: {filepath}")

    traffic_summary.analyze(filepath)
    device_activity.analyze(filepath)
    ip_set = ip_analysis.get_unique_ips(filepath)

    black_listed_ips = {"192.168.1.232", "192.168.1.1"}
    ip_analysis.check_black_listed_ips(ip_set, black_listed_ips)


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


