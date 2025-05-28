from modules import traffic_summary, device_activity, capture_tshark, local_db

def main(filepath="captures\\output.pcap"):
    print(f"Loading file: {filepath}")

    traffic_summary.analyze(filepath)
    device_activity.analyze(filepath)

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


