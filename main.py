from modules import traffic_summary, device_activity, capture_tshark

def main():
    filepath = 'sample_data/test123.pcapng'
    print(f"Loading file: {filepath}")

    traffic_summary.analyze(filepath)
    device_activity.analyze(filepath)

def capture_tshark_main():
    capture_tshark.start_capture()

if __name__ == "__main__":
    # Captures tshark data, commnet out to not collect data
    # capture_tshark_main()

    main()


