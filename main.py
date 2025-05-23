from modules import traffic_summary, device_activity

def main():
    filepath = 'sample_data/test123.pcapng'
    print(f"Loading file: {filepath}")

    traffic_summary.analyze(filepath)
    device_activity.analyze(filepath)

if __name__ == "__main__":
    main()
