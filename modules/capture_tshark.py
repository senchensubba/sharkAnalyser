import subprocess
import time
import os

def start_capture(interface='Wi-Fi', output_file='captures/output.pcap', duration=10):
    # Ensure output folder exists
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    # Build the tshark command
    cmd = [
        "tshark",
        "-i", interface,
        "-a", f"duration:{duration}",  # Auto-stop after X seconds
        "-w", output_file              # Output file
    ]

    print(f"Starting capture on {interface} for {duration} seconds...")
    subprocess.run(cmd)
    print(f"Capture saved to {output_file}")

def capture_tshark_main():
    start_capture()

if __name__ == "__main__":
    # Captures tshark data, commnet out to not collect data
    capture_tshark_main()