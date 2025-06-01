import pyshark
import pandas as pd
import time
import smtplib
from email.mime.text import MIMEText

def send_gmail_email(subject, body, sender, recipient, username, password):
    try:
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = sender
        msg['To'] = recipient

        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(username, password)
            server.sendmail(sender, [recipient], msg.as_string())
            print(f"Email sent to {recipient} with subject: {subject}")
    except Exception as e:
        print(f"Failed to send email: {e}")

def check_large_downloads(df, threshold_bytes, email_config):
    large_downloads = {}
    alert_body = ""

    for ip in df['Destination'].unique():
        total_received = df[df['Destination'] == ip]['Length'].sum()
        if total_received > threshold_bytes:
            large_downloads[ip] = total_received
            alert_body += f"{ip}: {total_received/1024/1024:.2f} MB\n"

    if large_downloads:
        print("\nALERT: Large downloads detected!")
        for ip, size in large_downloads.items():
            print(f"  -> {ip} received {size/1024/1024:.2f} MB")

        send_gmail_email(
            subject="Network Alert: Large Download Detected",
            body=alert_body,
            sender=email_config['sender'],
            recipient=email_config['recipient'],
            username=email_config['username'],
            password=email_config['password']
        )

def analyze(filepath):
    print("\n [Network Traffic Summary]")
    print(" Preparing to scan packets...")

    try:
        cap = pyshark.FileCapture(
            filepath,
            only_summaries=True,
            display_filter="dns or http"
        )
    except Exception as e:
        print(f" Could not open the file: {e}")
        return

    start_time = time.time()

    try:
        print(" Preloading packets into memory...")
        cap.load_packets()
        print(f" Loaded {len(cap)} packets in {round(time.time() - start_time, 2)} seconds.")
    except Exception as e:
        print(f" Failed to load packets: {e}")
        return

    packets = []
    print(" Starting analysis...")

    for i, pkt in enumerate(cap):
        try:
            packets.append({
                'No': int(pkt.no),
                'Time': float(pkt.time),
                'Source': pkt.source,
                'Destination': pkt.destination,
                'Protocol': pkt.protocol,
                'Length': int(pkt.length),
            })
            if i % 100 == 0:
                print(f"   -> Processed {i} packets...", end='\r')
        except Exception:
            continue

    cap.close()
    print(f"\n Processed {len(packets)} packets in total.")

    df = pd.DataFrame(packets)

    check_large_downloads(
        df=df,
        threshold_bytes=100 * 1024 * 1024,  # 100 MB
        email_config={
            'sender': "johnsmith314350@gmail.com",
            'recipient': "johnsmith314350@gmail.com",
            'username': "johnsmith314350@gmail.com",
            'password': "ohjlpjjajarmltwi"
        }
    )

    print(f"\n Total messages observed: {len(df)}")
    print(f" Total data transferred: {df['Length'].sum()} bytes")

    print("\n Most Common Communication Types (Protocols):")
    for protocol, count in df['Protocol'].value_counts().head(10).items():
        print(f"   -> {protocol}: {count} messages")

    print("\n Devices that sent the most messages (Source IPs):")
    for ip, count in df['Source'].value_counts().head(5).items():
        print(f"   -> {ip}: {count} messages sent")

    print("\n Most contacted devices or websites (Destination IPs):")
    for ip, count in df['Destination'].value_counts().head(5).items():
        print(f"   -> {ip}: {count} messages received")

    print("\n Finished traffic summary.\n")
