import pyshark
import pandas as pd

def detect_unusual_ports(filepath):
    print("\n [Unusual Port Usage Detection]")
    try:
        cap = pyshark.FileCapture(
            filepath,
            display_filter="tcp or udp"
        )
    except Exception as e:
        print(f" Could not open the file: {e}")
        return

    suspicious_ports = {4444, 6667, 31337}
    expected_ports = {
        22: "SSH",
        80: "HTTP",
        443: "HTTPS",
        53: "DNS",
        25: "SMTP"
    }

    seen_ports = {}
    unusual_ports = []

    print(" Scanning packets for port information...")
    for pkt in cap:
        try:
            transport_layer = pkt.transport_layer
            src_port = int(pkt[pkt.transport_layer].srcport)
            dst_port = int(pkt[pkt.transport_layer].dstport)

            for port in (src_port, dst_port):
                if port not in seen_ports:
                    seen_ports[port] = 1
                else:
                    seen_ports[port] += 1

                if port in suspicious_ports:
                    print(f" ALERT: Suspicious port detected -> Port {port}")
                elif port not in expected_ports and port < 1024:
                    unusual_ports.append(port)

        except Exception:
            continue

    cap.close()

    if unusual_ports:
        print("\n Unusual service ports used (below 1024 but not standard):")
        for port in sorted(set(unusual_ports)):
            print(f"   -> Port {port}")
    else:
        print(" No unusual low-numbered ports found.")

    print("\n Finished port usage analysis.\n")


def detect_frequent_dns_requests(filepath, dns_threshold=100, threat_feed=None):
    print("\n [Frequent DNS Request Detection]")
    try:
        cap = pyshark.FileCapture(
            filepath,
            display_filter="dns"
        )
    except Exception as e:
        print(f" Could not open the file: {e}")
        return

    dns_counter = {}
    suspicious_domains = []

    print(" Scanning DNS traffic...")
    for pkt in cap:
        try:
            if hasattr(pkt.dns, 'qry_name') and hasattr(pkt, 'ip'):
                src_ip = pkt.ip.src
                domain = pkt.dns.qry_name.lower()

                if src_ip not in dns_counter:
                    dns_counter[src_ip] = []

                dns_counter[src_ip].append(domain)

                # Basic suspicious domain check
                if threat_feed and domain in threat_feed:
                    print(f" ALERT: {domain} flagged as suspicious (seen in threat feed)")

        except AttributeError:
            continue

    cap.close()

    # Flag IPs with excessive DNS requests
    print("\n Clients with high DNS activity:")
    for ip, domains in dns_counter.items():
        if len(domains) > dns_threshold:
            print(f"   -> {ip} made {len(domains)} DNS requests")
            # Optional: print top domains
            top_domains = pd.Series(domains).value_counts().head(3)
            for dom, count in top_domains.items():
                print(f"      -> {dom}: {count} requests")

    print("\n Finished DNS analysis.\n")
