import pyshark
from collections import defaultdict
from urllib.parse import urlparse
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


def detect_suspicious_tlds_and_geos(filepath, suspicious_tlds=None, risky_countries=None, mock_geo_ip=None):
    print("\n [Suspicious TLD and Geolocation Detection]")

    if suspicious_tlds is None:
        suspicious_tlds = {".ru", ".cn", ".kp", ".ir", ".su", ".xyz"}

    if risky_countries is None:
        risky_countries = {"Russia", "China", "Iran", "North Korea"}

    if mock_geo_ip is None:
        mock_geo_ip = {
            "93.184.216.34": "United States",  # example.com
            "203.0.113.1": "China",
            "185.38.175.132": "Russia"
        }

    try:
        cap = pyshark.FileCapture(
            filepath,
            display_filter="dns"
        )
    except Exception as e:
        print(f" Could not open the file: {e}")
        return

    flagged_domains = set()
    flagged_ips = set()

    for pkt in cap:
        try:
            if hasattr(pkt.dns, 'qry_name'):
                domain = pkt.dns.qry_name.lower()
                tld = "." + domain.split('.')[-1]
                if tld in suspicious_tlds:
                    flagged_domains.add(domain)

            if hasattr(pkt, 'ip') and pkt.ip.dst in mock_geo_ip:
                country = mock_geo_ip[pkt.ip.dst]
                if country in risky_countries:
                    flagged_ips.add((pkt.ip.dst, country))

        except Exception:
            continue

    cap.close()

    if flagged_domains:
        print("\n ALERT: DNS queries to suspicious TLDs:")
        for dom in sorted(flagged_domains):
            print(f"   → {dom}")

    if flagged_ips:
        print("\n ALERT: IP communication with risky geolocations:")
        for ip, country in sorted(flagged_ips):
            print(f"   → {ip} ({country})")

    if not flagged_domains and not flagged_ips:
        print(" No suspicious TLDs or geo-locations found.")

    print("\n Finished TLD and Geo check.\n")


def detect_odd_protocol_behavior(filepath):
    print("\n [Odd Protocol Behavior Detection]")

    try:
        cap = pyshark.FileCapture(filepath, display_filter="tcp or http")
    except Exception as e:
        print(f" Could not open file: {e}")
        return

    suspicious_http_ports = set()
    handshake_tracker = defaultdict(set)  # key = (src, dst), value = TCP flags seen

    print(" Scanning for protocol misbehavior...")
    for pkt in cap:
        try:
            if hasattr(pkt, 'http') and hasattr(pkt.tcp, 'dstport'):
                port = int(pkt.tcp.dstport)
                if port != 80:  # HTTP not on 80 is weird
                    suspicious_http_ports.add(port)

            if hasattr(pkt.tcp, 'flags') and hasattr(pkt, 'ip'):
                flags = int(pkt.tcp.flags, 16)
                src = pkt.ip.src
                dst = pkt.ip.dst
                key = (src, dst)

                # SYN = 0x02, SYN-ACK = 0x12, ACK = 0x10
                handshake_tracker[key].add(flags)

        except Exception:
            continue

    cap.close()

    if suspicious_http_ports:
        print("\n ALERT: HTTP traffic on non-standard ports:")
        for port in sorted(suspicious_http_ports):
            print(f"   → Port {port}")

    suspicious_connections = []
    for (src, dst), flags in handshake_tracker.items():
        if 0x02 in flags and 0x10 not in flags and 0x12 not in flags:
            suspicious_connections.append((src, dst))

    if suspicious_connections:
        print("\n ALERT: Incomplete TCP handshakes (possible scans):")
        for src, dst in suspicious_connections:
            print(f"   → {src} → {dst} (SYN only, no ACK/SYN-ACK)")

    if not suspicious_http_ports and not suspicious_connections:
        print(" No unusual protocol behavior detected.")

    print("\n Finished protocol anomaly analysis.\n")


def detect_encrypted_traffic_to_untrusted_hosts(filepath, suspicious_sni_keywords=None):
    print("\n [Encrypted Traffic to Untrusted Hosts Detection]")

    if suspicious_sni_keywords is None:
        suspicious_sni_keywords = {"c2", "malware", "stealth", "dark", "anon", "xyz"}

    try:
        cap = pyshark.FileCapture(filepath, display_filter="ssl.handshake or tls.handshake")
    except Exception as e:
        print(f" Could not open the file: {e}")
        return

    flagged_certs = []
    flagged_sni = []

    for pkt in cap:
        try:
            if hasattr(pkt.tls, 'handshake_type'):
                hs_type = pkt.tls.handshake_type
                if '11' in hs_type or '0b' in hs_type:  # Certificate handshake
                    if hasattr(pkt.tls, 'certificate_issuer'):
                        issuer = pkt.tls.certificate_issuer.lower()
                        if 'self' in issuer:
                            flagged_certs.append((pkt.ip.dst, "Self-signed certificate"))

                    if hasattr(pkt.tls, 'certificate_validity_not_after'):
                        # Optionally: Add expiry check logic
                        pass  # Skipping deep date parsing for now

                if hasattr(pkt.tls, 'handshake_extensions_server_name'):
                    sni = pkt.tls.handshake_extensions_server_name.lower()
                    if any(keyword in sni for keyword in suspicious_sni_keywords):
                        flagged_sni.append((pkt.ip.dst, sni))

        except AttributeError:
            continue

    cap.close()

    if flagged_certs:
        print("\n ALERT: TLS connections with self-signed certs:")
        for ip, msg in flagged_certs:
            print(f"   → {ip}: {msg}")

    if flagged_sni:
        print("\n ALERT: Suspicious domains in SNI field:")
        for ip, sni in flagged_sni:
            print(f"   → {ip}: {sni}")

    if not flagged_certs and not flagged_sni:
        print(" No suspicious TLS certificate behavior detected.")

    print("\n Finished TLS traffic inspection.\n")
