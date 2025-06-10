import pyshark
import pandas as pd
from tqdm import tqdm  # progress bar


def build_dns_queries(pcap_file, popular_domains_file, filter_non_iot, non_iot_device_ips=None):
    """    Build DNS queries DataFrame from a pcap file.
    Args:
        pcap_file (str): Path to the pcap file containing DNS queries.
        popular_domains_file (str): Path to a CSV file containing popular domains.
        filter_non_iot (bool): Whether to filter out non-IoT devices based on IPs.
        non_iot_device_ips (list): List of IPs of non-IoT devices to filter out.
    Returns:
        pd.DataFrame: DataFrame containing DNS queries with columns ['ip', 'query_name', 'timestamp'].
        pd.DataFrame: DataFrame containing domains queried by IoT devices.
    """

    # Load popular domains
    popular_domains = set(pd.read_csv(popular_domains_file, header=None)[1])

    # Optionally: Load device mapping to filter out non-iot devices
    if filter_non_iot and not filter_non_iot:
        raise ValueError("You set filter_non_iot=True, but did not provide a list of non-IoT ips.")

    iot_rows = set()
    domain_rows = set()

    with pyshark.FileCapture(pcap_file, display_filter='dns') as capture:
        for packet in tqdm(capture, desc="Processing IoTDNS packets"):
            if 'DNS' not in packet:
                continue

            if not (hasattr(packet, 'dns') and hasattr(packet, 'ip')):
                continue

            domain = packet.dns.qry_name
            ip = packet.ip.dst
            timestamp = packet.frame_info.time_relative

            # filter out non-IoT devices if specified
            if filter_non_iot and ip in non_iot_device_ips:
                continue

            if domain not in popular_domains:
                domain_rows.add(domain)

            iot_rows.add((ip, domain, timestamp))

    iot_devices_queries = pd.DataFrame.from_records(
        list(iot_rows),
        columns=['ip', 'query_name', 'timestamp']
    )

    iot_devices_queries['timestamp'] = pd.to_numeric(iot_devices_queries['timestamp'])
    total_time = iot_devices_queries['timestamp'].max() - iot_devices_queries['timestamp'].min()

    iot_domains = pd.DataFrame({'query_name': list(domain_rows)})

    return iot_devices_queries, iot_domains, total_time
