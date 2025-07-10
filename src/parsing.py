import pyshark
import pandas as pd
from tqdm import tqdm  # progress bar


def build_dns_queries(pcap_file, popular_domains_file, filter_with_ips, non_iot_device_ips):
    """    Build DNS queries DataFrame from a pcap file.
    Args:
        pcap_file (str): Path to the pcap file containing DNS queries.
        popular_domains_file (str): Path to a CSV file containing popular domains.
        filter_with_ips (bool): Whether to filter out non-IoT devices based on IPs or based on MAC address.
        non_iot_device_ips (list): List of IPs of non-IoT devices to filter out.
    Returns:
        pd.DataFrame: DataFrame containing DNS queries with columns ['ip', 'query_name', 'timestamp'].
        pd.DataFrame: DataFrame containing domains queried by IoT devices.
    """
    # Load popular domains
    popular_domains = set(pd.read_csv(popular_domains_file, header=None)[1])

    iot_rows = set()
    domain_rows = set()

    # queries only
    filter_expr = 'dns && dns.flags.response == 0'
    filter_expr_IoTFinder = 'dns' #IoTFinder data only has responses

    with pyshark.FileCapture(pcap_file, display_filter=filter_expr) as capture:
        for packet in tqdm(capture, desc="Processing IoTDNS packets"):
            if 'DNS' not in packet:
                continue

            if not (hasattr(packet, 'dns') and hasattr(packet, 'ip')):
                continue

            domain = packet.dns.qry_name
            timestamp = packet.frame_info.time_relative
            is_response = packet.dns.flags_response.lower() == 'true'

            # filter out non-IoT devices if specified
            if filter_with_ips:
                if is_response:
                    identifier = packet.ip.dst
                else:
                    identifier = packet.ip.src
            else:
                if is_response:
                    identifier = packet.eth.dst
                else:
                    identifier = packet.eth.src

            if identifier not in non_iot_device_ips:
                continue

            if domain not in popular_domains:
                domain_rows.add(domain)

            iot_rows.add((identifier, domain, timestamp))

    iot_devices_queries = pd.DataFrame.from_records(
        list(iot_rows),
        columns=['ip', 'query_name', 'timestamp']
    )

    iot_devices_queries['timestamp'] = pd.to_numeric(iot_devices_queries['timestamp'])
    total_time = iot_devices_queries['timestamp'].max() - iot_devices_queries['timestamp'].min()

    iot_domains = pd.DataFrame({'query_name': list(domain_rows)})

    return iot_devices_queries, iot_domains, total_time
