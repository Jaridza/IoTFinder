import pyshark
import pandas as pd
from tqdm import tqdm # progress bar

def build_dns_queries(pcap_file, device_mapping_file, popular_domains_file):
    """
    Process DNS queries from a pcap file and returns:
    - A DataFrame of all DNS queries from IoT devices.
    - A DataFrame of IoT domains (excluding popular domains).
    Args:
        pcap_file (str): Path to the pcap file.
        device_mapping_file (str): Path to the CSV file containing device mapping used to filter non-iot devices.
        popular_domains_file (str): Path to the CSV file containing popular domains to filter out.
    Returns:
        pd.DataFrame: DataFrame containing DNS queries from IoT devices.
        pd.DataFrame: DataFrame containing IoT domains (excluding popular domains).
    """

    # Load popular domains
    popular_domains_csv = pd.read_csv(popular_domains_file, header=None)
    # popular_domains = popular_domains_csv[1].tolist()
    popular_domains = set(popular_domains_csv[1])

    # Load device mapping to filter out non-iot devices
    device_mapping = pd.read_csv(device_mapping_file, header=None)
    non_iot_devices = [53, 54, 58, 61, 62, 63, 64, 65]
    # iot_mapping = device_mapping.drop(non_iot_devices)
    iot_mapping = device_mapping[~device_mapping[0].isin(non_iot_devices)]

    # ipaddresses = iot_mapping[1].tolist()
    iot_ip_set = set(iot_mapping[1])

    iot_rows = set()
    domain_rows = set()
    # all_devices_rows = set()

    # Process pcap file
    capture = pyshark.FileCapture(input_file=pcap_file, display_filter='dns',)

    try:
        for packet in tqdm(capture, desc="Processing DNS packets"):
            if 'DNS' not in packet:
                continue

            domain = packet.dns.qry_name
            ip = packet.ip.dst
            timestamp = packet.frame_info.time_relative

            # add to all devices rows
            # all_devices_rows.add((ip, domain, timestamp))

            if ip not in iot_ip_set:
                continue

            if domain not in popular_domains:
                domain_rows.add(domain)

            iot_rows.add((ip, domain, timestamp))

    except Exception as e:
        print(e)
    finally:
        capture.close()

    # all_devices = pd.DataFrame.from_records(list(all_devices_rows), columns=['ip', 'query_name', 'timestamp'])

    iot_devices_queries = pd.DataFrame.from_records(
        list(iot_rows),
        columns=['ip', 'query_name', 'timestamp']
    )
    iot_domains = pd.DataFrame({'query_name': list(domain_rows)})

    return iot_devices_queries, iot_domains
