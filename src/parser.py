import pyshark
import pandas as pd
from tqdm import tqdm # progress bar

# def build_dns_queries(pcap_file, max_packets, device_mapping_file):
def build_dns_queries(pcap_file, device_mapping_file):
    """
    Build a DataFrame of DNS queries from a pcap file.

    Args:
        pcap_file (str): Path to the pcap file.
        max_packets (int): Maximum number of packets to process.
        device_mapping_file (str): Path to the CSV file containing device mapping used to filter non-iot devices.

    Returns:
        pd.DataFrame: DataFrame containing DNS queries from IoT devices.
    """

    # Load device mapping to filter out non-iot devices
    device_mapping = pd.read_csv(device_mapping_file, header=None)
    non_iot_devices = [53, 54, 58, 61, 62, 63, 64, 65]
    # iot_mapping = device_mapping.drop(non_iot_devices)
    iot_mapping = device_mapping[~device_mapping[0].isin(non_iot_devices)]

    ipaddresses = iot_mapping[1].tolist()

    # Initialize DataFrame for IoT devices
    iot_devices_queries = pd.DataFrame(columns=['ip', 'query_name', 'timestamp'])
    iot_rows = []

    # Process pcap file
    capture = pyshark.FileCapture(input_file=pcap_file,
                                  display_filter='dns',)
                                  # custom_parameters=['-c', str(max_packets)])

    try:
        for packet in tqdm(capture, desc="Processing DNS packets"):
            if 'DNS' not in packet:
                continue

            domain = packet.dns.qry_name
            ip = packet.ip.dst

            new_row = {
                'ip': ip,
                'query_name': domain,
                'timestamp': packet.frame_info.time_relative,
            }

            if packet.ip.dst in ipaddresses:
                iot_rows.append(new_row)
    except Exception as e:
        print(e)
    finally:
        capture.close()

    iot_devices_queries = pd.DataFrame(iot_rows)

    return iot_devices_queries
