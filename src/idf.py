import pandas as pd
import pyshark
from tqdm import tqdm
import numpy as np

def compute_idf(path, iot_domains):
    """
    Compute the IDF (Inverse Document Frequency) for each fingerprint in the dataset.
    Args:
        path (str): Path to the pcap file containing DNS queries (PDNS).
        iot_domains (pd.DataFrame): DataFrame containing IoT domains with a single column 'query_name'. Used to
        parse the pcap file and filter out domains not queried by IoT devices.
    Returns:
        domain_to_ips (pd.DataFrame): DataFrame mapping each domain to a set of IPs and its IDF value.
    """
    queries_rows = []
    domains_set = set(iot_domains['query_name'].values)

    # Process pcap file
    with pyshark.FileCapture(input_file=path,display_filter='dns') as capture:
        for packet in tqdm(capture, desc="Processing packets - in idf.py"):
            if "DNS" not in packet:
                continue

            if not (hasattr(packet, 'dns') and hasattr(packet, 'ip')):
                continue

            domain = packet.dns.qry_name
            ip = packet.ip.dst

            # check if domain is in domains df (then it is an iot domain in Q)
            # this is done to this dataset to filter and only get queries for the IoT domains in Q
            if domain in domains_set:
                new_row = {
                    'ip': ip,
                    'query_name': domain,
                    'timestamp': packet.frame_info.time_relative,
                }
                queries_rows.append(new_row)


    dns_queries = pd.DataFrame(queries_rows, columns=['ip', 'query_name', 'timestamp'])

    # Map each domain to a set of IPs that queried it
    domain_to_ips = dns_queries.groupby('query_name')['ip'].agg(set).reset_index().rename(columns={'ip': 'ips_set'})

    # Nc(qi) = number of client that queried domain qi
    domain_to_ips['Nc_qi'] = domain_to_ips['ips_set'].apply(len)

    # Nc = number of clients that queried any domain in Q (an IoT domain) - since dataset is already filtered
    # to only include domains queried by IoT devices, we can use the number of unique IPs in the dns_queries DataFrame
    # Nc = len(set.union(*domain_to_ips['ips_set'].tolist())) # 47
    Nc = dns_queries['ip'].nunique()  # Total number of unique IPs in the dataset

    domain_to_ips['idf'] = np.log(1 + (Nc / (domain_to_ips['Nc_qi'] + 1)))

    return domain_to_ips
