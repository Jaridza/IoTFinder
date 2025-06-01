import pandas as pd
import pyshark
from tqdm import tqdm
import numpy as np

def compute_idf(path, iot_domains):
    """
    Compute the IDF (Inverse Document Frequency) for each fingerprint in the dataset.
    Args:
        path (str): Path to the pcap file containing DNS queries (PDNS).
        iot_domains (pd.DataFrame): DataFrame containing IoT domains with a single column 'query_name'.
    Returns:
        dns_queries (pd.DataFrame): DataFrame containing DNS queries with columns 'ip', 'query_name', and 'timestamp'.
        domain_to_ips (pd.DataFrame): DataFrame mapping each domain to a set of IPs and its IDF value.
        total_time (float): Total time span of the DNS queries in seconds.
    """
    capture = pyshark.FileCapture(input_file=path,
                                  display_filter='dns')

    dns_queries = pd.DataFrame(columns=['ip', 'query_name', 'timestamp'])
    queries_rows = []

    # print(iot_domains.head())

    try:
        for packet in tqdm(capture, desc="Processing packets - in idf.py"):
            if "DNS" not in packet:
                continue

            domain = packet.dns.qry_name
            ip = packet.ip.dst

            # check if domain is in domains df (then it is an iot domain)
            if domain in iot_domains['query_name'].values:
                new_row = {
                    'ip': ip,
                    'query_name': domain,
                    'timestamp': packet.frame_info.time_relative,
                }
                queries_rows.append(new_row)
    finally:
        capture.close()

    dns_queries = pd.DataFrame(queries_rows)

    dns_queries['timestamp'] = pd.to_numeric(dns_queries['timestamp'])
    total_time = dns_queries['timestamp'].max() - dns_queries['timestamp'].min()

    domain_to_ips = dns_queries.groupby('query_name')['ip'].agg(set).reset_index().rename(columns={'ip': 'ips_set'})

    # calculate idf
    # Nc(qi) = number of client that queried domain qi
    domain_to_ips['Nc_qi'] = domain_to_ips['ips_set'].apply(len)

    Nc = len(set.union(*domain_to_ips['ips_set'].tolist())) # 47

    domain_to_ips['idf'] = np.log(1 + (Nc / (domain_to_ips['Nc_qi'] + 1)))

    return dns_queries, domain_to_ips, total_time
