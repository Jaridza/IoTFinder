import pandas as pd
import pyshark
from tqdm import tqdm
import numpy as np

# iot_domains used to parse the pcap files and only get queries to IoT domains
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

            # check if domain is in domains df (then it is an iot domain in Q)
            # this is done to this dataset to filter and only get queries for the IoT domains in Q
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

    # TODO: remove this, it is not used anymore
    # NOW IoTDNS are used to calculate the idf of the domains
    # IoTDNS_queries['timestamp'] = pd.to_numeric(IoTDNS_queries['timestamp'])
    # total_time = IoTDNS_queries['timestamp'].max() - IoTDNS_queries['timestamp'].min()
    #
    # domain_to_ips = IoTDNS_queries.groupby('query_name')['ip'].agg(set).reset_index().rename(columns={'ip': 'ips_set'})
    #
    # # calculate idf
    # # Nc(qi) = number of clients that queried domain qi
    # domain_to_ips['Nc_qi'] = domain_to_ips['ips_set'].apply(len)
    #
    # Nc = len(set.union(*domain_to_ips['ips_set'].tolist()))  # Total number of unique IPs querying IoT domains
    # domain_to_ips['idf'] = np.log(1 + (Nc / (domain_to_ips['Nc_qi'] + 1)))

    # this was from the pdns - it was used to calculate the idfs of the domains

    dns_queries['timestamp'] = pd.to_numeric(dns_queries['timestamp'])
    total_time = dns_queries['timestamp'].max() - dns_queries['timestamp'].min()

    domain_to_ips = dns_queries.groupby('query_name')['ip'].agg(set).reset_index().rename(columns={'ip': 'ips_set'})

    # calculate idf
    # Nc(qi) = number of client that queried domain qi
    domain_to_ips['Nc_qi'] = domain_to_ips['ips_set'].apply(len)

    Nc = len(set.union(*domain_to_ips['ips_set'].tolist())) # 47

    domain_to_ips['idf'] = np.log(1 + (Nc / (domain_to_ips['Nc_qi'] + 1)))

    return domain_to_ips
