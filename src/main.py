import pandas as pd
import pyshark
from tqdm import tqdm
import json

import matching
from fingerprint import build_fingerprints
from idf import compute_idf
from parser import build_dns_queries
from thresholds import calculate_thresholds


# TODO: remove this function, it is not used anymore
def get_iot_domains(pcap, popular_domains_file, device_mapping_file):
    """"
    Extracts IoT domains from a pcap file, filtering out popular domains and non-IoT devices.
    Used to calculate the IDF (Inverse Document Frequency) for IoT domains.
    Args:
        pcap (str): Path to the pcap file containing DNS queries.
        popular_domains_file (str): Path to the CSV file containing popular domains.
        device_mapping_file (str): Path to the CSV file mapping devices to IP addresses.
    Returns:
        pd.DataFrame: DataFrame containing IoT domains with a single column 'query_name'.
    """

    domains_capture = pyshark.FileCapture(input_file=pcap, display_filter='dns')

    # Load popular domains
    popular_domains_csv = pd.read_csv(popular_domains_file, header=None)
    # popular_domains = popular_domains_csv[1].tolist()
    popular_domains = set(popular_domains_csv[1])

    # Load device mapping to filter out non-iot devices
    device_mapping = pd.read_csv(device_mapping_file, header=None)
    non_iot_devices = [53, 54, 58, 61, 62, 63, 64, 65]
    iot_mapping = device_mapping.drop(non_iot_devices)

    # iot_ipaddresses = iot_mapping[1].tolist()
    iot_ip_set = set(iot_mapping[1])

    iot_rows = set()

    for packet in tqdm(domains_capture, desc="Processing DNS packets"):
        if "DNS" not in packet:
            continue

        if packet.ip.dst not in iot_ip_set:
            continue

        domain = packet.dns.qry_name

        if domain in popular_domains:
            continue

        iot_rows.add(domain)

    iot_domains = pd.DataFrame({'query_name': list(iot_rows)})

    return iot_domains

def main():
    # ----- Step 1: parse & filter -----
    print("Building DNS queries DataFrame…")
    IoTDNS_dns_queries, iot_domains = build_dns_queries(
        pcap_file='../data/raw/IoTDNS/dns_2019_08.pcap',
        # max_packets=500000,
        # used to filter non-IoT devices (fingerprints have to be formed from IoT devices only)
        device_mapping_file='../data/raw/IoTDNS/device_mapping.csv',
        popular_domains_file='../data/raw/cloudflare-radar_top-100-domains_20250513.csv'
    )

    # save to feather file
    IoTDNS_dns_queries.to_feather("../data/processed/large/iot_queries_BIG.feather")
    print(f"Number of DNS queries: {len(IoTDNS_dns_queries)}")
    # load father file
    # IoTDNS_dns_queries = pd.read_feather("../data/processed/large/iot_queries_BIG.feather")

    # save to feather file
    iot_domains.to_feather("../data/processed/large/domains_BIG.feather")
    # load feather file
    # iot_domains = pd.read_feather("../data/processed/large/domains_BIG.feather")

    # ----- Step 2: fingerprint -----
    print("Building fingerprints…")

    w = 3600  # 1 hour in seconds
    fingerprints = build_fingerprints(IoTDNS_dns_queries, w)
    # TODO: add new column for device_name here? or leave inside the function?
    # save to feather file
    fingerprints['fingerprint'] = fingerprints['fingerprint'].apply(json.dumps)
    fingerprints.to_feather("../data/processed/large/fingerprints_BIG.feather")
    print(f"Number of fingerprints: {len(fingerprints)}")
    # load feather file
    # fingerprints = pd.read_feather("../data/processed/large/fingerprints_BIG.feather")
    fingerprints['fingerprint'] = fingerprints['fingerprint'].apply(json.loads)

    # ----- Step 3: compute idf  -----
    # iot_domains = get_iot_domains(
    #     pcap='../data/raw/IoTDNS/dns_2019_08.pcap',
    #     # used to filter out popular domains (from May 13, 2025)
    #     popular_domains_file='../data/raw/cloudflare-radar_top-100-domains_20250513.csv',
    #     device_mapping_file='../data/raw/IoTDNS/device_mapping.csv'
    # )
    # # save to feather file
    # iot_domains.to_feather("../data/processed/large/domains_BIG.feather")
    # # load feather file
    # # iot_domains = pd.read_feather("../data/processed/large/domains_BIG.feather")

    print("Building IDF DataFrame…")
    pdns_dns_queries, domains_idf, pdns_total_time = compute_idf("../data/raw/IoTDNS/pdns.pcap",
                              iot_domains, IoTDNS_dns_queries)

    # save to feather file
    pdns_dns_queries.to_feather("../data/processed/large/pdns_queries_BIG.feather")
    domains_idf.to_feather("../data/processed/large/idf_BIG.feather")

    # ----- Step 4: calculate tf-idf -----
    print("Calculating TF-IDF for IoT devices…")

    tf_idf_iot_devices = matching.calculate_tf_idf_for_iot_devices(w, pdns_total_time, fingerprints, domains_idf)

    tf_idf_clients = matching.compute_tf_idf_for_clients(pdns_dns_queries, w)

    # save to feather files
    tf_idf_iot_devices['fingerprint'] = tf_idf_iot_devices['fingerprint'].apply(json.dumps)
    tf_idf_iot_devices['tf_idf'] = tf_idf_iot_devices['tf_idf'].apply(json.dumps)
    tf_idf_iot_devices.to_feather("../data/processed/large/tf_idf_iot_devices_BIG.feather")
    tf_idf_clients['fingerprint'] = tf_idf_clients['fingerprint'].apply(json.dumps)
    tf_idf_clients.to_feather("../data/processed/large/tf_idf_clients_BIG.feather")

    tf_idf_iot_devices['fingerprint'] = tf_idf_iot_devices['fingerprint'].apply(json.loads)
    tf_idf_iot_devices['tf_idf'] = tf_idf_iot_devices['tf_idf'].apply(json.loads)
    tf_idf_clients['fingerprint'] = tf_idf_clients['fingerprint'].apply(json.loads)

    # read feather files
    # tf_idf_iot_devices = pd.read_feather("../data/processed/tf_idf_iot_devices_BIG.feather")
    # tf_idf_clients = pd.read_feather("../data/processed/tf_idf_clients_BIG.feather")

    # ----- Step 5: calculate thresholds -----
    print("Calculating thresholds for IoT devices…")
    thresholds = calculate_thresholds("../data/raw/IoTDNS/ldns.pcap", w, tf_idf_iot_devices, iot_domains)
    # # save to feather file
    thresholds.to_feather("../data/processed/large/thresholds_BIG.feather")

    # thresholds = pd.read_feather("../data/processed/thresholds_BIG.feather")

    # ----- Step 6: Matching -----
    print("Matching IoT devices with clients…")
    matched_devices = matching.compute_similarity_scores(tf_idf_iot_devices, tf_idf_clients, domains_idf, thresholds)
    print(matched_devices)

    # ----- Step 7: Evaluate results -----
    mapping = pd.read_csv("../data/raw/IoTDNS/device_mapping.csv",
                          header=None,
                          names=["device_name_actual", "ip"])

    results = (matched_devices.merge(mapping, left_on='client_ip', right_on='ip', how='left').drop(columns='ip'))
    results = results.rename(columns={'device_name': 'device_name_predicted'})
    results['correct'] = (results['device_name_predicted'] == results['device_name_actual'])
    print("Results:")
    print(results)
    accuracy = results['correct'].mean()
    print(f"Overall accuracy: {accuracy:.1%}")


if __name__ == "__main__":
    main()