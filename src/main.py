import pandas as pd
import pyshark
from tqdm import tqdm
import json

import matching
from fingerprint import build_fingerprints
from idf import compute_idf
from parser import build_dns_queries
from thresholds import calculate_thresholds

def process_dns_queries(path):
    """
    Process DNS queries from a pcap file and return a DataFrame with processed queries.
    Args:
        path (str): Path to the pcap file.
    Returns:
        pd.DataFrame: DataFrame containing processed DNS queries.
    """
    iot_rows = []
    capture = pyshark.FileCapture(input_file=path,
                                  display_filter='dns')

    dns_queries = pd.DataFrame(columns=['ip', 'query_name', 'timestamp'])
    queries_rows = []

    try:
        for packet in tqdm(capture, desc="Processing packets - in idf.py"):
            if "DNS" not in packet:
                continue

            domain = packet.dns.qry_name
            ip = packet.ip.dst

            new_row = {
                'ip': ip,
                'query_name': domain,
                'timestamp': packet.frame_info.time_relative,
            }
            queries_rows.append(new_row)
    finally:
        capture.close()

    dns_queries['timestamp'] = pd.to_numeric(dns_queries['timestamp'])
    total_time = dns_queries['timestamp'].max() - dns_queries['timestamp'].min()

    dns_queries = pd.DataFrame(queries_rows)

    return dns_queries, total_time

def main():
    # ----- Step 1: parse & filter -----
    print("Building DNS queries DataFrame…")
    IoTDNS_dns_queries, iot_domains = build_dns_queries(
        pcap_file='../data/raw/IoTDNS/v1_iotdns.pcap',
        # used to filter non-IoT devices (fingerprints have to be formed from IoT devices only)
        device_mapping_file='../data/raw/IoTDNS/device_mapping.csv', #TODO: this is an issue, because it's specific to this dataset
        popular_domains_file='../data/raw/cloudflare-radar_top-100-domains_20250513.csv'
    )

    # save to feather file
    IoTDNS_dns_queries.to_feather("../data/processed/large/iot_queries_BIG.feather")
    # print(f"Number of DNS queries: {len(IoTDNS_dns_queries)}")
    # load father file
    IoTDNS_dns_queries = pd.read_feather("../data/processed/large/iot_queries_BIG.feather")

    # save to feather file
    iot_domains.to_feather("../data/processed/large/domains_BIG.feather")
    # load feather file
    iot_domains = pd.read_feather("../data/processed/large/domains_BIG.feather")

    # ----- Step 2: fingerprint -----
    print("Building fingerprints…")
    w = 3600  # 1 hour in seconds
    fingerprints = build_fingerprints(IoTDNS_dns_queries, w)
    # TODO: add new column for device_name here? or leave inside the function?
    #better to leave this one here and have a separate function for the other section even though they do the same thing

    # save to feather file
    fingerprints['fingerprint'] = fingerprints['fingerprint'].apply(json.dumps)
    fingerprints.to_feather("../data/processed/large/fingerprints_BIG.feather")
    print(f"Number of fingerprints: {len(fingerprints)}")
    # load feather file
    fingerprints = pd.read_feather("../data/processed/large/fingerprints_BIG.feather")

    # never comment
    fingerprints['fingerprint'] = fingerprints['fingerprint'].apply(json.loads)

    # ----- Step 3: compute idf  -----
    print("Building IDF DataFrame…")
    # TODO: remove return of pdns_dns_queries, pdns_total_time
    # here path is the Tp
    pdns_dns_queries, domains_idf, pdns_total_time = compute_idf("../data/raw/IoTDNS/v1_Tp.pcap",
                              iot_domains)

    # save to feather file
    pdns_dns_queries.to_feather("../data/processed/large/pdns_queries_BIG.feather")
    domains_idf.to_feather("../data/processed/large/idf_BIG.feather")

    # ----- Step 4: calculate tf-idf -----
    print("Calculating TF-IDF for IoT devices…")

    # we need to process Tt, so pdns_2 queries and use those here
    Tt_processed, Tt_total_time = process_dns_queries(path='../data/raw/IoTDNS/v1_Tt.pcap')

    # tf_idf_iot_devices = matching.calculate_tf_idf_for_iot_devices(w, pdns_total_time, fingerprints, domains_idf)
    tf_idf_iot_devices = matching.calculate_tf_idf_for_iot_devices(w,Tt_total_time, fingerprints, domains_idf)

    # tf_idf_clients = matching.compute_tf_idf_for_clients(pdns_dns_queries, w)
    tf_idf_clients = matching.compute_tf_idf_for_clients(Tt_processed, w)

    # save to feather files
    tf_idf_iot_devices['fingerprint'] = tf_idf_iot_devices['fingerprint'].apply(json.dumps)
    tf_idf_iot_devices['tf_idf'] = tf_idf_iot_devices['tf_idf'].apply(json.dumps)
    tf_idf_iot_devices.to_feather("../data/processed/large/tf_idf_iot_devices_BIG.feather")
    tf_idf_clients['fingerprint'] = tf_idf_clients['fingerprint'].apply(json.dumps)
    tf_idf_clients.to_feather("../data/processed/large/tf_idf_clients_BIG.feather")

    # read feather files
    tf_idf_iot_devices = pd.read_feather("../data/processed/tf_idf_iot_devices_BIG.feather")
    tf_idf_clients = pd.read_feather("../data/processed/tf_idf_clients_BIG.feather")

    # never comment
    tf_idf_iot_devices['fingerprint'] = tf_idf_iot_devices['fingerprint'].apply(json.loads)
    tf_idf_iot_devices['tf_idf'] = tf_idf_iot_devices['tf_idf'].apply(json.loads)
    tf_idf_clients['fingerprint'] = tf_idf_clients['fingerprint'].apply(json.loads)

    # ----- Step 5: calculate thresholds -----
    print("Calculating thresholds for IoT devices…")
    thresholds = calculate_thresholds("../data/raw/IoTDNS/v1_ldns.pcap", w, tf_idf_iot_devices, iot_domains)
    # # save to feather file
    thresholds.to_feather("../data/processed/large/thresholds_BIG.feather")

    thresholds = pd.read_feather("../data/processed/thresholds_BIG.feather")

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