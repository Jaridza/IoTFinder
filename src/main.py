import pandas as pd
import json
import time

import matching
from fingerprint import build_fingerprints
from idf import compute_idf
from parser import build_dns_queries
from thresholds import calculate_thresholds, process_dns_queries


def main():
    # ----- Step 1: parse & filter -----
    print("Building DNS queries DataFrame…")

    non_iot_device_ips = ["192.168.0.21", "192.168.0.22", "192.168.0.23", "192.168.0.24", "192.168.0.25",
                          "192.168.0.60", "192.168.0.61", "192.168.0.62", "192.168.0.65", "192.168.0.69",
                          "192.168.0.113", "192.168.0.138", "192.168.0.151", "192.168.0.159"]

    IoTDNS_dns_queries, iot_domains = build_dns_queries(
        pcap_file='../data/raw/IoTDNS/v1_iotdns.pcap',
        popular_domains_file='../data/raw/cloudflare-radar_top-100-domains_20250513.csv',
        filter_non_iot=True,
        non_iot_device_ips=non_iot_device_ips
    )

    # save to feather file
    IoTDNS_dns_queries.to_feather("../data/processed/large/iot_queries_BIG.feather")
    # load father file
    IoTDNS_dns_queries = pd.read_feather("../data/processed/large/iot_queries_BIG.feather")

    # save to feather file
    iot_domains.to_feather("../data/processed/large/domains_BIG.feather")
    # load feather file
    iot_domains = pd.read_feather("../data/processed/large/domains_BIG.feather")

    # ----- Step 2: fingerprint -----
    print("Building fingerprints…")
    w = 3600  # 1 hour in seconds
    # device_mapping_file is a csv file with the mapping (device name -> ip)
    fingerprints = build_fingerprints(IoTDNS_dns_queries, w, device_mapping_file="../data/raw/IoTDNS/device_mapping.csv")

    # save to feather file
    fingerprints['fingerprint'] = fingerprints['fingerprint'].apply(json.dumps)
    fingerprints.to_feather("../data/processed/large/fingerprints_BIG.feather")
    # load feather file
    fingerprints = pd.read_feather("../data/processed/large/fingerprints_BIG.feather")

    # never comment out
    fingerprints['fingerprint'] = fingerprints['fingerprint'].apply(json.loads)

    # ----- Step 3: compute idf  -----
    print("Building IDF DataFrame…")
    domains_idf = compute_idf("../data/raw/IoTDNS/v1_Tp.pcap", iot_domains)

    # save to feather file
    domains_idf.to_feather("../data/processed/large/idf_BIG.feather")
    # load feather file
    domains_idf = pd.read_feather("../data/processed/large/idf_BIG.feather")

    # ----- Step 4: calculate tf-idf -----
    print("Calculating TF-IDF for IoT devices…")
    Tt_processed, Tt_total_time = process_dns_queries(path='../data/raw/IoTDNS/v1_Tt.pcap')
    tf_idf_iot_devices = matching.calculate_tf_idf_for_iot_devices(w, Tt_total_time, fingerprints, domains_idf)
    #
    tf_idf_clients = matching.compute_tf_idf_for_clients(Tt_processed, w)

    # save to feather files
    tf_idf_iot_devices['fingerprint'] = tf_idf_iot_devices['fingerprint'].apply(json.dumps)
    tf_idf_iot_devices['tf_idf'] = tf_idf_iot_devices['tf_idf'].apply(json.dumps)
    tf_idf_iot_devices.to_feather("../data/processed/large/tf_idf_iot_devices_BIG.feather")
    tf_idf_clients['tf_idf'] = tf_idf_clients['tf_idf'].apply(json.dumps)
    tf_idf_clients.to_feather("../data/processed/large/tf_idf_clients_BIG.feather")

    # read feather files
    tf_idf_iot_devices = pd.read_feather("../data/processed/large/tf_idf_iot_devices_BIG.feather")
    tf_idf_clients = pd.read_feather("../data/processed/large/tf_idf_clients_BIG.feather")

    # never comment out
    tf_idf_iot_devices['fingerprint'] = tf_idf_iot_devices['fingerprint'].apply(json.loads)
    tf_idf_iot_devices['tf_idf'] = tf_idf_iot_devices['tf_idf'].apply(json.loads)
    tf_idf_clients['tf_idf'] = tf_idf_clients['tf_idf'].apply(json.loads)

    # ----- Step 5: calculate thresholds -----
    print("Calculating thresholds for IoT devices…")
    thresholds = calculate_thresholds("../data/raw/IoTDNS/v1_ldns.pcap", w, tf_idf_iot_devices, iot_domains)
    # save to feather file
    thresholds.to_feather("../data/processed/large/thresholds_BIG.feather")

    thresholds = pd.read_feather("../data/processed/large/thresholds_BIG.feather")

    # ----- Step 6: Matching -----
    print("Matching IoT devices with clients…")
    scores_df = matching.compute_similarity_scores(tf_idf_iot_devices, tf_idf_clients, domains_idf)
    matched_devices = matching.get_best_matches(scores_df, thresholds)

    # ----- Step 7: Evaluate results -----
    mapping = pd.read_csv("../data/raw/IoTDNS/device_mapping.csv",
                          header=None,
                          names=["device_name_actual", "ip"])

    pd.set_option('display.max_columns', None)

    results = (matched_devices.merge(mapping, left_on='client_ip', right_on='ip', how='left').drop(columns='ip'))
    results = results.rename(columns={'device_name': 'device_name_predicted'})
    results['correct'] = (results['device_name_predicted'] == results['device_name_actual'])
    print("Results:")
    print(results)
    accuracy = results['correct'].mean()
    print(f"Overall accuracy: {accuracy:.1%}")


if __name__ == "__main__":
    start = time.perf_counter()
    main()
    total = time.perf_counter() - start
    print(f"\nTotal runtime: {total:.2f} seconds")
    print(f"Total time: {total/60:.1f} minutes")
