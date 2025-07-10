import pandas as pd
import time
import os

import matching
from fingerprint import build_fingerprints
from idf import compute_idf
from parsing import build_dns_queries
from pcap_split import split_pcap_with_editcap
from thresholds import calculate_thresholds, process_dns_queries

def main():
    # TODO: fix the paths
    # TODO: fix the ip list - they are hardcoded rn
    # TODO: change so that we can train the model once and use it for multiple test datasets
    root = os.path.dirname(os.path.dirname(__file__))
    train_data = os.path.join(root, "data/raw/temp/static_train_merged.pcap")
    out_dir = os.path.join(root, "data/raw/")

    test_data = os.path.join(root, "data/raw/temp/static_test_merged.pcap")
    pop_domains = os.path.join(root, "data/raw/top100domains2025.csv")
    train_mapping = os.path.join(root, "data/raw/IoTDNS/device_mapping_iot.csv")
    test_mapping = os.path.join(root, "data/raw/IoTDNS/device_mapping_iot.csv")

    #iotfinder data
    iot_ips = [
    "192.168.0.1","192.168.0.2","192.168.0.4","192.168.0.5","192.168.0.6",
    "192.168.0.7","192.168.0.8","192.168.0.10","192.168.0.12","192.168.0.13",
    "192.168.0.14","192.168.0.15","192.168.0.16","192.168.0.17","192.168.0.18",
    "192.168.0.19","192.168.0.21","192.168.0.22","192.168.0.23","192.168.0.24",
    "192.168.0.25","192.168.0.26","192.168.0.27","192.168.0.28","192.168.0.29",
    "192.168.0.30","192.168.0.31","192.168.0.32","192.168.0.33","192.168.0.34",
    "192.168.0.35","192.168.0.36","192.168.0.37","192.168.0.38","192.168.0.39",
    "192.168.0.41","192.168.0.42","192.168.0.43","192.168.0.44","192.168.0.45",
    "192.168.0.47","192.168.0.48","192.168.0.49","192.168.0.50","192.168.0.51",
    "192.168.0.52","192.168.0.53","192.168.0.54","192.168.0.55","192.168.0.56",
    "192.168.0.57","192.168.0.58","192.168.0.59","192.168.0.62","192.168.0.63",
    "192.168.0.64","192.168.0.67","192.168.0.68"
]
    non_iot_device_ips = []

    iot_devices_exp12= ["40:ca:63:cf:0d:6a","20:1f:3b:08:7f:e3","c8:d7:78:52:31:90","00:31:92:e1:7b:17","74:da:88:5d:4c:3d"
        ,"ec:b5:fa:a8:e5:09","1c:90:ff:16:a7:fe","e4:bc:96:03:8d:bb","10:b2:32:d2:df:48","3c:31:74:45:9e:72"
        ,"94:b9:7e:06:1a:57","28:73:f6:67:73:a9","a4:cf:12:e7:06:24","34:3e:a4:71:a0:1f","18:b4:30:f4:0e:58"
        ,"d4:f5:47:36:e0:c1","fc:49:2d:58:bd:3c","3c:39:e7:28:fd:5c","1c:90:ff:e7:ca:f1","bc:fd:0c:d1:ad:5f"
        ,"b8:06:0d:78:0f:8a","1c:90:ff:5c:1e:52","ec:74:8c:5f:4b:90"]

    iot_us = ["08:66:98:a2:21:9e","00:03:7f:4f:c6:b5","20:f8:5e:cc:18:1f","ec:fa:bc:82:20:bb","34:ce:00:99:9b:83",
                     "50:c7:bf:a0:f3:76","9c:8e:cd:0a:33:1b","f4:b8:5e:31:73:db","ae:ca:06:08:d3:e6","00:0c:43:20:32:bb",
                     "00:fc:5c:e0:81:86","b0:d5:9d:b9:f0:b4","b0:fc:0d:c9:00:4c","6c:72:20:c5:0a:3f","c0:97:27:73:aa:38",
                     "18:74:2e:41:4d:35","fc:a1:83:38:e0:2d","00:71:47:c0:91:93","6c:56:97:35:39:f4","70:2c:1f:3b:36:53",
                     "20:df:b9:5f:41:7e","0c:2a:69:0e:91:16","00:0e:f3:3b:85:e5","d8:f7:10:c3:34:e4","38:8c:50:68:d7:5c",
                     "84:18:26:7d:cf:a2","dc:4f:22:c1:58:05","d8:28:c9:10:b5:60","18:b4:30:c8:d8:28","98:84:e3:e4:35:bd",
                     "88:de:a9:08:03:b9","84:c0:ef:2f:42:cc","b0:ce:18:27:9f:e4","24:fd:5b:04:1b:75","dc:4f:22:28:b6:5b",
                     "00:17:88:68:5f:61","14:91:82:b4:4b:5f","50:c7:bf:5a:2e:a0","78:a5:dd:1a:15:19","c0:97:27:81:67:99",
                     "00:21:cc:4d:ce:8c","f0:b4:29:41:ec:d7","34:ce:00:83:99:35","7c:49:eb:35:7a:49","34:ce:00:8b:22:74",
                     "22:ef:03:1a:97:b9"]

    iot_uk = ["b0:f1:ec:d4:26:ae","50:32:37:b8:c7:0f","f4:b8:5e:68:8f:35","00:03:7f:96:d8:ec","ae:ca:06:0e:ec:89",
              "fc:ee:e6:2e:23:a3","cc:f7:35:49:f4:05","00:fc:8b:84:22:10","5c:41:5a:29:ad:97","cc:f7:35:25:af:4d",
              "54:60:09:6f:32:84","20:df:b9:13:e5:2e","b8:2c:a0:28:3e:6b","00:0e:f3:2c:d4:04","84:18:26:7c:1a:56",
              "dc:4f:22:89:fc:e7","64:16:66:2a:98:62","70:ee:50:36:98:da","f0:45:da:36:e6:23","c8:3a:6b:fa:1c:00",
              "fc:03:9f:93:22:62","b0:ce:18:20:43:bf","0c:2a:69:11:01:ba","d0:52:a8:a4:e6:46","68:c6:3a:ba:c2:6b",
              "ec:b5:fa:00:98:da","58:ef:68:99:7d:ed","50:c7:bf:ca:3f:9d","50:c7:bf:b1:d2:78","78:a5:dd:28:a1:b7",
              "78:11:dc:76:69:b0","78:11:dc:ec:a3:ab","7c:49:eb:88:da:82","0c:8c:24:0b:be:fb"]


    # non_iot_device_ips = ["40:f3:08:ff:1e:da", "74:2f:68:81:69:42","ac:bc:32:d4:6f:2f","b4:ce:f6:a7:a3:c2",
    #                       "d0:a6:37:df:a1:e1", "f4:5c:89:93:cc:85"]

    filter_with_ips = False  # Set to True if you want to filter out non-IoT devices based on IPs
    window_size = 3600  # 1 hour in seconds

    fingerprints, domains_idf, thresholds = train_model(window_size,
                                                        train_data,
                                                        out_dir,
                                                        filter_with_ips,
                                                        iot_devices_exp12,
                                                        pop_domains,
                                                        train_mapping,)

    test_model(test_data,test_mapping,
               fingerprints, domains_idf, thresholds, window_size, filter_with_ips)


def train_model(window_size, train_data, out_dir, filter_with_ips ,non_iot_device_ips,pop_domains, device_mapping):
    """
    Train the IoT device identification model using DNS queries from a pcap file.
    Args:
        window_size (int): Size of the time window in seconds for processing DNS queries.
        train_data (str): Path to the training pcap file containing DNS queries.
        out_dir (str): Output directory where processed files will be saved.
        filter_with_ips (bool): Whether to filter out non-IoT devices based on IP addresses.
                                True filtering based on IPs, False filtering based on Mac Addresses.
        non_iot_device_ips (list): List of IP addresses of non-IoT devices.
        pop_domains (str): Path to the file containing popular domains for filtering DNS queries.
        device_mapping (str): Path to the device mapping file for IoT devices.
    """
    # ----- Step 1: Parse and filter DNS queries -----
    print("Parsing and filtering DNS queries from pcap file...")
    iotdns_pcap, tp_dataset_pcap, ldns_pcap = split_pcap_with_editcap(train_data,out_dir)

    IoTDNS_dns_queries, iot_domains, Tl_total_time = build_dns_queries(
        pcap_file=iotdns_pcap,
        popular_domains_file=pop_domains,
        filter_with_ips=filter_with_ips,
        non_iot_device_ips=non_iot_device_ips  # This should be provided if filter_non_iot is True
    )

    # ----- Step 2: Build fingerprints -----
    print("Building fingerprints for IoT devices...")
    fingerprints = build_fingerprints(IoTDNS_dns_queries, window_size, device_mapping_file=device_mapping)

    # ----- Step 3: Compute IDF -----
    print("Computing IDF values for domains...")
    domains_idf = compute_idf(tp_dataset_pcap, iot_domains, filter_with_ips)

    # ----- Step 4: Calculate thresholds -----
    print("Calculating thresholds...")
    tl_tf_idf_iot_devices = matching.calculate_tf_idf_for_iot_devices(window_size, Tl_total_time, fingerprints,
                                                                      domains_idf)
    thresholds = calculate_thresholds(ldns_pcap, window_size, tl_tf_idf_iot_devices, domains_idf, device_mapping, filter_with_ips)

    return fingerprints, domains_idf, thresholds


def test_model(test_data, device_mapping, fingerprints, domains_idf, thresholds, w, filter_with_ips):
    # ----- Step 5: calculate tf-idf -----
    print("Calculating TF-IDF for clients and IoT devices...")
    Tt_processed, Tt_total_time = process_dns_queries(path=test_data, filter_with_ips=filter_with_ips)

    tf_idf_iot_devices = matching.calculate_tf_idf_for_iot_devices(w, Tt_total_time, fingerprints, domains_idf)

    tf_idf_clients = matching.compute_tf_idf_for_clients(Tt_processed, w, domains_idf)

    # ----- Step 6: Matching -----
    print("Matching IoT devices with clients...")
    scores_df = matching.compute_similarity_scores(tf_idf_iot_devices, tf_idf_clients, domains_idf)

    matched_devices = matching.get_best_matches(scores_df, thresholds)

    # ----- Step 7: Evaluate results -----
    print("Evaluating results...")
    mapping = pd.read_csv(device_mapping,
                          header=None,
                          names=["device_name_actual", "ip"])

    results = (
        matched_devices
        .merge(mapping, left_on='client_ip', right_on='ip', how='left')
        .drop(columns=['ip'])
    )

    results = results.rename(columns={'device_name': 'device_name_predicted'})
    results['device_name_predicted'] = results['device_name_predicted'].fillna('unknown')

    results['device_name_actual'] = results['device_name_actual'].fillna('unknown')

    results['correct'] = (results['device_name_predicted'] == results['device_name_actual'])

    trained = set(fingerprints['device_name'])

    # only take into account the rows where the actual device name is known
    keep = (
            (results['device_name_predicted'] != 'unknown')
            | (results['device_name_actual'].isin(trained))
            | (results['device_name_actual'] == 'unknown')
    )
    eval_df = results[keep]

    print(eval_df)
    return eval_df

if __name__ == "__main__":
    start = time.perf_counter()
    main()
    total = time.perf_counter() - start
    print(f"Total time: {total / 60:.1f} minutes")
