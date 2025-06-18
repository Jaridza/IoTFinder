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
    root = os.path.dirname(os.path.dirname(__file__))
    train_data = os.path.join(root, "data/raw/temp/dns_2019_08.pcap")
    out_dir = os.path.join(root, "data/raw/")

    test_data = os.path.join(root, "data/raw/temp/dns_2019_09.pcap")
    pop_domains = os.path.join(root, "data/raw/top100domains2025.csv")
    device_mapping = os.path.join(root, "data/raw/IoTDNS/device_mapping_iot.csv")

    window_size = 3600  # 1 hour in seconds
    # non_iot_device_ips = ["192.168.0.21", "192.168.0.22", "192.168.0.23", "192.168.0.24", "192.168.0.25",
    #                       "192.168.0.60", "192.168.0.61", "192.168.0.62", "192.168.0.65", "192.168.0.69",
    #                       "192.168.0.113", "192.168.0.138", "192.168.0.151", "192.168.0.159"]
    non_iot_device_ips = []


    # non_iot_device_ips = ["40:f3:08:ff:1e:da", "74:2f:68:81:69:42","ac:bc:32:d4:6f:2f","b4:ce:f6:a7:a3:c2",
                          # "d0:a6:37:df:a1:e1", "f4:5c:89:93:cc:85"]

    filter_with_ips = False  # Set to True if you want to filter out non-IoT devices based on IPs

    fingerprints, domains_idf, thresholds = train_model(window_size,
                                                        train_data,
                                                        out_dir,
                                                        filter_with_ips,
                                                        non_iot_device_ips,
                                                        pop_domains,
                                                        device_mapping)

    test_model(test_data,device_mapping,
               fingerprints, domains_idf, thresholds, window_size, filter_with_ips)


def train_model(window_size, train_data, out_dir, filter_with_ips ,non_iot_device_ips,pop_domains, device_mapping):
    # Step 1: Parse and filter DNS queries
    iotdns_pcap, tp_dataset_pcap, ldns_pcap = split_pcap_with_editcap(train_data,out_dir,ratios=(0.6, 0.2, 0.2))

    IoTDNS_dns_queries, iot_domains, Tl_total_time = build_dns_queries(
        pcap_file=iotdns_pcap,
        popular_domains_file=pop_domains,
        filter_with_ips=filter_with_ips,
        non_iot_device_ips=non_iot_device_ips  # This should be provided if filter_non_iot is True
    )
    print("IoT DNS Queries:")
    print(IoTDNS_dns_queries.head(50))

    # Step 2: Build fingerprints
    fingerprints = build_fingerprints(IoTDNS_dns_queries, window_size, device_mapping_file=device_mapping)
    print("Fingerprints:")
    print(fingerprints)

    # Step 3: Compute IDF
    domains_idf = compute_idf(tp_dataset_pcap, iot_domains, filter_with_ips)
    print("Domains IDF:")
    print(domains_idf)

    # Step 4: Calculate thresholds
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
    print("SCORES DF:")
    print(scores_df)
    matched_devices = matching.get_best_matches(scores_df, thresholds)
    print("Matched devices:")
    print(matched_devices)

    # ----- Step 7: Evaluate results -----
    mapping = pd.read_csv(device_mapping,
                          header=None,
                          names=["device_name_actual", "ip"])

    # i think from here

    pd.set_option('display.max_columns', None)

    results = (matched_devices.merge(mapping, left_on='client_ip', right_on='ip', how='inner').drop(columns='ip'))
    results = results.rename(columns={'device_name': 'device_name_predicted'})
    results['correct'] = (results['device_name_predicted'] == results['device_name_actual'])

    # normalize both to lowercase colon‐separated
    # matched_devices['client_ip'] = matched_devices['client_ip'].str.lower()
    # mapping['ip'] = mapping['ip'].str.lower()

    print("RESULTS HERE:")
    # eval_df = results.dropna(subset=['device_name_actual'])
    print(results)

    # from sklearn.metrics import classification_report
    # y_true = eval_df['device_name_actual']
    # y_pred = eval_df['device_name_predicted']
    #
    # print(classification_report(y_true, y_pred))

    # print("Results:")
    # print(results)
    #
    accuracy = results['correct'].mean()
    print(f"Overall accuracy: {accuracy:.1%}")
    return results

if __name__ == "__main__":
    start = time.perf_counter()
    main()
    total = time.perf_counter() - start
    print(f"Total time: {total / 60:.1f} minutes")
