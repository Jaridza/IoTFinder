import json
import math

import numpy as np
import pandas as pd
import pyshark
from pyarrow.feather import read_feather
from sklearn.metrics import roc_curve
from tqdm import tqdm

from matching import compute_tf_idf_for_clients

def cosine_similarity_pairs(pairs1, pairs2):
    """
    Compute cosine similarity between two TF‐IDF vectors,
    each given as an iterable of (term, weight) pairs.
    """
    # Turn into dicts for fast lookup
    d1 = dict(pairs1)
    d2 = dict(pairs2)

    # Intersection of terms
    common_terms = set(d1.keys()) & set(d2.keys())
    if not common_terms:
        return 0.0

    # Dot product over shared terms
    dot = sum(d1[t] * d2[t] for t in common_terms)

    # Norms
    norm1 = math.sqrt(sum(v * v for v in d1.values()))
    norm2 = math.sqrt(sum(v * v for v in d2.values()))

    # Avoid division by zero
    return dot / (norm1 * norm2) if (norm1 and norm2) else 0.0


def calculate_thresholds(ldns_path, window_time, fingerprints, idf):
    """
    Calculate thresholds for IoT devices based on DNS queries.
    This function processes DNS packets, computes TF-IDF vectors for clients,
    and calculates thresholds based on ROC curve analysis.
    """
    capture = pyshark.FileCapture(input_file=ldns_path,
                                  display_filter='dns')

    df_row= []

    # prepare dns_queries DataFrame
    for packet in tqdm(capture, desc="Processing packets - in threshold.py"):
        if "DNS" not in packet:
            continue

        domain = packet.dns.qry_name
        ip = packet.ip.dst

        new_row = {
            'ip': ip,
            'query_name': domain,
            'timestamp': packet.frame_info.time_relative,
        }
        df_row.append(new_row)

    thresholds_client_queries = pd.DataFrame(df_row,columns=["ip","query_name","timestamp"])

    mapping_df = pd.read_csv(
        "../data/raw/IoTDNS/device_mapping.csv",  # replace with your path
        header=None,
        names=["device_name", "ip"]
    )
    ip_to_name = dict(zip(mapping_df["ip"], mapping_df["device_name"]))

    # calculate tf-idf vectors
    tf_idf_client = compute_tf_idf_for_clients(thresholds_client_queries,window_time)
    dev_thresh = []

    for _,dev_k in fingerprints.iterrows():
        dev_tf_idf = dev_k['tf_idf']
        dev_name = dev_k['device_name']
        scores = []
        y_true = []
        for _, client_k in tf_idf_client.iterrows():
            client_tf_idf = client_k['fingerprint']
            # compute similarity score
            score = cosine_similarity_pairs(dev_tf_idf, client_tf_idf)
            scores.append(score)
            # check if the device_name for this client ip, and check if it's the same as the device_name for the device
            client_ip = client_k['ip']
            y_true.append(1 if client_ip in ip_to_name and ip_to_name[client_ip] == dev_name else 0)

        # compute ROC curve
        fpr, tpr, thresholds = roc_curve(y_true, scores)
        print("FPR:", fpr)
        print("TPR:", tpr)
        print("Thresholds:", thresholds)

        phi = 0.001
        print("before dropping inf‐thresholds:", thresholds)
        # Drop the inf‐threshold entry up front:
        finite = np.isfinite(thresholds)
        fpr_f = fpr[finite]
        thr_f = thresholds[finite]
        print("finite:", finite)
        print("after dropping inf‐thresholds:", thr_f)


        if phi <= fpr_f[0]:
            theta_k = max(0.5, thr_f[0])
        # elif phi >= fpr_f[-1]:
        #     theta_k = max(0.5, thr_f[-1])
        else:
            low_index = np.max(np.where(fpr_f <= phi))
            high_index = np.min(np.where(fpr_f >= phi))

            fpr_A, t_A = fpr_f[low_index], thr_f[low_index]
            fpr_B, t_B = fpr_f[high_index], thr_f[high_index]

            # thresholds_rev = thresholds[::-1]

            # If they’re the same FPR, just pick t_A
            # if fpr_B == fpr_A:
            #     t_F = t_A
            # else:
            t_F = t_A + (phi - fpr_A) * (t_B - t_A) / (fpr_B - fpr_A)
            # t_F = np.interp(phi, fpr, thresholds_rev)

            theta_k = max(0.5, (t_A + t_F) / 2)

        # save threshold to device_row new df with holds_device_name and threshold
        dev_thresh.append({'device_name': dev_name, 'threshold': theta_k})

    # save the thresholds to a DataFrame
    thresholds_df = pd.DataFrame(dev_thresh)
    # save to feather
    thresholds_df.to_feather("../data/processed/thresholds_iot_devices.feather")

    print(thresholds_df)
    return thresholds_df