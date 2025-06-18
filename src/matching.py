import pandas as pd
import re,ast
import numpy as np

from fingerprint import compute_window_probabilities


def calculate_tf_idf_for_iot_devices(w, total_time, fingerprints, idf_df):
    """
    Calculate the TF-IDF vector representation for IoT devices based on DNS queries.
    This function reads fingerprints and IDF values, then computes the TF-IDF vectors
    for each IoT device.
    Args:
        w (int): Time window size in seconds.
        total_time (float): Total time span of the DNS queries in seconds.
        fingerprints (pd.DataFrame): DataFrame containing IoT device fingerprints with 'fingerprint' column.
        idf_df (pd.DataFrame): DataFrame containing IDF values for domains with 'query_name' and 'idf' columns.
    Returns:
        pd.DataFrame: DataFrame containing IoT device fingerprints with TF-IDF vectors.
    """
    # Nt = total_time / w  # Number of time windows
    Nt = float(np.ceil(total_time / w))

    # compute TF-IDF vector representation
    # fkj = pkj * Nt
    # we get vector Vk {(qkj, fkj)}
    # we get TD-IDF: fkj * IDF (of domain)

    idf_dict = dict(zip(idf_df['query_name'], idf_df['idf']))
    tf_idf_column = []
    for index, row in fingerprints.iterrows():
        tf_idf_row = []
        tuples = row['fingerprint']
        # print type of tuples
        if not isinstance(tuples, list):
            raise ValueError(f"Expected a list of tuples, got {type(tuples)} instead.")

        for t in tuples:
            # t[0] is the domain
            # t[1] is the probability of the domain
            fkj = t[1] * Nt
            # get tf-idf vector
            idf = idf_dict.get(t[0], 0.0)

            psi = fkj * idf
            tf_idf_row.append((t[0], psi))

        tf_idf_column.append(tf_idf_row)

    fingerprints['tf_idf'] = tf_idf_column
    return fingerprints

def compute_tf_idf_for_clients(dns_queries, w, idf):
    """
    Compute the TF-IDF vectors for clients based on their DNS queries.
    This function calculates the probabilities of each query appearing in a given time window.
    Args:
        dns_queries (pd.DataFrame): DataFrame containing DNS queries with columns ['ip', 'query_name', 'timestamp'].
        w (int): Size of the time window in seconds.
    Returns:
        pd.DataFrame: DataFrame with columns ['ip', 'tf_idf'] where tf_idf is a list of tuples (query_name, probability).
        The tf_idf column represents the DNS behavior of each client.
    """
    probabilities = compute_window_probabilities(dns_queries, w)
    idf_series = idf.set_index('query_name')['idf']

    # apply idf
    probabilities['idf'] = probabilities['query_name'].map(idf_series).fillna(0)
    probabilities['probabilities'] = probabilities['probabilities'] * probabilities['idf']

    client_tf_idf_vector = (probabilities.groupby('ip')
                            .apply(lambda x: pd.Series({'tf_idf': list(zip(x['query_name'], x['probabilities']))}),
                                   include_groups=False)
                            .reset_index())

    return client_tf_idf_vector


def safe_dict_from_vec(vec):
    """
    Take your tf_idf_vector and build a dict only from those elements that are truly 2-tuples (domain, weight).
    """
    if not vec:
        return {}

    if isinstance(vec, str):
        cleaned = re.sub(r'np\.float64\(\s*([^)]+?)\s*\)', r'\1', vec)
        try:
            vec = ast.literal_eval(cleaned)
        except Exception:
            return {}

    out = {}
    for item in vec:
        if isinstance(item, (list, tuple)) and len(item) == 2:
            dom, w = item
            out[dom] = float(w)
    return out

def compute_cosine_similarity(psi, gamma):
    """
    Compute the cosine similarity between two vectors psi and gamma (two numpy arrays).
    Args:
        psi (np.ndarray): First vector (IoT device fingerprint).
        gamma (np.ndarray): Second vector (client TF-IDF vector).
    Returns:
        float: Cosine similarity score between psi and gamma.
    """
    dot = np.dot(psi, gamma)
    norm_psi = float(np.linalg.norm(psi))
    norm_gamma = float(np.linalg.norm(gamma))
    denominator = norm_psi * norm_gamma

    if denominator > 0:
        similarity_score = dot / denominator
    else:
        similarity_score = 0.0

    return similarity_score

def compute_similarity_scores(fingerprints, client_tf_idf_vector, domains_idf):
    """
    Compute similarity scores between IoT device fingerprints and client TF-IDF vectors.
    This function calculates the similarity score for each client against each IoT device.
    Args:
        fingerprints (pd.DataFrame): DataFrame containing IoT device fingerprints with 'fingerprint' column.
        client_tf_idf_vector (pd.DataFrame): DataFrame containing client TF-IDF vectors with 'fingerprint' column.
        domains_idf (pd.DataFrame): DataFrame containing IDF values for domains with 'query_name' and 'idf' columns.
    Returns:
        pd.DataFrame: DataFrame containing the best similarity scores for each client.
    """
    fingerprints['tf_idf_dict'] = (
        fingerprints['tf_idf']
        .apply(safe_dict_from_vec)
    )
    client_tf_idf_vector['tf_idf_dict'] = (
        client_tf_idf_vector['tf_idf']
        .apply(safe_dict_from_vec)
    )

    # turn into dictionary to loop up idf
    idf_dict = dict(zip(domains_idf['query_name'], domains_idf['idf']))

    scores = []  # (client, device, similarity score)
    for _, dev in fingerprints.iterrows():
        dev_name = dev['device_name']
        dev_dict = dev['tf_idf_dict']

        for _, client in client_tf_idf_vector.iterrows():
            client_ip = client['ip']
            client_dict = client['tf_idf_dict']
            # dictionary: domain to frequency
            cli_vec = {}
            for domain, freq in client_dict.items():
                idf = idf_dict.get(domain, 0.0)  # look up domain's IDF, default 0.0
                cli_vec[domain] = freq * idf

            domains = list(dev_dict.keys())  # TODO: check if there can be duplicates here, if it was taken care of
            psi = np.array([dev_dict[domain] for domain in domains])
            gamma = np.array([cli_vec.get(domain, 0.0) for domain in domains])# if domain not found in client then set to 0

            similarity_score = compute_cosine_similarity(psi, gamma)
            scores.append((client_ip, dev_name, similarity_score))

    scores_df = pd.DataFrame(scores, columns=['client_ip', 'device_name', 'similarity_score'])
    return scores_df


def get_best_matches(scores_df, thresholds_df):
    """
    Get the best matches for each client based on similarity scores and thresholds.
    Args:
        scores_df (pd.DataFrame): DataFrame containing similarity scores with 'client_ip', 'device_name', and 'similarity_score' columns.
        thresholds_df (pd.DataFrame): DataFrame containing device thresholds with 'device_name' and 'threshold' columns.
    Returns:
        pd.DataFrame: DataFrame containing the best matches for each client.
    """
    merged = scores_df.merge(thresholds_df, on='device_name')
    matches = merged[merged['similarity_score'] >= merged['threshold']].copy()
    matches['relative'] = matches['similarity_score'] - matches['threshold']

    best_by_score = matches.loc[matches.groupby('client_ip')['similarity_score'].idxmax()]
    best_by_relative = matches.loc[matches.groupby('client_ip')['relative'].idxmax()]

    # best_scores = (
    #     scores_df.sort_values(by='similarity_score', ascending=False).groupby('client_ip', as_index=False).first())
    print("Best matches by absolute score:")
    print(best_by_score)
    print("Best matches by margin above threshold:")
    print(best_by_relative)
    return best_by_relative


