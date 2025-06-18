import pandas as pd
import numpy as np


def compute_window_probabilities(query_df, window_size):
    """Compute the probabilities of each query appearing in a given time window.
    Args:
        query_df (pd.DataFrame): DataFrame containing DNS queries with columns ['ip', 'query_name', 'timestamp'].
        window_size (int): Size of the time window in seconds.
    Returns:
        pd.DataFrame: DataFrame with columns ['ip', 'query_name', 'window_count', 'probabilities'].
    """
    query_df = query_df.copy()
    query_df['timestamp'] = pd.to_numeric(query_df['timestamp'])
    total_time = float(query_df['timestamp'].max() - query_df['timestamp'].min())

    # number of windows
    # Nw = total_time / window_size
    Nw = int(np.ceil(total_time / window_size))

    # map each query to a window index
    query_df['window_index'] = (query_df['timestamp'] // window_size).astype(int)
    # collapse duplicates (query only needs to have appeared once in each window)
    query_df.drop_duplicates(subset=['ip', 'query_name', 'window_index'], inplace=True)

    # count in how many windows it (<ip, domain>) appeared
    counts_df = (query_df.groupby(['ip', 'query_name']).size().reset_index(name='window_count'))

    counts_df['window_count'] = pd.to_numeric(counts_df['window_count'])
    counts_df['probabilities'] = (counts_df['window_count']) / Nw

    return counts_df


def build_fingerprints(query_df, window_time, device_mapping_file):
    """Build fingerprints from DNS queries.
    Args:
        query_df (pd.DataFrame): DataFrame containing DNS queries with columns ['ip', 'query_name', 'timestamp'].
        window_time (int): Size of the time window in seconds.
        device_mapping_file (str): Path to a CSV file mapping device names to IPs.
    Returns:
        pd.DataFrame: DataFrame with columns ['device_name', 'fingerprint']
        where fingerprint is a list of tuples (query, probability).
    """
    probabilities = compute_window_probabilities(query_df, window_time)

    # for each ip -> set of tuples (query, probability)
    fingerprints = (
        probabilities
        .groupby('ip')
        .apply(lambda x: pd.Series({'fingerprint': list(zip(x['query_name'], x['probabilities']))}),
               include_groups=False)
        .reset_index()
    )

    print("Fingerprintssss:")
    print(fingerprints)

    # mapping device names to fingerprints (device_name -> identifier (ip/mac address))
    mapping = pd.read_csv(device_mapping_file,
                          header=None,
                          names=["device_name", "ip"])

    print("Mapping:")
    print(mapping)

    fingerprints = fingerprints.merge(mapping, on='ip', how='left')

    fingerprints = fingerprints.dropna(subset=['device_name'])

    fingerprints.drop(columns=['ip'], inplace=True)

    print("Devices found in fingerprints:")
    print(fingerprints['device_name'].unique())

    return fingerprints
