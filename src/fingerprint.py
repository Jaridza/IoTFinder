import pandas as pd

def build_fingerprints(query_df, window_time):
    """
    Build statistical fingerprints for each device based on DNS queries.
    :param query_df: DataFrame containing DNS queries with columns ['ip', 'query_name', 'timestamp'].
    :param window_time: Time window size in seconds to group queries.
    :return: DataFrame with columns ['ip', 'fingerprint'] where fingerprint is a list of tuples (query_name, probability).
    """
    query_df['timestamp'] = pd.to_numeric(query_df['timestamp'])
    total_time = float(query_df['timestamp'].max() - query_df['timestamp'].min())
    # number of windows
    Nw = total_time / window_time

    # map each query to a window index
    query_df['window_index'] = (query_df['timestamp'] // window_time).astype(int)

    # collapse duplicates (query only needs to have appeared once in each window)
    query_df.drop_duplicates(subset=['ip', 'query_name', 'window_index'], inplace=True)

    # count in how many windows it (<ip, domain>) appeared
    counts = query_df.value_counts(subset=['ip', 'query_name'])
    counts.name = "window_count"
    counts_df = counts.reset_index()  # makes it a column

    counts_df['window_count'] = pd.to_numeric(counts_df['window_count'])
    counts_df['probabilities'] = (counts_df['window_count']) / Nw

    # for each ip -> set of tuples (query, probability)
    fingerprints = (
        counts_df
        .groupby('ip')
        .apply(lambda x: pd.Series({'fingerprint': list(zip(x['query_name'],x['probabilities']))}), include_groups=False)
        .reset_index()
    )

    # THIS IS SPECIFIC TO THE DATASET - mapping device names to fingerprints
    mapping = pd.read_csv("../data/raw/IoTDNS/device_mapping.csv",
                          header=None,
                          names=["device_name", "ip"])

    fingerprints = fingerprints.merge(mapping, on='ip', how='left')
    print(fingerprints.head())
    # TODO: remove the ip column?

    return fingerprints
