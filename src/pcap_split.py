import os
import subprocess

def split_pcap_with_editcap(test_data, output_dir, ratios=(0.6,0.2,0.2)):
    # make sure the output directory exists
    os.makedirs(output_dir, exist_ok=True)

    # count total packets in the pcap file
    info = subprocess.check_output(["capinfos", "-cM", test_data], text=True)
    total_packets = int(info.strip().split()[-1])

    # compute ratios
    iotdns_ratio = int(total_packets * ratios[0])
    tp_ratio = int(total_packets * ratios[1])
    ldns_ratio = total_packets - iotdns_ratio - tp_ratio
    print("iotdns_ratio:", iotdns_ratio)
    print("tp_ratio:", tp_ratio)
    print("ldns_ratio:", ldns_ratio)


    # ranges
    ranges = [f"1-{iotdns_ratio}",
              f"{iotdns_ratio + 1}-{iotdns_ratio + tp_ratio}",
              f"{iotdns_ratio + tp_ratio + 1}-{total_packets}"]

    print("Ranges:", ranges)

    # call editcap
    outs = [f"{output_dir}_iotdnsv2.pcap",
            f"{output_dir}_tpv2.pcap",
            f"{output_dir}_ldnsv2.pcap"]

    for rng, out in zip(ranges, outs):
        subprocess.check_call(["editcap", "-r", test_data, out, rng])

    return tuple(outs)




# split_pcap_with_editcap("../data/raw/IoTDNS/dns_2019_08.pcap", "../data/raw/IOTDNS", ratios=(0.6, 0.2, 0.2))
