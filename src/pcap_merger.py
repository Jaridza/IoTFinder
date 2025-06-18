import glob
import os
import subprocess
import sys


def merge_pcaps(input_files, output_file):
    """
    Merge multiple PCAP files into a single PCAP file.

    Args:
        input_files (list of str): List of paths to input PCAP files.
        output_file (str): Path to the output merged PCAP file.
    """

    command = ['mergecap', '-w', output_file] + input_files
    print(command)
    subprocess.run(command, check=True)
    print(f"Merged {len(input_files)} PCAP files into {output_file}.")


def collect_pcap_files(inputs):
    """
    Given a list of file paths or directory paths, collect all pcap/pcapng files.
    Returns a sorted list of file paths.
    """
    files = []
    for path in inputs:
        if os.path.isdir(path):
            # find .pcap and .pcapng in this directory (non-recursive)
            patterns = [os.path.join(path, '*.pcap'), os.path.join(path, '*.pcapng')]
            for pattern in patterns:
                found = glob.glob(pattern)
                if found:
                    files.extend(found)
        elif os.path.isfile(path):
            files.append(path)
        else:
            print(f"[Warning] '{path}' is not a file or directory, skipping.", file=sys.stderr)
    # Remove duplicates and sort
    unique_files = sorted(set(files))
    return unique_files


inputs_files = collect_pcap_files(["/Users/jaridzatromp/Downloads/Experiment-2/Exp-2_static/"])
merge_pcaps(inputs_files, "/Users/jaridzatromp/Downloads/Experiment-2/Exp-2_static/merged.pcap")
