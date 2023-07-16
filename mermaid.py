import csv
import subprocess
import sys
import re
import argparse
from ipwhois import IPWhois
from ipaddress import IPv6Address, IPv4Address
from ipwhois import exceptions

# Constants
DEFAULT_INPUT_FILE = 'top-100.csv'
UNRESOLVED_AS = 'AS???'
MTR_OUTPUT_HEADER_LINES = 2  # Number of header lines in MTR output

def run_mtr_and_get_output(domain, ip_version=None):
    """
    Runs MTR and captures the output.
    If host resolution fails or result contains local IP, None is returned.
    """
    command = ['mtr', f'{ip_version or "-"}zbw', domain]
    result = subprocess.run(command, capture_output=True, text=True)
    if "Failed to resolve host" in result.stderr or '127.0.0.1' in result.stdout:
        return None
    else:
        return result.stdout

def get_asn_from_ip(ip):
    """
    Fetches the ASN for the given IP address.
    Returns UNRESOLVED_AS constant for undefined or problematic IPs.
    """
    if ip == '???':
        return UNRESOLVED_AS

    lookup_ip = ip
    if ip.lower().startswith('64:ff9b:'):
        ipv6 = IPv6Address(ip)
        lookup_ip = str(IPv4Address(ipv6.packed[-4:]))

    try:
        obj = IPWhois(lookup_ip)
        results = obj.lookup_rdap(depth=1)
        asn = results["asn"]
    except (exceptions.HTTPLookupError, exceptions.IPDefinedError):
        asn = UNRESOLVED_AS

    # Ensure 'AS' prefix
    if asn and not str(asn).upper().startswith('AS'):
        asn = 'AS' + str(asn)

    return asn

def parse_mtr_output(mtr_output, domain):
    """
    Parses MTR output and returns AS paths.
    For each line in MTR output, it extracts ASN, domain and IP address, and prepares a dictionary.
    """
    as_paths = []
    lines = mtr_output.split('\n')

    for i, line in enumerate(lines[MTR_OUTPUT_HEADER_LINES:], start=1):
        parts = line.split()
        if len(parts) < 3 or not re.match(r'\d', parts[0]):
            continue

        as_number = parts[1]
        if len(parts) >= 4 and parts[3].startswith('(') and parts[3].endswith(')'):
            domain_name = parts[2]
            ip = parts[3][1:-1]  # Remove parentheses from IP address
        else:
            domain_name = ''
            ip = parts[2]

        if ip != '???':
            if domain_name == '':
                domain_name = ip
            if as_number == 'AS???':
                as_number = get_asn_from_ip(ip) or UNRESOLVED_AS
        else:
            domain_name = f'???_to_{domain}_{i}'

        as_paths.append({'as': as_number, 'domain_name': domain_name, 'ip': ip})

    print(as_paths)
    return as_paths

def parse_arguments():
    """
    Parses command-line arguments.
    Expects input file path and IP version as arguments.
    """
    parser = argparse.ArgumentParser(description='MTR Parser')
    parser.add_argument('input_file', nargs='?', default=DEFAULT_INPUT_FILE,
                        help='Input file path')
    parser.add_argument('--ip_version', choices=['-4', '-6'], default=None,
                        help='IP version for MTR command')

    return parser.parse_args()

def generate_mermaid_code(as_paths, domain, mermaid_dict):
    """
    Generates Mermaid code from AS paths.
    Each AS path is processed and added to a dictionary representation of a graph.
    """
    for i in range(len(as_paths)):
        as_number = as_paths[i]['as']
        domain_name = as_paths[i]['domain_name']
        ip = as_paths[i]['ip']
        if as_number not in mermaid_dict:
            mermaid_dict[as_number] = {'nodes': [], 'edges': {}}

        if domain_name not in mermaid_dict[as_number]['nodes']:
            mermaid_dict[as_number]['nodes'].append(domain_name)

        if i > 0:
            previous_as_number = as_paths[i-1]['as']
            previous_domain_name = as_paths[i-1]['domain_name']
            edge = (previous_domain_name, domain_name)

            target_as = as_number if as_number != previous_as_number else previous_as_number
            if edge not in mermaid_dict[target_as]['edges']:
                mermaid_dict[target_as]['edges'][edge] = domain
            elif mermaid_dict[target_as]['edges'][edge] != domain:
                mermaid_dict[target_as]['edges'][edge] = None

    return mermaid_dict

def generate_mermaid_text(mermaid_dict):
    """
    Generates text representation of Mermaid diagram.
    For each node and edge in the mermaid dictionary, it generates the corresponding text representation.
    """
    mermaid_text = "graph TB\n"
    for as_number, as_info in mermaid_dict.items():
        for node in as_info['nodes']:
            display_node = node if not node.startswith('???_to_') else '???'
            mermaid_text += f'  {node}("{display_node}")\n' if as_number == UNRESOLVED_AS else f'  subgraph {as_number}\n    {node}("{display_node}")\n  end\n'
        for edge, domain in as_info['edges'].items():
            mermaid_text += f'  {edge[0]} -- "{domain}" --> {edge[1]}\n' if domain else f'  {edge[0]} ---> {edge[1]}\n'
    return mermaid_text

def main():
    """
    Main execution function.
    Reads CSV file with domains, runs MTR, parses the output, generates the Mermaid graph, and writes the result to an output file.
    """
    args = parse_arguments()

    mermaid_dict = {}
    with open(args.input_file, 'r') as file:
        reader = csv.reader(file)
        for row in reader:
            domain = row[0]
            mtr_output = run_mtr_and_get_output(domain, args.ip_version)
            if mtr_output is None:
                print(f'Failed to resolve hostname for {domain}. Skipping...')
                continue

            as_paths = parse_mtr_output(mtr_output, domain)
            mermaid_dict = generate_mermaid_code(as_paths, domain, mermaid_dict)
            mermaid_code = generate_mermaid_text(mermaid_dict)
            print(f'Mermaid code:\n{mermaid_code}\n')

            with open('output.mmd', 'w') as file:
                file.write(mermaid_code)

if __name__ == "__main__":
    main()

