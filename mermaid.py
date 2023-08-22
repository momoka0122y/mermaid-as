import json  # New line
import networkx as nx
import csv
import subprocess
import sys
import re
import argparse
from ipwhois import IPWhois
from ipaddress import IPv6Address, IPv4Address
from ipwhois import exceptions

AS_NAME_CACHE = {}  # New line
DEFAULT_INPUT_FILE = 'top-100.csv'
UNRESOLVED_AS = 'AS???'
MTR_OUTPUT_HEADER_LINES = 2  # Number of header lines in MTR output

def merge_nodes(mermaid_dict):
    node_edges = {}
    merged_nodes = {}

    for as_number, as_info in mermaid_dict.items():
        print(f"Checking edges for {as_number}")
        for edge, _ in as_info['edges'].items():
            for node in edge:
                if not node.startswith('???_to_'):
                    continue
                if node not in node_edges:
                    node_edges[node] = {'in': set(), 'out': set()}
                if node == edge[0]:
                    node_edges[node]['out'].add(edge[1])
                else:
                    node_edges[node]['in'].add(edge[0])

    for node, edges in node_edges.items():
        merged_nodes[node] = node  # Initially, each node is merged into itself
        for other_node, other_edges in node_edges.items():
            if other_node == node:
                continue
            if edges['in'] == other_edges['in'] and edges['out'] == other_edges['out']:
                print(f"Merging {other_node} into {node}")
                merged_nodes[other_node] = node

    for as_number, as_info in mermaid_dict.items():
        for edge in list(as_info['edges']):
            new_edge = (merged_nodes.get(edge[0], edge[0]), merged_nodes.get(edge[1], edge[1]))
            if new_edge != edge:
                domain = as_info['edges'].pop(edge)
                as_info['edges'][new_edge] = None if domain else domain

        mermaid_dict[as_number]['nodes'] = [merged_nodes.get(node, node) for node in as_info['nodes'] if merged_nodes.get(node, node) in as_info['nodes']]

    return mermaid_dict




def run_mtr_and_get_output(domain, ip_version=None):
    """
    Runs MTR and captures the output.
    If host resolution fails or result contains local IP, None is returned.
    """
    command = ['sudo', '/opt/homebrew/Cellar/mtr/0.95/sbin/mtr', f'{ip_version or "-"}zbw', domain]
    result = subprocess.run(command, capture_output=True, text=True)
    if "Failed to resolve host" in result.stderr or '127.0.0.1' in result.stdout:
        return None
    else:
        return result.stdout
    
def get_as_info_from_ip(ip):
    command = ['whois', ip]
    result = subprocess.run(command, capture_output=True, text=True)

    inetnum_pattern = re.compile(r'inetnum:\s+([\d.]+)\s+-\s+([\d.]+)')
    netname_pattern = re.compile(r'netname:\s+(\w+)')
    smallest_range = float('inf')
    smallest_netname = '???'

    lines = result.stdout.split('\n')
    i = 0
    while i < len(lines):
        line = lines[i]
        inetnum_match = inetnum_pattern.match(line)
        if inetnum_match:
            start_ip, end_ip = inetnum_match.groups()
            start_ip = tuple(map(int, start_ip.split('.')))
            end_ip = tuple(map(int, end_ip.split('.')))
            ip_range = sum((b - a) * 256 ** (3 - j) for j, (a, b) in enumerate(zip(start_ip, end_ip)))
            
            if ip_range < smallest_range:
                smallest_range = ip_range
                # Continue searching for 'netname:' after finding 'inetnum:'
                found_netname = False
                for j in range(i + 1, len(lines)):
                    netname_match = netname_pattern.match(lines[j])
                    if netname_match:
                        smallest_netname = netname_match.groups()[0]
                        found_netname = True
                        break # Break the inner loop once 'netname:' is found
                if not found_netname:
                    smallest_netname = '???'
        i += 1

    return smallest_netname











def parse_mtr_output(mtr_output, domain, simple=False):
    """
    Parses MTR output and returns AS paths.
    For each line in MTR output, it extracts ASN, domain and IP address, and prepares a dictionary.
    """
    as_paths = []
    lines = mtr_output.split('\n')
    as_group_list = []  # List of Lists to maintain the nodes in the same AS in order
    for i, line in enumerate(lines[MTR_OUTPUT_HEADER_LINES:], start=1):
        parts = line.split()
        if len(parts) < 3 or not re.match(r'\d', parts[0]):
            continue

        as_number = parts[1]
        domain_name = ''
        ip = ''

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
                as_number= get_as_info_from_ip(ip)
        else:
            domain_name = f'???_to_{domain}_{i}'

        if simple:
            if not as_group_list or as_group_list[-1][0]['as'] != as_number:
                as_group_list.append([{'as': as_number, 'domain_name': domain_name, 'ip': ip}])
            else:
                as_group_list[-1].append({'as': as_number, 'domain_name': domain_name, 'ip': ip})
        else:
            as_paths.append({'as': as_number, 'domain_name': domain_name, 'ip': ip})

        if i == 3:
            ip += '(start)'
            domain_name += '(start)'

    if simple:
        for group in as_group_list:
            if len(group) > 1:
                as_paths.append(group[0])  # Add the first node
                as_paths.append(group[-1])  # Add the last node
            else:
                as_paths += group  # If only one node, just add it

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
    parser.add_argument('--simple', action='store_true',
                        help='Only display the first and last node in each AS path')

    return parser.parse_args()

def normalize_node_name(name):
    """
    Normalizes a node name by replacing consecutive dashes with a single dash.
    """
    return re.sub(r'-+', '-', name)


def generate_mermaid_code(as_paths, domain, mermaid_dict):
    """
    Generates Mermaid code from AS paths.
    Each AS path is processed and added to a dictionary representation of a graph.
    """
    for i in range(len(as_paths)):
        as_number = as_paths[i]['as']
        domain_name = as_paths[i]['domain_name']
        domain_name = normalize_node_name(domain_name)
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
    created_subgraphs = set()

    # Create nodes
    for as_number, as_info in mermaid_dict.items():
        for node in as_info['nodes']:
            display_node = node if not node.startswith('???_to_') else '???'
            if as_number == UNRESOLVED_AS or as_number == '???':
                mermaid_text += f'  {node}("{display_node}")\n'
            else:
                if as_number not in created_subgraphs:
                    # Create a subgraph name using AS number and AS name if availabl
                    subgraph_name =  as_number

                    mermaid_text += f'  subgraph "{subgraph_name.strip()}"\n'  # Put "" around subgraph name
                    created_subgraphs.add(as_number)
                mermaid_text += f'    {node}("{display_node}")\n'
        if as_number in created_subgraphs:
            mermaid_text += f'  end\n'

    # Create edges
    for as_number, as_info in mermaid_dict.items():
        for edge, domain in as_info['edges'].items():
            mermaid_text += f'  {edge[0]} -- "{domain}" --> {edge[1]}\n' if domain else f'  {edge[0]} ---> {edge[1]}\n'

    return mermaid_text.strip()  # remove trailing and leading whitespaces



    


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

            as_paths = parse_mtr_output(mtr_output, domain, args.simple)
            mermaid_dict = generate_mermaid_code(as_paths, domain, mermaid_dict)

            # Merge nodes here
            mermaid_dict = merge_nodes(mermaid_dict)

            # print(mermaid_dict)

            mermaid_code = generate_mermaid_text(mermaid_dict)
            print(f'Mermaid code:\n{mermaid_code}\n')

            if len(mermaid_code) <= 50000:  # Check the number of characters
                with open('output.mmd', 'w') as file:
                    file.write(mermaid_code)
            else:
                print("The text is too long to be written into the file.")

if __name__ == "__main__":
    main()



