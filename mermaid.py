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
    """
    Fetches the ASN and AS name for the given IP address.
    Returns UNRESOLVED_AS constant for undefined or problematic IPs.
    """
    try:
        # Use IPWhois to do a lookup on the IP address
        ipwhois = IPWhois(ip)
        result = ipwhois.lookup_rdap(depth=1)
        print("whois", result)
        as_number = result['asn']
        as_name = result['asn_description']

        # Cache AS name for later use
        AS_NAME_CACHE[as_number] = as_name
    except exceptions.IPDefinedError:
        return UNRESOLVED_AS, ""
    except Exception as e:
        print(f"Error while getting AS info from IP: {e}")
        return UNRESOLVED_AS, ""

    # If as_name is not defined, set it to empty string
    if as_name is None:
        as_name = ""

    # Return the AS number and AS name
    return as_number, as_name






def parse_mtr_output(mtr_output, domain, simple=False, include_as_name=False):
    """
    Parses MTR output and returns AS paths.
    For each line in MTR output, it extracts ASN, domain and IP address, and prepares a dictionary.
    """
    as_paths = []
    lines = mtr_output.split('\n')
    as_group_list = []  # List of Lists to maintain the nodes in the same AS in order
    as_name = ''
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
                as_number, as_name = get_as_info_from_ip(ip)
                if as_number == UNRESOLVED_AS:
                    as_name = ''
        else:
            domain_name = f'???_to_{domain}_{i}'
            as_name = '' 

        if simple:
            if not as_group_list or as_group_list[-1][0]['as'] != as_number:
                as_group_list.append([{'as': as_number, 'domain_name': domain_name, 'ip': ip, 'as_name': as_name}])
            else:
                as_group_list[-1].append({'as': as_number, 'domain_name': domain_name, 'ip': ip, 'as_name': as_name})
        else:
            as_paths.append({'as': as_number, 'domain_name': domain_name, 'ip': ip, 'as_name': as_name})

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
    parser.add_argument('--include_as_name', action='store_true',  # New line
                        help='Include AS names in the output')  # New line

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
            if as_number == UNRESOLVED_AS:
                mermaid_text += f'  {node}("{display_node}")\n'
            else:
                if as_number not in created_subgraphs:
                    # Get AS name from global cache
                    as_name = AS_NAME_CACHE.get(as_number[2:], "")
                    # Create a subgraph name using AS number and AS name if available
                    subgraph_name = f"{as_number}-{as_name.strip()}" if as_name else as_number

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


def generate_inet_henge_json(mermaid_dict):
    inet_henge_json = {
        'nodes': [],
        'links': []
    }
    created_nodes = {}

    # Create nodes
    for as_number, as_info in mermaid_dict.items():
        for node in as_info['nodes']:
            display_node = node #if not node.startswith('???_to_') else '???'
            
            if node not in created_nodes:
                identifier = node  # Using the original node value as the identifier
                node_info = {
                    'identifier': identifier,
                    'name': display_node,
                    'meta': {
                        # Additional meta information can be added here if available
                    },
                    'icon': './images/router.png'  # Default icon
                }
                inet_henge_json['nodes'].append(node_info)
                created_nodes[node] = identifier

    # Create edges
    for as_number, as_info in mermaid_dict.items():
        for edge, domain in as_info['edges'].items():
            source_identifier = created_nodes.get(edge[0])
            target_identifier = created_nodes.get(edge[1])
            link_info = {
                'source': source_identifier,
                'target': target_identifier,
                'meta': {
                    'domain': domain if domain else None
                    # Additional meta information can be added here if available
                }
            }
            inet_henge_json['links'].append(link_info)

    # Converting the JSON dictionary to a JSON string
    return json.dumps(inet_henge_json, indent=4)



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

            as_paths = parse_mtr_output(mtr_output, domain, args.simple, args.include_as_name)
            mermaid_dict = generate_mermaid_code(as_paths, domain, mermaid_dict)

            mermaid_code = generate_inet_henge_json(mermaid_dict)
            print(f'Mermaid code:\n{mermaid_code}\n')

            # Merge nodes here
            mermaid_dict = merge_nodes(mermaid_dict)

            print(mermaid_dict)

            mermaid_code = generate_inet_henge_json(mermaid_dict)
            print(f'Mermaid code:\n{mermaid_code}\n')

            if len(mermaid_code) <= 50000:  # Check the number of characters
                with open('output.mmd', 'w') as file:
                    file.write(mermaid_code)
            else:
                print("The text is too long to be written into the file.")

if __name__ == "__main__":
    main()



