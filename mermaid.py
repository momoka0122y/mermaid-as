import csv
import subprocess
import sys
from ipwhois import IPWhois
import re 

def run_mtr_and_get_output(domain):
    command = [ 'mtr', '-4zbw', domain]
    result = subprocess.run(command, capture_output=True, text=True)
    if "Failed to resolve host" in result.stderr:
        return None
    return result.stdout



def parse_mtr_output(mtr_output, domain):
    as_paths = []
    lines = mtr_output.split('\n')
    for i, line in enumerate(lines[2:], start=1):  # Skip the first two lines
        parts = line.split()
        if len(parts) < 2 or not re.match(r'\d', parts[0]):
            continue
        as_number, ip = parts[1], parts[2]
        if as_number == "AS???":
            try:
                if ip != "???":
                    obj = IPWhois(ip)
                    results = obj.lookup_rdap(depth=1)
                    as_number = results["asn"]
                else:
                    ip = f'???_to_{domain}_{i}'
            except Exception:
                pass
        if as_number == 'NA':
            as_number = 'AS???'
        as_paths.append({'as': as_number, 'ip': ip})
    return as_paths



def generate_mermaid_code(as_paths, domain, mermaid_dict):
    for i in range(len(as_paths)):
        as_number = as_paths[i]['as']
        ip = as_paths[i]['ip']
        if as_number not in mermaid_dict:
            mermaid_dict[as_number] = {'nodes': [], 'edges': {}}
        if ip not in mermaid_dict[as_number]['nodes']:
            mermaid_dict[as_number]['nodes'].append(ip)
        if i > 0:
            previous_as_number = as_paths[i-1]['as']
            previous_ip = as_paths[i-1]['ip']
            edge = (previous_ip, ip)
            if as_number != previous_as_number:  # if the AS number has changed, add the edge to the current AS
                if edge not in mermaid_dict[as_number]['edges']:
                    mermaid_dict[as_number]['edges'][edge] = domain
                elif edge in mermaid_dict[as_number]['edges'] and mermaid_dict[as_number]['edges'][edge] != None:
                    # if the edge has been used by a different domain, set it to None
                    if mermaid_dict[as_number]['edges'][edge] != domain:
                        mermaid_dict[as_number]['edges'][edge] = None
            else:  # if the AS number has not changed, add the edge to the previous AS
                if edge not in mermaid_dict[previous_as_number]['edges']:
                    mermaid_dict[previous_as_number]['edges'][edge] = domain
                elif edge in mermaid_dict[previous_as_number]['edges'] and mermaid_dict[previous_as_number]['edges'][edge] != None:
                    # if the edge exists and has been used by a different domain, set it to None
                    if mermaid_dict[previous_as_number]['edges'][edge] != domain:
                        mermaid_dict[previous_as_number]['edges'][edge] = None
    return mermaid_dict


def generate_mermaid_text(mermaid_dict):
    mermaid_text = "graph TB\n"
    for as_number, as_info in mermaid_dict.items():
        for node in as_info['nodes']:
            display_node = node if not node.startswith('???_to_') else '???'
            if as_number == 'AS???':
                mermaid_text += '  ' + node + '("' + display_node + '")\n'
            else:
                mermaid_text += '  subgraph ' + as_number + '\n'
                mermaid_text += '    ' + node + '("' + display_node + '")\n'
                mermaid_text += '  end\n'
    for as_number, as_info in mermaid_dict.items():
        for edge, domain in as_info['edges'].items():
            if domain:
                mermaid_text += '  ' + edge[0] + ' -- "' + domain + '" --> ' + edge[1] + '\n'
            else:
                mermaid_text += '  ' + edge[0] + ' ---> ' + edge[1] + '\n'
    return mermaid_text


def main():
    input_file = sys.argv[1] if len(sys.argv) > 1 else 'top-100.csv'
    mermaid_dict = {}

    with open(input_file, 'r') as file:
        reader = csv.reader(file)
        for row in reader:
            domain = row[0]  # domain is in the second column
            mtr_output = run_mtr_and_get_output(domain)
            if mtr_output is None:
                print(f'Failed to resolve hostname for {domain}. Skipping...')
                continue
            as_paths = parse_mtr_output(mtr_output,domain)
            mermaid_dict = generate_mermaid_code(as_paths, domain, mermaid_dict)
            mermaid_code = generate_mermaid_text(mermaid_dict)
            print(f'Mermaid code:\n{mermaid_code}\n')

            with open('output.mmd', 'w') as file:
                file.write(mermaid_code)

if __name__ == "__main__":
    main()

