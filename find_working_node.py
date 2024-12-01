import socket

def read_nodes(file_path):
    """Read nodes from the nodes_main.txt file and clean up entries."""
    nodes = []
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if line:  # Skip empty lines
                # Split by whitespace or '#' to remove comments
                clean_line = line.split()[0] if "#" in line else line
                nodes.append(clean_line)
    return nodes

def connect_to_node(node):
    """Attempt to connect to a Bitcoin node."""
    try:
        ip, port = node.split(":")
        port = int(port)
        with socket.create_connection((ip, port), timeout=5) as sock:
            print(f"Successfully connected to node: {node}")
            return True
    except (socket.timeout, socket.error, ValueError) as e:
        print(f"Failed to connect to node: {node} - {e}")
        return False

def find_working_node(nodes_file):
    """Iterate through nodes and return the first working node."""
    nodes = read_nodes(nodes_file)
    for node in nodes:
        if connect_to_node(node):
            return node
    print("No working nodes found.")
    return None

if __name__ == "__main__":
    # Path to your nodes_main.txt file
    nodes_file = "nodes_main.txt"
    working_node = find_working_node(nodes_file)
    if working_node:
        print(f"Working node found: {working_node}")
    else:
        print("Could not find a working node.")
