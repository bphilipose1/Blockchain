import socket
import hashlib
import struct
import time


# Constants
MAGIC_BYTES = bytearray.fromhex("f9beb4d9")  # Mainnet magic bytes
HDR_SZ = 24  # Bitcoin message header size
PORT = 8333  # Default Bitcoin port
VERSION = 70015  # Protocol version
BHOST = '5.14.1.135'
BPORT = 8333
SU_ID = 4140754
TARGET_BLOCK = SU_ID % 10000

'''-------------------------------------------------------------------------------------------------------------'''

def compactsize_t(n):
    if n < 252:
        return uint8_t(n)
    if n < 0xffff:
        return uint8_t(0xfd) + uint16_t(n)
    if n < 0xffffffff:
        return uint8_t(0xfe) + uint32_t(n)
    return uint8_t(0xff) + uint64_t(n)


def unmarshal_compactsize(b):
    key = b[0]
    if key == 0xff:
        return b[0:9], unmarshal_uint(b[1:9])
    if key == 0xfe:
        return b[0:5], unmarshal_uint(b[1:5])
    if key == 0xfd:
        return b[0:3], unmarshal_uint(b[1:3])
    return b[0:1], unmarshal_uint(b[0:1])


def bool_t(flag):
    return uint8_t(1 if flag else 0)


def ipv6_from_ipv4(ipv4_str):
    pchIPv4 = bytearray([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff])
    return pchIPv4 + bytearray((int(x) for x in ipv4_str.split('.')))


def ipv6_to_ipv4(ipv6):
    return '.'.join([str(b) for b in ipv6[12:]])


def uint8_t(n):
    return int(n).to_bytes(1, byteorder='little', signed=False)


def uint16_t(n, byteorder='little'):
    return int(n).to_bytes(2, byteorder=byteorder, signed=False)


def int32_t(n):
    return int(n).to_bytes(4, byteorder='little', signed=True)


def uint32_t(n):
    return int(n).to_bytes(4, byteorder='little', signed=False)


def int64_t(n):
    return int(n).to_bytes(8, byteorder='little', signed=True)


def uint64_t(n):
    return int(n).to_bytes(8, byteorder='little', signed=False)


def unmarshal_int(b):
    return int.from_bytes(b, byteorder='little', signed=True)


def unmarshal_uint(b, byteorder='little'):
    return int.from_bytes(b, byteorder=byteorder, signed=False)


def print_message(msg, text=None):
    """
    Report the contents of the given bitcoin message
    :param msg: bitcoin message including header
    :return: message type
    """
    print('\n{}MESSAGE'.format('' if text is None else (text + ' ')))
    print('({}) {}'.format(len(msg), msg[:60].hex() + ('' if len(msg) < 60 else '...')))
    payload = msg[HDR_SZ:]
    command = print_header(msg[:HDR_SZ], checksum(payload))
    if command == 'version':
        print_version_msg(payload)
    # FIXME print out the payloads of other types of messages, too
    return command


def print_version_msg(b):
    """
    Report the contents of the given bitcoin version message (sans the header)
    :param payload: version message contents
    """
    # pull out fields
    version, my_services, epoch_time, your_services = b[:4], b[4:12], b[12:20], b[20:28]
    rec_host, rec_port, my_services2, my_host, my_port = b[28:44], b[44:46], b[46:54], b[54:70], b[70:72]
    nonce = b[72:80]
    user_agent_size, uasz = unmarshal_compactsize(b[80:])
    i = 80 + len(user_agent_size)
    user_agent = b[i:i + uasz]
    i += uasz
    start_height, relay = b[i:i + 4], b[i + 4:i + 5]
    extra = b[i + 5:]

    # print report
    prefix = '  '
    print(prefix + 'VERSION')
    print(prefix + '-' * 56)
    prefix *= 2
    print('{}{:32} version {}'.format(prefix, version.hex(), unmarshal_int(version)))
    print('{}{:32} my services'.format(prefix, my_services.hex()))
    time_str = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(unmarshal_int(epoch_time)))
    print('{}{:32} epoch time {}'.format(prefix, epoch_time.hex(), time_str))
    print('{}{:32} your services'.format(prefix, your_services.hex()))
    print('{}{:32} your host {}'.format(prefix, rec_host.hex(), ipv6_to_ipv4(rec_host)))
    print('{}{:32} your port {}'.format(prefix, rec_port.hex(), unmarshal_uint(rec_port, 'big')))
    print('{}{:32} my services (again)'.format(prefix, my_services2.hex()))
    print('{}{:32} my host {}'.format(prefix, my_host.hex(), ipv6_to_ipv4(my_host)))
    print('{}{:32} my port {}'.format(prefix, my_port.hex(), unmarshal_uint(my_port, 'big')))
    print('{}{:32} nonce'.format(prefix, nonce.hex()))
    print('{}{:32} user agent size {}'.format(prefix, user_agent_size.hex(), uasz))
    print('{}{:32} user agent \'{}\''.format(prefix, user_agent.hex(), str(user_agent, encoding='utf-8')))
    print('{}{:32} start height {}'.format(prefix, start_height.hex(), unmarshal_uint(start_height)))
    print('{}{:32} relay {}'.format(prefix, relay.hex(), bytes(relay) != b'\0'))
    if len(extra) > 0:
        print('{}{:32} EXTRA!!'.format(prefix, extra.hex()))


def print_header(header, expected_cksum=None):
    """
    Report the contents of the given bitcoin message header
    :param header: bitcoin message header (bytes or bytearray)
    :param expected_cksum: the expected checksum for this version message, if known
    :return: message type
    """
    magic, command_hex, payload_size, cksum = header[:4], header[4:16], header[16:20], header[20:]
    command = str(bytearray([b for b in command_hex if b != 0]), encoding='utf-8')
    psz = unmarshal_uint(payload_size)
    if expected_cksum is None:
        verified = ''
    elif expected_cksum == cksum:
        verified = '(verified)'
    else:
        verified = '(WRONG!! ' + expected_cksum.hex() + ')'
    prefix = '  '
    print(prefix + 'HEADER')
    print(prefix + '-' * 56)
    prefix *= 2
    print('{}{:32} magic'.format(prefix, magic.hex()))
    print('{}{:32} command: {}'.format(prefix, command_hex.hex(), command))
    print('{}{:32} payload size: {}'.format(prefix, payload_size.hex(), psz))
    print('{}{:32} checksum {}'.format(prefix, cksum.hex(), verified))
    return command


'''-------------------------------------------------------------------------------------------------------------'''

def checksum(payload):
    """
    Calculate the checksum of the given payload
    :param payload: payload to checksum
    :return: checksum
    """
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]

def create_message(command, payload=b""):
    command_bytes = command.encode('utf-8').ljust(12, b'\x00')  # Ensure 12 bytes
    payload_length = len(payload)
    ret_checksum = checksum(payload)
    return MAGIC_BYTES + command_bytes + int32_t(payload_length) + ret_checksum + payload
 
def version_message():
    """Craft a version message."""
    version = uint32_t(VERSION)
    services = uint64_t(0)
    timestamp = uint64_t(int(time.time()))
    addr_recv_services = uint64_t(1)
    addr_recv_ip = ipv6_from_ipv4(BHOST)
    addr_recv_port = uint16_t(BPORT)
    addr_trans_services = uint64_t(1)
    cur_ip = socket.gethostbyname(socket.gethostname())  # Get current IP
    addr_trans_ip = ipv6_from_ipv4(cur_ip)
    addr_trans_port = uint16_t(PORT)
    nonce = uint64_t(0)
    user_agent = uint8_t(0)  # Empty user agent
    start_height = uint32_t(0)
    relay = uint8_t(0)  # Relay transactions off

    payload = (
        version +
        services +
        timestamp +
        addr_recv_services + addr_recv_ip + addr_recv_port +
        addr_trans_services + addr_trans_ip + addr_trans_port +
        nonce +
        user_agent +
        start_height +
        relay
    )
    return payload

def connect_to_node(ip, port):
    """Connect to a Bitcoin node and return the socket."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip, port))
    print(f"Connected to node {ip}:{port}")
    return sock

def recv_all(sock, size):
    data = b""
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise ConnectionError("Socket connection broken")
        data += part
    return data

def get_getblocks_message(starting_hash, stop_hash=bytearray(32)):
    """
    Create a getblocks message payload to request block headers starting from a specific hash.
    :param starting_hash: The hash of the block to start fetching from (32 bytes).
    :param stop_hash: The hash to stop fetching at (default: all zeroes).
    :return: Serialized getblocks message payload.
    """
    version = uint32_t(VERSION)  # Protocol version
    hash_count = compactsize_t(1)  # Number of hashes (starting point only)
    return version + hash_count + starting_hash + stop_hash


def parse_inv_message(payload):
    """
    Parse an 'inv' message payload and extract inventory items.
    """
    offset = 0

    # Extract count (compactSize uint)
    count_bytes, count = unmarshal_compactsize(payload)
    offset += len(count_bytes)

    print(f"Inventory count: {count}")

    inventory = []
    for _ in range(count):
        # Each inventory entry is 36 bytes: 4 bytes for type, 32 bytes for hash
        type_id = unmarshal_uint(payload[offset:offset + 4])
        hash_value = payload[offset + 4:offset + 36]
        inventory.append((type_id, hash_value.hex()))
        offset += 36

    return inventory


def create_getdata_message(block_hash):
    payload = struct.pack("<I", 1)  # Number of inventory items
    payload += struct.pack("<I", 0x02)  # MSG_BLOCK type
    payload += block_hash[::-1]  # Block hash (little-endian)
    return payload



def main():
    """Main function to exchange version and verack messages."""
    try:
        #connect to the Bitcoin node
        sock = connect_to_node(BHOST, BPORT)
        sock.settimeout(10)

        #Step 1: Send the version message
        v_message = version_message()
        v_packet = create_message("version", v_message)
        sock.sendall(v_packet)
        print_message(v_packet, "sending")

        # Step 2: Receive and handle the version response
        response = recv_all(sock, HDR_SZ + 111)  # Header + estimated payload size
        print_message(response, "received")

        # Step 3: Send the verack message
        verack_packet = create_message("verack")
        sock.sendall(verack_packet)
        print_message(verack_packet, "sending")

        # Step 4: Receive and handle the verack response
        response = recv_all(sock, HDR_SZ)  # Verack has no payload
        print_message(response, "recieved")
        
        # Step 5: Handle additional messages (e.g., ping, sendheaders, sendcmpct)
        while True:
            try:
                # Receive and process header
                response = recv_all(sock, HDR_SZ)
                payload_size = unmarshal_uint(response[16:20])
                response += recv_all(sock, payload_size)
                command = print_message(response, "received")

                # Handle specific messages
                if command == "ping":
                    #sending pong message to keep the P2P alive
                    nonce = response[HDR_SZ:HDR_SZ + 8]
                    pong_message = create_message("pong", nonce)
                    sock.sendall(pong_message)
                    print_message(pong_message, "sending")
                elif command == "addr":
                    print("Received peer addresses")
                elif command == "feefilter":
                    print("Received feefilter message")
                    break
                else:
                    print(f"Unhandled command: {command}")

            except socket.timeout:
                print("Timeout reached, no more messages.")
                break
            except socket.error as e:
                print(f"Socket error: {e}")
                break

            
        # Step 5: Send getblocks message
        print('step5\n\n\n\n\n\n\n\n\n\n\n\n')
        last_hash = bytearray(32)  # Genesis block hash (all zeroes)
        block_inventory = []
        found = False

        while not found:
            print('Requesting more blocks...')
            getblocks_payload = get_getblocks_message(last_hash)  # Request blocks starting from last_hash
            getblocks_packet = create_message("getblocks", getblocks_payload)
            sock.sendall(getblocks_packet)
            print_message(getblocks_packet, "sending")

            # Step 6: Receive inv response
            response = recv_all(sock, HDR_SZ)  # Receive header first
            payload_size = unmarshal_uint(response[16:20])
            response += recv_all(sock, payload_size)  # Receive the rest of the payload
            print_message(response, "received")

            # Parse the inv message
            inventory = parse_inv_message(response[HDR_SZ:])
            block_inventory.extend(inventory)  # Append new inventory to our list
            print(f"Received {len(inventory)} inventory items, checking for block {TARGET_BLOCK}")

            # Check if the target block is in the current inventory

            if len(block_inventory) >= TARGET_BLOCK:
                target_block = block_inventory[TARGET_BLOCK - 1]  # Adjust for zero-based index
                print(f"Block {TARGET_BLOCK} found: Type {target_block[0]}")
                found = True
                break
            else:
                print(f'Not found yet, current inventory size: {len(block_inventory)}')

        #print out target block from the inventory
        print(f'Inventory: {len(block_inventory)}')
        print(f"Target block ({TARGET_BLOCK}): {block_inventory[TARGET_BLOCK - 1]}")


        # Step 6: Request the full block with getdata message
        block_hash = bytes.fromhex(block_inventory[TARGET_BLOCK - 1][1])
        getdata_payload = create_getdata_message(block_hash)
        getdata_packet = create_message("getdata", getdata_payload)
        sock.sendall(getdata_packet)
        print_message(getdata_packet, "sending")

        # Step 7: Receive the block message
        sock.settimeout(30)
        response = recv_all(sock, HDR_SZ)  # Header first
        payload_size = unmarshal_uint(response[16:20])
        response += recv_all(sock, payload_size)  # Receive the rest of the block message
        print_message(response, "received")

        # Step 8: Parse and display the transactions in the block
        transactions = parse_block_message(response[HDR_SZ:])
        print(f"Transactions in block {TARGET_BLOCK}:")
        for tx_idx, tx in enumerate(transactions):
            print(f"Transaction {tx_idx + 1}: {tx}")

        # Close the connection
        sock.close()
        print("Connection successfully closed")
    except (socket.error, socket.timeout) as e:
        print(f"Failed to connect or exchange messages: {e}")

if __name__ == "__main__":
    main()