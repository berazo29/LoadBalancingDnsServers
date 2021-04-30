""""
Author: Bryan Erazo

Reference: https://routley.io/posts/hand-writing-dns-messages/
Details: function send_udp_message() was borrowed from the above site

"""
import argparse
from sys import argv
import socket
import binascii

def hex_encode(word):
    str_encoded = ''

    if word == '':
        return str_encoded

    else:
        x = word.split('.')
        for i in x:
            if len(i) < 16:
                str_len = str(hex(len(i))).replace('0x', '0')
            else:
                str_len = str(hex(len(i))).replace('0x','')
            str_ = str(i).encode('utf-8')

            str_encoded += str_len + binascii.hexlify(str_).decode('utf-8')
    return str_encoded


def space_hex(s):
    if s == '':
        return ''
    return ' '.join(map('{}{}'.format, *(s[::2], s[1::2]))).strip()


# Extract number of answer only if valid
def extract_ans(hex_str):
    if hex_str == '':
        return 0
    if len(hex_str) < 16:
        return 0
    x = int(hex_str[12:16], 16)
    return x


# Extract ip from hex when only one answer
def extract_one_ip(hex_str):
    if hex_str == '':
        return ''
    size = len(hex_str)
    if size < 16:
        return ''

    x = hex_str[size - 8:]
    x = space_hex(x).split(' ')
    ip = ''
    for i in x:
        ip += str(int(i, 16)) + '.'
    ip = ip.rstrip(ip[-1])
    return ip


def send_udp_message(message, address, port):
    """send_udp_message sends a message to UDP server

    message should be a hexadecimal encoded string
    """
    message = message.replace(" ", "").replace("\n", "")
    server_address = (address, port)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(binascii.unhexlify(message), server_address)
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()
    return binascii.hexlify(data).decode("utf-8")


def is_in_local_table(ip_addresses, key):

    if key in ip_addresses.keys():
        return True
    else:
        return False


def load_local_dns_table(ip_addresses, key, ip):

    if is_in_local_table(ip_addresses, key):
        return ip_addresses
    else:
        ip_addresses[key] = ip


parser = argparse.ArgumentParser(description="""TOP SERVER TS1""")
parser.add_argument('port', type=int, help='This is TS1 port to listen', action='store')
# parser.add_argument('next_port', type=int, help='This is the top server port to listen', action='store')
args = parser.parse_args(argv[1:])
print(args)

# LOCAL TABLE
local_ip_addresses = {}



# Create a new socket
try:
    ss = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("[TS1]: Server socket created")

except socket.error as error:
    print("Server socket error: {}".format(error))
    exit()

server_addr = ('', args.port)
ss.bind(server_addr)
ss.listen(1)

# print server info
host = socket.gethostname()
print("[TS1]: Server hostname is {}".format(host))
localhost_ip = socket.gethostbyname(host)
print("[TS1]: Server IP address is {}".format(localhost_ip))
print("[TS1]: Server port number is {}".format(args.port))
print("[TS1]: Server DNS UDP {} {} port {}".format('GOOGLE', '8.8.8.8', 53))

# Parts of the message
header = "AA AA 01 00 00 01 00 00 00 00 00 00"
end = "00 00 01 00 01"
hits = 0
misses = 0
while True:
    # print LOCAL DNS, i=hits and misses
    print("[TS1]: LOCAL DND_TABLE {}\n".format(local_ip_addresses))
    print("hits:{} misses:{}".format(hits, misses))
    # accept a client
    csockid, addr = ss.accept()
    print("[TS1]: Got a connection request from a client at {}".format(addr))

    with csockid:
        while True:

            # Read the request from client
            data = csockid.recv(512)
            data = data.decode('utf-8')

            # Check local dns_table
            if is_in_local_table(local_ip_addresses, data.lower()):
                hits += 1
                csockid.sendall(local_ip_addresses[data.lower()].encode('utf-8'))
                break

            # Build message with UDP protocol format
            body = space_hex(hex_encode(data))
            message = header + " " + body + " " + end

            # Request ip address from google DNS following UDP protocol
            response = send_udp_message(message, "8.8.8.8", 53)
            # print(response)

            # Number of answer from google
            num_ans = extract_ans(response)

            # No answer close connection
            if num_ans == 0:
                if data != '':
                    msg = 'nothing'
                    load_local_dns_table(local_ip_addresses, data.lower(), msg)
                    csockid.sendall(msg.encode('utf-8'))
                    misses += 1
                break
            # Get the ip from last bytes
            elif num_ans == 1:
                sent = extract_one_ip(response)
                print('[TS1]: {}'.format(sent))
                load_local_dns_table(local_ip_addresses, data.lower(), sent)
                misses += 1
                csockid.sendall(sent.encode('utf-8'))

            else:
                #
                res_answer = response.split('c00c')
                res_header = res_answer.pop(0)

                # print(res_answer)

                sent = ''

                for i in res_answer:
                    num = int(i[0:4], 16)

                    # Check for type 1 and extract the ip
                    if num == 1:
                        sent += extract_one_ip(i) + ','
                    else:
                        # if not type 1 return the other and the ip
                        sent += 'other' + ',' + extract_one_ip(i) + ','

                # Remove extra character at the end
                sent = sent.rstrip(sent[-1])
                print('[TS1]: {}'.format(sent))
                load_local_dns_table(local_ip_addresses, data.lower(), sent)
                misses += 1
                csockid.sendall(sent.encode('utf-8'))

# ss.close()
# exit()