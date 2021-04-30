""""
Author: Bryan Erazo

"""
import argparse
from sys import argv
import socket


def send_top_server(message, ip_address):
    # Check for status
    answer = ''
    hostname = ip_address['ip']
    port = ip_address['port']
    server_address = (hostname, port)
    try:
        ss = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ss.connect(server_address)
        ss.sendall(message.encode('utf-8'))
        answer = ss.recv(512).decode('utf-8')

    except:
        print("[LS] Top server not response : {}".format(error))

    finally:
        ss.close()

    return answer


parser = argparse.ArgumentParser(description="""Root Server""")
# parser.add_argument('-f', type=str, help='File to read for root server', default='PROJI-DNSRS.txt', action='store', dest='in_file')
parser.add_argument('port', type=int, help='This is the ls root server port to listen', action='store')
parser.add_argument('ts1Hostname', type=str, help='This is the top server 1 TS1 hostname', action='store')
parser.add_argument('ts1ListenPort', type=int, help='This is the top server 1 port to listen', action='store')
parser.add_argument('ts2Hostname', type=str, help='This is the top server 2 TS2 hostname', action='store')
parser.add_argument('ts2ListenPort', type=int, help='This is the top server 1 port to listen', action='store')
# parser.add_argument('next_port', type=int, help='This is the top server port to listen', action='store')
args = parser.parse_args(argv[1:])
print(args)

# load the top servers
ip_addresses = {0: {'ip': args.ts1Hostname, 'port': args.ts1ListenPort, 'online': 1},
                1: {'ip': args.ts2Hostname, 'port': args.ts2ListenPort, 'online': 1}}

# with open(args.in_file) as f:
#     for line in f:
#         (key, ip, flag) = line.strip().split(' ')
#         key = key.lower()
#         ip_addresses[key] = sorted({ip, flag})
# # print(ip_addresses)

# Find next server ip address
thostname = 'NOTHING'

# Create a new socket
try:
    ss = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("[LS]: Server socket created")

except socket.error as error:
    print("Server socket error: {}".format(error))
    exit()

server_addr = ('', args.port)
ss.bind(server_addr)
ss.listen(1)

# print server info
host = socket.gethostname()
print("[LS]: Server hostname is {}".format(host))
localhost_ip = socket.gethostbyname(host)
print("[LS]: Server IP address is {}".format(localhost_ip))
print("[LS]: Server port number is {}".format(args.port))

while True:

    # accept a client
    csockid, addr = ss.accept()
    print("[S]: Got a connection request from a client at {}".format(addr))

    with csockid:
        while True:
            data = csockid.recv(512)
            data = data.decode('utf-8')
            if data != '':
                top_server_index_request = hash(data) % 2
                print("[LS]: Ask to TS{} for ({})".format(top_server_index_request, data))
                try:
                    tp_response = send_top_server(data, ip_addresses[top_server_index_request])
                    print("[TS:{}]: {}".format(top_server_index_request, tp_response))
                    if tp_response == 'nothing':
                        print("[TS:{}]: {}".format(top_server_index_request, tp_response))
                        raise Exception


                except:
                    if top_server_index_request == 0:
                        new_index = 1
                    elif top_server_index_request == 1:
                        new_index = 0
                    print("[LS]: TS{} not response Ask to TS{} for ({})".format(top_server_index_request, new_index,
                                                                                   data))

                    try:
                        tp_response = send_top_server(data, ip_addresses[new_index])
                        print("[TS{}]: ({})".format(new_index, tp_response))
                        if tp_response == 'nothing':
                            raise Exception
                    except:
                        print("[LS]: TS{} and TS{} servers are down Error dispatched to client".format(top_server_index_request, new_index))
                        tp_response = data+" - Error:HOST NOT FOUND"

                csockid.sendall(str(tp_response).encode('utf-8'))
            elif data is None or data == '':
                break

# ss.close()
# exit()
