'''
# tshark -r com.chengyu.bar-2-False.pcap -Tfields -e tls.handshake.extensions_server_name -Y 'tls.handshake.extension.type == 0'
#OK one: tshark -r your_pcap_file.pcap -T fields -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e tls.handshake.extensions_server_name -Y "ssl.handshake.extensions_server_name"
'''

import glob
import json
import os

from parse import parse
from mitmproxy import io, http
from custom_define import walk_pkg_names
from custom_define import DEVICE, PKG, IS_MITM, HOST, URL, METHOD, SRC_IP, SRC_PORT, DEST_IP, DEST_PORT, FRIDA_ON, CERT_TYPE, STATUS, TS, TLS_SETUP, TLS_START
from custom_define import CONNECT_LOWERCASE
from custom_define import PASSTHROUGH



HTTP_PORT = 80
HTTPS_PORT = 443


def is_empty_file(file):
    return False if os.path.getsize(file) else True


def skip_flow(flow):
    if not isinstance(flow, http.HTTPFlow) or flow.request.scheme.lower() == "http":
        return True
    return False


def get_client_address(flow):
    client_addr = None
    if hasattr(flow.client_conn, "peername"):
        client_addr = flow.client_conn.peername
    else:
        client_addr = flow.client_conn.address
    return client_addr[0], client_addr[1]


def get_server_address(flow):
    # server_name = flow.server_conn.address    # address can be either the remote server domain or the ip address
    # server_addr = flow.server_conn.ip_address
    server_addr = None
    if hasattr(flow.server_conn, "peername"):
        server_addr = flow.server_conn.peername
    elif hasattr(flow.server_conn, "ip_address"):
        server_addr = flow.server_conn.ip_address
    else:
        server_addr = flow.server_conn.ip_address()

    if server_addr != None:
        return server_addr[0], server_addr[1]
    else:
        return None, None


def parse_network(device, out_dir):
    # parse mitmdump
    is_mitm = True
    for app in walk_pkg_names(out_dir):
        print(f"-------------- Process {app} -----------------")
        print("\t Step 1: Network")
        for mitm in glob.glob(os.path.join(out_dir, app, "mitmdump*")):
            if is_empty_file(mitm):
                continue
            (cert_type, frida_on) = parse('mitmdump-{}-{}', os.path.basename(mitm))
            if os.path.exists(os.path.join(out_dir, app, f"res_mitm-{cert_type}-{frida_on}"+".json")):
                continue
            freader = io.FlowReader(open(mitm, "rb"))
            request_list = list()
            for flow in freader.stream():
                if skip_flow(flow):
                    continue

                request = flow.request
                host = request.host
                url = request.url
                # print(url)
                method = request.method
                if request.method.lower() == CONNECT_LOWERCASE:
                    continue

                src_ip, src_port = get_client_address(flow)
                dest_ip, dest_port = get_server_address(flow)
                start_ts = flow.client_conn.timestamp_start
                setup_ts = flow.client_conn.timestamp_tls_setup


                print(f"{src_ip}:{src_port} --> {dest_ip}:{dest_port}")

                request_list.append({DEVICE:device, PKG:app, IS_MITM:is_mitm, CERT_TYPE:cert_type, FRIDA_ON:frida_on, HOST: host, URL: url, METHOD: method,
                                     SRC_IP:src_ip, SRC_PORT:src_port, DEST_IP:dest_ip, DEST_PORT:dest_port, TLS_START: start_ts, TLS_SETUP: setup_ts})

            if len(request_list) != 0:
                result_file = os.path.join(out_dir, app, f"res_mitm-{cert_type}-{frida_on}"+".json")
                with open(result_file, "w") as f:
                    json.dump(request_list, f)
