import glob
import json
import os
import socket
from parse import parse


from custom_define import DEVICE, PKG, FRIDA_ON, CERT_TYPE, FORCED, IPV4, R_UID, UID, PID, PNAME


PARSED = "parsed"
HTTP_PORT = 80
HTTPS_PORT = 443
HEX_ADDR_LEN = 8


def is_empty_file(file):
    return False if os.path.getsize(file) else True


def extract_running_uid(out_dir, app, case_type):
    r_uid = 0
    time_file = os.path.join(out_dir, app, "time.txt")
    with open(time_file, "r") as f:
        for line in f:
            if case_type in line:
                r_uid = line.split(":")[0]
                break
    return r_uid


def make_valid_hex_addr(hex_addr):
    l = len(hex_addr)
    for n in range(l, HEX_ADDR_LEN):
        hex_addr = "0" + hex_addr
    return hex_addr


def recover_bigendian(big_hex_addr, big_hex_port):
    addr = big_hex_addr if len(big_hex_addr) == HEX_ADDR_LEN else make_valid_hex_addr(big_hex_addr)
    try:
        ip_bytes = bytes.fromhex(addr)
        rev_addr = socket.inet_ntoa(ip_bytes)
        addr = ".".join(reversed(rev_addr.split(".")))
    except Exception:
        pass

    port = big_hex_port
    try:
        port = int(big_hex_port[2:4] + big_hex_port[0:2], 16)
    except Exception:
        pass

    return addr, port


def create_traffic_separation(device, out_dir, app):
    for tfile in glob.glob(os.path.join(out_dir, app, "traffic-*.txt")):
        if is_empty_file(tfile):
            continue
        temp_bn = os.path.basename(tfile)[0: -4]
        res_file = os.path.join(out_dir, app, "res_" + temp_bn+".json")
        if os.path.exists(res_file):
            # print(f"{res_file} exists, {tfile} has been parsed")
            continue
        request_list = list()
        cert_type, frida_on = parse("traffic-{}-{}.txt", os.path.basename(tfile))
        with open(tfile, "r") as f:
            try:
                for row in f:
                    row = " ".join(row.split())
                    if "bpf_trace_printk:" not in row:
                        continue
                    proc_data, conn_data, uid_data = row.split(" [")[0], row.split("bpf_trace_printk: ")[1].split(",")[0], row.split(",")[-1]
                    pid = proc_data.split("-")[-1]
                    pname = proc_data[0: proc_data.find(pid)-1]
                    conn, hex_addr, hex_port = parse("{}=({}:{})", conn_data)
                    forced = True if conn.startswith("Forced-") else False
                    if not forced:
                        continue
                    is_ipv4 = False if conn.endswith("Data6") else True
                    uid = None
                    try:
                        uid = parse("uid={}", uid_data)[0]
                    except TypeError:
                        continue
                    addr, port = recover_bigendian(hex_addr, hex_port)
                    
                    case_type = str(cert_type) + "-" + str(frida_on)
                    r_uid = extract_running_uid(out_dir, app, case_type)

                    request_list.append({DEVICE:device, PKG:app, CERT_TYPE:cert_type, FRIDA_ON:frida_on, FORCED:forced, IPV4:is_ipv4, UID:uid, R_UID:r_uid, PNAME:pname, PID:pid, 
                                        "addr":addr, "port":port})
            except UnicodeDecodeError as ue:
                print("Exception:" + str(ue))
                continue
        if len(request_list) != 0:
            result_file = os.path.join(out_dir, app, f"res_traffic-{cert_type}-{frida_on}.json")
            with open(result_file, "w") as f:
                json.dump(request_list, f)

