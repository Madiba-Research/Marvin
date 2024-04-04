import os
import sys
import sqlite3
import glob
import json
from parse import parse


from custom_define import walk_pkg_names, is_timestamp_in_tls_handshake

from custom_define import DEVICE, PKG, IS_MITM, HOST, SRC_IP, SRC_PORT, DEST_IP, DEST_PORT, FRIDA_ON, CERT_TYPE, STATUS, TS, TLS_SETUP, TLS_START
from custom_define import FORCED, IPV4, R_UID, UID, PID, PNAME
from custom_define import FUNC, STAGE, CLASS, ISSUEDN, SUBJECTDN, EXPIRE, STACKTRACE
from custom_define import PASSTHROUGH
from custom_define import RES_CHECK_JSON, RES_VERIFY_JSON


from custom_define import TABLE_NETWORK, TABLE_PASSTHROUGH, TABLE_TRAFFIC_SEPARATION, TABLE_VALIDATION, TABLE_ATTRIBUTION

# Set environment variable before import create_attribution
computer = sys.argv[1]
OUT_DIR = sys.argv[2]
database = sys.argv[3]
# os.environ["DATABASE"] = database
# print(os.environ["DATABASE"])


conn = sqlite3.connect(database)
cursor = conn.cursor()

cursor.execute('''CREATE TABLE IF NOT EXISTS network (device text, pkg text, is_mitm boolean, cert_type int, frida_on boolean, host text, src_ip text, src_port int, dest_ip text, dest_port int, \
                                                      tls_start int, tls_setup int)''')
cursor.execute('''CREATE TABLE IF NOT EXISTS passthrough (device text, pkg text, cert_type int, frida_on boolean, host text, dest_ip text, dest_port int, status text, ts text)''')
cursor.execute('''CREATE TABLE IF NOT EXISTS traffic_separation (device text, pkg text, cert_type int, frida_on boolean, forced boolean, is_ipv4 boolean, uid int, r_uid int, pname text, pid int, addr text, port int)''')
cursor.execute('''CREATE TABLE IF NOT EXISTS validation (device text, pkg text, cert_type int, frida_on boolean, stage int, func text, class text, host text, \
                  subjectDN text, issueDN text, expire text, conn_validator text, conn_creator text, stacktrace text, ts text)''')
cursor.execute('''CREATE TABLE IF NOT EXISTS attribution (device text, pkg text, cert_type int, frida_on boolean, host text, func text, class text, \
                  subjectDN text, issueDN text, expire text, frame_1 text, stacktrace text, ts text)''')

# cursor.execute_2('''CREATE TABLE IF NOT EXISTS attribution (device text, pkg text, cert_type int, frida_on boolean, host text, attribution_type text, is_hijacked boolean, \
#                   subjectDN text, conn_creator text, conn_validator text, counter_c int, counter_v int, stacktrace text)''')


def parse_passthrough(device, out_dir):
    result_list = []
    for app in walk_pkg_names(out_dir):
        app_dir = os.path.join(out_dir, app)
        for ptf in glob.glob(os.path.join(app_dir, "passthrough*.txt")):
            # print(ptf)
            cert_type, frida_on = parse("passthrough-{}-{}.txt", os.path.basename(ptf))
            with open(ptf, "r") as f:
                for row in f:
                    # print(ptf, row)
                    if "<no address>" in row:
                        continue
                    status, dest_ip, dest_port, host, ts = parse("{}:{}:{} -> {}, {}", row)
                    status = status.split(" ")[1]
                    print(status, dest_ip, dest_port, host, ts)
                    if status != PASSTHROUGH:
                        result_list.append({DEVICE: device, PKG: app, CERT_TYPE: cert_type, FRIDA_ON: frida_on, HOST: host, 
                                            DEST_IP: dest_ip.strip(), DEST_PORT: dest_port, STATUS: status, TS: ts})
    
    return result_list


def parse_attribution():
    attribution_list = []
    sql = f"SELECT tn.device, tn.pkg, tn.cert_type, tn.frida_on, tn.host, tn.tls_start, tn.tls_setup, tv.host, tv.class, tv.func, tv.subjectDN, tv.issueDN, tv.expire, tv.frame_1, tv.stacktrace, tv.ts \
           FROM {TABLE_NETWORK} as tn JOIN {TABLE_VALIDATION} AS tv ON tn.device=tv.device and tn.pkg=tv.pkg and tn.cert_type=tv.cert_type and tn.frida_on=tv.frida_on"
    cursor = conn.cursor()
    cursor = cursor.execute(sql)

    for row in cursor:
        device, pkg, cert_type, frida_on, host_n, tls_start, tls_setup, host_v, class_v, func, subjectDN, issueDN, expire, frame_1, st, ts_v = \
        row[0], row[1], row[2],   row[3],   row[4],    row[5],    row[6], row[7],  row[8], row[9],  row[10],  row[11], row[12], row[13], row[14], row[15]

        ts_v = float(ts_v) if "." in ts_v else float(ts_v)/1000
        if (host_n == host_v) and is_timestamp_in_tls_handshake(tls_start, ts_v, tls_setup):
            attribution_list.append({DEVICE:device, PKG:pkg, CERT_TYPE:cert_type, FRIDA_ON: frida_on, HOST:host_n, FUNC:func, CLASS:class_v, SUBJECTDN: subjectDN, ISSUEDN: issueDN, 
                                 EXPIRE:expire, FRAME_1: frame_1, STACKTRACE:st, TS:ts_v})
            continue
        elif (host_v == None and host_n != None) and is_timestamp_in_tls_handshake(tls_start, ts_v, tls_setup):
            attribution_list.append({DEVICE:device, PKG:pkg, CERT_TYPE:cert_type, FRIDA_ON: frida_on, HOST:host_n, FUNC:func, CLASS:class_v, SUBJECTDN: subjectDN, ISSUEDN: issueDN, 
                                 EXPIRE:expire, FRAME_1: frame_1, STACKTRACE:st, TS:ts_v})
            continue

    return attribution_list


network_list = []
def write_network_database(out_dir):
    for app in  walk_pkg_names(out_dir):
        pattern  = "res_mitm-*.json"
        for result_file in glob.glob(os.path.join(out_dir, app, pattern)):
            with open(result_file, "r") as f:
                jdata = json.load(f)
                network_list.extend(jdata)

    print("len(network)=", len(network_list))
    nw_values = set()      
    for nw in network_list:
        if (nw[DEVICE], nw[PKG], nw[IS_MITM], nw[CERT_TYPE], nw[FRIDA_ON], nw[HOST], nw[SRC_IP], nw[SRC_PORT], nw[DEST_IP], nw[DEST_PORT], nw[TLS_START], nw[TLS_SETUP]) in nw_values:
            continue
        cursor.execute(f"INSERT OR IGNORE INTO {TABLE_NETWORK} (device, pkg, is_mitm, cert_type, frida_on, host, src_ip, src_port, dest_ip, dest_port, tls_start, tls_setup ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (nw[DEVICE], nw[PKG], nw[IS_MITM], nw[CERT_TYPE], nw[FRIDA_ON], nw[HOST], nw[SRC_IP], nw[SRC_PORT], nw[DEST_IP], nw[DEST_PORT], nw[TLS_START], nw[TLS_SETUP]))
        nw_values.add((nw[DEVICE], nw[PKG], nw[IS_MITM], nw[CERT_TYPE], nw[FRIDA_ON], nw[HOST], nw[SRC_IP], nw[SRC_PORT], nw[DEST_IP], nw[DEST_PORT], nw[TLS_START], nw[TLS_SETUP]))


def write_passthrough_database(passthrough_list):
    pth_values = set()
    print("len(passthrough)=", len(passthrough_list))
    for pth in passthrough_list:
        if (",".join(pth)) in pth_values:
            continue
        cursor.execute(f"INSERT OR IGNORE INTO {TABLE_PASSTHROUGH} (device, pkg, cert_type, frida_on, host, dest_ip, dest_port, status, ts) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (pth[DEVICE], pth[PKG], pth[CERT_TYPE], pth[FRIDA_ON], pth[HOST], pth[DEST_IP], pth[DEST_PORT], pth[STATUS], pth[TS]))
    conn.commit()



def write_traffic_separation_database(out_dir):
    traffic_list = []
    for app in  walk_pkg_names(out_dir):
        # traffic_separation
        for result_file in glob.glob(os.path.join(out_dir, app, "res_traffic-*.json")):
            with open(result_file, "r") as f:
                jdata = json.load(f)
                traffic_list.extend(jdata)

    print("len(traffic_separation)=", len(traffic_list))
    tf_values = set()
    for tf in traffic_list:
        if (tf[DEVICE], tf[PKG], tf[CERT_TYPE], tf[FRIDA_ON], tf[FORCED], tf[IPV4], tf[UID], tf[R_UID], tf[PNAME], tf[PID], tf["addr"], tf["port"]) in tf_values:
            continue
        cursor.execute(f"INSERT OR IGNORE INTO {TABLE_TRAFFIC_SEPARATION} (device, pkg, cert_type, frida_on, forced, is_ipv4, uid, r_uid, pname, pid, addr, port) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", 
                     (tf[DEVICE], tf[PKG], tf[CERT_TYPE], tf[FRIDA_ON], tf[FORCED], tf[IPV4], tf[UID], tf[R_UID], tf[PNAME], tf[PID], tf["addr"], tf["port"]))
        tf_values.add((tf[DEVICE], tf[PKG], tf[CERT_TYPE], tf[FRIDA_ON], tf[FORCED], tf[IPV4], tf[UID], tf[R_UID], tf[PNAME], tf[PID], tf["addr"], tf["port"]))
        
    conn.commit()


# Write to Database
# def write_validaton_database(out_dir):
#     validation_list = list()
#     for app in  walk_pkg_names(out_dir):
#         for pattern in [RES_CHECK_JSON, RES_VERIFY_JSON]:
#             for result_file in glob.glob(os.path.join(out_dir, app, pattern)):
#                 with open(result_file, "r") as f:
#                     jdata = json.load(f)
#                     validation_list.extend(jdata)
#     print(f"len(validation)={len(validation_list)}")
#     for j_dict in validation_list:
#         cursor.execute(f"INSERT OR IGNORE INTO {TABLE_VALIDATION} \
#                        (device, pkg, cert_type, frida_on, stage, func, class, host, subjectDN, issueDN, expire, conn_validator, conn_creator, stacktrace, ts) \
#                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
#                        (j_dict[DEVICE], j_dict[PKG], j_dict[CERT_TYPE], j_dict[FRIDA_ON], j_dict[STAGE], j_dict[FUNC], j_dict[CLASS], j_dict[HOST], j_dict[SUBJECTDN],
#                          j_dict[ISSUEDN], j_dict[EXPIRE], j_dict[CONN_VALIDATOR], j_dict[CONN_CREATOR], j_dict[STACKTRACE], j_dict[TS]))
#     conn.commit()



def write_attribution_database():
    attribution_list = parse_attribution()
    print(f"len(attribution)={len(attribution_list)}")
    for data in attribution_list:
        cursor.execute(f"INSERT OR IGNORE INTO {TABLE_ATTRIBUTION} \
                       (device, pkg, cert_type, frida_on, host, func, class, subjectDN, issueDN, expire, frame_1, stacktrace, ts) \
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                       (data[DEVICE], data[PKG],  data[CERT_TYPE], data[FRIDA_ON], data[HOST], data[FUNC], data[CLASS],data[SUBJECTDN],
                        data[ISSUEDN], data[EXPIRE], data[FRAME_1], data[STACKTRACE], data[TS]))
    conn.commit()
    

def write_attribution_database_2(attribution_list):
    # attribution_list = []
    # res_file = os.path.join(out, "res_attribution.json")
    # with open(res_file, "f") as f:
    #     jdata = json.load(f)
    #     attribution_list.extend(jdata)
    # print(f"len(attribution)={len(attribution_list)}")
    for data in attribution_list:
        cursor.execute(f"INSERT OR IGNORE INTO {TABLE_ATTRIBUTION} \
                       (device, pkg, cert_type, frida_on, host, attribution_type, is_hijacked, subjectDN, conn_creator, conn_validator, counter_c, counter_v, stacktrace) \
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                       (data[DEVICE], data[PKG],  data[CERT_TYPE], data[FRIDA_ON], data[HOST], data[ATTRIBUTION_TYPE], data[IS_HIJACKED],data[SUBJECTDN],
                        data[CONN_CREATOR], data[CONN_VALIDATOR], data[COUNT_CREATOR], data[COUNT_VALIDATOR], data[STACKTRACE]))
    conn.commit()
    # attribution_list = create_attribution()
    # write_attribution_database_2(attribution_list)


def main():
    passthrough_list = parse_passthrough(computer, OUT_DIR)
    write_passthrough_database(passthrough_list)
    write_network_database(OUT_DIR)
    write_traffic_separation_database(OUT_DIR)
    write_validaton_database(OUT_DIR)


if __name__ == "__main__":
    # python3 create_db.py timber ./out test.db
    main()
