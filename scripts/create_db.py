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
from custom_define import ATTRIBUTION_TYPE, HIJACKED, CONN_CREATOR, CONN_VALIDATOR, COUNT_CREATOR, COUNT_VALIDATOR
from custom_define import PASSTHROUGH, FAILURE, SUCCESS
from custom_define import RES_CHECK_JSON, RES_VERIFY_JSON


from custom_define import TABLE_NETWORK, TABLE_PASSTHROUGH, TABLE_TRAFFIC_SEPARATION, TABLE_VALIDATION, TABLE_ATTRIBUTION
from custom_define import CREATE_TABLE_SQLS


computer = sys.argv[1]
OUT_DIR = sys.argv[2]
database = sys.argv[3]

os.environ["DATABASE"] = database

from my_parsers import start_parse

from parse_attribution import do_attribution



conn = sqlite3.connect(database)
cursor = conn.cursor()

# cursor.execute('''CREATE TABLE IF NOT EXISTS network (device text, pkg text, is_mitm boolean, cert_type int, frida_on boolean, host text, src_ip text, src_port int, dest_ip text, dest_port int, \
#                                                       tls_start int, tls_setup int)''')
# cursor.execute('''CREATE TABLE IF NOT EXISTS passthrough (device text, pkg text, cert_type int, frida_on boolean, host text, dest_ip text, dest_port int, status text, ts text)''')
# cursor.execute('''CREATE TABLE IF NOT EXISTS traffic_separation (device text, pkg text, cert_type int, frida_on boolean, forced boolean, is_ipv4 boolean, uid int, r_uid int, pname text, pid int, addr text, port int)''')
# cursor.execute('''CREATE TABLE IF NOT EXISTS validation (device text, pkg text, cert_type int, frida_on boolean, stage int, func text, class text, host text, \
#                   subjectDN text, issueDN text, expire text, conn_validator text, conn_creator text, stacktrace text, ts text)''')
# cursor.execute('''CREATE TABLE IF NOT EXISTS attribution (device text, pkg text, cert_type int, frida_on boolean, host text, func text, class text,  stacktrace text, attribution_type text, hijacked boolean, \
#                   subjectDN text, conn_creator text, conn_validator text, count_creator int, count_validator int)''')


cursor.execute(CREATE_TABLE_SQLS[TABLE_NETWORK])
cursor.execute(CREATE_TABLE_SQLS[TABLE_PASSTHROUGH])
cursor.execute(CREATE_TABLE_SQLS[TABLE_TRAFFIC_SEPARATION])
cursor.execute(CREATE_TABLE_SQLS[TABLE_VALIDATION])
cursor.execute(CREATE_TABLE_SQLS[TABLE_ATTRIBUTION])



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
                    if status.startswith("Pass"):
                        status = PASSTHROUGH
                    elif status.startswith("Fail"):
                        status = FAILURE
                    print(status, dest_ip, dest_port, host, ts)
                    result_list.append({DEVICE: device, PKG: app, CERT_TYPE: cert_type, FRIDA_ON: frida_on, HOST: host, 
                                        DEST_IP: dest_ip.strip(), DEST_PORT: dest_port, STATUS: status, TS: ts})
    
    return result_list


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


def write_validaton_database(out_dir):
    validation_list = list()
    for app in  walk_pkg_names(out_dir):
        for pattern in [RES_CHECK_JSON, RES_VERIFY_JSON]:
            for result_file in glob.glob(os.path.join(out_dir, app, pattern)):
                with open(result_file, "r") as f:
                    jdata = json.load(f)
                    validation_list.extend(jdata)
    print(f"len(validation)={len(validation_list)}")
    for j_dict in validation_list:
        cursor.execute(f"INSERT OR IGNORE INTO {TABLE_VALIDATION} \
                       (device, pkg, cert_type, frida_on, stage, func, class, host, subjectDN, issueDN, expire, conn_validator, conn_creator, stacktrace, ts) \
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                       (j_dict[DEVICE], j_dict[PKG], j_dict[CERT_TYPE], j_dict[FRIDA_ON], j_dict[STAGE], j_dict[FUNC], j_dict[CLASS], j_dict[HOST], j_dict[SUBJECTDN],
                         j_dict[ISSUEDN], j_dict[EXPIRE], j_dict[CONN_VALIDATOR], j_dict[CONN_CREATOR], j_dict[STACKTRACE], j_dict[TS]))
    conn.commit()


def write_attribution_database():
    attribution_list = do_attribution()
    print(f"len(attribution)={len(attribution_list)}")
    for data in attribution_list:
        cursor.execute(f"INSERT OR IGNORE INTO {TABLE_ATTRIBUTION} \
                       (device, pkg, cert_type, frida_on, host, func, class, subjectDN, stacktrace, attribution_type, hijacked, conn_creator, conn_validator, count_creator, count_validator) \
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,?, ?)",
                       (data[DEVICE], data[PKG],  data[CERT_TYPE], data[FRIDA_ON], data[HOST], data[FUNC], data[CLASS],data[SUBJECTDN], data[STACKTRACE],
                        data[ATTRIBUTION_TYPE], data[HIJACKED], data[CONN_CREATOR], data[CONN_VALIDATOR], data[COUNT_CREATOR], data[COUNT_VALIDATOR]))
    conn.commit()



def create_database():
    print("---- Create Database: " + OUT_DIR + " -------------")
    passthrough_list = parse_passthrough(computer, OUT_DIR)
    write_passthrough_database(passthrough_list)
    write_network_database(OUT_DIR)
    write_traffic_separation_database(OUT_DIR)

    write_validaton_database(OUT_DIR)
    write_attribution_database()


def main():
    start_parse(computer, OUT_DIR)
    create_database()



if __name__ == "__main__":
    # python3 create_db.py timber ./out test.db
    main()
