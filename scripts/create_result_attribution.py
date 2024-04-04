import sqlite3
import sys
import base64
import csv
import tldextract


from custom_define import TABLE_ATTRIBUTION, TABLE_NETWORK, TABLE_VALIDATION
from custom_define import write_csv
from custom_define import extract_short_package_name


from custom_define import APP_CONN_VALIDATED_BY_APP_CODE
from custom_define import LIB_CONN_VALIDATED_BY_LIB_CODE
from custom_define import APP_CONN_HIJACKED_BY_LIB_CODE 
from custom_define import LIB_CONN_HIJACKED_BY_LIB_CODE 
from custom_define import LIB_CONN_HIJACKED_BY_APP_CODE

from custom_define import UNTRUSTED_ROOT, SELF_SIGNED, EXPIRATION, DOMAIN_MISMATCH


database = sys.argv[1]
conn = sqlite3.connect(database)
cursor = conn.cursor()


SECURE_LIBS = ["com.alipay", "com.google", "com.applovin", "None"]


THIRD_PARTY_THRESHOLD = 5
# HIJACKING_THRESHOLD = 2


INSECURE_APPS_CHN = 795
WIFI_APPS = 1401


def classify_apps(fname):
    sql = f"SELECT COUNT(DISTINCT pkg) FROM {TABLE_ATTRIBUTION}"
    cursor = conn.cursor()
    cursor = cursor.execute(sql)
    print("Attributed Apps", cursor.fetchall())

    sql = f"SELECT attribution_type, COUNT(DISTINCT pkg) FROM {TABLE_ATTRIBUTION} GROUP BY attribution_type"
    cursor = conn.cursor()
    cursor = cursor.execute(sql)
    
    with open(fname, "w") as f:
        writer = csv.writer(f)
        for row in cursor:
            a_type, count = row[0], row[1]
            writer.writerow([a_type, count, "%"])


def count_hijacked_apps():
    hijacked_apps = set()
    sql = f"SELECT COUNT(DISTINCT pkg) FROM {TABLE_ATTRIBUTION} WHERE attribution_type LIKE '%HIJACKED%'"
    cursor = conn.cursor()
    cursor = cursor.execute(sql)
    print("Hijacked Apps:", cursor.fetchall())


def classify_insecure_connections(fname):
    total_insecure_conns = set()
    # sql = f"SELECT DISTINCT pkg, host, cert_type, frida_on, dest_ip, dest_port FROM {TABLE_NETWORK} GROUP BY pkg, host, cert_type, frida_on, dest_ip, dest_port"
    sql = f"SELECT DISTINCT pkg, host, cert_type, frida_on, dest_ip, dest_port FROM {TABLE_NETWORK} GROUP BY pkg, host, cert_type, frida_on, dest_ip, dest_port"
    cursor = conn.cursor()
    cursor = cursor.execute(sql)
    for row in cursor:
        total_insecure_conns.add(row)
    print(f"Total insecure TLS connections: {len(total_insecure_conns)}")

    attri_insecure_conns = dict()
    # sql = f"SELECT DISTINCT n.pkg, n.host, n.cert_type, n.frida_on, n.dest_ip, n.dest_port, a.attribution_type FROM {TABLE_NETWORK} AS n JOIN {TABLE_ATTRIBUTION} AS a ON " \
    #        f"n.pkg=a.pkg AND n.host=a.host AND n.cert_type=a.cert_type AND n.frida_on = a.frida_on "\
    #         " GROUP BY n.pkg, n.host, n.cert_type, n.frida_on, n.dest_ip, n.dest_port"
    sql = f"SELECT DISTINCT n.pkg, n.host, n.cert_type, n.frida_on, n.dest_ip, n.dest_port, a.attribution_type FROM {TABLE_NETWORK} AS n JOIN {TABLE_ATTRIBUTION} AS a ON " \
           f"n.pkg=a.pkg AND n.host=a.host AND n.cert_type=a.cert_type AND n.frida_on = a.frida_on "\
            " GROUP BY n.pkg, n.host, n.cert_type, n.frida_on, n.dest_ip, n.dest_port, a.attribution_type"
    cursor = conn.cursor()
    cursor = cursor.execute(sql)
    for row in cursor:
        pkg, host, cert_type, frida_on, dest_ip, dest_port, attri = row[0], row[1], row[2], row[3], row[4], row[5], row[6]
        if attri not in attri_insecure_conns:
            attri_insecure_conns[attri] = dict()
        if cert_type not in attri_insecure_conns[attri]:
            attri_insecure_conns[attri][cert_type] = set()
        attri_insecure_conns[attri][cert_type].add(row)

    with open(fname, "w") as f:
        writer = csv.writer(f)
        for attr in attri_insecure_conns:
            data = attri_insecure_conns[attr]
            count = 0
            for cert_type in data:
                count += len(data[cert_type])
            writer.writerow([attr, count])


# def sankey_diagram(fname):
#     sql = f"SELECT DISTINCT pkg, host, cert_type, frida_on, attribution_type FROM {TABLE_ATTRIBUTION} GROUP BY pkg, host, cert_type, frida_on, attribution_type"
#     cursor = conn.cursor()
#     cursor = cursor.execute(sql)
#     sankey_result = []
#     for row in cursor:
#         pkg, host, cert_type, frida_on, attri = row[0], row[1], row[2], row[3], row[4]
#         conn_type, code_type, hijacked = None, None, None
#         if attri == APP_CONN_VALIDATED_BY_APP_CODE  or attri == APP_CONN_HIJACKED_BY_LIB_CODE:
#             conn_type = "AppConn"
#         else:
#             conn_type = "LibConn"

#         if attri== APP_CONN_VALIDATED_BY_APP_CODE or attri == LIB_CONN_HIJACKED_BY_APP_CODE or attri == LIB_CONN_HIJACKED_BY_LIB_CODE:
#             code_type = "AppCode"
#         else:
#             code_type = "LibCode"
        
#         if attri == APP_CONN_HIJACKED_BY_LIB_CODE or attri == LIB_CONN_HIJACKED_BY_LIB_CODE or attri == LIB_CONN_HIJACKED_BY_APP_CODE:
#             hijacked = True
#         else: 
#             hijacked = False
#         sankey_result.append([pkg, host, conn_type, code_type, hijacked, attri])
#     with open(fname, "w") as f:
#         writer = csv.writer(f)
#         writer.writerows(sankey_result)


# Apps with 2 default setters
def race_validation(fname):
    setters_in_app = dict()
    sql = f"SELECT DISTINCT v.device, v.pkg, v.func, v.conn_creator FROM {TABLE_VALIDATION} AS v INNER JOIN {TABLE_NETWORK} AS N ON v.device=n.device AND v.pkg=n.pkg AND func LIKE 'setDefault%' GROUP BY v.pkg, v.func, v.conn_creator"
    cursor = conn.cursor()
    cursor = cursor.execute(sql)
    apps = set()
    for row in cursor:
        device, pkg, func, creator = row[0], row[1], row[2], row[3]
        creator = extract_short_package_name(creator)
        if creator in SECURE_LIBS:
            continue

        if pkg not in setters_in_app:
            setters_in_app[pkg] = set()
        setters_in_app[pkg].add((func, creator))

    with open(fname, "w") as f:
        writer = csv.writer(f)
        for pkg in setters_in_app:
            if len(setters_in_app) < 2:
                continue
            for item in setters_in_app[pkg]:
                apps.add(pkg)
                print(pkg, item)
                writer.writerow([pkg, item[0], item[1]])
    print(f"size={len(apps)}")


# 1. Who is calling setDefaultSSLSocket
def detect_global_functions():
    cursor = conn.cursor()
    sql = f"SELECT DISTINCT pkg, conn_creator FROM {TABLE_VALIDATION} WHERE func LIKE 'setDefault%' GROUP BY conn_creator, pkg"
    cursor = cursor.execute(sql)
    result_dict = {}
    for row in cursor:
        pkg, creator = row[0], row[1]
        size = len(creator.split("."))
        short_creator = creator if size <= 3 else ".".join(creator.split(".")[0:3])
        if short_creator not in result_dict:
            result_dict[short_creator] = set()
        result_dict[short_creator].add(pkg)

    sorted_result = dict(sorted(result_dict.items(), key=lambda item: len(item[1]), reverse=True))
    with open("violator_v.csv", "w") as f:
        writer = csv.writer(f)
        for key in sorted_result:
            count = len(sorted_result[key])
            print(key, count)
            writer.writerow([key, count])
 


if __name__ == "__main__":
    print("--------------- Chinese Attribution--------------------")
    classify_apps("attri_app.csv")
    count_hijacked_apps()
    classify_insecure_connections("gp_attri_conn.csv")
    race_validation("racing_hijacking.csv")
    detect_global_functions()
