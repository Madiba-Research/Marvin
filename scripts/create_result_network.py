
import csv
import sys
import sqlite3
import os
from parse import parse

import tldextract
tldextract.extract

CERT_TYPES = [1, 2, 3, 4]

UNTRUSTED_ROOT, SELF_SIGNED, EXPIRATION, DOMAIN_MISMATCH = range(1, 5)
# print(UNTRUSTED_ROOT, SELF_SIGNED, EXPIRATION, DOMAIN_MISMATCH)

from custom_define import SUCCESS, FAILURE, PASSTHROUGH
# SUCCESS, FAILURE, PASSTHROUGH = "Success", "Failure", "Passthrough"


conn = sqlite3.connect(sys.argv[1])
cursor = conn.cursor()


def walk_pkg_names(path):
    return next(os.walk(path))[1]


def secure_vs_insecure(fname):
    sql = f"SELECT DISTINCT pkg, host, cert_type, dest_ip, dest_port, status FROM passthrough WHERE status!='{SUCCESS}' GROUP BY pkg, host, cert_type, dest_ip, dest_port, status"
    cursor = conn.cursor()
    cursor = cursor.execute(sql)
    secure_dict = dict()
    for row in cursor:
        pkg, host, cert_type, dest_ip, dest_port, status = row[0], row[1], row[2], row[3], row[4], row[5]
        if status == PASSTHROUGH or status == FAILURE:
            # print(row)
            if cert_type not in secure_dict:
                secure_dict[cert_type] = set()
            secure_dict[cert_type].add((pkg, host, cert_type, dest_ip, dest_port))

    # Insecure
    sql = f"SELECT DISTINCT pkg, host, cert_type, frida_on, dest_ip, dest_port FROM network WHERE is_mitm=True GROUP BY pkg, host, cert_type, frida_on, dest_ip, dest_port"
    cursor = conn.cursor()
    cursor = cursor.execute(sql)
    insecure_dict = dict()
    total_insecure = 0
    for row in cursor:
        pkg, host, cert_type, frida_on, dest_ip, dest_port = row[0], row[1], row[2], row[3], row[4], row[5]
        if cert_type not in insecure_dict:
            insecure_dict[cert_type] = set()
        insecure_dict[cert_type].add((pkg, host, frida_on, cert_type, dest_ip, dest_port))
        total_insecure += 1
    print("total insecure TLS connections:", total_insecure)
    
    

    with open(fname, "w") as f:
        writer = csv.writer(f)
        for ct in secure_dict:
            # print(ct)
            writer.writerow([ct, len(secure_dict[ct]), len(insecure_dict[ct])])


def _get_host_counter():
    hosts = dict()
    sql = f"SELECT host, COUNT(DISTINCT pkg) FROM network WHERE is_mitm=True GROUP BY host "
    cursor = conn.cursor()
    cursor = cursor.execute(sql)
    for row in cursor:
        h, c = row[0], row[1]
        hosts[h] = c
    return hosts
    

def percent_of_fp_tp_connection(fname):
    hosts_counter = _get_host_counter()
    result_dict = {}
    sql = f"SELECT DISTINCT pkg, host, cert_type, frida_on, dest_ip, dest_port FROM network WHERE is_mitm=True GROUP BY pkg, host, cert_type, frida_on, dest_ip, dest_port"
    cursor = conn.cursor()
    cursor = cursor.execute(sql)
    for row in cursor:
        h, ct = row[1], row[2]
        if ct not in result_dict:
            result_dict[ct] = {"fp": 0, "tp": 0}
        if hosts_counter[h] >= 5:
            result_dict[ct]["tp"] += 1
        else:
            result_dict[ct]["fp"] += 1

    with open(fname, "w") as f:
        writer = csv.writer(f)
        for ct in result_dict:
            fp = result_dict[ct]["fp"]
            tp = result_dict[ct]["tp"]
            writer.writerow([ct, fp, tp, "{:.3f}".format(fp/(fp+tp)), "{:.3f}".format(tp/(fp+tp))])


def _get_domain_counter():
    domains = dict()
    sql = f"SELECT DISTINCT host, COUNT(DISTINCT pkg) FROM network WHERE is_mitm=True GROUP BY host"
    cursor = conn.cursor()
    cursor = cursor.execute(sql)
    for row in cursor:
        h, c = row[0], row[1]
        d = extract_domain(h)
        if d not in domains:
            domains[d] = c
        else:
            domains[d] += c
    return domains


def extract_domain(url):
    if not url.startswith(url):
        url = "https://" + url
    ext = tldextract.extract(url)
    return ext.domain +"." + ext.suffix


# def secure_insecure_tls_connections(file):
#     sql = f"SELECT DISTINCT pkg, host, cert_type, frida_on, dest_ip, dest_port, status FROM passthrough GROUP BY pkg, host, frida_on, dest_ip, dest_port, status"
#     cursor = conn.cursor()
#     cursor = cursor.execute(sql)
#     secure_dict = dict()
#     insecure_dict = dict()
#     for row in cursor:
#         pkg, host, cert_type, frida_on, dest_ip, dest_port, status = row[0], row[1], row[2], row[3], row[4], row[5], row[6]
#         if status == PASSTHROUGH or status == FAILURE:
#             if cert_type not in secure_dict:
#                 secure_dict[cert_type] = set()
#             secure_dict[cert_type].add((pkg, host, frida_on, dest_ip, dest_port))
#         else:
#             if cert_type not in insecure_dict:
#                 insecure_dict[cert_type] = set()
#             insecure_dict[cert_type].add((pkg, host, frida_on, dest_ip, dest_port))

#     with open(file, "w") as f:
#         writer = csv.writer(f)
#         for ct in secure_dict:
#             writer.writerow([ct, len(secure_dict[ct]), len(insecure_dict[ct])])

#     return insecure_dict



def main():
    secure_vs_insecure("secure_vs_insecure.csv")
    percent_of_fp_tp_connection("gp_percent_domains.csv")


if __name__ == "__main__":
    # create_network_result [database]
    main()
