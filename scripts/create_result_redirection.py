import sys
import csv

from custom_define import connect_db

from create_insecure_apps import count_wifi_apps


db_name = sys.argv[1]
conn = connect_db(db_name)


def count_forced_apps():
    internet_apps = count_wifi_apps()
    # Count Insecure Apps:
    sql = "SELECT DISTINCT pkg FROM network"
    cursor = conn.cursor()
    cursor = conn.execute(sql)
    print("All Insecure Apps", len(cursor.fetchall()))

    sql = "SELECT DISTINCT pkg FROM traffic_separation WHERE forced=1"
    cursor = conn.cursor()
    cursor = conn.execute(sql)
    forced_apps = set()
    for row in cursor:
        forced_apps.add(row[0])
    fixed_forced_apps = forced_apps.intersection(internet_apps)
    print("Forced Apps", len(fixed_forced_apps))

    forced_tls_apps = set()
    sql = "SELECT DISTINCT pkg FROM traffic_separation WHERE forced=1 AND port=443"
    cursor = conn.cursor()
    cursor = conn.execute(sql)
    for row in cursor:
        forced_tls_apps.add(row[0])
    fixed_forced_tls_apps = forced_tls_apps.intersection(internet_apps)
    print("Forced HTTPS Apps", len(fixed_forced_tls_apps))

    forced_insecure_apps = set()
    sql = "SELECT DISTINCT n.pkg FROM network AS n JOIN traffic_separation AS t ON t.device=n.device AND t.pkg=n.pkg AND t.forced=1 AND t.addr=n.dest_ip AND t.port=n.dest_port \
            AND t.cert_type=n.cert_type AND t.frida_on=n.frida_on GROUP BY t.pkg, t.addr, t.port, t.cert_type, t.frida_on"
    cursor = conn.cursor()
    cursor = conn.execute(sql)
    for row in cursor:
        forced_insecure_apps.add(row[0])
    print("Forced Insecure TLS Apps", len(forced_insecure_apps))

   
def count_redirected_conns():
    print("--------------- Redirected Connections -----------------")
    sql = "SELECT DISTINCT pkg, addr, port, cert_type, frida_on FROM traffic_separation WHERE forced=1"
    cursor = conn.cursor()
    cursor = cursor.execute(sql)
    all_redirected_conns = set()
    for row in cursor:
        all_redirected_conns.add(row)
    print("ALL Redirected Conn", len(all_redirected_conns))

    sql = "SELECT DISTINCT pkg, addr, port, cert_type, frida_on FROM traffic_separation WHERE forced=1 AND port=443"
    cursor = conn.cursor()
    cursor = cursor.execute(sql)
    redirected_https = set()
    for row in cursor:
        redirected_https.add(row)
    print("ALL Redirected Conn(HTTPS)", len(redirected_https))

    sql2 = "SELECT DISTINCT n.pkg, n.dest_ip, n.dest_port, n.cert_type, n.frida_on FROM  network AS n JOIN traffic_separation AS t ON t.device=n.device AND t.pkg=n.pkg AND t.forced=1 AND t.addr=n.dest_ip AND t.port=n.dest_port \
            AND t.cert_type=n.cert_type AND t.frida_on=n.frida_on AND t.port=443 GROUP BY n.pkg, n.dest_ip, n.dest_port, n.cert_type, n.frida_on"
    cursor = conn.cursor()
    cursor = cursor.execute(sql2)
    redirected_insecure_https = set()
    with open("redirection-insecure.csv", 'w') as f:
        writer = csv.writer(f)
        for row in cursor:
            redirected_insecure_https.add(row)
            writer.writerow(row)
    print("Redirected Insecure Connections(HTTPS)=", len(redirected_insecure_https))

    sql3 = "SELECT DISTINCT pkg, dest_ip, dest_port, cert_type, frida_on FROM  network GROUP BY pkg, dest_ip, dest_port, cert_type, frida_on"
    cursor = conn.cursor()
    cursor = cursor.execute(sql3)
    all_insecure_https = set()
    for row in cursor:
        all_insecure_https.add(row)
    print("All Insecure Connections(HTTPS)=", len(all_insecure_https))


if __name__ == "__main__":
    count_forced_apps()
    count_redirected_conns()
