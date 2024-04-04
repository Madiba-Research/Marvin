import sqlite3
import sys
import csv

import tldextract


database = sys.argv[1]
conn = sqlite3.connect(sys.argv[1])
cursor = conn.cursor()

UNTRUSTED_ROOT, SELF_SIGNED, EXPIRATION, DOMAIN_MISMATCH = range(1, 5)
SUCCESS, FAILURE, PASSTHROUGH = "Success", "Failure", "Passthrough"


WIFI_CHN_APPS = 2744
WIFI_GP_APPS =  4637

# Count Wifi
def count_wifi_apps():
    wifi_apps = set()
    sql = "SELECT DISTINCT pkg FROM network"
    cursor = conn.cursor()
    cursor = conn.execute(sql)
    for row in cursor:
        wifi_apps.add(row[0])

    sql2 = "SELECT DISTINCT pkg FROM passthrough"
    cursor = conn.cursor()
    cursor = conn.execute(sql2)
    for row in cursor:
        wifi_apps.add(row[0])
    print("Wifi Apps:", len(wifi_apps))
    return wifi_apps


def count_insecure_apps(out_file):
    sql = "SELECT COUNT(DISTINCT pkg) FROM network where is_mitm=true"
    cursor = conn.cursor()
    cursor = cursor.execute(sql)
    print(f"Insecure Apps: {cursor.fetchall()}")

    sql = "SELECT cert_type, COUNT(DISTINCT pkg) FROM network WHERE is_mitm=true GROUP BY cert_type"
    cursor = conn.cursor()
    cursor = cursor.execute(sql)
    with open(out_file, "w") as f:
        writer = csv.writer(f)
        for row in cursor:
            writer.writerow([row[0], row[1]])


# Table
def create_distribution_table_2(out_file, number_of_wifiApps):
    result_dict = {
        UNTRUSTED_ROOT: {},
        SELF_SIGNED: {},
        EXPIRATION: {},
        DOMAIN_MISMATCH: {}
    }
    sql = "SELECT DISTINCT pkg, cert_type, host, dest_ip, dest_port FROM network WHERE is_mitm=true GROUP BY pkg, cert_type, host, dest_ip, dest_port"
    cursor = conn.cursor()
    cursor = cursor.execute(sql)
    for row in cursor:
        pkg, cert_type, host, dest_ip, dest_port = row[0], row[1], row[2], row[3], row[4]
        if pkg in result_dict[cert_type]:
            result_dict[cert_type][pkg] += 1
        else:
            result_dict[cert_type][pkg] = 1

    distribution_result = {}
    for cert_type in result_dict:
        key = ">=1"
        if key not in distribution_result:
            distribution_result[key] = dict()
        distribution_result[key][cert_type] = result_dict[cert_type]
        for pkg in result_dict[cert_type]:
            count_conn = result_dict[cert_type][pkg]
            if count_conn >= 1 and count_conn <= 10:
                key = "[1-10]"
            elif count_conn >= 11 and count_conn <= 20:
                key = "[11-20]"
            elif count_conn >= 21 and count_conn <= 30:
                key = "[21-30]"
            elif count_conn > 30:
                key = ">30"
            else:
                continue

            if key not in distribution_result:
                distribution_result[key] = dict()
            if cert_type not in distribution_result[key]:
                distribution_result[key][cert_type] = set()
            distribution_result[key][cert_type].add(pkg)

    with open(out_file, "w") as f:
        writer = csv.writer(f)
        for key in distribution_result:
            for ct in distribution_result[key]:
                percent = float(len(distribution_result[key][ct]))/number_of_wifiApps
                percent = f"{percent:.1%}"
                writer.writerow([ct, key, len(distribution_result[key][ct]), percent])

    app_groups_ingore_certtype = dict()
    for bin_key in distribution_result:
        if bin_key not in app_groups_ingore_certtype:
            app_groups_ingore_certtype[bin_key] = set()
        for cert_type in distribution_result[bin_key]:
            pkgs = distribution_result[bin_key][cert_type]
            app_groups_ingore_certtype[bin_key].update(pkgs)
        percent = float(len(app_groups_ingore_certtype[bin_key]))/number_of_wifiApps
        percent = f"{percent:.1%}"
        print(bin_key, len(app_groups_ingore_certtype[bin_key]), percent)



# ********************************************************************************************************************************************************************



def main():
    print("------------------Google App Results-------------------")
    wifi_apps = count_wifi_apps()
    count_insecure_apps("gp_apps.csv")
    create_distribution_table_2("gp_distribution.csv", len(wifi_apps))


if __name__ == "__main__":
    main()



# def delete_duplicate_apps():
    # apps_dict = dict()
    # sql = "SELECT DISTINCT pkg, device FROM network"

    # cursor = conn.cursor()
    # cursor = cursor.execute(sql)
    # for row in cursor:
    #     pkg, device = row[0], row[1]
    #     if pkg not in apps_dict:
    #         apps_dict[pkg] = set()
    #     apps_dict[pkg].add(device)

    # for app in apps_dict:
    #     devices = apps_dict[app]
    #     if len(devices) > 1:
            # print(app, apps_dict[app])
    #         tables = ['network', 'passthrough', 'traffic_separation', 'validation', 'attribution']
    #         for t in tables:
    #             d= ''
    #             if 'rt_pro' in devices:
    #                 d = 'rt_pro'
    #             elif 'creek' in devices:
    #                 d = 'creek'
    #             elif 'timber' in devices:
    #                 d = 'timber'
    #             sql = f"delete from {t} where pkg='{app}' and device !='{d}'"
    #             cursor = conn.cursor()
    #             cursor = cursor.execute(sql)
    # conn.commit()
