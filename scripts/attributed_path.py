import os
import sqlite3
import sys
import urllib.parse
import csv


from parse import parse
import glob

from mitmproxy import io, tcp


TABLE_PATH = "path"

OUT_DICT = {
    "timber": ["/media/disk/TLSProject/out-phantom", "/media/disk/TLSProject/out-phantom", "./out/"],
    "wool": ["/home/wool/Workspace/non-standard2/out-chn-ndss/" ],
    # "cotton": ["/home/cotton/Workspace/non-standard2/out-chn-ndss/"]
}

DATABASE_DICT = {
    "timber": "/home/wolf/chn-new.db",
    "wool": "/home/wool/Workspace/"
}

device = sys.argv[1]
outs = OUT_DICT[device]
print(outs)


database = DATABASE_DICT[device]
print(database)

conn = sqlite3.connect(database)
cursor = conn.cursor()

cursor.execute('''CREATE TABLE IF NOT EXISTS path (device text, pkg text, cert_type int, frida_on boolean, host text, url text, attribution_type text, method text, func text, class text, stacktrace text, hijacked boolean, \
                  subjectDN text, conn_creator text, conn_validator text)''')


CERT_TYPE = [1, 2, 3, 4]
FRIDA_ON = ["True", "False"]

def extract_path():
    for out in outs:
        pkg_folders = next(os.walk(out))[1]
    for pkg_name in pkg_folders:
        out_pkg = os.path.join(out, pkg_name)
        for f in glob.glob(out_pkg + "/mitmdump-*"):
            # 1. Read mitmdump file
            (case_type, frida_status) = parse('mitmdump-{}-{}', os.path.basename(f))
            freader = io.FlowReader(open(f, "rb"))
            request_dict = dict()
            try:
                for request in freader.stream():
                    url = request.request.host + request.request.path
                    request_dict[url] = request.request.method
            except:
                pass

            # 2. Read Database
            database_set = set()
            case_type = int(case_type)
            frida_status = True if frida_status=="True" else False
            cursor = conn.cursor()
            # sql = f"SELECT DISTINCT device, pkg, cert_type, frida_on, host, func, class, attribution_type, stacktrace, hijacked, subjectDN, conn_creator, conn_validator FROM attribution WHERE " \
            #         f"pkg='{pkg_name}' AND cert_type={case_type} AND frida_on='{frida_status}'"
            sql = f"SELECT DISTINCT device, pkg, host, func, class, hijacked, attribution_type FROM attribution WHERE " \
                    f"pkg='{pkg_name}' AND cert_type={case_type} AND frida_on='{frida_status}'"
            cursor = cursor.execute(sql)
            for row in cursor:
                # device, pkg, cert_type, frida_on, host, func, clss, stacktrace, attri_type, hijacked, subjectDN, conn_creator, conn_validator = row[0], row[1], row[2], row[3], \
                #     row[4], row[5], row[6], row[7], row[8], row[9], row[10], row[11], row[12]
                database_set.add(row)

            # 3. Find the URL for the host in the attribution table
            result_list = list()
            for url in request_dict:
                netloc = urllib.parse.urlparse("http://" + url).netloc
                for row in database_set:
                    device, pkg, host, func, clss, hijacked, attri_type = row[0], row[1], row[2], row[3], row[4], row[5], row[6]
                    if netloc != host:
                        continue
                    items = list(row)
                    items.insert(3, "https://" + url)
                    items.insert(4, request_dict[url])
                    print(items)
                    result_list.append(items)

            # 4. Write to csv files
            with open("new_path.csv", "a") as f:
                writer = csv.writer(f)
                writer.writerows(result_list)

            # Write to database
            # for row in result_list:
            #     cursor.execute(f"INSERT OR IGNORE INTO {TABLE_PATH} (device, pkg, cert_type, frida_on, host, url, method, func, class, attribution_type, hijacked, stacktrace, subjectDN, conn_creator, conn_validator) \
            #                      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            #             (row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7], row[8], row[9], row[10], row[11], row[12], row[13], row[14]))
        # conn.commit()


# python3 attributed_path.py timber
if __name__ == "__main__":
    extract_path()
