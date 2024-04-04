import os
import sys
import json
import sqlite3
import re
from parse import parse

leaks = []
hardcoded_keys = []
all_packets = set()
words_path = []
all_words = []
c = 0

requests = list()
responses = list()

out_dir = sys.argv[1]
db_name = sys.argv[2]


def load_json(fpath):
    data = None
    with open(fpath, 'r') as f:
        data = json.load(f)
    return data


for root, dirnames, filenames in os.walk(out_dir):
    for filename in filenames:
        fpath = os.path.join(root, filename)
        p = parse("leak-{}-{}.json", filename)
        if p != None:
            (cert_type, frida_on) = p.fixed
        # print(parse("leak-{}-{}.json",filename).fixed)
        # if filename == "leak.json":
            with open(os.path.join(root, filename), "r") as j:
                try:
                    leak_obj = json.load(j)
                except:
                    print(root)
                    raise ("sss")
                for lok, lov in leak_obj.items():
                    pkg_name = leak_obj["package"]

                    if lok == "package":
                        continue
                    elif lok == "hardcode_keys":
                        for hard_key in lov:
                            (_t, _i) = hard_key.split("|")
                            hardcoded_keys.append((pkg_name, _t, _i))
                    else:
                        for ilo in lov:
                            leak_item = dict()
                            leak_item["cert_type"] = cert_type
                            leak_item["frida_on"] = bool(frida_on)
                            leak_item["pkg"] = pkg_name
                            leak_item["channel"] = lok
                            leak_item["device"] = "6"  # root.split("/")[1]
                            # root.split("-")[1].split("/")[0]
                            leak_item["cat"] = "chinese"

                            if ilo.find('>') == -1:
                                leak_item["send"] = False
                                (context, leak_item["addr"]) = ilo.split("<")
                            else:
                                leak_item["send"] = True
                                (context, leak_item["addr"]) = ilo.split(">")

                            if context.find('@') == -1:
                                full_item = context
                                (leak_item["stage"], leak_item["alg"], leak_item["key"],
                                 leak_item["iv"], leak_item["3rd"]) = (None, None, None, None, None)
                            else:
                                (full_item,
                                 cryptgraphic) = context.split("@")
                                (leak_item["stage"], leak_item["alg"], leak_item["key"],
                                 leak_item["iv"], api_source) = cryptgraphic.split(":")
                                if api_source == "java":
                                    leak_item["3rd"] = False
                                else:
                                    leak_item["3rd"] = True
                            if full_item.find('*') == -1:
                                semi_full_item = full_item
                                leak_item["path"] = None

                            else:
                                (semi_full_item,
                                 path) = full_item.split("*")
                                # try:
                                leak_item["path"] = path

                            leak_item["meta"] = None
                            if semi_full_item.find('%') == -1:
                                leak_item["item"] = semi_full_item
                                leak_item["meta"] = None
                            else:
                                (leak_item["item"],
                                 meta) = semi_full_item.split("%")
                                _meta = meta.encode()
                                if (leak_item["item"] in ("lon", "lat") and not (len(_meta.split(b".")) == 2 and _meta.replace(b".", b"", 1).isdigit())):
                                    continue
                                leak_item["meta"] = meta

                        leaks.append(leak_item)

        # elif filename == 'requests.json':
        #     requests += load_json(fpath)
        # elif filename == 'responses.json':
        #     responses += load_json(fpath)

con = sqlite3.connect(db_name)
cur = con.cursor()

cur.execute('''CREATE TABLE IF NOT EXISTS leaks (device integer,cat text,pkg text,channel text, item text,meta blob,path text, send bool, addr text, stage integer,alg text,key text,iv text,is_3rd bool,cert_type int,frida_on bool)''')
cur.execute(
    '''CREATE TABLE IF NOT EXISTS hard_keys (pkg text,type text, item item)''')
# cur.execute('''CREATE TABLE IF NOT EXISTS requests (pkg text, host text, path text, port integer, method text, scheme text, timestamp text)''')
# cur.execute('''CREATE TABLE IF NOT EXISTS responses (pkg text, content_type text, status_code integer, timestamp text)''')
for leak in leaks:
    cur.execute("insert into leaks values ( ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,?,?)",
                (leak["device"], leak["cat"], leak["pkg"], leak["channel"], leak["item"], leak["meta"], leak["path"], leak["send"], leak["addr"], leak["stage"], leak["alg"], leak["key"], leak["iv"], leak["3rd"], leak["cert_type"], leak["frida_on"]))
for (pkg, t, i) in hardcoded_keys:
    cur.execute("insert into hard_keys values (?, ?,?)", (pkg, t, i))

# for req in requests:
#     cur.execute("INSERT INTO requests(pkg, host, path, port, method, scheme, timestamp) values (?, ?, ?, ?, ?, ?, ?)",
#                 (req["pkg"], req["host"], req["path"], req["port"], req["method"], req["scheme"], req["timestamp"]))

# for resp in responses:
#     cur.execute("INSERT INTO responses(pkg, status_code, timestamp) values (?, ?, ?)",
#                 (resp["pkg"], resp["status_code"], resp["timestamp"]))

con.commit()
# sqlite3.Binary((leak["meta"] if type(leak["meta"]) != type(None) else b""))
con.close()
# select * from leaks where channel = "https_crypt";


# # The apps that has sucessfully analyzed
# $ select count(DISTINCT pkg) from leaks;

# # The apps uses https insecure
# $ select count(DISTINCT pkg) from leaks where channel = "https";

# # The Apps uses http with additional cryptographic channel over insecure https
# $ select count(DISTINCT pkg) from leaks where channel = "https_crypt";

# # The Apps uses http with additional cryptographic channel over http
# $ select count(DISTINCT pkg) from leaks where channel = "http_crypt";

# # The Apps uses fixed key:
# $ select DISTINCT pkg from (select DISTINCT s1.* from (SELECT * from leaks where stage == 1) as s1, (SELECT * from leaks where stage == 2) as s2 where s1.pkg == s2.pkg and s1.key == s2.key) where alg not like '%RSA%' and channel=='https_crypt' and key!='';


# # The Apps uses hardcoded key:
# $ select count(DISTINCT l.pkg) from hard_keys as h, leaks as l where l.pkg=h.pkg and h.item = l.key and l.channel="https_crypt";
