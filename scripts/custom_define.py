
import os
import sqlite3
import csv
import base64



SUCCESS, FAILURE, PASSTHROUGH = "Success", "Failure", "Passthrough"
UNTRUSTED_ROOT, SELF_SIGNED, EXPIRATION, DOMAIN_MISMATCH = range(1, 5)


THIRD_PARTY_THRESHOLD = 5

RES_CHECK_JSON  = "res_check.json"
RES_VERIFY_JSON = "res_verify.json"



TABLE_NETWORK     = "network"
TABLE_PASSTHROUGH = "passthrough"
TABLE_TRAFFIC_SEPARATION = "traffic_separation"
TABLE_VALIDATION     = "validation"
TABLE_ATTRIBUTION = "attribution"


DEVICE    = "device"
PKG       = "pkg"
IS_MITM   = "is_mitm"
HOST      = "host"
SRC_IP    = "src_ip"
SRC_PORT  = "src_port"
DEST_IP   = "dest_ip"
DEST_PORT = "dest_port"
FRIDA_ON  = "frida_on"
CERT_TYPE = "cert_type"
TS        = "ts"
URL       = "url"
METHOD    = "method"

# network
STATUS    = "status"
TLS_START = "tls_start"
TLS_SETUP = "tls_setup"


# traffic separation
FORCED    = "forced"
STAGE     = "stage"
PNAME     = "pname"
PID       = "pid"
UID       = "uid"
R_UID     = "r_uid"
IPV4      = "is_ipv4"


# validaton
FUNC         = "func"
CLASS        = "class"
SUBJECTDN    = "subjectDN"
ISSUEDN      = "issueDN"
EXPIRE       = "expire"
FRAME_1      = "frame_1"
STACKTRACE   = "stacktrace"



# Attribution
HIJACKED = "hijacked"
ATTRIBUTION_TYPE = "attribution_type"
COUNT_CREATOR = "count_creator"
COUNT_VALIDATOR = "count_validator"

CONN_VALIDATOR = "conn_validator"
CONN_CREATOR = "conn_creator"


CONNECT_LOWERCASE = "connect"


APP_CONN_VALIDATED_BY_APP_CODE   = "APP_CONN_VALIDATED_BY_APP_CODE"
LIB_CONN_VALIDATED_BY_LIB_CODE   = "LIB_CONN_VALIDATED_BY_LIB_CODE"
APP_CONN_HIJACKED_BY_LIB_CODE    = "APP_CONN_HIJACKED_BY_LIB_CODE"
LIB_CONN_HIJACKED_BY_LIB_CODE    = "LIB_CONN_HIJACKED_BY_LIB_CODE"
LIB_CONN_HIJACKED_BY_APP_CODE    = "LIB_CONN_HIJACKED_BY_APP_CODE"


CERTIFICATE_HOST_MAP = {
    "*.aug19-2022-1.ias.qq.com": "android.bugly.qq.com",
    "aug19-2022-1.ias.qq.com": "android.bugly.qq.com",
    "feb10-2023-2.ias.qq.com": "h.trace.qq.com"
}


# CREATE_NETWORK_SQL            = '''CREATE TABLE IF NOT EXISTS network (device text, pkg text, is_mitm boolean, cert_type int, frida_on boolean, host text, src_ip text, src_port int, dest_ip text, dest_port int, \
#                                         tls_start int, tls_setup int)'''
# CREATE_PASSTHROUGH_SQL        = '''CREATE TABLE IF NOT EXISTS passthrough (device text, pkg text, cert_type int, frida_on boolean, host text, dest_ip text, dest_port int, status text, ts text)'''
# CREATE_TRAFFIC_SEPARATION_SQL = '''CREATE TABLE IF NOT EXISTS traffic_separation (device text, pkg text, cert_type int, frida_on boolean, forced boolean, is_ipv4 boolean, uid int, r_uid int, pname text, pid int, addr text, port int)'''
# CREATE_VALIDATION_SQL         = '''CREATE TABLE IF NOT EXISTS validation (device text, pkg text, cert_type int, frida_on boolean, stage int, func text, class text, host text, \
#                                         subjectDN text, issueDN text, expire text, conn_validator text, conn_creator text, stacktrace text, ts text)'''
# CREATE_ATTRIBUTION_SQL        = '''CREATE TABLE IF NOT EXISTS attribution (device text, pkg text, cert_type int, frida_on boolean, host text, func text, class text,  stacktrace text, attribution_type text, hijacked boolean, \
#                                         subjectDN text, conn_creator text, conn_validator text, count_creator int, count_validator int)'''


CREATE_TABLE_SQLS = {
    TABLE_NETWORK: '''CREATE TABLE IF NOT EXISTS network (device text, pkg text, is_mitm boolean, cert_type int, frida_on boolean, host text, src_ip text, src_port int, dest_ip text, dest_port int, tls_start int, tls_setup int)''',
    TABLE_PASSTHROUGH: '''CREATE TABLE IF NOT EXISTS passthrough (device text, pkg text, cert_type int, frida_on boolean, host text, dest_ip text, dest_port int, status text, ts text)''',
    TABLE_TRAFFIC_SEPARATION: '''CREATE TABLE IF NOT EXISTS traffic_separation (device text, pkg text, cert_type int, frida_on boolean, forced boolean, is_ipv4 boolean, uid int, r_uid int, pname text, pid int, addr text, port int)''',
    TABLE_VALIDATION: '''CREATE TABLE IF NOT EXISTS validation (device text, pkg text, cert_type int, frida_on boolean, stage int, func text, class text, host text, subjectDN text, issueDN text, expire text, conn_validator text, conn_creator text, stacktrace text, ts text)''',
    TABLE_ATTRIBUTION: '''CREATE TABLE IF NOT EXISTS attribution (device text, pkg text, cert_type int, frida_on boolean, host text, func text, class text,  stacktrace text, attribution_type text, hijacked boolean, subjectDN text, conn_creator text, conn_validator text, count_creator int, count_validator int)'''
}


TABLE_PARAMS_DICTS = {
    TABLE_NETWORK: '''device, pkg, is_mitm, cert_type, frida_on, host, src_ip, src_port, dest_ip, dest_port, tls_start, tls_setup''',
    TABLE_PASSTHROUGH: '''device, pkg, cert_type, frida_on, host, dest_ip, dest_port, status, ts''',
    TABLE_TRAFFIC_SEPARATION: '''device, pkg, cert_type, frida_on, forced, is_ipv4, uid, r_uid, pname, pid, addr, port''',
    TABLE_VALIDATION: '''device, pkg, cert_type, frida_on, stage, func, class, host, subjectDN, issueDN, expire, conn_validator, conn_creator, stacktrace, ts''',
    TABLE_ATTRIBUTION: '''device, pkg, cert_type, frida_on, host, func, class, stacktrace, attribution_type, hijacked, subjectDN, conn_creator, conn_validator, count_creator, count_validator'''
}



def connect_db(db_name):
    conn = sqlite3.connect(db_name)
    return conn


def walk_pkg_names(path):
    return next(os.walk(path))[1]


def extract_short_package_name(package):
    name = None
    if len(package) == 0:
        return name
    if "$" in package:
        package = package.split('$')[0]
    items = package.split(".")
    if len(items) < 2:
        return None
    if len(items) >=2:
        name = ".".join(items[0: 2])
    else:
        name = ".".join(items)
    return name.strip()


def is_timestamp_in_tls_handshake(ts_start, ts_v, ts_setup, tolerant=1.5):
    if ts_v is None or ts_start is None or ts_setup is None:
        return False
    ts_v = float(ts_v)
    # validate_ts is set in computer, which added some delays of transfering from phone to computer. Therefore, validate_ts may be later than end_ts
    if (ts_v>=ts_start and ts_v <= ts_setup) or abs(ts_setup - ts_v) < tolerant or abs(ts_v - ts_start) < tolerant:
        return True
    return False


def extract_cn(subjectDN):
    cn = None
    if subjectDN != None and "CN=" in subjectDN:
        cn = subjectDN.split("CN=")[1]
        cn = cn.split(",")[0] if "," in cn else cn
        if "*." in cn:
            cn = cn.split("*.")[1]
    return cn



def write_csv(data, fname):
    with open (fname, "w") as f:
        writer = csv.writer(f)
        for item in data:
            writer.writerow([item])


def strip_invalid_character(frame):
    frame = frame.replace("at ", "") if "at" in frame else frame
    frame = frame.strip()
    if "(" in frame:
        frame = frame.split("(")[0]
    return frame

def is_standard_call(frame):
    if "at " in frame:
        frame = frame.replace("at ", "").strip()
    if frame.startswith("java") or frame.startswith("javax") or frame.startswith("android") or frame.startswith("androidx") or frame.startswith("com.android") or \
        frame.startswith("okhttps") or frame.startswith("okhttp3") or frame.startswith("org.apache"):
        return True
    return False




def extract_validator_and_creator(st_b64):
    st_utf8 = base64.b64decode(st_b64).decode("utf-8")
    validator, creator = None, None
    st_utf8 = st_utf8.strip("java.lang.Exception")
    frames = st_utf8.split("\n\t")
    for frame in frames:
        if len(frame) == 0:
            continue
        if validator is None:
            validator  = strip_invalid_character(frame)
            # frames.remove(frame)
            continue
        if not is_standard_call(frame):
            # print(frame)
            creator = strip_invalid_character(frame)
            break
    if creator is None:
        creator = strip_invalid_character(frames[2])
    
    # print(validator, creator)
    return validator, creator

# st_b64 = "amF2YS5sYW5nLkV4Y2VwdGlvbgoJYXQgY29tLmRkamsubGliLmh0dHAuSHR0cENsaWVudCQyLmNoZWNrU2VydmVyVHJ1c3RlZChOYXRpdmUgTWV0aG9kKQoJYXQgY29tLmFuZHJvaWQub3JnLmNvbnNjcnlwdC5QbGF0Zm9ybS5jaGVja1NlcnZlclRydXN0ZWQoUGxhdGZvcm0uamF2YToyNjApCglhdCBjb20uYW5kcm9pZC5vcmcuY29uc2NyeXB0LkNvbnNjcnlwdEVuZ2luZS52ZXJpZnlDZXJ0aWZpY2F0ZUNoYWluKENvbnNjcnlwdEVuZ2luZS5qYXZhOjE2MzgpCglhdCBjb20uYW5kcm9pZC5vcmcuY29uc2NyeXB0Lk5hdGl2ZUNyeXB0by5FTkdJTkVfU1NMX3JlYWRfZGlyZWN0KE5hdGl2ZSBNZXRob2QpCglhdCBjb20uYW5kcm9pZC5vcmcuY29uc2NyeXB0Lk5hdGl2ZVNzbC5yZWFkRGlyZWN0Qnl0ZUJ1ZmZlcihOYXRpdmVTc2wuamF2YTo1NjkpCglhdCBjb20uYW5kcm9pZC5vcmcuY29uc2NyeXB0LkNvbnNjcnlwdEVuZ2luZS5yZWFkUGxhaW50ZXh0RGF0YURpcmVjdChDb25zY3J5cHRFbmdpbmUuamF2YToxMDk1KQoJYXQgY29tLmFuZHJvaWQub3JnLmNvbnNjcnlwdC5Db25zY3J5cHRFbmdpbmUucmVhZFBsYWludGV4dERhdGEoQ29uc2NyeXB0RW5naW5lLmphdmE6MTA3OSkKCWF0IGNvbS5hbmRyb2lkLm9yZy5jb25zY3J5cHQuQ29uc2NyeXB0RW5naW5lLnVud3JhcChDb25zY3J5cHRFbmdpbmUuamF2YTo4NzYpCglhdCBjb20uYW5kcm9pZC5vcmcuY29uc2NyeXB0LkNvbnNjcnlwdEVuZ2luZS51bndyYXAoQ29uc2NyeXB0RW5naW5lLmphdmE6NzQ3KQoJYXQgY29tLmFuZHJvaWQub3JnLmNvbnNjcnlwdC5Db25zY3J5cHRFbmdpbmUudW53cmFwKENvbnNjcnlwdEVuZ2luZS5qYXZhOjcxMikKCWF0IGNvbS5hbmRyb2lkLm9yZy5jb25zY3J5cHQuQ29uc2NyeXB0RW5naW5lU29ja2V0JFNTTElucHV0U3RyZWFtLnByb2Nlc3NEYXRhRnJvbVNvY2tldChDb25zY3J5cHRFbmdpbmVTb2NrZXQuamF2YTo4NTgpCglhdCBjb20uYW5kcm9pZC5vcmcuY29uc2NyeXB0LkNvbnNjcnlwdEVuZ2luZVNvY2tldCRTU0xJbnB1dFN0cmVhbS4tJCROZXN0JG1wcm9jZXNzRGF0YUZyb21Tb2NrZXQoVW5rbm93biBTb3VyY2U6MCkKCWF0IGNvbS5hbmRyb2lkLm9yZy5jb25zY3J5cHQuQ29uc2NyeXB0RW5naW5lU29ja2V0LmRvSGFuZHNoYWtlKENvbnNjcnlwdEVuZ2luZVNvY2tldC5qYXZhOjI0MSkKCWF0IGNvbS5hbmRyb2lkLm9yZy5jb25zY3J5cHQuQ29uc2NyeXB0RW5naW5lU29ja2V0LnN0YXJ0SGFuZHNoYWtlKENvbnNjcnlwdEVuZ2luZVNvY2tldC5qYXZhOjIyMCkKCWF0IG9raHR0cDMuaW50ZXJuYWwuY29ubmVjdGlvbi5SZWFsQ29ubmVjdGlvbi5jb25uZWN0VGxzKFJlYWxDb25uZWN0aW9uLmphdmE6MzM2KQoJYXQgb2todHRwMy5pbnRlcm5hbC5jb25uZWN0aW9uLlJlYWxDb25uZWN0aW9uLmVzdGFibGlzaFByb3RvY29sKFJlYWxDb25uZWN0aW9uLmphdmE6MzAwKQoJYXQgb2todHRwMy5pbnRlcm5hbC5jb25uZWN0aW9uLlJlYWxDb25uZWN0aW9uLmNvbm5lY3QoUmVhbENvbm5lY3Rpb24uamF2YToxODUpCglhdCBva2h0dHAzLmludGVybmFsLmNvbm5lY3Rpb24uRXhjaGFuZ2VGaW5kZXIuZmluZENvbm5lY3Rpb24oRXhjaGFuZ2VGaW5kZXIuamF2YToyMjQpCglhdCBva2h0dHAzLmludGVybmFsLmNvbm5lY3Rpb24uRXhjaGFuZ2VGaW5kZXIuZmluZEhlYWx0aHlDb25uZWN0aW9uKEV4Y2hhbmdlRmluZGVyLmphdmE6MTA4KQoJYXQgb2todHRwMy5pbnRlcm5hbC5jb25uZWN0aW9uLkV4Y2hhbmdlRmluZGVyLmZpbmQoRXhjaGFuZ2VGaW5kZXIuamF2YTo4OCkKCWF0IG9raHR0cDMuaW50ZXJuYWwuY29ubmVjdGlvbi5UcmFuc21pdHRlci5uZXdFeGNoYW5nZShUcmFuc21pdHRlci5qYXZhOjE2OSkKCWF0IG9raHR0cDMuaW50ZXJuYWwuY29ubmVjdGlvbi5Db25uZWN0SW50ZXJjZXB0b3IuaW50ZXJjZXB0KENvbm5lY3RJbnRlcmNlcHRvci5qYXZhOjQxKQoJYXQgb2todHRwMy5pbnRlcm5hbC5odHRwLlJlYWxJbnRlcmNlcHRvckNoYWluLnByb2NlZWQoUmVhbEludGVyY2VwdG9yQ2hhaW4uamF2YToxNDIpCglhdCBva2h0dHAzLmludGVybmFsLmh0dHAuUmVhbEludGVyY2VwdG9yQ2hhaW4ucHJvY2VlZChSZWFsSW50ZXJjZXB0b3JDaGFpbi5qYXZhOjExNykKCWF0IG9raHR0cDMuaW50ZXJuYWwuY2FjaGUuQ2FjaGVJbnRlcmNlcHRvci5pbnRlcmNlcHQoQ2FjaGVJbnRlcmNlcHRvci5qYXZhOjk0KQoJYXQgb2todHRwMy5pbnRlcm5hbC5odHRwLlJlYWxJbnRlcmNlcHRvckNoYWluLnByb2NlZWQoUmVhbEludGVyY2VwdG9yQ2hhaW4uamF2YToxNDIpCglhdCBva2h0dHAzLmludGVybmFsLmh0dHAuUmVhbEludGVyY2VwdG9yQ2hhaW4ucHJvY2VlZChSZWFsSW50ZXJjZXB0b3JDaGFpbi5qYXZhOjExNykKCWF0IG9raHR0cDMuaW50ZXJuYWwuaHR0cC5CcmlkZ2VJbnRlcmNlcHRvci5pbnRlcmNlcHQoQnJpZGdlSW50ZXJjZXB0b3IuamF2YTo5MykKCWF0IG9raHR0cDMuaW50ZXJuYWwuaHR0cC5SZWFsSW50ZXJjZXB0b3JDaGFpbi5wcm9jZWVkKFJlYWxJbnRlcmNlcHRvckNoYWluLmphdmE6MTQyKQoJYXQgb2todHRwMy5pbnRlcm5hbC5odHRwLlJldHJ5QW5kRm9sbG93VXBJbnRlcmNlcHRvci5pbnRlcmNlcHQoUmV0cnlBbmRGb2xsb3dVcEludGVyY2VwdG9yLmphdmE6ODgpCglhdCBva2h0dHAzLmludGVybmFsLmh0dHAuUmVhbEludGVyY2VwdG9yQ2hhaW4ucHJvY2VlZChSZWFsSW50ZXJjZXB0b3JDaGFpbi5qYXZhOjE0MikKCWF0IG9raHR0cDMuaW50ZXJuYWwuaHR0cC5SZWFsSW50ZXJjZXB0b3JDaGFpbi5wcm9jZWVkKFJlYWxJbnRlcmNlcHRvckNoYWluLmphdmE6MTE3KQoJYXQgY29tLmRkamsubGliLmh0dHAucmVzcG9uc2UuUmVzcG9uc2VJbnRlcmNlcHRvci5pbnRlcmNlcHQoUmVzcG9uc2VJbnRlcmNlcHRvci5qYXZhOjE1KQoJYXQgb2todHRwMy5pbnRlcm5hbC5odHRwLlJlYWxJbnRlcmNlcHRvckNoYWluLnByb2NlZWQoUmVhbEludGVyY2VwdG9yQ2hhaW4uamF2YToxNDIpCglhdCBva2h0dHAzLmludGVybmFsLmh0dHAuUmVhbEludGVyY2VwdG9yQ2hhaW4ucHJvY2VlZChSZWFsSW50ZXJjZXB0b3JDaGFpbi5qYXZhOjExNykKCWF0IGNvbS5kZGprLmxpYi5odHRwLkh0dHBDbGllbnQkMS5pbnRlcmNlcHQoSHR0cENsaWVudC5qYXZhOjgwKQoJYXQgb2todHRwMy5pbnRlcm5hbC5odHRwLlJlYWxJbnRlcmNlcHRvckNoYWluLnByb2NlZWQoUmVhbEludGVyY2VwdG9yQ2hhaW4uamF2YToxNDIpCglhdCBva2h0dHAzLmludGVybmFsLmh0dHAuUmVhbEludGVyY2VwdG9yQ2hhaW4ucHJvY2VlZChSZWFsSW50ZXJjZXB0b3JDaGFpbi5qYXZhOjExNykKCWF0IGNvbS5qay5saWJiYXNlLnNlcnZlci5IdHRwSGVhZGVySW50ZXJjZXB0b3IuaW50ZXJjZXB0KEh0dHBIZWFkZXJJbnRlcmNlcHRvci5qYXZhOjg3KQoJYXQgb2todHRwMy5pbnRlcm5hbC5odHRwLlJlYWxJbnRlcmNlcHRvckNoYWluLnByb2NlZWQoUmVhbEludGVyY2VwdG9yQ2hhaW4uamF2YToxNDIpCglhdCBva2h0dHAzLmludGVybmFsLmh0dHAuUmVhbEludGVyY2VwdG9yQ2hhaW4ucHJvY2VlZChSZWFsSW50ZXJjZXB0b3JDaGFpbi5qYXZhOjExNykKCWF0IG9raHR0cDMuUmVhbENhbGwuZ2V0UmVzcG9uc2VXaXRoSW50ZXJjZXB0b3JDaGFpbihSZWFsQ2FsbC5qYXZhOjIyOSkKCWF0IG9raHR0cDMuUmVhbENhbGwkQXN5bmNDYWxsLmV4ZWN1dGUoUmVhbENhbGwuamF2YToxNzIpCglhdCBva2h0dHAzLmludGVybmFsLk5hbWVkUnVubmFibGUucnVuKE5hbWVkUnVubmFibGUuamF2YTozMikKCWF0IGphdmEudXRpbC5jb25jdXJyZW50LlRocmVhZFBvb2xFeGVjdXRvci5ydW5Xb3JrZXIoVGhyZWFkUG9vbEV4ZWN1dG9yLmphdmE6MTEzNykKCWF0IGphdmEudXRpbC5jb25jdXJyZW50LlRocmVhZFBvb2xFeGVjdXRvciRXb3JrZXIucnVuKFRocmVhZFBvb2xFeGVjdXRvci5qYXZhOjYzNykKCWF0IGphdmEubGFuZy5UaHJlYWQucnVuKFRocmVhZC5qYXZhOjEwMTIpCg=="
# extract_validator_and_creator(st_b64)
