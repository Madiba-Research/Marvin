
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
CONN_VALIDATOR    = "conn_validator"
CONN_CREATOR = "conn_creator"
STACKTRACE   = "stacktrace"

# Attribution
ATTRIBUTION_TYPE = "attribution_type"
IS_HIJACKED = "hijacked"
COUNT_CREATOR = "count_creator"
COUNT_VALIDATOR = "count_validator"




CONNECT_LOWERCASE = "connect"


APP_CONN_VALIDATED_BY_APP_CODE   = "APP_CONN_VALIDATED_BY_APP_CODE"
LIB_CONN_VALIDATED_BY_LIB_CODE   = "LIB_CONN_VALIDATED_BY_LIB_CODE"
APP_CONN_HIJACKED_BY_LIB_CODE    = "APP_CONN_HIJACKED_BY_LIB_CODE"
LIB_CONN_HIJACKED_BY_LIB_CODE    = "LIB_CONN_HIJACKED_BY_LIB_CODE"
LIB_CONN_HIJACKED_BY_APP_CODE    = "LIB_CONN_HIJACKED_BY_APP_CODE"


VERIFY = "verify"
CHECK_SERVER_TRUSTED = 'checkServerTrusted'


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
        frame.startswith("okhttps") or frame.startswith("okhttp3"):
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
            continue
        if not is_standard_call(frame):
            creator = strip_invalid_character(frame)

    if creator is None:
        creator = strip_invalid_character(frames[2])
    
    return validator, creator

