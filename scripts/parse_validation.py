import base64
import glob
import json
import os

from parse import parse
from copy import deepcopy


from custom_define import walk_pkg_names
from custom_define import DEVICE, PKG, HOST, CERT_TYPE, FRIDA_ON, STAGE, FUNC, CLASS, SUBJECTDN, ISSUEDN, EXPIRE, CONN_VALIDATOR, CONN_CREATOR, STACKTRACE, TS
from custom_define import RES_CHECK_JSON, RES_VERIFY_JSON
from custom_define import DOMAIN_MISMATCH
from custom_define import extract_validator_and_creator


# THRESHOLD = 1000

SET_DEFAULT_SSL_SOCKET_FACTORY = "setDefaultSSLSocketFactory"
SET_DEFAULT_HOSTNAME_VERIFIER  = "setDefaultHostnameVerifier"



def check_parsed(app_dir, pattern):
    result_file = os.path.join(app_dir, pattern)
    return True if os.path.exists(result_file) else False


def find_host_in_verify(vfile, subjectDN, issueDN):
    # find the hostname in the corresponding verify file
    if not os.path.exists(vfile):
        return None
    hosts = set()
    with open(vfile, "r") as f:
        for row in f:
            subject_dn, issue_dn, expire_v, ts_v = "", "", "", ""
            data_dict = json.loads(row)
            if "subjectDN" in data_dict:
                subject_dn = data_dict["subjectDN"]
            if "issueDN" in data_dict:
                issue_dn = data_dict["issueDN"]
            if "expire" in data_dict:
                expire_v = data_dict["expire"]
            if "ts" in data_dict:
                ts_v = data_dict["ts"]
            # ts_i, ts_vi = int(ts), int(ts_v)
            # delta = ts_i- ts_vi if ts_i > ts_vi else ts_vi - ts_i
            # if subject_dn == subjectDN and issue_dn == issueDN and expire == expire_v and delta <= THRESHOLD:
            if subject_dn == subjectDN and issue_dn == issueDN:
                hosts.add(data_dict["hostname"])
    return hosts


def _init_dict(device, app, stage, cert_type, frida_on):
    row_dict = {}
    row_dict[DEVICE]       = device
    row_dict[PKG]          = app
    row_dict[STAGE]        = stage
    row_dict[CERT_TYPE]    = cert_type
    row_dict[FRIDA_ON]     = frida_on
    row_dict[CLASS]        = None
    row_dict[FUNC]         = None
    row_dict[HOST]         = None
    row_dict[SUBJECTDN]    = None
    row_dict[ISSUEDN]      = None
    row_dict[EXPIRE]       = None
    row_dict[STACKTRACE]   = None
    row_dict[CONN_VALIDATOR] = None
    row_dict[CONN_CREATOR] = None
    row_dict[TS]           = None

    return row_dict

        
# parse check* file
def _parse_json(fpath, device, app, stage, cert_type, frida_on):
    result_list = []
    with open(fpath, "r") as f:
        basename = os.path.basename(fpath)
        for row in f:
            row_dict = _init_dict(device, app, stage, cert_type, frida_on)
            data_dict = json.loads(row)
            row_dict["cert_type"] = cert_type
            if "class" in data_dict:
                row_dict[CLASS] = data_dict["class"]
            if "subjectDN" in data_dict:
                row_dict[SUBJECTDN] = data_dict["subjectDN"]
            if "issueDN" in data_dict:
                row_dict[ISSUEDN] = data_dict["issueDN"]
            if "expire" in data_dict:
                row_dict[EXPIRE] = data_dict["expire"]
            if "stacktrace" in data_dict:
                row_dict[STACKTRACE] = data_dict["stacktrace"]
                row_dict[CONN_VALIDATOR], row_dict[CONN_CREATOR] = extract_validator_and_creator(data_dict["stacktrace"])
            if "ts" in data_dict:
                row_dict[TS] = data_dict["ts"]
            if "func" in data_dict:
                row_dict[FUNC] = data_dict["func"]
            elif basename.startswith("verify"):
                row_dict[FUNC] = "verify"
            if "hostname" in data_dict:
                row_dict[HOST] = data_dict["hostname"]
                result_list.append(row_dict)
            elif basename.startswith("check"):
                # row_dict[HOST] = None
                result_list.append(row_dict)
                if SUBJECTDN not in data_dict or ISSUEDN not in data_dict:
                    row_dict[HOST] = None
                    result_list.append(row_dict)
                    continue
                dir = os.path.dirname(fpath)
                verify_file = f"verify-{stage}-{cert_type}-{frida_on}.txt"
                verify_fpath = os.path.join(dir, verify_file)
                hosts = find_host_in_verify(verify_fpath, data_dict[SUBJECTDN], row_dict[ISSUEDN])
                if hosts is not None:
                    for h in hosts:
                        temp_dict = deepcopy(row_dict)
                        temp_dict[HOST] = h
                        result_list.append(temp_dict)
                        # result_list.append({DEVICE: device, PKG: app, CERT_TYPE: cert_type, HOST: h, FRIDA_ON: frida_on, STAGE: stage, CLASS: row_dict[CLASS], FUNC: row_dict[FUNC],
                        #                     SUBJECTDN: row_dict[SUBJECTDN], ISSUEDN: row_dict[ISSUEDN], EXPIRE: row_dict[EXPIRE], STACKTRACE: row_dict[STACKTRACE], 
                        #                     CONN_VALIDATOR: row_dict[CONN_VALIDATOR], CONN_CREATOR: row_dict[CONN_CREATOR], TS: row_dict[TS]})

    return result_list

    
def parse_check(device, out_dir):
    for app in walk_pkg_names(out_dir):
        app_dir = os.path.join(out_dir, app)
        if check_parsed(app_dir, RES_CHECK_JSON):
            continue
        print(f"---------------------{app}------------------------------")
        result_list = []
        for ckf in glob.glob(os.path.join(app_dir, "check*.txt")):
            stage, cert_type, frida_on = parse("check-{}-{}-{}.txt", os.path.basename(ckf))
            if int(cert_type) == DOMAIN_MISMATCH:
                continue
            result_list_one_file = _parse_json(ckf, device, app, stage, cert_type, frida_on)
            result_list.extend(result_list_one_file)
        result_file = os.path.join(app_dir, RES_CHECK_JSON)
        if len(result_list) != 0:
            with open(result_file, "w") as f:
                json.dump(result_list, f)



# parse verify* file
def parse_verify(device, out_dir):
    for app in walk_pkg_names(out_dir):
        app_dir = os.path.join(out_dir, app)
        if check_parsed(app_dir, RES_VERIFY_JSON):
            continue
        result_list = []
        for vf in glob.glob(os.path.join(app_dir, "verify*.txt")):
            stage, cert_type, frida_on = parse("verify-{}-{}-{}.txt", os.path.basename(vf))
            if int(cert_type) != DOMAIN_MISMATCH:
                continue
            result_list_one_file = _parse_json(vf, device, app, stage, cert_type, frida_on)
            result_list.extend(result_list_one_file)
        result_file = os.path.join(app_dir, RES_VERIFY_JSON)
        if len(result_list) != 0:
            with open(result_file, "w") as f:
                json.dump(result_list, f)
