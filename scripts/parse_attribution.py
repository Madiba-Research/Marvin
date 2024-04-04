import os
import sys
from custom_define import connect_db
from custom_define import is_standard_call, extract_validator_and_creator, extract_cn
from custom_define import extract_short_package_name
import json


from custom_define import DOMAIN_MISMATCH

from custom_define import TABLE_NETWORK, TABLE_VALIDATION
from custom_define import THIRD_PARTY_THRESHOLD

from custom_define import APP_CONN_VALIDATED_BY_APP_CODE   
from custom_define import LIB_CONN_VALIDATED_BY_LIB_CODE     
from custom_define import LIB_CONN_HIJACKED_BY_LIB_CODE      
from custom_define import APP_CONN_HIJACKED_BY_LIB_CODE     
from custom_define import LIB_CONN_HIJACKED_BY_APP_CODE      

from custom_define import DEVICE, PKG, HOST, CERT_TYPE, FRIDA_ON, SUBJECTDN, FUNC, CLASS
from custom_define import CONN_CREATOR, CONN_VALIDATOR, ATTRIBUTION_TYPE, HIJACKED, COUNT_CREATOR, COUNT_VALIDATOR, STACKTRACE

from custom_define import CERTIFICATE_HOST_MAP


db_name = os.environ['DATABASE']
conn = connect_db(db_name)



def count_code_package():
    package_counter = dict()
    sql = f"SELECT DISTINCT pkg, cert_type, frida_on, host, subjectDN, func, conn_creator, conn_validator, stacktrace FROM {TABLE_VALIDATION} WHERE func NOT LIKE '%setDefault%'" \
           "GROUP BY pkg, host, subjectDN, cert_type, frida_on, host, func, stacktrace"
    cursor = conn.cursor()
    cursor = cursor.execute(sql)
    for row in cursor:
        pkg, creator, validator = row[0], row[6], row[7]
        short_validator = extract_short_package_name(validator)
        short_creator = extract_short_package_name(creator)
        if short_validator not in package_counter:
            package_counter[short_validator] = set()
        package_counter[short_validator].add(pkg)
        if short_creator not in package_counter:
            package_counter[short_creator] = set()
        package_counter[short_creator].add(pkg)
    return package_counter


def is_host_insecure(device, pkg, host, cert_type, frida_on):
    result = False
    sql = f"SELECT DISTINCT pkg, host FROM {TABLE_NETWORK} WHERE device='{device}' and pkg='{pkg}' and host='{host}'and cert_type='{cert_type}' and frida_on='{frida_on}'"
    cursor = conn.cursor()
    cursor = cursor.execute(sql)
    for row in cursor:
        pkg, h = row[0], row[1]
        if h == host:
            result = True
            break
    return result


def _select_host_from_network(device, pkg, cert_type, frida_on, cn):
    if "*." in cn:
        cn = cn.replace("*.", "")
    sql = f"SELECT DISTINCT device, pkg, host FROM {TABLE_NETWORK} WHERE device='{device}' and pkg='{pkg}' and cert_type='{cert_type}' and frida_on='{frida_on}' and host LIKE '%{cn}%'"
    # if "*." in cn or cn_len<=2:
    #     cn = cn.replace("*.", "")
    #     sql = f"SELECT DISTINCT device, pkg, host FROM {TABLE_NETWORK} WHERE pkg='{pkg}' and cert_type='{cert_type}' and frida_on='{frida_on}' and host LIKE '%{cn}%'"
    # else:
    #     sql = f"SELECT DISTINCT device, pkg, host FROM {TABLE_NETWORK} WHERE pkg='{pkg}' and cert_type='{cert_type}' and frida_on='{frida_on}' and host='{cn}'"

    # print(sql)
    cursor = conn.cursor()
    cursor = cursor.execute(sql)
    hosts = set()
    for row in cursor:
        # print(row, "\n")
        _, pkg, host = row[0], row[1], row[2]
        hosts.add(host)
    return hosts


def find_host_in_network(device, pkg, cert_type, frida_on, subjectCN):
    cn = extract_cn(subjectCN)
    hosts = set()
    if cn is None:
        return hosts
    hosts = _select_host_from_network(device, pkg, cert_type, frida_on, cn)
    if len(hosts) < 1 and cn in CERTIFICATE_HOST_MAP:
        host = CERTIFICATE_HOST_MAP[cn]
        hosts = _select_host_from_network(device, pkg, cert_type, frida_on, host)
        # print("cn=", host, hosts)
        
    return hosts


def do_attribution():
    result_list = []
    package_counter = count_code_package()
    sql = f"SELECT DISTINCT device, pkg, cert_type, frida_on, host, subjectDN, func, class, conn_creator, conn_validator, stacktrace FROM {TABLE_VALIDATION} WHERE func NOT LIKE '%setDefault%'" \
           "GROUP BY device, pkg, cert_type, frida_on, host, subjectDN, func, class, stacktrace"
    cursor = conn.cursor()
    cursor = cursor.execute(sql)
    for row in cursor:
        device, pkg, cert_type, frida_on, host, subjectCN, func, class_v, creator, validator, stacktrace = \
            row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7], row[8], row[9], row[10]
        # validator, creator = extract_validator_and_creator(stacktrace)
        if is_standard_call(validator):
            continue
        short_validator = extract_short_package_name(validator)
        short_creator = extract_short_package_name(creator)
        counter_c, counter_v =  len(package_counter[short_creator]), len(package_counter[short_validator])
        attribution = None
        hijacked = True if short_creator != short_validator else False
        if counter_c < THIRD_PARTY_THRESHOLD and counter_v < THIRD_PARTY_THRESHOLD:
            attribution = APP_CONN_VALIDATED_BY_APP_CODE
        elif counter_c >= THIRD_PARTY_THRESHOLD and counter_v >= THIRD_PARTY_THRESHOLD and not hijacked:
            attribution = LIB_CONN_VALIDATED_BY_LIB_CODE
        elif counter_c < THIRD_PARTY_THRESHOLD and counter_v >= THIRD_PARTY_THRESHOLD:
            attribution = APP_CONN_HIJACKED_BY_LIB_CODE
        elif counter_c >= THIRD_PARTY_THRESHOLD and counter_v < THIRD_PARTY_THRESHOLD:
            attribution = LIB_CONN_HIJACKED_BY_APP_CODE
        elif counter_c >= THIRD_PARTY_THRESHOLD and counter_v >= THIRD_PARTY_THRESHOLD and hijacked:
            attribution = LIB_CONN_HIJACKED_BY_LIB_CODE
        # else:
        #     print(f"ERROR: app={pkg}", f"host={host}", f"class={validator}", f"count_domain={counter_c}", f"count_code={package_counter[short_validator]}", f"hijacked={hijacked}", f"st={stacktrace}")
        if host is not None and is_host_insecure(device, pkg, host, cert_type, frida_on):
            result_list.append({DEVICE: device, PKG: pkg, CERT_TYPE: cert_type, FRIDA_ON: frida_on, HOST: host, FUNC: func, CLASS: class_v, STACKTRACE: stacktrace, ATTRIBUTION_TYPE: attribution, HIJACKED: hijacked,
                    SUBJECTDN: subjectCN, CONN_CREATOR: creator, CONN_VALIDATOR: validator, COUNT_CREATOR:counter_c, COUNT_VALIDATOR: counter_v})
        else:    
            if subjectCN is not None:
                hosts = find_host_in_network(device, pkg, cert_type, frida_on, subjectCN)
                if len(hosts) >=1:
                    for h in hosts:
                        result_list.append({DEVICE: device, PKG: pkg, CERT_TYPE: cert_type, FRIDA_ON: frida_on, HOST: h, FUNC: func, CLASS: class_v, STACKTRACE: stacktrace, ATTRIBUTION_TYPE: attribution, HIJACKED: hijacked,
                                SUBJECTDN: subjectCN, CONN_CREATOR: creator, CONN_VALIDATOR: validator, COUNT_CREATOR:counter_c, COUNT_VALIDATOR: counter_v})
                else:
                    print(f"WARNING:::device={device}, app={pkg}", f"cert_type={cert_type}", f"frida_on={frida_on}", f"host={host}", f"subjectCN={subjectCN}")
    return result_list
