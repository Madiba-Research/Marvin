import os
import sys
from custom_define import connect_db
from custom_define import is_standard_call, extract_validator_and_creator, extract_cn
from custom_define import extract_short_package_name
import json



from custom_define import TABLE_NETWORK, TABLE_VALIDATION
from custom_define import THIRD_PARTY_THRESHOLD

from custom_define import APP_CONN_VALIDATED_BY_APP_CODE   
from custom_define import LIB_CONN_VALIDATED_BY_LIB_CODE     
from custom_define import LIB_CONN_HIJACKED_BY_LIB_CODE      
from custom_define import APP_CONN_HIJACKED_BY_LIB_CODE     
from custom_define import LIB_CONN_HIJACKED_BY_APP_CODE      

from custom_define import DEVICE, PKG, HOST, CERT_TYPE, FRIDA_ON, SUBJECTDN, FUNC, CLASS
from custom_define import CONN_CREATOR, CONN_VALIDATOR, ATTRIBUTION_TYPE, HIJACKED, COUNT_CREATOR, COUNT_VALIDATOR, STACKTRACE


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


def find_host_in_network(pkg, cert_type, frida_on, subjectCN, conn):
    cn = extract_cn(subjectCN)
    if "*." in subjectCN:
        sql = f"SELECT DISTINCT device, pkg, host FROM {TABLE_NETWORK} WHERE pkg='{pkg}' and cert_type='{cert_type}' and frida_on='{frida_on}' and host LIKE '%{cn}%'"
    else:
        sql = f"SELECT DISTINCT pkg, host FROM {TABLE_NETWORK} WHERE pkg='{pkg}' and cert_type='{cert_type}' and frida_on='{frida_on}' and host='{cn}'"
    # print(sql)
    cursor = conn.cursor()
    cursor = cursor.execute(sql)
    hosts = set()
    for row in cursor:
        pkg, host = row[0], row[1]
        hosts.add(host)
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
        if host is not None:
            result_list.append({DEVICE: device, PKG: pkg, CERT_TYPE: cert_type, FRIDA_ON: frida_on, HOST: host, FUNC: func, CLASS: class_v, STACKTRACE: stacktrace, ATTRIBUTION_TYPE: attribution, HIJACKED: hijacked,
                    SUBJECTDN: subjectCN, CONN_CREATOR: creator, CONN_VALIDATOR: validator, COUNT_CREATOR:counter_c, COUNT_VALIDATOR: counter_v})
        else:    
            if subjectCN is not None:
                hosts = find_host_in_network(pkg, cert_type, frida_on, subjectCN, conn)
                if len(hosts) >=1:
                    for h in hosts:
                        result_list.append({DEVICE: device, PKG: pkg, CERT_TYPE: cert_type, FRIDA_ON: frida_on, HOST: h, FUNC: func, CLASS: class_v, STACKTRACE: stacktrace, ATTRIBUTION_TYPE: attribution, HIJACKED: hijacked,
                                SUBJECTDN: subjectCN, CONN_CREATOR: creator, CONN_VALIDATOR: validator, COUNT_CREATOR:counter_c, COUNT_VALIDATOR: counter_v})
                else:
                    count += 1
                    print(f"1111,ERROR:::app={pkg}", f"host={host}", f"cert_type={cert_type}", f"subjectCN={subjectCN}", f"stacktrace={stacktrace}")
    return result_list
    # with open("res_attribution.json", "w") as f:
    #     json.dump(result_list, f)


# create_attribution()
