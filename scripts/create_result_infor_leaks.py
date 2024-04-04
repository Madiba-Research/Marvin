def get_host_counter():
    hosts_counter = dict()
    sql = "SELECT pkg, host FROM network GROUP BY pkg, host"
    cursor = conn.cursor()
    cursor = cursor.execute(sql)
    for row in cursor:
        pkg, h = row[0], row[1]
        if h not in hosts_counter:
            hosts_counter[h] = set()
        hosts_counter[h].add(pkg)

    return hosts_counter


leaks_dict = {
    "Device": ("device", "manufacturer", "cpu", "displayid", "abi", "model", "resolution"),
    "Network": ("operator", "wifi-ip", "GatewayIPAddr"),
    "Location": ("timezone", "mylat2", "mylat3", "mylat4", "mylon2", "mylon3", "mylon4"),  
    "UserAsset":("number", "contactname", "installed_packages", "search", "mobile", "mobile2", "device-email")
}
leak_items = ("device", "manufacturer", "cpu", "displayid", "abi", "model", "resolution", "operator", "wifi-ip", "GatewayIPAddr", 
              "timezone", "mylat2", "mylat3", "mylat4", "mylon2", "mylon3", "mylon4",
              "number", "contactname", "installed_packages", "search", "mobile", "mobile2", "device-email")
def create_infor_leaks_santex():
    hosts_counter = get_host_counter()

    sql = "SELECT DISTINCT pkg, item, channel, addr FROM leaks WHERE (item not like 'key|%' or item not like 'key|%') GROUP BY pkg, item, channel, addr"
    cursor = conn.cursor()
    cursor = cursor.execute(sql)

    result_dict = dict()
    for row in cursor:
        pkg, item, chn, addr = row[0], row[1], row[2], row[3]
        addr = row[3]
        dest = None
        if addr not in hosts_counter or len(hosts_counter[addr]) < THIRD_PARTY_THRESHOLD:
            dest = "APP"
        else:
            dest = "THIRD_PARTY"
        if item not in leak_items:
            print("Not find: ", item)
            continue
        key = ",".join([item, chn, dest])
        if key not in result_dict:
            result_dict[key] = 1
        else:
            result_dict[key] += 1
    
    for key in result_dict:
        print(key, ",", result_dict[key])

  if __name__ == "__main__":
    create_infor_leaks_santex()
