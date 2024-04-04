1. stacktrace 
columns: device, pkg, class_name/pid, cert_type, is_native, host, item, order, timestamp, src_port, stage

Input files: conn.txt, verify.txt
Note:
(1) Filter host in mitmdump files
(2) in native file, host should refer to mitmdump file
(3) in java, class_name refer to class name; in native side, class_name refers to pid from conn

2. traffic_seperation:
device, pkg, cert_type, is_frida_on, running_uid, uid, pid, is_forced, process_name, ip, port, is_ipv4, host, is_mitm
Input file: traffic.txt,

Note:
(1) ip, port: refer to ConnectionData. (should be readable)
(2) process_name, pid refer to ChromeNet-1111 column
(3) running_uid from time.txt

3. network:
device, pkg, cert_type, is_frida_on, host/sni, is_mitm, schema, src_ip, src_port, dest_ip, dest_port

Note:
(1) mitmdump: host
(2) pcap: sni
