activities = list()

import device
import functools
import sys
import exceptions
import hooker
import time
import static
import dynamic
import logging
import os
import shutil
import glob
import subprocess
from parse import parse

root = logging.getLogger()
root.setLevel(logging.DEBUG)
# root.setLevel(logging.WARNING)

ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
FORMAT = "[%(asctime)s - %(filename)s:%(lineno)s - %(funcName)s() ] %(message)s"
formatter = logging.Formatter(FORMAT)
ch.setFormatter(formatter)
root.addHandler(ch)


def main():
    logging.debug("value")
    try:
        devices = device.get_active_devices()
    except:
        _, value, _ = sys.exc_info()
        logging.debug(value)
        sys.exit(1)
    else:
        cdevice = None
        for d in devices:
            if d.d.serialno == "10.42.0.148:5555":
                cdevice = d
                break
            cdevice = d
    print(cdevice.d.serialno)
    cdevice = devices[0]

    with open("packages.txt", "r") as packages:
        for _i, pkg_name in enumerate(packages.read().splitlines()):
            if (not (os.path.exists("out/" + pkg_name+"/"+pkg_name + "-4-True.pcap") or os.path.exists("out/" + pkg_name+"/"+pkg_name + "-4-False.pcap"))) or os.path.exists("out/" + pkg_name + ".fail"):
                certificate_type = 1
                certificate_type_dynamic = False
                for f in glob.glob("out/" + pkg_name+"/traffic-*.txt"):
                    (x,y) = parse('traffic-{}-{}.txt', os.path.basename(f))
                    if certificate_type <= int(x):
                        certificate_type = int(x)
                        if bool(y) == True:
                            certificate_type_dynamic = True
                if certificate_type == 1:
                    certificate_type_dynamic = True
                for certificate_type_i in range(certificate_type,5):

                    for f in glob.glob("out/" + pkg_name+"/*"+str(certificate_type_i)+"-True*"):
                        os.remove(f)
                    for f in glob.glob("out/" + pkg_name+"/*"+str(certificate_type_i)+"-False*"):
                        os.remove(f)
            else:
                continue
            cdevice.uninstall_3rd_party_apps()
            logging.debug(pkg_name)
            if cdevice.install_app(pkg_name, reinstall=False) == False:
                print(f"install {pkg_name} failure")
                continue
            print(cdevice.get_package_uid(pkg_name))
            cdevice.store_app(pkg_name)
            static_analysis = static.Package(pkg_name)
            is_dynamic_analysis_on = True
            is_failed = False
            has_crypto = False
            for cert_type,dynamic_analysis in list([(cert_type,dynamic_analysis) for cert_type in ["1","2","3","4"][(certificate_type-1):] for dynamic_analysis in [True,False][int(not certificate_type_dynamic):]]):
                print(f"app={pkg_name}, cert_type={cert_type}, dynamic_analysis={dynamic_analysis}")
                if (is_failed == False and dynamic_analysis == False) or (is_failed == True and has_crypto == False and dynamic_analysis == True):
                    continue
                traffic_file = open("out/"+pkg_name+"/traffic-"+cert_type+"-"+str(dynamic_analysis)+".txt", "w")
                traffic_file_p = subprocess.Popen(["adb", "-t", cdevice.transport_id ,"shell","su", "-c" , "'cat /sys/kernel/tracing/trace_pipe'"],stdout=traffic_file)
                cdevice.install_app(pkg_name, reinstall=False)
                package_uid = cdevice.get_package_uid(pkg_name)
                for p in static_analysis.process:
                    cdevice.shell("su -c \"magisk --denylist add "+pkg_name+" "+p+"\"")
                adid = cdevice.shell("su -c 'grep \"adid_key\" /data/data/com.google.android.gms/shared_prefs/adid_settings.xml | egrep \"[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{8}\" -o'")
                with open("out/"+pkg_name+"/adid.txt", "a") as f:
                    f.write(adid+"\n")
                perms, service_name = cdevice.grant_app_permissions(pkg_name)
                (p, mitm) = cdevice.start_capture(pkg_name,cert_type+"-"+str(dynamic_analysis))
                # Stop Hooking
                # if dynamic_analysis:
                #     cdevice.shell("su -c \"touch /data/local/tmp/frida-enabled\"")
                #     time.sleep(1)
                # else:
                #     cdevice.shell("su -c \"rm /data/local/tmp/frida-enabled\"")
                if is_dynamic_analysis_on == False or dynamic_analysis==False:
                    cdevice.shell("su -c \"rm /data/local/tmp/frida-enabled\"")
                else:
                    cdevice.shell("su -c \"touch /data/local/tmp/frida-enabled\"")
                    time.sleep(1)
                    h = dynamic.Dynamic(cdevice, pkg_name, static_analysis,cert_type+"-"+str(dynamic_analysis))
                    h.run()

                analysis_time = int(time.time())
                with open("out/"+pkg_name+"/time.txt", "a") as f:
                    f.write(package_uid+":"+cert_type+"-"+str(dynamic_analysis)+"-s1+:"+str(analysis_time)+"\n")
                cdevice.run_app(pkg_name)
                cdevice.start_interaction(pkg_name, 1, analysis_time,cert_type,dynamic_analysis)
                cdevice.close_app(pkg_name)
                print("close: " +pkg_name )
                with open("out/"+pkg_name+"/time.txt", "a") as f:
                    f.write(package_uid+":"+cert_type+"-"+str(dynamic_analysis)+"-s1-:"+str(int(time.time()))+"\n")
                cdevice.store_files(pkg_name, 1)
                if  is_failed == False and cert_type == "1" and (cdevice.is_app_not_opening(pkg_name) or cdevice.is_app_crashed_by_id(package_uid)):
                    is_failed = True
                if os.path.exists("out/"+pkg_name+"/crypt-1-"+cert_type+"-"+str(dynamic_analysis)+".txt") and is_dynamic_analysis_on:
                    has_crypto = True
                    logging.debug("======> "+pkg_name+" 2nd")
                    open("out/"+pkg_name+"/2nd.lock", 'a').close()
                    if cdevice.install_app(pkg_name, reinstall=True) == False:
                        raise "Unable to install"
                    cdevice.grant_app_permissions(
                        pkg_name, perms=perms, service_name=service_name)
                    analysis_time = int(time.time())
                    with open("out/"+pkg_name+"/time.txt", "a") as f:
                        f.write(package_uid+":"+cert_type+"-"+str(dynamic_analysis)+"-s2+:"+str(analysis_time)+"\n")
                    cdevice.run_app(pkg_name)
                    cdevice.start_interaction(pkg_name, 2, analysis_time,cert_type,dynamic_analysis)
                    cdevice.close_app(pkg_name)
                    with open("out/"+pkg_name+"/time.txt", "a") as f:
                        f.write(package_uid+":"+cert_type+"-"+str(dynamic_analysis)+"-s2-:"+str(int(time.time()))+"\n")
                    cdevice.store_files(pkg_name, 2)
                    os.remove("out/"+pkg_name+"/2nd.lock")
                # Stop Hooking
                if is_dynamic_analysis_on:
                    h.stop()
                if has_crypto == False:
                   is_dynamic_analysis_on = False 
                cdevice.stop_capture(p, mitm, pkg_name,cert_type+"-"+str(dynamic_analysis))
                cdevice.uninstall_app(pkg_name)
                traffic_file_p.kill()
                traffic_file.close()
                cdevice.shell("su -c \"rm /data/local/tmp/frida-enabled\"")
if __name__ == '__main__':
    main()
