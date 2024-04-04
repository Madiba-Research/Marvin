import time
import json
import functools
import logging
import os
import sys
import subprocess
import frida


def fh(method, body):
    params = ""
    for i, (key, _) in enumerate(body.items()):
        if i > 0:
            params += "+'\\\\\", \\\\\"'+"
            # params += "+'\\\\\"], [\\\\\"'+"
        params += "btoa(" + key+")"
#Java.use('android.provider.Settings$Secure').getString(Java.use('android.app.ActivityThread').currentApplication().getApplicationContext().getContentResolver(), 'android_id')
    exec = "var ret = this." + \
        method.name+"("+(", ".join([key for key, value in body.items()]))+");"
    return exec+"send('{\"crypto\":\"{\\\\\"class_name\\\\\":\\\\\""+method.class_name+"\\\\\",\\\\\"method_name\\\\\":\\\\\""+method.name+"\\\\\",\\\\\"args\\\\\":["+("\\\\\"'+"+params+"+'\\\\\"" if params else "")+"],\\\\\"ret\\\\\":\\\\\"'+btoa(ret)+'\\\\\",\\\\\"stackTrace\\\\\":\\\\\"'+btoa(Java.use(\"android.util.Log\").getStackTraceString(Java.use(\"java.lang.Exception\").$new()))+'\\\\\"}\"}');return ret;"
    #console.log('"+method.class_name.decode("utf-8")+":"+method.name.decode("utf-8")+"("+("'+"+params+"+'" if params else "")+")->'+ret);

#Java.use('android.provider.Settings$Secure').getString(Java.use('android.app.ActivityThread').currentApplication().getApplicationContext().getContentResolver(), 'android_id');


class Dynamic:
    def __init__(self, device, package, static,cert_type):
        self.frida = device.frida
        self.device = device
        self.package = package
        self.sessions = set()
        self.jscode = str()

        def candid_methods(
            m): return "java.lang.String" in m or "java.lang.Byte" in m or "byte" == m
        # args , ret = description_mapper(method.get_descriptor())
        # self.params, self.return_type
        rooted_methods = static.get_methods(
            lambda m: (("rooted" in m.name.lower()) and "path" not in m.class_name and ".db." not in m.class_name and "google" not in m.class_name and "kotlin" not in m.class_name and m.return_type == "boolean"))
        self.jscode = "Java.perform(function () {"+(
            "".join((m.to_frida((lambda _m, _b: ""), "return false;") for m in rooted_methods)))+(
            "".join((m.to_frida((lambda _m, _b: "p0 = false;")) for m in static.get_methods(
                lambda m: (("root" in m.name.lower() and "detect" in m.name.lower()) and ".db." not in m.class_name and "path" not in m.class_name and "google" not in m.class_name and m.return_type == "void" and len(m.params) == 1 and m.params[0] == "boolean")))))+"});"

        # fake_verifiers = static.get_methods(
        #     lambda m: (("verify" == m.name.lower()) and "google" not in m.class_name and "java" not in m.class_name and "kotlin" not in m.class_name and m.return_type == "boolean" and len(m.params) == 2))

        # self.jscode = "Java.perform(function () {"+(
        #     "".join((m.to_frida((lambda _m, _b: ""), "return true;") for m in fake_verifiers)))+"});"

        # self.jscode += "Java.perform(function () {"+(
        #     "".join((m.to_frida((lambda _m,_b: "p0 = false;")) for m in static.get_methods(
        #     lambda m: (("root" in m.name.lower() and "detect" in m.name.lower()) and ".db." not in m.class_name and "path" not in m.class_name and "google" not in m.class_name and m.return_type == "void" and len(m.params) == 1 and m.params[0] == "boolean")))))+"});"
        # crypto_methods = static.get_methods(
        #     lambda m: (((("encrypt" in m.name.lower() or "decrypt" in m.name.lower()) and ("aes" in m.name.lower() or "rsa" in m.name.lower() or "byte" in m.name.lower() and "compress" in m.name.lower() and "string" in m.name.lower())) or ("encrypt" == m.name.lower() or "decrypt" == m.name.lower())) and ".db." not in m.class_name and 1 <= len(m.params) >= 3  and all([candid_methods(param) for param in m.params]) and candid_methods(m.return_type)))

        crypto_methods = static.get_methods(
            lambda m: (("encrypt" == m.name.lower() or "decrypt" in m.name.lower()) and ".db." not in m.class_name and 1 <= len(m.params) <= 4 and all([candid_methods(param) for param in m.params]) and candid_methods(m.return_type)))
        self.jscode += "Java.perform(function () {"+(
            "".join((m.to_frida(fh) for m in crypto_methods)))+"});"

        print(self.jscode)
        for file in ("general.js",  "bypass_root_detection.js", "built_in_crypto.js","native.js", "java.js", "m.js", "n.js", "sk.js"): #"native.js", "java.js", "media.js", "fs.js",
            with open("js/"+file) as f:
                # print(self.jscode)
                self.jscode += f.read()
        # "java.lang.Object" in m or "JSONObject" in m or

        self.spawn = functools.partial(spawn_added,cert_type=cert_type, frida_device=self.frida, device=self.device,
                                       package=self.package, jscode=self.jscode, processes=dict(), fs=dict(), sessions=self.sessions)
        self.frida.on("spawn-added", self.spawn)
        self.frida.on("child-added", self.spawn)


    def run(self):
        try:
            self.frida.enable_spawn_gating()
        except (frida.NotSupportedError, frida.ProcessNotRespondingError) as e:
            print(f"✗ Frida crash: {e}")
            os.system('kill -9 {pid}'.format(pid=os.getpid()))
            # os.system("adb reboot")

    def stop(self):
        # self.frida.close()
        try:
            self.frida.disable_spawn_gating()
            self.frida.off("spawn-added", self.spawn)
            self.frida.off("child-added", self.spawn)
            for session in self.sessions:
                session.detach()
        except:
            pass


def spawn_added(spawn,cert_type, frida_device, device, package, jscode, processes, fs, sessions):  # identifier pid
    print(spawn.identifier+"::::::"+package)
    if spawn.identifier.startswith(package) or is_spawn_add(spawn):
        logging.debug("Process:"+str(spawn))
        processes[spawn.pid] = spawn.identifier
        if spawn.identifier.startswith(package+":") or spawn.identifier == package:
            try:
                session = frida_device.attach(spawn.pid)
                sessions.add(session)
                script = session.create_script(jscode)
                script.on("message", functools.partial(on_message, package=package, processes=processes, fs=fs,cert_type=cert_type))
                script.load()
            except:
                session.detach()
        else:
            pass
        try:
            frida_device.resume(spawn.pid)
        except Exception as e:
            logging.debug("Errrr:"+str(spawn) + ": " + str(e))
            pass
    else:
        for p in frida_device.enumerate_processes():
            if p.pid == spawn.pid:
                print("killed" + str(spawn.pid) + ":" + spawn.identifier)
                frida_device.resume(spawn.pid)
                frida_device.kill(spawn.pid)
                device.close_app(spawn.identifier)


def is_spawn_add(spawn):
    apps = ["com.android", "com.google.process", "com.google.android", "com.research.helper", "com.topjohnwu.magisk", "com.tencent.mm"]
    for app in apps:
        if spawn.identifier.startswith(app):
            return True
    return False


def on_message(message,data,cert_type, package, processes, fs):
    stage = "-2" if os.path.exists("out/"+package+"/2nd.lock") else "-1"
    try:
        # print(message["payload"])
        # print(message)
        conn = json.loads(message["payload"])
        if "crypto" in conn:
            with open("out/"+package+"/crypt"+stage+"-"+cert_type+".txt", "a") as f:
                c = json.loads(conn["crypto"])
                c["ts"] = time.time()
                f.write(json.dumps(c) + '\n')
        elif "key-iv" in conn:
            with open("out/"+package+"/key-iv"+stage+"-"+cert_type+".txt", "a") as f:
                k = json.loads(conn["key-iv"])
                k["ts"] = time.time()
                f.write(json.dumps(k) + '\n')
        elif "deviceid" in conn:
            with open("out/"+package+"/device_id"+stage+"-"+cert_type+".txt", "w") as f:
                f.write(str(conn["deviceid"]) + '\n')
        elif "adid" in conn:
            with open("out/"+package+"/adid"+stage+"-"+cert_type+".txt", "w") as f:
                f.write(str(conn["adid"]) + '\n')
        # elif "fs" in conn:
        #     with open("out/"+package+"/fs"+stage+".txt", "a") as f:
        #         conn["fs"]["ts"] = time.time()
        #         f.write(json.dumps(conn["fs"]) + '\n')
        # elif "media" in conn:
        #     with open("out/"+package+"/media"+stage+".txt", "a") as f:
        #         c = json.loads(conn["media"])
        #         ts = time.time()
        #         c["ts"] = ts
        #         print("adb exec-out screencap -p > out/" +
        #               package+"/media-"+str(ts)+".png")
        #         pp = subprocess.Popen(
        #             ["adb", "exec-out", "screencap", "-p"], stdout=subprocess.PIPE,)
        #         stdoutdata, stderrdata = pp.communicate()
        #         with open("out/"+package+"/media"+stage+"-"+str(ts)+".png", "wb") as fm:
        #             fm.write(stdoutdata)
        #         pp.wait()
        #         # c["ts"] = time.time()
        #         f.write(json.dumps(c) + '\n')
#         elif "loadlibrary" in conn:
#             with open("out/"+package+"/loadlibrary"+stage+"-"+cert_type+".txt", "a") as f:
#                 conn["loadlibrary"]["ts"] = time.time()
#                 f.write(json.dumps(conn["loadlibrary"]) + "\n")
        elif "verify" in conn:
            with open("out/"+package+"/verify"+stage+"-"+cert_type+".txt", "a") as f:
                f.write(json.dumps(conn["verify"]) + "\n")
        elif "check" in conn:
            with open("out/"+package+"/check"+stage+"-"+cert_type+".txt", "a") as f:
                f.write(json.dumps(conn["check"]) + "\n")
        elif "createSocket" in conn:
            with open("out/"+package+"/createSocket"+stage+"-"+cert_type+".txt", "a") as f:
                f.write(json.dumps(conn["createSocket"]) + "\n")
        else:
            t = "java" if "java" in conn else "native"
            conn[t]["pid"] = str(conn[t]["pid"])+"-"+processes[conn[t]["pid"]]
            with open("out/"+package+"/conn"+stage+"-"+cert_type+".txt", "a") as f:
                f.write(str(conn) + '\n')
    except Exception as e:
        logging.debug("mm")
        print(e)
        print(message)

