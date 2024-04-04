import frida
import functools
import json
import time
import logging

def spawn_added(spawn, package, jscode, frida_device, processes):  # identifier pid
    processes[spawn.pid] = spawn.identifier
    logging.debug(processes)
    logging.debug("spawn_added:", spawn)
    print("--------")
    print(package)
    print(spawn.identifier)
    if spawn.identifier.startswith(package):
        session = frida_device.attach(spawn.pid)
        script = session.create_script(jscode)
        script.on("message", functools.partial(
            on_message, processes=processes))
        script.load()
        frida_device.resume(spawn.pid)


def on_message(message, data, processes):
    logging.debug(message)
    conn = json.loads(message["payload"])
    t = "java" if "java" in conn else "native"
    conn[t]["pid"] = str(conn[t]["pid"])+"-"+processes[conn[t]["pid"]]
    conn[t]["ts"] = int(time.time())
    # logging.debug(conn)

# frida_device = frida.get_device_manager().enumerate_devices()[-1]
# processes = dict()
# jscode = str()


# frida_device.on("spawn-added", functools.partial(spawn_added,
#                                                  package="com.topwar.gp", jscode=jscode, frida_device=frida_device, processes=processes))
# frida_device.enable_spawn_gating()
