import json
import base64
import ast
import sys
from typing import OrderedDict
import magic
import gzip

def decimaltobyte(input):
    return bytes([i & ((1 << 8) - 1) for i in ast.literal_eval(input)])

def byteify(input):
    return input.encode('utf-8') if type(input) == str else input
    
def get_args(line):
    l = list()
    for arg in line["args"]:
        if arg.find(',') != -1 and arg.find('<') == -1:
            l.append(decimaltobyte(arg))
        elif arg.isdigit():
            l.append(arg)
        else:
            try:
                l.append(base64.b64decode(arg))
            except:
                l.append(arg)
    return l


def get_ret(line):
    if line["ret"].find(',') != -1 and line["ret"].find('<') == -1:
        return decimaltobyte(line["ret"])
    elif line["ret"].isdigit():
        return line["ret"]
    else:
        try:
            return base64.b64decode(line["ret"])
        except:
            return line["ret"]


with open(sys.argv[1]) as file:
    f = open(sys.argv[1]+".data", "wb")
    lines = file.readlines()
    for line in lines:
        l = json.loads(line.strip())
        for arg in get_args(l):
            if magic.from_buffer(arg, mime=True) in ("application/x-gzip"):
                try:
                    f.write(gzip.decompress(arg))
                except:
                    f.write(byteify(arg))
            else:
                f.write(byteify(arg))
        ret = get_ret(l)
        if magic.from_buffer(ret, mime=True) in ("application/x-gzip"):
            f.write(gzip.decompress(ret))
        else:
            f.write(byteify(ret))
    f.close()
