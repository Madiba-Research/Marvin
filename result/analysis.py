import base64
import binascii
import bz2
from enum import unique
import gzip
import hashlib
import json
import math
import multiprocessing
import os
import socket
import string
import sys
import urllib
import zlib
from itertools import repeat
from operator import itemgetter
from zipfile import ZipFile
import re
import xmltodict
import shutil

import dpkt
# import magic
import io as oio
from mitmproxy import io, tcp


def remove(path):
    # print(path)
    """ param <path> could either be relative or absolute. """
    if os.path.isfile(path) or os.path.islink(path):
        os.remove(path)  # remove the file
    elif os.path.isdir(path):
        shutil.rmtree(path)  # remove dir and all contains
    else:
        raise ValueError("file {} is not a file or dir.".format(path))


def has_printable(input, n=33):
    printable_chars = bytes(string.printable, 'ascii')
    for p in [input[i:i+n] for i in range(0, len(input), n)]:
        if all(char in printable_chars for char in p):
            return True
    if input.endswith(b"\x00\x00\x00\x00"):
        return True
    return False


def is_close(a, b, tol=1e-9):
    return abs(a-b) <= tol


def partof(_part, _wholes, t="none"):
    wholes = _wholes if type(_wholes) == list else [_wholes]
    n = 66
    for whole in wholes:
        whole = extract(whole)
        # if t == "req_headers":
        #     print(whole)
        #     print(type(whole))
        if type(whole) == str:
            whole = whole.encode('utf-8')
        # try:
        if len(whole) >= 16:
            # print(itemTransformer(_part))

            for _encode_type, part in itemTransformer(_part).items():
                if type(part) == str:
                    part = part.encode('utf-8')
                if part in whole:
                    # if t == "req_headers":
                    #     print(whole)
                    #     print(part)
                    #     print("00000")
                    return True
                for p in [part[i:i+n] for i in range(0, len(part), n)]:
                    if (len(p) > 32 and p in whole):
                        # and b"\x00\x00\x00\x00" not in p:
                        if not all(c == 'A' or c == '=' for c in p):
                            # if t == "req_headers":
                            #     print(whole)
                            #     print(part)
                            #     print("1111")
                            return True
        # except:
        #     raise("aaaa")
    return False


def zip_extract(data, apk=False):
    input_zip = ZipFile(oio.BytesIO(data))
    zip = bytes()
    for name in input_zip.namelist():
        if apk:
            skip_list = ("bmp", "gif", "jpg", "jpeg", "png", "psd", "tif", "tiff", "svg", "webp", "3gp", "avi", "flv", "m4p", "m4v", "mkv", "mov", "mp4", "mpeg",
                         "mpg", "ogg", "ogv", "srt", "webm", "wmv", "aac", "flac", "m3u", "m4a", "mp3", "wav", "wma", "doc", "docx", "odt", "pdf", "rtf", "_metadata")
            if name.endswith(skip_list):
                continue
        # print(name)
        zip += extract(input_zip.read(name))
    return zip


def extract(data):
    if len(data) <= 4:
        return data
    if mayBase64(data):
        data = base64.b64decode(data)
    if type(data) == str:
        data = data.encode('utf-8', 'surrogateescape')
    if type(data) != bytes:
        return data
    if all(c < 128 for c in data) and len(re.findall(b"%[0-7][0-9a-fA-F]", data)) > 5:
        data = urllib.parse.unquote(data if type(
            data) == str else data.decode()).encode('utf-8')
    # mime = magic.from_buffer(data, mime=True)
    # if mime in ("application/x-gzip", "application/gzip"):
    if data[:3] in (b"\x1F\x8B\x08"):
        try:
            data = gzip.decompress(data)
        except:
            pass
    # elif mime == "application/x-bzip2":
    elif data[:3] in (b"\x42\x5A\x68"):
        try:
            data = bz2.decompress(data)
        except:
            pass
    # elif mime == "application/zlib":
    elif data[:2] in (b"\x78\x01", b"\x78\x9c", b"\x78\xda"):
        try:
            data = zlib.decompress(data)
        except:
            pass
    # elif mime == "application/zip":
    elif data[:4] in (b"\x50\x4B\x03\x04", b"\x50\x4B\x07\x08"):
        try:
            data = zip_extract(data)
        except:
            pass
    else:
        pass
        # print(mime)
    if type(data) == str:
        data = data.encode('utf-8')
    return data


def isSend(pkt, data):
    wifi_mac = (data["wifi-mac"][0] if type(data["wifi-mac"])
                == list else data["wifi-mac"])

    if (pkt.src == binascii.unhexlify(wifi_mac.replace(':', ''))):
        return True
    elif (pkt.dst == binascii.unhexlify(wifi_mac.replace(':', ''))):
        return False
    else:
        return None


def mayBase64(s):
    if type(s) == str:
        try:
            s = s.encode('utf-8')
        except:
            return False
    try:
        if base64.b64encode(base64.b64decode(s, validate=True)) == s.rstrip() and len(s) > 6 and ((len(s.rstrip(b'=')) % 4 != 0 and s.endswith(b"=")) or (not s.endswith(b"=") and (len(s.strip(b'=')) % 4) == 0)) and 6.0 > entropy(s) > 4.1:
            try:
                int(s, 16)
                return False
            except:
                return True
    except Exception:
        return False
    return False


def entropy(string):
    "Calculates the Shannon entropy of a string"

    # get probability of chars in string
    prob = [float(string.count(c)) / len(string)
            for c in dict.fromkeys(list(string))]

    # calculate the entropy
    entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])

    return entropy


def cryptoAPI(crypt, crypts, keys, stage):
    res = dict()
    res["stage"] = stage
    res["ts"] = crypt["ts"]
    res["algorithm"] = None
    res["iv"] = None
    res["key"] = None
    res["3rd"] = None
    res["plaintext"] = None
    res["ciphertext"] = None
    res["encrypt"] = None
    res["class_name"] = crypt["class_name"]
    res["method_name"] = crypt["method_name"]
    _input = bytes()
    _output = bytes()
    if res["method_name"] == "doFinal":
        # return None
        res["3rd"] = False
        key = None
        updates = []
        keys = [key for key in keys if crypt["hashcode"] ==
                key["hashcode"] and crypt["ts"] >= key["ts"]]
        if keys:
            key = max(keys, key=itemgetter("ts"))
        if key:
            res["encrypt"] = True if int(key["args"][0]) == 1 else False
            res["key"] = base64.b64decode(key["args"][1])
            res["iv"] = base64.b64decode(
                key["IV"]) if len(key["IV"]) > 1 else None
            res["algorithm"] = key["algorithm"]
        for i in range(crypts.index(crypt)-1, -1, -1):
            if crypts[i]["class_name"] == "javax.crypto.Cipher":
                if crypts[i]["hashcode"] == crypt["hashcode"]:
                    if crypts[i]["method_name"] == "doFinal":
                        break
                    else:
                        updates.insert(0, crypts[i])

        for update in updates:
            arg_len = len(update["args"])
            _input += base64.b64decode(update["args"][0])
            if arg_len == 1:
                _output += base64.b64decode(update["ret"])
            if arg_len == 2:
                _output += base64.b64decode(update["args"][1])
            elif arg_len == 3:
                _output += base64.b64decode(update["ret"]
                                            )[:int(update["args"][2])]
            elif arg_len == 4 or arg_len == 5:
                _output += base64.b64decode(update["args"][3])[
                    :int(update["args"][2])]

        crypt_len = len(crypt["args"])

        if crypt_len == 0:
            _output += base64.b64decode(crypt["ret"])
        elif crypt_len == 1:
            _input += base64.b64decode(crypt["args"][0])
            _output += base64.b64decode(crypt["ret"])
        elif crypt_len == 2 and crypt["args"][1].isdigit():
            res["encrypt"] = res["encrypt"] if res["encrypt"] != None else (
                True if has_printable(_input) else False if has_printable(_output) else None)
            if res["encrypt"]:
                _input += base64.b64decode(crypt["args"][0])
            else:
                _output += base64.b64decode(crypt["args"][0])
        elif crypt_len == 2 and not crypt["args"][1].isdigit():
            _input += base64.b64decode(crypt["args"][0])
            _output += base64.b64decode(crypt["args"][1])
        elif crypt_len == 3:
            _input += base64.b64decode(crypt["args"][0])
            _output += base64.b64decode(crypt["ret"])
        elif crypt_len in (4, 5):
            _input += base64.b64decode(crypt["args"][0])
            _output += base64.b64decode(crypt["args"][3])

        res["encrypt"] = res["encrypt"] if res["encrypt"] != None else (
            True if has_printable(_input) else False if has_printable(_output) else None)
        # if crypt_len >= 1 and not (crypt_len == 2 and crypt["args"][1].isdigit()):
        #     _input += base64.b64decode(crypt["args"][0])
        # if crypt_len == 0 or crypt_len == 1 or crypt_len == 3:
        #     _output += base64.b64decode(crypt["ret"])
        # if crypt_len == 2 and crypt["args"][1].isdigit():
        #     _input += base64.b64decode(crypt["args"][0])
        # if crypt_len == 2 and not crypt["args"][1].isdigit():
        #     _output += base64.b64decode(crypt["args"][1])
        # if crypt_len == 4 or crypt_len == 5:
        #     _output += base64.b64decode(crypt["args"][3])

        # if res["encrypt"] == None and has_printable(_input):
        #     res["encrypt"] = True
        # elif res["encrypt"] == None and has_printable(_output):
        #     res["encrypt"] = False
        # res["encrypt"] = True if res["encrypt"] == None and has_printable(_input): else False if res["encrypt"] == None and has_printable(_output) else None

    elif "crypt" in res["method_name"].lower() and len(crypt["ret"]) > 5:
        _output = crypt["ret"]
        res["3rd"] = True
        arg = []
        if "encrypt" in res["method_name"].lower():
            res["encrypt"] = True
        else:
            res["encrypt"] = False
        for _arg in crypt["args"]:
            arg.append(base64.b64decode(_arg))
        if len(arg) == 1:
            # return None
            _input = arg[0]
        if len(arg) == 2:
            # return None
            _arg_0 = set()
            _arg_1 = set()
            [(_arg_0.add(_c["args"][0]), _arg_1.add(_c["args"][1])) for _c in crypts if res["class_name"] ==
             _c["class_name"] and res["method_name"] == _c["method_name"] and len(_c["args"]) == 2]
            if len(_arg_0) > len(_arg_1):
                _input = arg[0]
                res["key"] = arg[1]
            elif len(_arg_0) < len(_arg_1):
                _input = arg[1]
                res["key"] = arg[0]
            elif (((len(arg[1]) in (16, 24, 32) or (mayBase64(arg[1]) and len(base64.b64decode(arg[1])) in (16, 24, 32))) and "rsa" not in res["method_name"].lower()) or ((len(arg[1]) == 8 or (mayBase64(arg[1]) and len(base64.b64decode(arg[1])) == 8)) and "des" in res["method_name"].lower())):
                _input = arg[0]
                res["key"] = arg[1]
            elif (((len(arg[0]) in (16, 24, 32) or (mayBase64(arg[0]) and len(base64.b64decode(arg[0])) in (16, 24, 32))) and "rsa" not in res["method_name"].lower()) or ((len(arg[0]) == 8 or (mayBase64(arg[0]) and len(base64.b64decode(arg[0])) == 8)) and "des" in res["method_name"].lower())):
                _input = arg[1]
                res["key"] = arg[0]
            elif len(arg[0]) > 32 and len(arg[0]) > len(arg[1]):
                _input = arg[0]
                res["key"] = arg[1]
            elif len(arg[1]) > 32 and len(arg[1]) > len(arg[0]):
                _input = arg[1]
                res["key"] = arg[0]
            else:
                _input = arg[0]
                res["key"] = arg[1]
        if len(arg) == 3:
            _arg_0 = set()
            _arg_1 = set()
            _arg_2 = set()
            [(_arg_0.add(_c["args"][0]), _arg_1.add(_c["args"][1]), _arg_2.add(_c["args"][2])) for _c in crypts if res["class_name"] ==
             _c["class_name"] and res["method_name"] == _c["method_name"] and len(_c["args"]) == 3]
            if ((len(arg[1]) in (16, 24, 32) and (len(arg[0]) in (16, 24, 32)) and "rsa" not in res["method_name"].lower()) or (mayBase64(arg[1]) and mayBase64(arg[0]) and len(base64.b64decode(arg[1])) in (16, 24, 32) and len(base64.b64decode(arg[0])) in (16, 24, 32))):
                _input = arg[2]
                res["key"] = arg[1]
                res["iv"] = arg[0]
            elif ((len(arg[1]) in (16, 24, 32) and (len(arg[2]) in (16, 24, 32)) and "rsa" not in res["method_name"].lower())) or (mayBase64(arg[1]) and mayBase64(arg[2]) and len(base64.b64decode(arg[1])) in (16, 24, 32) and len(base64.b64decode(arg[2])) in (16, 24, 32)):
                _input = arg[0]
                res["key"] = arg[1]
                res["iv"] = arg[2]
            elif ((len(arg[2]) in (16, 24, 32) and (len(arg[0]) in (16, 24, 32)) and "rsa" not in res["method_name"].lower()) or (mayBase64(arg[2]) and mayBase64(arg[0]) and len(base64.b64decode(arg[2])) in (16, 24, 32) and len(base64.b64decode(arg[0])) in (16, 24, 32))):
                _input = arg[1]
                res["key"] = arg[2]
                res["iv"] = arg[0]
            elif ((len(arg[0]) in (16, 24, 32) and "rsa" not in res["method_name"].lower()) or (mayBase64(arg[0]) and len(base64.b64decode(arg[0])) in (16, 24, 32))):
                if len(arg[1]) > 32 and len(arg[1]) > len(arg[2]):
                    _input = arg[1]
                    res["key"] = arg[0]
                elif len(arg[2]) > 32 and len(arg[2]) > len(arg[1]):
                    _input = arg[2]
                    res["key"] = arg[0]
            elif ((len(arg[1]) in (16, 24, 32) and "rsa" not in res["method_name"].lower()) or (mayBase64(arg[1]) and len(base64.b64decode(arg[1])) in (16, 24, 32))):
                if len(arg[0]) > 32 and len(arg[0]) > len(arg[2]):
                    _input = arg[0]
                    res["key"] = arg[1]
                elif len(arg[2]) > 32 and len(arg[2]) > len(arg[0]):
                    _input = arg[2]
                    res["key"] = arg[1]
            elif ((len(arg[2]) in (16, 24, 32) and "rsa" not in res["method_name"].lower()) or (mayBase64(arg[2]) and len(base64.b64decode(arg[2])) in (16, 24, 32))):
                if len(arg[1]) > 32 and len(arg[1]) > len(arg[0]):
                    _input = arg[1]
                    res["key"] = arg[2]
                elif len(arg[0]) > 32 and len(arg[0]) > len(arg[1]):
                    _input = arg[0]
                    res["key"] = arg[2]
        if mayBase64(res["key"]) and res["key"][:-1] == '\n':
            res["key"] = res["key"].rstrip()
        if mayBase64(res["iv"]) and res["iv"][:-1] == '\n':
            res["iv"] = res["iv"].rstrip()
        if mayBase64(_input) and _input[:-1] == '\n':
            _input = _input.rstrip()
        _output = crypt["ret"].rstrip() if mayBase64(
            crypt["ret"]) and crypt["ret"][:-1] == '\n' else crypt["ret"]
        # if print(res["key"]) and res["key"][:-1]=='\n':
    if res["encrypt"] == True:
        res["plaintext"] = _input
        res["ciphertext"] = _output
    else:
        res["plaintext"] = _output
        res["ciphertext"] = _input
    if _input and _output and len(_input) > 7 and len(_output) > 7 and not (all(c == 0 for c in _input) or all(c == 0 for c in _output)):
        return res
    else:
        return None


def report(full_path, data, infix, base_path="./"):
    # print(infix)
    app = full_path.split(
        "/")[-2] if full_path.endswith("/") else full_path.split("/")[-1]
    path = base_path+"/"+''.join(str(e)+"/" for e in (full_path.split(
        "/")[:-2] if full_path.endswith("/") else full_path.split("/")[:-1]))+"/"
    if not os.path.exists(path+app+"/"+app+"-"+infix+".pcap"):
        return

    print("+++{}+++".format(app))
    cryptApi = list()
    packets = dict()
    # whole_files = dict()
    # files_buffer = dict()
    non_http_packets = list()
    normal_http = list()
    normal_https = list()
    non_http_crypt = list()
    http_crypt = list()
    https_crypt = list()
    # files_buffer_crypt = list()
    # whole_files_crypt = list()
    used_keys = list()
    # <start of cryptographic function analysis
    if os.path.exists(path+app+"/crypt-1"+"-"+infix+".txt"):
        crypt_1 = [json.loads(line.strip())
                   for line in open(path+app+"/crypt-1"+"-"+infix+".txt", "r").readlines()]
        crypts_1 = list()
        keys_1 = list()
        for c in crypt_1:
            if c['method_name'] in ("init-key", "init-cert"):
                keys_1.append(c)
            else:
                crypts_1.append(c)
        crypts_1 = sorted(crypts_1, key=lambda i: i['ts'])
        keys_1 = sorted(keys_1, key=lambda i: i['ts'])
        cryptApi += [i for i in [cryptoAPI(item, crypts_1, keys_1, 1)
                                 for item in crypts_1] if i != None]

    if os.path.exists(path+app+"/crypt-2"+"-"+infix+".txt"):
        crypt_2 = [json.loads(line.strip())
                   for line in open(path+app+"/crypt-2"+"-"+infix+".txt", "r").readlines()]
        crypts_2 = list()
        keys_2 = list()
        for c in crypt_2:
            if c['method_name'] in ("init-key", "init-cert"):
                keys_2.append(c)
            else:
                crypts_2.append(c)
        crypts_2 = sorted(crypts_2, key=lambda i: i['ts'])
        keys_2 = sorted(keys_2, key=lambda i: i['ts'])
        cryptApi += [i for i in [cryptoAPI(item, crypts_2, keys_2, 2)
                                 for item in crypts_2] if i != None]
    _tmp_2_cryptApi = []
    for d in cryptApi:
        if len(_tmp_2_cryptApi) == 0:
            _tmp_2_cryptApi.append(d)
            continue
        _dc = d.copy()
        del _dc["ts"]
        for _d in _tmp_2_cryptApi:
            __dc = _d.copy()
            del __dc["ts"]
            if __dc == _dc:
                break
        else:
            _tmp_2_cryptApi.append(d)
    print(app+": "+str(len(cryptApi))+"->"+str(len(_tmp_2_cryptApi)))
    cryptApi = _tmp_2_cryptApi
    newcryptApi = []
    for crypt_outter in cryptApi:
        if partof(crypt_outter["ciphertext"], crypt_outter["plaintext"]) or (crypt_outter["algorithm"] == None and crypt_outter["3rd"] == False):
            continue
        for crypt_inner in cryptApi:
            if (crypt_inner["ciphertext"] == crypt_outter["plaintext"] or crypt_inner["ciphertext"] == extract(crypt_outter["plaintext"])) and crypt_inner["3rd"] == False and crypt_inner["plaintext"] != crypt_outter["ciphertext"] and crypt_inner["encrypt"] == crypt_outter["encrypt"] and not all(0 == char for char in crypt_inner["plaintext"]) and crypt_inner["stage"] == crypt_outter["stage"] and not (crypt_inner["algorithm"] == None and crypt_inner["3rd"] == False):

                nestedApi = [(incApi, ncApi) for incApi, ncApi in enumerate(
                    newcryptApi) if ncApi["ciphertext"] == crypt_outter["ciphertext"] and ncApi["ts"] == crypt_outter["ts"]]
                # print(crypt_inner)
                # print("-------")
                # print(crypt_outter)
                # print("+++++++")
                if len(nestedApi) == 0:
                    tmp_crypt = crypt_outter.copy()
                    tmp_crypt["algorithm"] = b"nested"
                    tmp_crypt["iv"] = b"nested"
                    tmp_crypt["key"] = b"nested"
                    tmp_crypt["nested"] = [crypt_outter, crypt_inner]
                    tmp_crypt["plaintext"] = crypt_inner["plaintext"]
                    newcryptApi.append(tmp_crypt)
                else:
                    incApi, ncApi = nestedApi[0]
                    ncApi["nested"].append(crypt_inner)
                    ncApi["plaintext"] = crypt_inner["plaintext"]
                    newcryptApi[incApi] = ncApi

    cryptApi += newcryptApi
    # print(newcryptApi)
    # if os.path.exists(path+app+"/fs-1.txt"):
    #     fs_1 = [json.loads(line.strip())
    #             for line in open(path+app+"/fs-1.txt", "r").readlines()]
    #     for fs in fs_1:
    #         if fs["function"] == "write" and "1-"+str(fs["fd"])+"-"+fs["path"] not in files_buffer:
    #             _buffer = bytes()
    #             for _fs in fs_1:
    #                 if _fs["function"] == "write" and fs["fd"] == _fs["fd"] and fs["path"] == _fs["path"]:
    #                     _buffer += base64.b64decode(_fs["data"])

    #             files_buffer["1-"+str(fs["fd"])+"-"+fs["path"]] = _buffer

    # if os.path.exists(path+app+"/fs-2.txt"):
    #     fs_1 = [json.loads(line.strip())
    #             for line in open(path+app+"/fs-2.txt", "r").readlines()]
    #     for fs in fs_1:
    #         if fs["function"] == "write" and "2-"+str(fs["fd"])+"-"+fs["path"] not in files_buffer:
    #             _buffer = bytes()
    #             for _fs in fs_1:
    #                 if _fs["function"] == "write" and fs["fd"] == _fs["fd"] and fs["path"] == _fs["path"]:
    #                     _buffer += base64.b64decode(_fs["data"])

    #             files_buffer["2-"+str(fs["fd"])+"-"+fs["path"]] = _buffer

    # for root, _dirs, dump_files in os.walk(path+app+"/files-1"):
    #     for name in dump_files:
    #         file_path = os.path.join(root, name)
    #         with open(file_path, "rb") as f:
    #             whole_files[file_path[len(path+app):]] = f.read()

    # for root, _dirs, dump_files in os.walk(path+app+"/files-2"):
    #     for name in dump_files:
    #         file_path = os.path.join(root, name)
    #         with open(file_path, "rb") as f:
    #             whole_files[file_path[len(path+app):]] = f.read()

    # result = [os.path.join(dp, f) for dp, dn, filenames in os.walk(PATH) for f in filenames if os.path.splitext(f)[1] == '.txt']
    # <start non-http
    for addr, packet in packets.items():
        if addr.lower().startswith("udp"):
            # skip QUIC and DNS
            if addr.endswith(":443") or addr.endswith(":53"):
                continue
        elif addr.lower().startswith("tcp"):
            if any((addr.endswith(h) for h in ("192.168.180.62:8080"))):
                continue

        try:
            dpkt.http.Request(packet[0])
            # print(addr)
            # print(packet[0])
        except:
            try:
                dpkt.ssl.TLS(packet[0])
            except:
                for p in packet:
                    non_http_packets.append((addr, p))
            else:
                continue
        else:
            continue

    # end non-http>
    # <start http
    if os.path.exists(path+app+"/mitmdump"+"-"+infix+""):
        freader = io.FlowReader(open(path+app+"/mitmdump"+"-"+infix+"", "rb"))
        try:
            for request in freader.stream():
                if type(request) == tcp.TCPFlow or any((request.request.host.endswith(h) for h in ("googleadservices.com", "googleusercontent.com", "googlesyndication.com googlevideo.com", "google-analytics.com", "google.com", "googleapis.com", "gvt1.com", "doubleclick.net", "googletagservices.com", "googlesyndication.com", "googletagmanager.com", "googlevideo.com", "google.ca", "google.ru", "3gppnetwork.org", "gstatic.com", "youtube.com", "googlezip.net", "app-measurement.com", "gvt1.com", "gvt2.com"))):
                    continue
                if request.request.path.endswith(".js") and request.response != None and "content-type" in request.response.headers and request.response.headers["content-type"] == "text/javascript":
                    continue
                if request.request.method == "CONNECT":
                    continue
                tmp_res = {
                    "host": request.request.host}
                tmp_req = {"req_headers": request.request.headers,
                           "host": request.request.host,
                           "path": request.request.path,
                           "ws": [((m.content.encode('utf-8')+(b">" if m.from_client else b"<")) if type(m.content) == str else (m.content+(b">" if m.from_client else b"<"))) for m in request.websocket.messages if len(m.content) >= 1] if (request.websocket != None and len(request.websocket.messages) > 1) else []}
                if request.response is not None:
                    tmp_res["res_headers"] = request.response.headers
                    if request.response.raw_content is not None and "content-type" in request.response.headers and not (request.response.headers["content-type"] in ("image/png", "image/jpeg", "image/webp", "text/css", "image/gif", "application/zip", "image/x-icon", "JPG", "audio/mpeg", "video/mpeg") and len(request.response.raw_content) > 4*1024):
                        tmp_res["res_raw"] = request.response.raw_content
                if request.request is not None and request.request.raw_content is not None:
                    tmp_req["req_raw"] = request.request.raw_content
                if request.request.scheme == "http":
                    normal_http.append(tmp_res)
                    normal_http.append(tmp_req)
                else:
                    normal_https.append(tmp_res)
                    normal_https.append(tmp_req)
        except:
            pass
    # end http>
    for crypt in cryptApi:
        ciphertext = extract(crypt["ciphertext"])
        for addr, _data in non_http_packets:
            if chr(_data[-1]) == '>' and crypt["encrypt"]:
                if partof(ciphertext, _data):
                    non_http_crypt.append(((addr, _data), crypt))
                    used_keys.append(crypt)
            elif chr(_data[-1]) == '<' and crypt["encrypt"] == False:
                if partof(ciphertext, _data):
                    non_http_crypt.append(((addr, _data), crypt))
                    used_keys.append(crypt)

        for m in normal_http:
            for k, v in m.items():
                if k == "ws" and v:
                    for ws in v:
                        if partof(ciphertext, ws):
                            _m = m.copy()
                            _m["direction"] = bytes([ws[-1]])
                            _m["target"] = k
                            _m["meta"] = "W->"
                            http_crypt.append((_m, crypt))
                            used_keys.append(crypt)
                            # print(path+app)
                            # print("zzz")
                else:
                    #                     print(bytes(request.request.headers))
                    # print(type(request.request.headers))
                    if k in ("req_headers", "res_headers"):
                        for ii, vv in v.items():
                            if partof(ciphertext, vv):
                                __raw_data_item = m.copy()
                                __raw_data_item["target"] = k
                                __raw_data_item["meta"] = "H->"+ii.lower()
                                http_crypt.append((__raw_data_item, crypt))
                                # print(__raw_data_item)
                                used_keys.append(crypt)
                                # pass
                            # __raw_data_item["data"] = vv.encode()
                            # raw_data.append(_raw_data_item)
                        continue
                    if partof(ciphertext, v):
                        _m = m.copy()
                        _m["target"] = k
                        http_crypt.append((_m, crypt))
                        used_keys.append(crypt)

        for m in normal_https:
            # if "nested" in crypt:
            #     if b"PUBLIC" in crypt["plaintext"]:
            #         print(crypt)
            # print(base64.b64encode(ciphertext))
            for k, v in m.items():
                if k == "ws" and v:
                    for ws in v:
                        if partof(ciphertext, ws):
                            _m = m.copy()
                            _m["direction"] = bytes([ws[-1]])
                            _m["target"] = k
                            _m["meta"] = "W->"
                            https_crypt.append((_m, crypt))
                            used_keys.append(crypt)
                            # print((_m, crypt))
                            # print(path+app)
                            print("zzz")
                else:
                    if k in ("req_headers", "res_headers"):
                        for ii, vv in v.items():
                            if partof(ciphertext, vv):
                                __raw_data_item = m.copy()
                                __raw_data_item["target"] = k
                                __raw_data_item["meta"] = "H->"+ii.lower()
                                http_crypt.append((__raw_data_item, crypt))
                                used_keys.append(crypt)
                        continue
                    if partof(ciphertext, v, k):
                        _m = m.copy()
                        _m["target"] = k
                        https_crypt.append((_m, crypt))
                        used_keys.append(crypt)
        # sss
        # for fb_path, fb_content in files_buffer.items():
        #     if partof(ciphertext, fb_content):
        #         files_buffer_crypt.append(((fb_path, fb_content), crypt))
        #         used_keys.append(crypt)

        # for fb_path, fb_content in whole_files.items():
        #     if partof(ciphertext, fb_content):
        #         whole_files_crypt.append(((fb_path, fb_content), crypt))
        #         used_keys.append(crypt)

    for fname in ("non_http"+"-"+infix+".crypt", "http"+"-"+infix+".crypt", "https"+"-"+infix+".crypt", "everything"+"-"+infix+".crypt"):
        fullname = path+app+"/"+fname
        if os.path.exists(fullname):
            remove(fullname)
    raw_crypt_file = dict()

    if cryptApi:
        dst_folder = path+app+"/everything"+"-"+infix+".crypt"
        os.makedirs(dst_folder)
        crypt_file_details = []
        for _i, crypt in enumerate(cryptApi):
            plaintext = extract(crypt["plaintext"])
            # try:
            _path = str(crypt["stage"])+("-e-" if crypt["encrypt"] else "-d-")+(
                "nested-" if "nested" in crypt else "normal-")+str(crypt["ts"])+"-"+str(_i)
            # except:
            #     print(app)
            #     continue
            f_path = dst_folder+"/"+_path
            with open(f_path, "ab") as n_c:
                n_c.write(plaintext)
            crypt_file_details.append("{path}@{stage}:{algorithm}:{key}:{iv}:{thrid_party}~{addr}".format(path=_path, stage=crypt["stage"], algorithm=(crypt["algorithm"] if crypt["algorithm"] else ""), key=(
                base64.b64encode(crypt["key"]).decode("utf-8") if crypt["key"] else ""), iv=(base64.b64encode(crypt["iv"]).decode("utf-8") if crypt["iv"] else ""), thrid_party=("3rd" if crypt["3rd"] else "java"), addr="Unknown"))
        raw_crypt_file["everything"] = crypt_file_details

    if non_http_crypt:
        dst_folder = path+app+"/non_http"+"-"+infix+".crypt"
        os.makedirs(dst_folder)
        crypt_file_details = []
        for _i, ((_addr, _data), c) in enumerate(non_http_crypt):
            plaintext = extract(c["plaintext"])
            _path = str(c["stage"])+("-e-" if c["encrypt"] else "-d-") + \
                ("nested-" if "nested" in crypt else "normal-") + \
                str(c["ts"])+"-"+str(_i)
            f_path = dst_folder+"/"+_path
            with open(f_path, "ab") as n_c:
                n_c.write(plaintext)
            crypt_file_details.append("{path}@{stage}:{algorithm}:{key}:{iv}:{thrid_party}{direction}{addr}".format(path=_path, stage=c["stage"], algorithm=(c["algorithm"] if c["algorithm"] else ""), key=(
                base64.b64encode(c["key"]).decode("utf-8") if c["key"] else ""), iv=(base64.b64encode(c["iv"]).decode("utf-8") if c["iv"] else ""), thrid_party=("3rd" if c["3rd"] else "java"), direction=chr(_data[-1]), addr=_addr))
        raw_crypt_file["non_http"] = crypt_file_details

    if http_crypt:
        dst_folder = path+app+"/http"+"-"+infix+".crypt"
        os.makedirs(dst_folder)
        crypt_file_details = []
        for _i, (m, c) in enumerate(http_crypt):
            plaintext = extract(c["plaintext"])
            _path = str(c["stage"])+("-e-" if c["encrypt"] else "-d-") + \
                ("nested-" if "nested" in crypt else "normal-") + \
                str(c["ts"])+"-"+str(_i)
            f_path = dst_folder+"/"+_path
            with open(f_path, "ab") as n_c:
                n_c.write(plaintext)
            crypt_file_details.append("{path}@{stage}:{algorithm}:{key}:{iv}:{thrid_party}{direction}{addr}".format(path=_path, stage=c["stage"], algorithm=(c["algorithm"] if c["algorithm"] else ""), key=(
                base64.b64encode(c["key"]).decode("utf-8") if c["key"] else ""), iv=(base64.b64encode(c["iv"]).decode("utf-8") if c["iv"] else ""), thrid_party=("3rd" if c["3rd"] else "java"), addr=(m["host"] if type(m["host"]) == str else m["host"].decode()), direction=m["direction"] if "direction" in m else (
                ">" if "path" in m else "<")))
        raw_crypt_file["http"] = crypt_file_details

    if https_crypt:
        dst_folder = path+app+"/https"+"-"+infix+".crypt"
        os.makedirs(dst_folder)
        crypt_file_details = []
        for _i, (m, c) in enumerate(https_crypt):
            plaintext = extract(c["plaintext"])
            _path = str(c["stage"])+("-e-" if c["encrypt"] else "-d-") + \
                ("nested-" if "nested" in c else "normal-") + \
                str(c["ts"])+"-"+str(_i)
            f_path = dst_folder+"/"+_path
            with open(f_path, "ab") as n_c:
                n_c.write(plaintext)
            crypt_file_details.append("{path}@{stage}:{algorithm}:{key}:{iv}:{thrid_party}{direction}{addr}".format(path=_path, stage=c["stage"], algorithm=(c["algorithm"] if c["algorithm"] else ""), key=(
                base64.b64encode(c["key"]).decode("utf-8") if c["key"] else ""), iv=(base64.b64encode(c["iv"]).decode("utf-8") if c["iv"] else ""), thrid_party=("3rd" if c["3rd"] else "java"), addr=(m["host"] if type(m["host"]) == str else m["host"].decode()), direction=(">" if "path" in m else "<")))
        raw_crypt_file["https"] = crypt_file_details

    # if whole_files_crypt:
    #     dst_folder = path+app+"/whole_files.crypt"
    #     os.makedirs(dst_folder)
    #     crypt_file_details = []
    #     for _i, ((addr,_), c) in enumerate(whole_files_crypt):
    #         plaintext = extract(c["plaintext"])
    #         _path = str(c["stage"])+("-e-" if c["encrypt"] else "-d-")+("nested-" if "nested" in crypt else "normal-")+str(c["ts"])+"-"+str(_i)
    #         f_path = dst_folder+"/"+_path
    #         with open(f_path, "ab") as n_c:
    #             n_c.write(plaintext)
    #         crypt_file_details.append("{path}@{stage}:{algorithm}:{key}:{iv}:{thrid_party}{direction}{addr}".format(path=_path,stage=c["stage"], algorithm=(c["algorithm"] if c["algorithm"] else ""), key=(
    #             base64.b64encode(c["key"]).decode("utf-8") if c["key"] else ""), iv=(base64.b64encode(c["iv"]).decode("utf-8") if c["iv"] else ""), thrid_party=("3rd" if c["3rd"] else "java"),addr = addr,direction = ">"))
    #         raw_crypt_file["whole_files"] = crypt_file_details

    # if files_buffer_crypt:
    #     dst_folder = path+app+"/files_buffer.crypt"
    #     os.makedirs(dst_folder)
    #     crypt_file_details = []
    #     for _i, ((addr,_), c) in enumerate(files_buffer_crypt):
    #         plaintext = extract(c["plaintext"])
    #         _path = str(c["stage"])+("-e-" if c["encrypt"] else "-d-")+("nested-" if "nested" in crypt else "normal-")+str(c["ts"])+"-"+str(_i)
    #         f_path = dst_folder+"/"+_path
    #         with open(f_path, "ab") as n_c:
    #             n_c.write(plaintext)
    #         crypt_file_details.append("{path}@{stage}:{algorithm}:{key}:{iv}:{thrid_party}{direction}{addr}".format(path=_path,stage=c["stage"], algorithm=(c["algorithm"] if c["algorithm"] else ""), key=(
    #             base64.b64encode(c["key"]).decode("utf-8") if c["key"] else ""), iv=(base64.b64encode(c["iv"]).decode("utf-8") if c["iv"] else ""), thrid_party=("3rd" if c["3rd"] else "java"),addr = addr,direction = ">"))
    #         raw_crypt_file["files_buffer"] = crypt_file_details

    # if os.path.getsize(fullname) == 0:
    hardcode_keys = hardcode_key_finder(path+app, used_keys)
    result = dict()
    formed_data = transformer(data, path+app, infix)
    result["hardcode_keys"] = hardcode_keys
    result["http"] = finder(formed_data, normal_http,
                            used_keys, CT.http, path+app)
    result["https"] = finder(formed_data, normal_https,
                             used_keys, CT.https, path+app)
    # result["file"] = finder(formed_data, [whole_files],
    #                         used_keys, CT.whole_file, path+app)
    # result["file_buffer"] = finder(
    #     formed_data, [files_buffer], used_keys, CT.file_buffer, path+app)
    result["non_http_packets"] = finder(
        formed_data, non_http_packets, used_keys, CT.non_http, path+app)
    result["http_crypt"] = finder(
        formed_data, http_crypt, used_keys, CT.http_crypt, path+app)
    result["https_crypt"] = finder(
        formed_data, https_crypt, used_keys, CT.https_crypt, path+app)
    # result["file_crypt"] = finder(
    #     formed_data, whole_files_crypt, used_keys, CT.whole_file_crypt, path+app)
    # result["file_buffer_crypt"] = finder(
    #     formed_data, files_buffer_crypt, used_keys, CT.file_buffer_crypt, path+app)
    result["non_http_crypt"] = finder(
        formed_data, non_http_crypt, used_keys, CT.non_http_crypt, path+app)
    final_result = {k: list(v) for k, v in result.items() if v != set()}
    final_result["package"] = app
    with open(path+app+'/leak'+"-"+infix+'.json', 'w') as outfile:
        json.dump(final_result, outfile, indent=4)
    with open(path+app+'/raw_crypt'+"-"+infix+'.json', 'w') as rcoutfile:
        json.dump(raw_crypt_file, rcoutfile, indent=4)

    # print(final_result)
# com.commsource.beautyplus
    print("---{}---".format(app))


def apk_search(data):
    input_zip = ZipFile(oio.BytesIO(data))
    zip = bytes()
    for name in input_zip.namelist():
        skip_list = ("bmp", "gif", "jpg", "jpeg", "png", "psd", "tif", "tiff", "svg", "webp", "3gp", "avi", "flv", "m4p", "m4v", "mkv", "mov", "mp4", "mpeg",
                     "mpg", "ogg", "ogv", "srt", "webm", "wmv", "aac", "flac", "m3u", "m4a", "mp3", "wav", "wma", "doc", "docx", "odt", "pdf", "rtf", "_metadata")
        if name.endswith(skip_list):
            continue
        zip += extract(input_zip.read(name))
    return zip


def hardcode_key_finder(path, keys):
    leaks = set()
    key_list = set()
    if len(keys) == 0:
        return leaks
    for crypt in keys:
        if crypt["key"] != None and len(crypt["key"]) > 2:
            key_list.add(("key", crypt["key"]))
        if crypt["iv"] != None and len(crypt["iv"]) > 2 and not all(0 == char for char in crypt["iv"]):
            key_list.add(("iv", crypt["iv"]))
    apks = bytes()
    for f in os.listdir(path):
        if f.endswith('.apk'):
            with open(path+"/"+f, "rb") as file:
                # apks += zip_extract(file.read(), apk=True)

                input_zip = ZipFile(oio.BytesIO(file.read()))
                zip = bytes()
                for name in input_zip.namelist():
                    skip_list = ("bmp", "gif", "jpg", "jpeg", "png", "psd", "tif", "tiff", "svg", "webp", "3gp", "avi", "flv", "m4p", "m4v", "mkv", "mov", "mp4", "mpeg",
                                 "mpg", "ogg", "ogv", "srt", "webm", "wmv", "aac", "flac", "m3u", "m4a", "mp3", "wav", "wma", "doc", "docx", "odt", "pdf", "rtf", "_metadata")
                    if name.endswith(skip_list):
                        continue

                    for k, v in key_list:
                        for _encode_type, cryptographyItem in itemTransformer(v).items():
                            if cryptographyItem in extract(input_zip.read(name)):
                                leaks.add(
                                    k+"|"+base64.b64encode(v).decode("utf-8"))

    return leaks


class CT:
    http = 1
    https = 2
    whole_file = 3
    file_buffer = 4
    non_http = 5
    http_crypt = 6
    https_crypt = 7
    whole_file_crypt = 8
    file_buffer_crypt = 9
    non_http_crypt = 10


def finder(data, packets, used_keys, t, path):
    leaks = set()
    raw_data = list()
    final_raw_data = list()
    key_list = set()
    # founded_words = list()
    # <prepare raw data
    if t == CT.https or t == CT.http:
        for m in packets:
            raw_data_item = dict()
            raw_data_item["host"] = m["host"].encode(
                "utf-8") if type(m["host"]) == str else m["host"]
            raw_data_item["direction"] = b">" if "path" in m else b"<"
            for k, v in m.items():
                _raw_data_item = raw_data_item.copy()
                _raw_data_item["target"] = k
                if k == "ws" and v:
                    for ws in v:
                        __raw_data_item = _raw_data_item.copy()
                        __raw_data_item["direction"] = bytes([ws[-1]])
                        __raw_data_item["data"] = ws[:-1]
                        __raw_data_item["meta"] = "W->"
                        raw_data.append(__raw_data_item)
                else:
                    if k in ("req_headers", "res_headers"):
                        for ii, vv in v.items():
                            __raw_data_item = _raw_data_item.copy()
                            __raw_data_item["meta"] = "H->"+ii.lower()
                            __raw_data_item["data"] = vv.encode(
                                'utf-8', 'surrogateescape')
                            raw_data.append(__raw_data_item)
                        continue
                        #     print(ii)
                        # v = bytes(v)
                        # print(v)
                    _raw_data_item["data"] = v
                    raw_data.append(_raw_data_item)
    elif t == CT.http_crypt or t == CT.https_crypt:
        for m, crypt in packets:
            raw_data_item = dict()
            raw_data_item["host"] = m["host"].encode(
                "utf-8") if type(m["host"]) == str else m["host"]
            raw_data_item["direction"] = m["direction"] if "direction" in m else (
                b">" if "path" in m else b"<")
            raw_data_item["target"] = m["target"]
            raw_data_item["data"] = crypt["plaintext"]
            raw_data_item["crypt"] = crypt
            if "meta" in m:
                raw_data_item["meta"] = m["meta"]
            # print(11)
            # print(raw_data_item)
            raw_data.append(raw_data_item)
    elif t == CT.file_buffer or t == CT.whole_file:
        for _packets in packets:
            for k, v in _packets.items():
                raw_data_item = dict()
                raw_data_item["host"] = k.encode(
                    "utf-8") if type(k) == str else k
                raw_data_item["direction"] = b">"
                raw_data_item["target"] = b""
                raw_data_item["data"] = v
                raw_data.append(raw_data_item)
    elif t == CT.non_http:
        for k, v in packets:
            raw_data_item = dict()
            raw_data_item["host"] = k.encode("utf-8") if type(k) == str else k
            raw_data_item["direction"] = (
                bytes([v[-1]]) if type(v[-1]) == int else v[-1])
            raw_data_item["target"] = b""
            raw_data_item["data"] = v
            raw_data.append(raw_data_item)
    elif t == CT.file_buffer_crypt or t == CT.whole_file_crypt or t == CT.non_http_crypt:
        for (k, v), crypt in packets:
            raw_data_item = dict()
            raw_data_item["host"] = k.encode("utf-8") if type(k) == str else k
            raw_data_item["direction"] = (bytes(
                [v[-1]]) if type(v[-1]) == int else v[-1]) if t == CT.non_http_crypt else b">"
            raw_data_item["target"] = b""
            raw_data_item["data"] = crypt["plaintext"]
            raw_data_item["crypt"] = crypt
            raw_data.append(raw_data_item)
    # prepare raw data>

    if t == CT.file_buffer_crypt or t == CT.whole_file_crypt or t == CT.non_http_crypt or t == CT.http_crypt or t == CT.https_crypt:
        for crypt in used_keys:
            if crypt["key"] != None and len(crypt["key"]) > 2:
                key_list.add(("key", crypt["key"]))
            if crypt["iv"] != None and len(crypt["iv"]) > 2 and not all(0 == char for char in crypt["iv"]):
                key_list.add(("iv", crypt["iv"]))
    for f_rawd in raw_data:
        full_rawd = []
        if type(f_rawd["data"]) == list and f_rawd["target"] == "ws":
            for ws in f_rawd["data"]:
                _f_rawd = f_rawd.copy()
                _f_rawd["direction"] = bytes([ws[-1]])
                _f_rawd["data"] = ws[:-1]
                _f_rawd["meta"] = "W->"
                full_rawd.append(_f_rawd)
        else:
            full_rawd = [f_rawd]

        for rawd in full_rawd:
            extract_1 = try_extract(rawd)
            if len(extract_1) <= 1:
                final_raw_data += extract_1
            else:
                for _extract_1 in extract_1:
                    extract_2 = try_extract(_extract_1)
                    if len(extract_2) <= 1:
                        final_raw_data += extract_2
                    else:
                        for _extract_2 in extract_2:
                            final_raw_data += try_extract(_extract_2)
        # while True: wwwwwwwww
        #     ___tmp = try_extract(rawd)
        #     if len(___tmp) == 1:
        #         final_raw_data.append(___tmp)

            # ___tmp += try_extract(rawd)
        # final_raw_data.append(_rawd)

        # _rawd = rawd.copy()
        # _rawd["data"] = extract(extracted_raw_data)
        # final_raw_data.append(_rawd)
        # if b"gps_adid_attempt=1" in extracted_raw_data:
        #     print(extracted_raw_data)
        # print(extracted_raw_data)
        # print(urllib.parse.parse_qs(extracted_raw_data))
        # print(extracted_raw_data)
    tokens = set()
    for raw in final_raw_data:
        # if raw["target"] == "path":
        # print((raw["target"]))
        # try:
        extracted_raw_data = extract(raw["data"])
        extracted_raw_data = extracted_raw_data if type(
            extracted_raw_data) == bytes else extracted_raw_data.encode("utf-8")
        if len(extracted_raw_data) == 0:
            print(raw)
        # except:
        #     print(raw["data"])
        #     raise("222")
        for _type_data, coded_data in data.items():
            for name_data, value_data in coded_data.items():
                # if raw["target"] == "ws":
                #     print(raw["target"])
                #     print(extracted_raw_data)
                # print(value_data)
                for lv_data in (value_data if type(value_data) == list else [value_data]):
                    if len(lv_data) == 0:
                        # print((name_data, value_data))
                        continue
                    item_result = ""
                    if name_data.endswith("-word"):
                        if "meta" not in raw or extracted_raw_data.isdigit():
                            continue
                        meta = raw["meta"].encode("utf-8")
                        # if meta.isdigit():
                        #     continue
                        # if lv_data == b"token":
                        #     print(meta.lower())
                        #     print(base64.b64encode(extracted_raw_data))
                        #     print(t)
                        if (lv_data in meta.lower() and name_data != "password-word") or (meta.lower().endswith(b">"+lv_data) and name_data == "password-word"):
                            # if (lv_data in meta.lower()):
                            # print(extracted_raw_data)
                            # item_result = (lv_data+b"*"+base64.b64encode(meta)+b"%"+base64.b64encode(extracted_raw_data)).decode()
                            # if len(extracted_raw_data) == 0:
                            #     print("sass")
                            item_result = (
                                lv_data+b"%"+base64.b64encode(extracted_raw_data)).decode()
                            if name_data in ("token-word", "session-word", "cookie-word", "authorization-word", "secret-word", "password-word", "jwt-word"):
                                tokens.add((lv_data, extracted_raw_data))
                    elif lv_data in extracted_raw_data:
                        if name_data == 'other-wifi-bssid':
                            print(lv_data)
                            print(extracted_raw_data)
                        item_result = name_data
                    if len(item_result) > 2:
                        if "meta" in raw:
                            item_result += (b"*"+base64.b64encode(
                                raw["meta"].encode("utf-8"))).decode()
                        if "crypt" in raw:
                            crypt_details = "@{stage}:{algorithm}:{key}:{iv}:{thrid_party}".format(stage=raw["crypt"]["stage"], algorithm=(raw["crypt"]["algorithm"] if raw["crypt"]["algorithm"] else ""), key=(
                                base64.b64encode(raw["crypt"]["key"]).decode("utf-8") if raw["crypt"]["key"] else ""), iv=(base64.b64encode(raw["crypt"]["iv"]).decode("utf-8") if raw["crypt"]["iv"] else ""), thrid_party=("3rd" if raw["crypt"]["3rd"] else "java"))
                            item_result += crypt_details
                        item_result += (raw["direction"] +
                                        raw["host"]).decode("utf-8")+("/ws" if raw["target"] == "ws" else "")  # +("/"+raw["target"] if raw["target"] != "" else "").encode("utf-8")

                        # if name_data.endswith("-word"):
                        #     _founded_words = dict()
                        #     _founded_words["direction"] = "send" if raw["direction"] == b">" else "receive"
                        #     _founded_words["name"] = name_data
                        #     # _founded_words["target"] = raw["target"]
                        #     _founded_words["place"] = t
                        #     _founded_words["data"] = base64.b64encode(
                        #         extracted_raw_data).decode("utf-8")
                        #     founded_words.append(_founded_words)

                        leaks.add(item_result)
                if raw["direction"] == b">":
                    for k, v in tokens:
                        if v in extracted_raw_data:
                            item_result = (k+b"%"+base64.b64encode(v)).decode()
                            if "meta" in raw:
                                item_result += (b"*"+base64.b64encode(
                                    raw["meta"].encode("utf-8"))).decode()

                            # print(item_result)
                            if "crypt" in raw:
                                crypt_details = "@{stage}:{algorithm}:{key}:{iv}:{thrid_party}".format(stage=raw["crypt"]["stage"], algorithm=(raw["crypt"]["algorithm"] if raw["crypt"]["algorithm"] else ""), key=(
                                    base64.b64encode(raw["crypt"]["key"]).decode("utf-8") if raw["crypt"]["key"] else ""), iv=(base64.b64encode(raw["crypt"]["iv"]).decode("utf-8") if raw["crypt"]["iv"] else ""), thrid_party=("3rd" if raw["crypt"]["3rd"] else "java"))
                                item_result += crypt_details
                            item_result += (raw["direction"] +
                                            raw["host"]).decode("utf-8")+("/ws" if raw["target"] == "ws" else "")  # +("/"+raw["target"] if raw["target"] != "" else "").encode("utf-8")
                            # print(item_result)
                            leaks.add(item_result)
        for k, v in key_list:
            for _encode_type, cryptographyItem in itemTransformer(v).items():
                if cryptographyItem in extracted_raw_data:
                    key_item_result = k+"|"+base64.b64encode(v).decode("utf-8")
                    if "meta" in raw:
                        key_item_result += (b"*"+base64.b64encode(
                            raw["meta"].encode("utf-8"))).decode()

                    if "crypt" in raw:
                        crypt_details = "@{stage}:{algorithm}:{key}:{iv}:{thrid_party}".format(stage=raw["crypt"]["stage"], algorithm=(raw["crypt"]["algorithm"] if raw["crypt"]["algorithm"] else ""), key=(
                            base64.b64encode(raw["crypt"]["key"]).decode("utf-8") if raw["crypt"]["key"] else ""), iv=(base64.b64encode(raw["crypt"]["iv"]).decode("utf-8") if raw["crypt"]["iv"] else ""), thrid_party=("3rd" if raw["crypt"]["3rd"] else "java"))
                        key_item_result += crypt_details
                    key_item_result += (raw["direction"] +
                                        raw["host"]).decode("utf-8")
                    leaks.add(key_item_result)
    # if len(founded_words) > 0:
    #     with open(path+"/extracted.words".format(t), "w") as words_file:
    #         for sfounded in founded_words:
    #             json.dump(sfounded, words_file)

    return leaks


def extract_verify(v):
    try:
        if type(v) == str:
            v = v.encode("utf-8")
        if (type(v) == bytes and (len(v) <= 3 or (v.isdigit() and int(v) < 10000))) or (type(v) == int and v < 100000) or (type(v) == float and 1.1 > abs(v)):
            return False
        if (type(v) == bytes and (len(v.split(b".")) == 2 and v.lstrip(b'-').replace(b".", b"", 1).isdigit() and int(v.lstrip(b'-').split(b".")[0]) < 1)):
            return False
        if (type(v) == list and len(v) == 0) or (type(v) == bytes and v in (b"true", b"false", b"null", b"none")):
            return False
    except:
        return False
    return True


def try_extract(rawd):
    extracted_raw_data = extract(rawd["data"])
    final_raw_data = list()
    # except:
    #     print(rawd)
    if len(extracted_raw_data) < 4:
        if extract_verify(rawd["data"]):
            return [rawd]
        else:
            return []
    new_raws = []
    p = ""
    try:
        new_raws = json.loads(extracted_raw_data)
        p = "J"
    except:
        try:
            new_raws = xmltodict.parse(extracted_raw_data)
            p = "X"
        except:
            pass
            # try:
            #     new_raws = urllib.parse.parse_qs(extracted_raw_data)
            #     print(new_raws)
            #     p="U"
            # except:
            #     return [rawd]
    # print(extracted_raw_data)
    if type(new_raws) == dict and len(new_raws) > 0:
        # return [rawd]
        # if type(new_raws) == bool or type(new_raws) == type(None):
        #     return []
        # if type(new_raws) in (int,float) or (len(new_raws) > 0):
        items = dict()
        dict_extract(new_raws, items, p)
        for i in items.items():
            _rawd = rawd.copy()
            if "meta" in _rawd:
                _rawd["meta"] = _rawd["meta"]+"@"+i[0].lower()
            else:
                _rawd["meta"] = i[0].lower()
            _rawd["data"] = extract(i[1])
            if extract_verify(i[1]):
                final_raw_data.append(_rawd)
        # print(extract(i[1]))
        return final_raw_data
        # return final_raw_data
    try:
        final_raw_data.append(rawd)
        n_data = urllib.parse.parse_qs(extracted_raw_data)
        if len(n_data) > 0:
            items = dict()
            dict_extract(n_data, items, "U")
            for i in items.items():
                _rawd = rawd.copy()
                if "meta" in _rawd:
                    _rawd["meta"] = _rawd["meta"]+"@"+i[0].lower()
                else:
                    _rawd["meta"] = i[0].lower()
                _rawd["data"] = extract(i[1])
                if extract_verify(i[1]):
                    final_raw_data.append(_rawd)
                # print(_rawd["meta"])
    except:
        if "data" in rawd and extract_verify(rawd["data"]):
            return [rawd]
        else:
            return []
    return final_raw_data


def dict_extract(input, items, parent="-"):
    if type(input) == dict:
        for i in input.items():
            dict_extract(i[1], items, parent=parent+">" +
                         (i[0] if type(i[0]) == str else i[0].decode()))
        return
    if type(input) == type(None) or type(input) == bool:
        return
    if type(input) == list:
        for i, inp in enumerate(input):
            dict_extract(inp, items, parent=parent+"[{}]".format(i))
        return
    if (type(input) == str and len(input) > 3) or type(input) in (float, int):
        items[parent] = str(input).encode("utf-8")
        return items[parent]


def toHex(s):
    if type(s) == str:
        return ''.join([str('{:x}'.format(ord(o))) for o in s])
    if type(s) == bytes:
        return b''.join(['{:x}'.format(o).encode("utf-8") for o in s])


def transformer(data, path, infix):
    res = {"normal": dict(), "capitalize": dict(), "upper": dict(), "lower": dict(), "hexCapitalize": dict(), "hexUpper": dict(
    ), "hexLower": dict(), "UpperHexUpper": dict(
    ), "UpperHexLower": dict(), "urlUpper": dict(), "urlLower": dict(), "base64": dict(), "md5hex": dict(), "sha1hex": dict(), "sha256hex": dict(), "md5": dict(), "sha1": dict(), "sha256": dict()}

    for k, v in data.items():
        # if type(v) != list:
        #     print(path+"/"+v[1:]+".txt")
        #     print(path+"/"+v[1:]+"-"+infix+".txt")

        if type(v) != list and v.startswith("@") and os.path.exists(path+"/"+v[1:]+".txt"):
            # print(path+"/"+v[1:]+".txt")
            with open(path+"/"+v[1:]+".txt", 'r') as f:
                v = f.readline().strip('\n').strip()
        elif type(v) != list and v.startswith("@") and os.path.exists(path+"/"+v[1:]+"-"+infix+".txt"):
            # print(path+"/"+v[1:]+"-"+infix+".txt")
            with open(path+"/"+v[1:]+"-"+infix+".txt", 'r') as f:
                v = f.readline().strip('\n').strip()
        res["normal"][k] = [_v.encode()
                            for _v in v] if type(v) == list else v.encode()
        if not k.endswith("-word"):
            res["capitalize"][k] = [_v.capitalize().encode()
                                    for _v in v] if type(v) == list else v.capitalize().encode()
            res["upper"][k] = [_v.upper().encode()
                               for _v in v] if type(v) == list else v.upper().encode()
            res["lower"][k] = [_v.lower().encode()
                               for _v in v] if type(v) == list else v.lower().encode()
            res["hexCapitalize"][k] = [toHex(_v.capitalize()).encode() for _v in v] if type(
                v) == list else toHex(v.capitalize()).encode()
            res["hexUpper"][k] = [toHex(_v.upper()).encode() for _v in v] if type(
                v) == list else toHex(v.upper()).encode()
            res["hexLower"][k] = [toHex(_v.lower()).encode() for _v in v] if type(
                v) == list else toHex(v.lower()).encode()
            res["UpperHexUpper"][k] = [toHex(_v.upper()).upper().encode() for _v in v] if type(
                v) == list else toHex(v.upper()).encode()
            res["UpperHexLower"][k] = [toHex(_v.lower()).upper().encode() for _v in v] if type(
                v) == list else toHex(v.lower()).encode()
            res["urlUpper"][k] = [urllib.parse.quote_plus(_v.upper()).encode() for _v in v] if type(
                v) == list else urllib.parse.quote_plus(v.upper()).encode()
            res["urlLower"][k] = [urllib.parse.quote_plus(_v.lower()).encode() for _v in v] if type(
                v) == list else urllib.parse.quote_plus(v.lower()).encode()
            res["base64"][k] = [base64.b64encode(_v.encode())[:-4] for _v in v] if type(
                v) == list else base64.b64encode(v.encode())[:-4]
            res["md5hex"][k] = [hashlib.md5(_v.encode()).hexdigest().encode() for _v in v] if type(
                v) == list else hashlib.md5(v.encode()).hexdigest().encode()
            res["sha1hex"][k] = [hashlib.sha1(_v.encode()).hexdigest().encode() for _v in v] if type(
                v) == list else hashlib.sha1(v.encode()).hexdigest().encode()
            res["sha256hex"][k] = [hashlib.sha256(_v.encode()).hexdigest().encode() for _v in v] if type(
                v) == list else hashlib.sha256(v.encode()).hexdigest().encode()
            res["md5"][k] = [hashlib.md5(_v.encode()).digest() for _v in v] if type(
                v) == list else hashlib.md5(v.encode()).digest()
            res["sha1"][k] = [hashlib.sha1(_v.encode()).digest() for _v in v] if type(
                v) == list else hashlib.sha1(v.encode()).digest()
            res["sha256"][k] = [hashlib.sha256(_v.encode()).digest() for _v in v] if type(
                v) == list else hashlib.sha256(v.encode()).digest()
    return res


def itemTransformer(v):
    res = dict()

    res["normal"] = [_v
                     for _v in v] if type(v) == list else v
    res["capitalize"] = [_v.capitalize()
                         for _v in v] if type(v) == list else v.capitalize()
    res["upper"] = [_v.upper()
                    for _v in v] if type(v) == list else v.upper()
    res["lower"] = [_v.lower()
                    for _v in v] if type(v) == list else v.lower()
    res["hexUpper"] = [toHex(_v.upper()) for _v in v] if type(
        v) == list else toHex(v.upper())
    res["hexLower"] = [toHex(_v.lower()) for _v in v] if type(
        v) == list else toHex(v.lower())
    res["UpperHexUpper"] = [toHex(_v.upper()).upper() for _v in v] if type(
        v) == list else toHex(v.upper())
    res["UpperHexLower"] = [toHex(_v.lower()).upper() for _v in v] if type(
        v) == list else toHex(v.lower())
    res["urlUpper"] = [urllib.parse.quote_plus(_v.upper()).encode("utf-8") for _v in v] if type(
        v) == list else urllib.parse.quote_plus(v.upper()).encode("utf-8")
    res["urlLower"] = [urllib.parse.quote_plus(_v.lower()).encode("utf-8") for _v in v] if type(
        v) == list else urllib.parse.quote_plus(v.lower()).encode("utf-8")
    res["base64"] = [base64.b64encode(_v.encode(
    ))[:-4] for _v in v] if type(v) == list else base64.b64encode(v if type(v) == bytes else v.encode())[:-4]
    return res


def main():
    with open(sys.argv[len(sys.argv)-1], "r") as json_file:
        jdata = json.load(json_file)
    for cert_type, dynamic_analysis in list([(cert_type, dynamic_analysis) for cert_type in ["1", "2", "3", "4"] for dynamic_analysis in [True, False]]):
        infix = cert_type+"-"+str(dynamic_analysis)

        if len(sys.argv) == 3:
            print(sys.argv[1])
            report(sys.argv[1], jdata, infix)
        if len(sys.argv) == 4:
            path = sys.argv[1]+"/"
    #         with open(path+"/adid.txt") as adid_f:
    #             for adid_item in adid_f.readlines():
    #                 adid.append(adid_item.rstrip())
    #                 adid.append(adid_item.rstrip().replace('-', ''))
    #         jdata["adid"] = adid
    # #        print(jdata["adid"])
            apps = [app for app in os.listdir(
                path) if (os.path.exists(path+app+"/"+app+"-"+infix+".pcap") and (True if sys.argv[2] == "y" else not os.path.exists(path+app+"/leak-"+infix+".json")))]
            pool = multiprocessing.Pool(400)
            # pool = multiprocessing.Pool(multiprocessing.cpu_count())
            print(1)
            M = pool.starmap(report, zip(
                apps, repeat(jdata),repeat(infix), repeat(path)))
# def report(full_path, data, infix, base_path="./"):


if __name__ == "__main__":
    main()
