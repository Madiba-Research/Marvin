import urllib.request
import lxml.html
import os
import shutil
import sys
from multiprocessing import Pool
import re

out = sys.argv[1]

def d(f):
    pkg = f.split(".fail")[0]
    r_dir = out+"/"+pkg+"/"
    if os.path.isdir(r_dir):
        return
    headers = {'User-Agent': 'Mozilla/5.0'}
    print(pkg)
    try:
        req = urllib.request.Request(
            'https://m.apkpure.com/o/{}/download?from=details'.format(pkg), None, headers)
        html = urllib.request.urlopen(req).read()
        # print(html)
        doc = lxml.html.fromstring(html)
        d_path = doc.xpath('//html/body/div["page-q"]/div/iframe/@src')[0]
        d_req = urllib.request.Request(d_path, None, headers)
        with urllib.request.urlopen(d_req) as response:
            file_name = response.info().get_filename()
            file_name = pkg+".xapk" if file_name.endswith(".xapk") else "base.apk"
    except:
        try:
            req = urllib.request.Request(
                'https://apktada.com/download-apk/{}'.format(pkg), None, headers)
            html = urllib.request.urlopen(req).read()
            doc = lxml.html.fromstring(html)
            d_path = doc.xpath('//html/body/div/div[@class="container"]/div[@class="main"]/div[@class="row"]/*//p/a/@href')[0]
            d_req = urllib.request.Request(d_path, None, headers)
            with urllib.request.urlopen(d_req) as response:
                file_name = response.info().get_filename()
                file_name = pkg+".xapk" if file_name.endswith(".xapk") else "base.apk"
        except:
            return
    current_dir = os.getcwd()
    if not os.path.isdir(r_dir):
        os.mkdir(r_dir)
        os.system("aria2c -x8 '{}' -d {} -o {}".format(d_path, r_dir,file_name))
        if file_name.endswith(".xapk") or file_name.endswith(".zip"):
            os.chdir(r_dir)
            os.system("7z x -aoa '{}'".format(file_name))
            if os.path.isdir("Android/obb/{}".format(pkg)):
                os.system("mv Android/obb/{}/* .".format(pkg))
                shutil.rmtree("Android")
            if file_name.endswith(".xapk"):
                os.rename(pkg+".apk", "base.apk")
            else:
                os.rename(re.sub('zip$', 'apk', file_name), "base.apk")
            os.remove(file_name)
            if os.path.isdir("icon.png"):
                os.remove("icon.png")
            if os.path.isdir("manifest.json"):
                os.remove("manifest.json")
            if os.path.isdir("How-to-install.txt"):
                os.remove("How-to-install.txt")
            os.chdir(current_dir)
        print(file_name)

            # content = response.read().decode('utf-8')
if __name__ == '__main__':
    #files = [file for file in os.listdir(out) if file.endswith(".fail")]
    with open('packages.txt', 'r') as pf:
        files = [file.strip()+".fail" for file in pf.readlines()]
    with Pool(25) as p:
        print(p.map(d, files))

