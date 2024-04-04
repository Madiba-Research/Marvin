# https://androzoo.uni.lu/markets

import csv
import os
import time

from enum import Enum
from lxml import etree

import requests


EMPTY_FILE = ""

OUT_DIR = './out_anzhi/'

header = {
    'User-Agent': "Mozilla/5.0 (X11; Linux x86_64; rv:12.0) Gecko/20220101 Firefox/12.0"
}

class Category(Enum):
    SYSTEM = "sort_39_"
    PHONE = "sort_40_"
    BROWSER = "sort_41_"
    INPUT = "sort_42_"
    MUSIC = "sort_43_"
    DESKTOP = "sort_44_"
    VIDEOS = "sort_45_"
    PHOTOGRAPH = "sort_46_"
    WEATHER = "sort_47_"
    SHOPPING = "sort_48_"
    FINANCE = "sort_49_"
    COMPREHENSIVE = "sort_50_"
    COMMUNICATION = "sort_51_"
    SOCIAL = "sort_52_"
    NEWS = "sort_53_"
    OFFICE = "sort_54_"
    READ = "sort_55_"

    def __str__(self):
        return str(self.value)



# xpath: //div[contains(@class, 'app_icon')]/a//@href
# download url: href + #
class AnzhiDownloader():
    def __init__(self, cat):
        self.site = "http://www.anzhi.com"
        self.count = 0
        self.type = str(cat)
        self.out_folder = OUT_DIR + self.type
        self.total = 0
        self.initial_urls = dict()
        self.download_urls = dict()


    def download_apps(self, start, end, total):
        self.total = total
        for page in range(start, end+1):
            self.crawl_initial_urls(page)
            dl_fname = self.crawl_download_urls(page)
            self.aria2c_download(dl_fname, total)


    def crawl_initial_urls(self, page):
        print(f"[Step 1]: Crawl app names and initial urls, page={page}----")
        base = self.site + "/" + self.type + str(page) + '_hot.html'
        fname = self.out_folder + str(page) + ".csv"
        if os.path.exists(fname):
            return
        print(f"    Request {base}")
        doc = requests.get(base, headers=header).text
        tree = etree.HTML(doc)
        pkg_hrefs = tree.xpath("//div[contains(@class, 'app_icon')]/a//@href")
        for pkg_href in pkg_hrefs:
            app_name = self._get_app_name(pkg_href)
            pkg_url = self.site + pkg_href
            doc2 = requests.get(pkg_url, headers=header).text
            tree2 = etree.HTML(doc2)
            od = tree2.xpath("//div[contains(@class, 'detail_down')]//a//@onclick[starts-with(., 'opendown')]")
            id = self._extract_id(od)
            url = self.site + "/dl_app.php?s=" + id + "&n=5"
            self.initial_urls[app_name] = url
            print(f"    Get {url}")
            time.sleep(0.5)
        with open(fname, "w") as f:
            writer = csv.writer(f)
            for key in self.initial_urls:
                value = self.initial_urls[key]
                writer.writerow([key, value])
        time.sleep(5)


    def crawl_download_urls(self, page):
        print(f"[Step 2]: Crawl redirected downnload urls, page={page}----")
        fname = self.out_folder + "dl_" + str(page) + ".csv"           
        if os.path.exists(fname):
            return fname
        initial_file = self.out_folder + str(page) + ".csv"
        with open(initial_file, 'r') as f:
            reader = csv.reader(f)
            for row in reader:
                apk, url = row[0], row[1]
                print(f"    Request {url}")
                resp = requests.get(url, headers=header, allow_redirects=False)
                if resp.status_code == 302: 
                    location = resp.headers['Location']
                    self.download_urls[apk] = location
                    print(f"    Get {location}")
                    time.sleep(0.5)
        with open(fname, "w") as f:
            writer = csv.writer(f)
            for key in self.download_urls:
                value = self.download_urls[key]
                writer.writerow([key, value])
        time.sleep(5)
        return fname


    def aria2c_download(self, url_file, total):
        print("[Step 3]: aria2 to download applications ----")
        apps_dict = {}
        with open(url_file, "r") as f:
            reader = csv.reader(f)
            for line in reader:
                name, url = line[0], line[1]
                apps_dict[name] = url
        if not apps_dict:
            print("[ERROR]::The links are empty. Check the reason")
        print(apps_dict)
        for app_name in apps_dict:
            if self.count > self.total:
                print(f"Stop download,  download apps task finished.")
                return
            if self._app_not_exist(app_name):
                print(f"Start to download {app_name}, dl_url={url}")
                out = self._get_output_folder(app_name)
                os.system(f"aria2c -x8 '{url}' -d {out}" + " -o base.apk")
                self.count = self.count + 1
                print(f"Downloaded {app_name}, count: {self.count}")
                # remove additional file
                rm_file = out + "*.aria2"
                if os.path.exists(rm_file):
                    os.remove(out + "*.aria2")
                time.sleep(5)
            else:
                print(f"{app_name} has already downloaded. Stop")


    def _get_output_folder(self, app_name):
        out_dir = OUT_DIR + self.type + "/" + app_name + "/"
        return out_dir


    def _app_not_exist(self, app_name):
        app_dir = OUT_DIR + self.type + "/" + app_name
        print("****app_dir: " + app_dir)
        if os.path.exists(app_dir + "/base.apk"):
            print(f"{app_name} has been downloaded. Continue")
            return False
        if not os.path.exists(app_dir):
            print('mkdir -p ' + app_dir)
            os.system('mkdir -p ' + app_dir)
        return True
        
    def _get_app_name(self, app_icon):
        start = app_icon.find('_')
        end = app_icon.find('.html')
        app_name = app_icon[start+1: end]
        return app_name

    def _extract_id(self, od):
        id = ""
        if len(od)==1:
            od = "".join(od)
            start = od.find("(")
            end = od.find(")")
            id = od[start+1:end]
        else:
            print(f"more than 1 opendown is found: {od}")
        return id

if __name__ == '__main__':
    # cat = Category["COMPREHENSIVE"], start with 31 next
    # cat = Category["SOCIAL"]， start with 19

    cat = Category["COMMUNICATION"]
    anzhi = AnzhiDownloader(cat)
    anzhi.download_apps(5, 6, 40)
