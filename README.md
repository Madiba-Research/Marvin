# Preparation
## Update proxy addresss in ebpf and compile ebpf

1. Push ebpf-v2.tar.gz to phone
$ adb push ebpf-v2.tar.gz /sdcard/Download
$ mv /sdcard/Download/ebpf-v2.tar.gz /data/
$ cd /data
$ tar -xvf ebpf-v2.tar.gz

2. Enter debian system
$ cd /data/ebpf
$ ./run

3. enter ebpf source code directory
$ cd /root/
$ Update code in d.c, e.c file

4. Compile ebpf
$ sudo bpftool cgroup detach /sys/fs/cgroup/ connect4 pinned /sys/fs/bpf/bpf_connect4; sudo rm /sys/fs/bpf/bpf_connect4; clang -O2 -g  -Wall -target bpf -I /usr/include/aarch64-linux-gnu -c d.c -o d.o ; sudo bpftool prog load d.o /sys/fs/bpf/bpf_connect4 type cgroup/connect4;sudo bpftool cgroup attach /sys/fs/cgroup/ connect4 pinned /sys/fs/bpf/bpf_connect4

$ sudo bpftool cgroup detach /sys/fs/cgroup/ connect6 pinned /sys/fs/bpf/bpf_connect6; sudo rm /sys/fs/bpf/bpf_connect6; clang -O2 -g  -Wall -target bpf -I /usr/include/aarch64-linux-gnu -c e.c -o e.o ; sudo bpftool prog load e.o /sys/fs/bpf/bpf_connect6 type cgroup/connect6;sudo bpftool cgroup attach /sys/fs/cgroup/ connect6 pinned /sys/fs/bpf/bpf_connect6

(Optional) Change DNS address in the debian system
$ nano /etc/resolv.conf
  nameserver 192.168.173.1
  
$ adb reboot


## Apply ebpf in Android
1. Push ebpf.tar.gz to Android
   $ adb push ebpf.tar.gz /data/
   
   $ cd /data/
   
   $ tar -xvf ebpf.tar.gz

3. Put ebpf in service directory, 
   $ adb push ebpf.sh /data/adb/service.d/
   
   $ chmod +x ebpf.sh
   
   $ cat ebpf.sh
   ```
      echo 1 > /sys/kernel/tracing/tracing_on
      /data/ebpf/run-command "/usr/sbin/bpftool prog load /root/d.o /sys/fs/bpf/bpf_connect4 type cgroup/connect4"
      /data/ebpf/run-command "/usr/sbin/bpftool cgroup attach /sys/fs/cgroup/ connect4 pinned /sys/fs/bpf/bpf_connect4"
      /data/ebpf/run-command "/usr/sbin/bpftool prog load /root/e.o /sys/fs/bpf/bpf_connect6 type cgroup/connect6"
      /data/ebpf/run-command "/usr/sbin/bpftool cgroup attach /sys/fs/cgroup/ connect6 pinned /sys/fs/bpf/bpf_connect6"
    ```

    - check if ebpf working
    $ cat /sys/kernel/tracing/tracing_on    ---> value should be 1

    $ cat /sys/kernel/tracing/trace_pipe

    - Modify Proxy address in ebpf, the default proxy address is: 62.180.168.192

    - (Optional) Modify uid in ebpf, current forward traffic whose uid>10000 to the proxy


## Magisk Frida
1. Create a new Frida
   $ cd /data/adb/modules/magisk-frida
   $ cat service.sh
   ```
      #!/system/bin/sh
      # Do NOT assume where your module will be located.
      # ALWAYS use $MODDIR if you need to know where this script
      # and module is placed.
      # This will make sure your module will still work
      # if Magisk change its mount point in the future
      MODDIR=${0%/*}

      # This script will be executed in late_start service mode

      # wait for boot to complete
      while [ "$(getprop sys.boot_completed)" != 1 ]; do
         sleep 1
      done

      # ensure boot has actually completed
      sleep 5

      # restart on crash

      while true; do
         if [[ -f "/data/local/tmp/frida-enabled" ]]
         then
            frida-server &
         else
         killall frida-server
         killall frida-helper-32
         fi
         sleep 1
      done
   ```

   - add executable mode to service.sh
   $ chmod +x service.sh

   (2) Hide Root in Frida
   Magisk -> Settings -> Zygisk (Enable)

2. Install Modules In Magisk
$ Install MagiskFrida

$ Install movecert-1.9

$ Install pixel-update-disabler

$ Install ccbins


## Certificate
install cert.der  in the phone
   $ adb push certificate/cert.der /sdcard/Download/
   $ install it as a CA certificate

   - Install "Move Certificate" in Magisk Modules


## Other Configurations
1. set proxy in Network settings
   bypass some domains: *.googleapis.com, *.gstatic.com, *.gvt1.com, *.gvt2.com

2. Disable mitmproxy certificate in Trusted Certificates of Android

3. Set screen timeout and screenlock
   Display: Screen timeout --> After 30 minutes
   Security: screenlock --> None

4. copy all the package names into packages.txt
   $ nano packages.txt
   - All apk files should be named as base.apk

5. GPS Setting
   - install com.research.helper
     $ adb install com.research.helper
   - turn off Location in Settings
   - Enable Mock Location in Android
     [Android] Developer -> Mock Location
<!-- # change the proxy address in general.js -->

6. Hide keyboard
    - install "no keyboard app"
    - Set Transparent Keyboard
      - Setting -> System -> Languages and input -> NoKeyboard
      - Setting -> System -> Languages and input -> Gboard

7. Prepare the initial data
   $ adb pull PXL_20211123_063430617.jpg /sdcard/DCIM/
   - Add new contacts information from 6.json
   - Create text messages


8. Update values in 6.json --> Pixel 6 phone

9. Disable Play Protection
   Google Play -> Profile icon -> Play Protection -> Setting -> Off


## Automatically connect to WIFI in the presence of WIFI
$ adb shell
$ su
flame:/ # mkdir /data/crontab
flame:/ # echo '* * * * * svc wifi enable' >> /data/crontab/root
flame:/ # echo '* * * * * settings put global airplane_mode_on 0' >> /data/crontab/root
flame:/ # echo 'crond -b -c /data/crontab' > /data/adb/service.d/crond.sh
flame:/ # chmod +x /data/adb/service.d/crond.sh
settings put global captive_portal_mode 0
    

# How to run the tool
$ while true; do killall -9 mitmdump; killall -9 python3; python3 main.py; adb reboot; sleep 150; done;

$ (Optional) while true; do killall -9 mitmdump; python3 main.py && kill -9 $!; adb reboot; sleep 150; done;


# How to analyze the result
1. Run analyse script
   - For Thirdeye Project:
   $ python3 anal.py out/ n 6.json

   - For TLS Project:
   $ cd results
   $ python3 analysis.py out/ n 6-timber.json


2. Generate database
   (Optional)$ rm -f res.db
   
   $ python3 json_parser.py

   (Optional)$ while true; do echo "Start Analyze"; python3 result/analysis.py out-chn-finish n 6-timber.json; sleep 30; done;


4. Check the database
   $ sqlite3 res.db

  
5. audroguard version: 3.4.0a1

6. If you want to use wechat in the phone, you need to exclude wechat uid in ebpf (d.c, e.c) files, otherwise, wechat cannot connect to its server due to traffic forwarding to proxy in ebpf.


# Parse TLS result

$ python3 create_db.py [computer] [out_dir] [target_database]

e.g: python3 create_db.py timber ./out test.db


# Other use commands
1. skip the current phase of analysis
   $ touch skip

2. add new words to click
   [[Android]] $ uiautomator dump
