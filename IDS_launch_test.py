#!/usr/bin/env python3.9

from subprocess import run
from time import sleep
import threading

script_path = "deauth_attack_detection_test.py"
python_command = "python3"

ap_mac = "c0:4a:00:33:3b:62"
client_mac = "70:5e:55:bc:86:0f"
broad_mac = "ff:ff:ff:ff:ff:ff"
launch_interval = 10  # launch interval in seconds after which a new instance of the script starts
thread_sleep_interval = 60  # how long is one probe interval
instances_launched = 0

while True:
    instances_launched += 1
    t = threading.Thread(target=run, args=([python_command, script_path, ap_mac, client_mac, broad_mac, str(instances_launched), str(thread_sleep_interval)],))
    t.start()
    sleep(launch_interval)
s