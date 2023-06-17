#!/usr/bin/env python3.9
import time
import os
os.environ['PYGAME_HIDE_SUPPORT_PROMPT']="hide"
import pygame
from time import time, sleep
from threading import *
from scapy.layers.dot11 import Dot11,Dot11Deauth, RadioTap, Dot11Disas
from scapy.sendrecv import sniff, AsyncSniffer
import sys

deauth_cnt: int = 0
disas_cnt: int = 0
data_frame_cnt: int =0
r_flag = False

num = 10000

reason_code = []

ap_mac = sys.argv[1]
client_mac = sys.argv[2]
broad_mac = sys.argv[3]
instance_num = sys.argv[4]
thread_sleep_interval = int(sys.argv[5])

iface = "wlan1"


def deauth_disassoc_callback(frame):  # counts malformed beacons
    global deauth_cnt, disas_cnt, r_flag
    if frame.haslayer(Dot11Deauth):
        deauth_cnt += 1
        dot11_layer = frame.getlayer(Dot11Deauth)
        reason_code.append(dot11_layer.reason)
    if frame.haslayer(Dot11Disas):
        disas_cnt += 1
        dot11_layer = frame.getlayer(Dot11Disas)
        reason_code.append(dot11_layer.reason)
    result = all(element == reason_code[0] for element in reason_code)
    if result:
        r_flag = True
    else:
        r_flag = False

def data_frames_callback(frame, target_mac=None, d_mac=None):
    global data_frame_cnt, disas_cnt, r_flag
    if frame.haslayer(Dot11) and frame[Dot11].subtype==40 :
        bssid=frame[Dot11].addr3
        s_mac=frame[Dot11].addr2
        d_mac = frame[Dot11].addr1
        frequency=frame[Radiotap].channel
        curr_channel = (frequency-2407)/5
        if bssid==ap_mac and (((s_mac==target_mac)or(d_mac==target_mac)) and curr_channel)==1:
            data_frame_cnt += 1


deauth_sniffer = AsyncSniffer(iface=iface, count=num, prn=deauth_disassoc_callback, store=0, monitor=True)
data_sniffer = AsyncSniffer(iface=iface, count=num, prn=data_frames_callback, store=0, monitor=True)


deauth_sniffer.start()
data_sniffer.start()

print("---------------------------------------------------------")
print(f"Probe interval number {instance_num} started")


sleep(thread_sleep_interval)

print(f"-----------Results of probe interval number {instance_num} started ----")
print("Deauth Count =", deauth_cnt)
print("Disass Count =", disas_cnt)
print("Data Frame Count =", data_frame_cnt)
print("---------------------------------------------------------")
print("                 Final Decision                          ")
print("---------------------------------------------------------")
if (deauth_cnt >= 10 and disas_cnt >= 10) and r_flag == True:        
    print("Deauthentication and Disassociation attack detected")
    print("DoS attack detected !!!!!!!!!")
    pygame.mixer.init()
    pygame.mixer.music.load("/home/pi/Desktop/Dos-attack-detection/emergency-alarm.wav")
    pygame.mixer.music.play()
    while pygame.mixer.music.get_busy() == True:
          continue    
elif (deauth_cnt >= 10) and r_flag == True:        
     print("Deauthentication attack detected")
     pygame.mixer.init()
     pygame.mixer.music.load("/home/pi/Desktop/Dos-attack-detection/emergency-alarm.wav")
     pygame.mixer.music.play()
     while pygame.mixer.music.get_busy() == True:
          continue    
elif (disas_cnt >= 10) and r_flag == True:        
     print("Disassociation attack detected")
     print("DoS attack detected !!!!!!!!!")
     pygame.mixer.init()
     pygame.mixer.music.load("/home/pi/Desktop/Dos-attack-detection/emergency-alarm.wav")
     pygame.mixer.music.play()
     while pygame.mixer.music.get_busy() == True:
          continue

else:
     print("No DoS attack found")
      
        
if ((deauth_cnt >= 10 or disas_cnt >= 10) or data_frame_cnt >=10):
#     print("DoS attack detected !!!!!!!!!")
    print("Abnormal Data Frames are detected!!!!!!!!!")
    




