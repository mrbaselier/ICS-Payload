#! /usr/bin/env python3



######## COPYRIGHT ########
# Copyright 2023 Jarno Baselier. All rights reserved.
# This software may be modified and distributed under the terms
# of the "Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International (CC BY-NC-SA 4.0) license. https://creativecommons.org/licenses/by-nc-sa/4.0/.

#Based on master-file for Step7 purposes (and configured for a Siemens Logo PLC) called "ics-payload.py":
#https://github.com/mrbaselier/ICS-Payload

#Yes, in this example file I define full packets while I could consolidate the information to make the payload more compact. I have chosen readability and customization over filesize.

# WHAT DOES THIS SCRIPT DO?
# 1. Send a Profinet package with a command to blink the screen



######## IMPORTS ########
from scapy.all import *



######## SETTINGS / VARIABLES ########
source_mac = '8c:f3:19:03:e4:b3'
destination_mac = '8c:f3:19:00:a6:de'
source_port = random.randint(20000,50000)
destination_port = 102
send_interface = "Ethernet 2"



######## FUNCTIONS ########
def string_to_bytes(value):
        value = str.encode(value)
        #print(value)
        return value

def int_to_bytes_1(value):
        value = value.to_bytes(1, byteorder='big')
        #print(value)
        return value

def int_to_bytes_2(value):
        value = value.to_bytes(2, byteorder='big')
        #print(value)
        return value

def int_to_bytes_4(value):
        value = value.to_bytes(4, byteorder='big')
        #print(value)
        return value



######## PART1 - Create valid Profinet package ########
profinet_frameid = int_to_bytes_2(65277)
profinet_serviceId = int_to_bytes_1(4)
profinet_serviceType = int_to_bytes_1(0)
profinet_xid_1 = int_to_bytes_1(0)
profinet_xid_2 = int_to_bytes_1(0)
profinet_xid_3 = int_to_bytes_1(25)
profinet_xid_4 = int_to_bytes_1(18)
profinet_reserved = int_to_bytes_2(0)
profinet_dcpdatalength = int_to_bytes_2(8)
profinet_block_option_control = int_to_bytes_1(5)
profinet_block_suboption_signal = int_to_bytes_1(3)
profinet_block_dcpblocklength = int_to_bytes_2(4)
profinet_block_blockqualifier = int_to_bytes_2(0)
profinet_block_signalvalue_1 =int_to_bytes_1(1)
profinet_block_signalvalue_2 =int_to_bytes_1(0)

#Compile Raw part of Profinet package
Profinet = profinet_frameid + profinet_serviceId + profinet_serviceType + profinet_xid_1 + profinet_xid_2 + profinet_xid_3 + profinet_xid_4 + profinet_reserved + profinet_dcpdatalength + profinet_block_option_control + profinet_block_suboption_signal + profinet_block_dcpblocklength + profinet_block_blockqualifier + profinet_block_signalvalue_1 + profinet_block_signalvalue_2



######## PART2 - Define Ethernet Layer ########
l1 = Ether(dst=destination_mac,
        src=source_mac,
        type=34962
     )



######## PART3 - Construct final package (appending the Profinet bytes) and send the package ########
#Construct Package
packet = l1 / Profinet

#Show Package
packet.show2()

#Send Package
sendp(packet,iface=send_interface)