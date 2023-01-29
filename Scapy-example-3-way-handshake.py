#! /usr/bin/env python3



######## COPYRIGHT ########
# Copyright 2023 Jarno Baselier. All rights reserved.
# This software may be modified and distributed under the terms
# of the "Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International (CC BY-NC-SA 4.0) license. https://creativecommons.org/licenses/by-nc-sa/4.0/.

#Based on master-file for Step7 purposes (and configured for a Siemens Logo PLC) called "ics-payload.py":
#https://github.com/mrbaselier/ICS-Payload

#Yes, in this example file I define full packets while I could consolidate the information to make the payload more compact. I have chosen readability and customization over filesize.

# WHAT DOES THIS SCRIPT DO?
# 1. Setup a TCP connection with a valid 3-way handshake
# 2. Gracefully close the connection



######## IMPORTS ########
from scapy.all import *
import struct
import binascii
import threading
import time
import codecs



######## SETTINGS / VARIABLES ########
source_ip = '192.168.178.57'
destination_ip = '192.168.178.30'
source_port = random.randint(20000,50000)
destination_port = 102
tcp_start_seq_nr = random.randint(20000,50000)
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



######## PART1 - Start with 3-way handshake - Send SYN and await response ########
l3 = IP(#version=4,
        flags=2,
        proto=6,
        src=source_ip,
        dst=destination_ip
     )
#TCP
tcp_options = [('MSS', 1460), ('SAckOK', b''), ('Timestamp', (3840354, 0)), ('NOP', None), ('WScale', 0)]
l4 = TCP(sport=source_port,
        dport=destination_port,
        flags='S',
        options=tcp_options,
        seq=tcp_start_seq_nr
        )

SYNpacket = l3 / l4

#Show packet
#SYNpacket.show2()

#Send packet and await response
RETURNPACKET = sr1(SYNpacket)



######## PART2 - After receiving SYN/ACK, send an ACK ########
l4 = TCP(sport=source_port,
        dport=destination_port,
        flags='A',
        seq=RETURNPACKET.ack,
        ack=RETURNPACKET.seq + 1
        )

ACKpacket = l3 / l4

#Show packet
#ACKpacket.show2()

#Send packet
send(ACKpacket)



######## PART3 - Close the connection, send a FIN ########
l4 = TCP(sport=source_port,
        dport=destination_port,
        flags='F',
        seq=RETURNPACKET.ack,
        ack=RETURNPACKET.seq + 1
        )

ACKpacket = l3 / l4

#Show packet
#ACKpacket.show2()

#Send packet
RETURNPACKET = sr1(ACKpacket)



######## PART4 - Close the connection. After receiving a FIN/ACK, reply with an ACK ########
l4 = TCP(sport=source_port,
        dport=destination_port,
        flags='A',
        seq=RETURNPACKET.ack,
        ack=RETURNPACKET.seq + 1
        )

ACKpacket = l3 / l4

#Show packet
#ACKpacket.show2()

#Send packet
send(ACKpacket)