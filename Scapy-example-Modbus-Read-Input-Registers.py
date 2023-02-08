#! /usr/bin/env python3



######## COPYRIGHT ########
# Copyright 2023 Jarno Baselier. All rights reserved.
# This software may be modified and distributed under the terms
# of the "Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International (CC BY-NC-SA 4.0) license. https://creativecommons.org/licenses/by-nc-sa/4.0/.

#Based on master-file for Step7 purposes (and configured for a Siemens Logo PLC) called "ics-payload.py":
#https://github.com/mrbaselier/ICS-Payload

#Yes, in this example file I define full packets while I could consolidate the information to make the payload more compact. I have chosen readability, information and customization over filesize.

# WHAT DOES THIS SCRIPT DO?
# 1. Setup 3-way handshake
# 2. Send Modbus over TCP command
# 3. Close TCP connection



######## IMPORTS ########
from scapy.all import *
import struct
import binascii
import threading
import time
import codecs



######## SETTINGS / VARIABLES ########
#randomize ports: random.randint(20000,50000)
source_ip = '192.168.178.57' #Master: 192.168.178.132
destination_ip = '192.168.178.52'
source_port = random.randint(20000,50000)
destination_port = 502
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
#tcp_options = [("MSS" , 1460),('Timestamp', (1098453, 0)),("NOP",None),("WScale",2),("NOP",None),("NOP",None),("SAckOK","")]
tcp_options = [('MSS', 1460), ('SAckOK', b''), ('Timestamp', (3840354, 0)), ('NOP', None), ('WScale', 0)]
l4 = TCP(sport=source_port,
        dport=destination_port,
        flags='S',
        #options=tcp_options,
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


######## PART3 - Send Modbus Command  - Read Input Registers ########
#Set Modbus Transaction ID
transid = 1

#Modbus/TCP
#Transaction identifier - Stream counter - The actual use for the transaction identifier is for synchronization between messages of server and client. This function is not always implemented.
modbus_transaction_id1 = int_to_bytes_1(0)
modbus_transaction_id2 = int_to_bytes_1(transid)
#Protocol Identifier, set by the master. Will always be 0.
modbus_protocol_id = int_to_bytes_2(0)
#The number of bytes in the message that follows. It is counted from Unit Identifier to the end of the message. 
modbus_length = int_to_bytes_2(6)
#The unit ID is used when dealing with Modbus Bridges. Typical bridges convert Modbus TCP to Modbus serial or Modbus plus. The Unit ID is either the device Id of serial device or it is index number that references a Modbus plus layered address. Most traditional Modbus/TCP devices ignore the unit Id completely. This value is usually 0.
modbus_unit_identifier = int_to_bytes_1(0)
#Modbus
#1 = Read Coils - 2 = Read Discrete Inputs - 4 = Read Input Registers - 5 = Write Single Coil - 6 = Write Single Register - 7 = Read Exception Status (serial=only) - 15 = Write Multiple Coils - 16 = Write Multiple Registers - 20 = Read File Record - 21 = Write File Record - 22 = Mask Write Register - 23 = Read/Write Multiple Registers - 24 = Read FIFO
modbus_function_code = int_to_bytes_1(4)
#Address of the first byte in Hi register
modbus_reference_number = int_to_bytes_2(0)
#The number of words to read
modbus_word_count = int_to_bytes_2(1)


#Compile Raw part of Modbus/TCP package
Modbus = modbus_transaction_id1 + modbus_transaction_id2 + modbus_protocol_id + modbus_length + modbus_unit_identifier + modbus_function_code + modbus_reference_number + modbus_word_count

#Payload - Define what protocol to send as raw data
payload = Modbus

l4 = TCP(sport=source_port,
dport=destination_port,
flags='PA',
seq=RETURNPACKET.ack,
ack=RETURNPACKET.len + RETURNPACKET.seq-43
)

COMMpacket = l3 / l4 / payload

#Show packet
COMMpacket.show2()

#Send packet and await response
RETURNPACKET = sr1(COMMpacket)


######## PART4 - After receiving return information, send an ACK ########
l4 = TCP(sport=source_port,
        dport=destination_port,
        flags='A',
        seq=RETURNPACKET.ack,
        ack=RETURNPACKET.len + RETURNPACKET.seq-40
        )

ACKpacket = l3 / l4

#Show packet
#ACKpacket.show2()

#Send packet
send(ACKpacket)


######## PART5 - Close the connection, send a FIN ########
l4 = TCP(sport=source_port,
        dport=destination_port,
        flags='F',
        seq=RETURNPACKET.ack,
        ack=RETURNPACKET.len + RETURNPACKET.seq-39
        )

FINpacket = l3 / l4

#Show packet
#ACKpacket.show2()

#Send packet
RETURNPACKET = sr1(FINpacket)



######## PART6 - After receiving return information, send an ACK ########
l4 = TCP(sport=source_port,
        dport=destination_port,
        flags='A',
        seq=RETURNPACKET.ack,
        ack=RETURNPACKET.len + RETURNPACKET.seq-40
        )

ACKpacket = l3 / l4

#Show packet
#ACKpacket.show2()

#Send packet
send(ACKpacket)