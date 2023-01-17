#! /usr/bin/env python3


######## COPYRIGHT ########
# Copyright 2023 Jarno Baselier. All rights reserved.
# This software may be modified and distributed under the terms
# of the "Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International (CC BY-NC-SA 4.0) license. https://creativecommons.org/licenses/by-nc-sa/4.0/.


######## IMPORTS ########
from scapy.all import *
import struct
import binascii


######## SETTINGS / VARIABLES ########
#Setting variables
#This setting is to specify the layer where tha package is send from. Options are "layer1 & layer2"
layer = "layer1"

#Set layer to 1 if you want to manually control it. If 0 then the computer calculates this layer
manual_layer_2 = 0
manual_layer_3 = 0
manual_layer_raw = 1

#Source / Destination variables
source_ip = 'x.x.x.x'
destination_ip = 'x.x.x.x'
source_port = 'iso_tsap'
destination_port = 36545
source_mac = 'xx:xx:xx:xx:xx:xx'
destination_mac = 'xx:xx:xx:xx:xx:xx'
send_interface = "Ethernet 2"

#Select if you want to loop the packet. 1 = yes and 0 = no
loop = 0


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


######## PAYLOAD SPECIFICATION ########

### Note, payloads are generated as RAW bytes in the "lRaw" layer

#=========================================================
#PROFINET
#https://rt-labs.com/docs/p-net/profinet_details.html

#FrameID values:
#8000 = 32768 decimal = Profinet cyclic - Output CR
#8001 = 32769 decimal = Profinet cyclic - Input CR
#fc01 = 64513 decimal = ALARM_HIGH
#fe01 = 65025 decimal = ALARM_LOW
#fefc = 65276 decimal = Profinet acyclic, DCP - HELLO
#fefd = 65277 decimal = Profinet acyclic, DCP - GET_SET
#fefe = 65278 decimal = Profinet acyclic, DCP - Identify request
#fefe = 65278 decimal = Profinet acyclic, DCP - IIdentify response
profinet_frameid = int_to_bytes_2(65277) #fefd Hex - Profinet acyclic, DCP - GET_SET
#ServiceID defines the action on the specific device
profinet_serviceId = int_to_bytes_1(4)
#0 = request response (request) -  1 = Response Success (answer)
profinet_serviceType = int_to_bytes_1(0)
#profinet_xid is usually not important to controll the hardware
profinet_xid_1 = int_to_bytes_1(0)
profinet_xid_2 = int_to_bytes_1(0)
profinet_xid_3 = int_to_bytes_1(25) #19 Hex
profinet_xid_4 = int_to_bytes_1(18) #12 Hex
#profinet_reserved is usually not important to controll the hardware
profinet_reserved = int_to_bytes_2(0)
#dcpdatalength defines the size of the Data block. Profinet DCP runs via “Profinet acyclic realtime”.
profinet_dcpdatalength = int_to_bytes_2(8)
#DATA BLOCK / CONTROL SIGNAL BLOCK
#https://rt-labs.com/docs/p-net/profinet_details.html
#Option and Suboption define the action to take. Note, this is in combination with the serviceID
"""
Service IDs     Option  Suboption       Description     Contains
3       1       1       MAC address     
3, 4, 5, 6      1       2       IP parameter    IP address, netmask, gateway
3, 4, 5, 6      1       3       Full IP suite   IP address, netmask, gateway, DNS
3, 5    2       1       Type of station Device vendor
3, 4, 5, 6      2       2       Name of station Also permanent/temporary
3, 5, 6 2       3       Device ID       VendorID, DeviceID
3, 5    2       4       Device role     ?
3, 5    2       5       Device options  Which options are available
Filter only     2       6       Alias name      
6       2       8       OEM device ID   
4       5       1       Start transaction       
4       5       2       End transaction 
4       5       3       Signal (Flash LED)      Flash once
4       5       4       Response        
4       5       6       Reset to factory        Type of reset
5       255     255     All     
6       6       1       Device initiative       Issues Hello at power on
"""
profinet_block_option_control = int_to_bytes_1(5)
profinet_block_suboption_signal = int_to_bytes_1(3)
#Defines the size of the upcoming block
profinet_block_dcpblocklength = int_to_bytes_2(4)
#0 = Save value temporary - 1 = Save value permanently
profinet_block_blockqualifier = int_to_bytes_2(0)
#Further defines the signal - 0x0100 (1-0) = Flash once - 
profinet_block_signalvalue_1 =int_to_bytes_1(1)
#profinet_block_signalvalue_2 is usually not important to controll the hardware
profinet_block_signalvalue_2 =int_to_bytes_1(0)

#Compile Raw part of Profinet package
Profinet = profinet_frameid + profinet_serviceId + profinet_serviceType + profinet_xid_1 + profinet_xid_2 + profinet_xid_3 + profinet_xid_4 + profinet_reserved + profinet_dcpdatalength + profinet_block_option_control + profinet_block_suboption_signal + profinet_block_dcpblocklength + profinet_block_blockqualifier + profinet_block_signalvalue_1 + profinet_block_signalvalue_2


#=========================================================
#TPKT
#TPKT is officially defined as "ISO Transport Service on top of the TCP." "TCP" and "ISO" relate to two rival suites of networking protocols. TPKT enables translation between these two groups.
#TPKT is an "encapsulation" protocol. It carries the OSI packet in its own packet's data payload and then passes the resulting structure to TCP, from then on, the packet is processed as a TCP/IP packet. The OSI programs passing data to TPKT are unaware that their data will be carried over TCP/IP because TPKT emulates the OSI protocol Transport Service Access Point (TSAP).

#Version of TPKT (always 3)
tpkt_version = int_to_bytes_1(3)
#Reserved is always 0 and is ignored
tpkt_reserved = int_to_bytes_1(0)
tpkt_spacer = int_to_bytes_1(0)
#Length of the data incl. the TPKT packet. So for instance TPKT + ISO + SiemensS7 = length of this field.
tpkt_length = int_to_bytes_1(22)

#Compile Raw part of the TPKT package
TPKT = tpkt_version + tpkt_reserved + tpkt_spacer + tpkt_length


#=========================================================
#ISO_8073 / Connection Oriented Transport Protocol / COTP
#COTP uses CLNP as its underlying network protocol.

#The Setup Communication Response is identical to the Setup Communication Request with the only difference that the Message Type has an ACK_DATA code of 0x03.
#Also does the response eventually provide different values for Max AMQ Caller, Max AMQ Callee and PDU Size.
#The values might be lower than in the request, but never higher.

#https://www.wireshark.org/docs/dfref/c/cotp.html
#ISO Size
iso_length = int_to_bytes_1(2)
iso_pdu_type = int_to_bytes_1(240)
#Indicates  the  order in which the DT TPDU was transmitted by a transport entity.
iso_tpdu_number = int_to_bytes_1(128)

#Compile Raw part of ISO_8073 package
ISO_8073 = iso_length + iso_pdu_type + iso_tpdu_number


#=========================================================
#SiemansS7
#https://packages.zeek.org/packages/view/ae81d07d-389a-11ed-ba82-0a598146b5c6
#http://gmiru.com/article/s7comm-part2/

#Special communication processors for the S7-400 series (CP 443) may use this protocol without the TCP/IP layers.
#The protocol is used by Siemens since the Simatic S7 product series was launched in 1994. The protocol is also used on top of other physical/network layers, like RS-485 with MPI (Multi-Point-Interface) or Profibus.

#To establish a connection to a S7 PLC there are 3 steps:
#1. Connect to PLC on TCP port 102 (uses the IP address of the PLC/CP)
#2. Connect on ISO layer (COTP Connect Request) (as a destination TSAP of two bytes length. The first byte of the destination TSAP codes the communication type (1=PG, 2=OP). The second byte of the destination TSAP codes the rack and slot number: This is the position of the PLC CPU. The slot number is coded in Bits 0-4, the rack number is coded in Bits 5-7.)
#3. Connect on S7comm layer (s7comm.param.func = 0xf0, Setup communication)

#S7 communication consists of (at least) the following protocols:
#COTP: ISO 8073 COTP Connection-Oriented Transport Protocol (spec. available as RFC905)
#TPKT: RFC1006 "ISO transport services on top of the TCP: Version 3", updated by RFC2126
#TCP: Typically, TPKT uses TCP as its transport protocol. The well known TCP port for TPKT traffic is 102.

#Header
#Protocol (S7) identifier
s7_protocol_id = int_to_bytes_1(50)
#Remote Operating Service Control - Message type. 1 = 0x01-Job Request (send by the master (e.g. read/write memory, read/write blocks, start/stop device, setup communication)) - 2 = 0x02-Ack: simple acknowledgement sent by the slave with no data field - 3 = 0x03-Ack-Data: acknowledgement with optional data field, contains the reply to a job request - 7 = 0x07-Userdata: an extension of the original protocol, the parameter field contains the request/response id, (used for programming/debugging, SZL reads, security functions, time setup, cyclic read..)
s7_rosctr = int_to_bytes_1(3)
s7_red_id_pt1 = int_to_bytes_1(0)
s7_red_id_pt2 = int_to_bytes_1(0)
#Reference ID Used to Link Requests to Responses. Generated by the master, incremented with each new transmission, used to link responses to their requests. The PLC just copies it to the reply
s7_protocol_dataunit_ref = int_to_bytes_2(520)
#The length of the parameter field, Big-Endian
s7_param_length_pt1 = int_to_bytes_1(0)
s7_param_length_pt2 = int_to_bytes_1(2)
#The length of the data field, Big-Endian
s7_data_length_pt1 = int_to_bytes_1(0)
s7_data_length_pt2 = int_to_bytes_1(1)
#Only present in the Ack-Data messages, the possible error constants are listed in the constants.txt (http://gmiru.com/resources/s7proto/constants.txt)
s7_error_class = int_to_bytes_1(0)
#Only present in the Ack-Data messages, the possible error constants are listed in the constants.txt (http://gmiru.com/resources/s7proto/constants.txt)
s7_error_code = int_to_bytes_1(0)
#Parameter - Depends on the MessageType - 1 = Setup Communication - 4 = Read Variable - 5 = Write Variable - 26 t/m 31 = Block Up/Download (0x1a-1f) - 40 = PLC Control (0x28) - 41 = PLC Stop (0x29)
s7_function = int_to_bytes_1(5)
#Number of following Request Item structures.
s7_item_count = int_to_bytes_1(1)
#Data - This structure is used to address the actual variables, its length and fields depend on the type of addressing being used. These items are only present in the Job request and are emitted from the corresponding Ack Data no matter what the addressing mode is or whether it is a read or write request.
s7_item = int_to_bytes_1(255)

#Compile Raw part of the Siemens S7 package
SiemensS7 = s7_protocol_id + s7_rosctr + s7_red_id_pt1 + s7_red_id_pt2 + s7_protocol_dataunit_ref + s7_param_length_pt1 + s7_param_length_pt2 + s7_data_length_pt1 + s7_data_length_pt2 + s7_error_class + s7_error_code + s7_function + s7_item_count + s7_item


######## DEFINE THE CUSTOM PAYLOAD (RAW PACKAGE) ########

#Payload - Define what protocol to send as raw data
payload = Profinet #+ TPKT + ISO_8073 + SiemensS7


######## REGULAR PACKET LAYERS (NONRAW) ########

#Ethernet
l1 = Ether(dst=destination_mac,
        src=source_mac,
        #Profinet = 0x8892 (34962 in decimal) - Note that “Profinet cyclic realtime” and “Profinet acyclic realtime” run directly on Ethernet layer 2 (they do not use IP or UDP), so no manual l2 or l3.
        type=34962
     )
#IP
l2 = IP(version=4, 
        ihl=5,
        tos=0x0,
        len=62,
        id=231,
        flags='',
        frag=0,
        ttl=255,
        proto='tcp',
        chksum=0xd4d3,
        src=source_ip,
        dst=destination_ip
     )
#TCP
l3 = TCP(sport=source_port,
        dport=destination_port,
        seq=19179,
        ack=1416649709,
        dataofs=5,
        reserved=0,
        flags='PA',
        window=3150,
        chksum=0x9cba,
        urgptr=0,
        options=[]
     )
#RAW
lRaw = raw = Raw(load = payload)


######## PACKET CONSTRUCTION ########
if layer == "layer1" and manual_layer_2 == 1 and manual_layer_3 == 1 and manual_layer_raw == 1:
        packet = l1 / l2 / l3 / lRaw
if layer == "layer1" and manual_layer_2 == 1 and manual_layer_3 == 0 and manual_layer_raw == 1:
        packet = l1 / l2 / lRaw
if layer == "layer1" and manual_layer_2 == 1 and manual_layer_3 == 1 and manual_layer_raw == 0:
        packet = l1 / l2 / l3
if layer == "layer1" and manual_layer_2 == 1 and manual_layer_3 == 0 and manual_layer_raw == 0:
        packet = l1 / l2
if layer == "layer1" and manual_layer_2 == 0 and manual_layer_3 == 1 and manual_layer_raw == 1:
        packet = l1 / l3 / lRaw
if layer == "layer1" and manual_layer_2 == 0 and manual_layer_3 == 0 and manual_layer_raw == 1:
        packet = l1 / lRaw
if layer == "layer1" and manual_layer_2 == 0 and manual_layer_3 == 1 and manual_layer_raw == 0:
        packet = l1/ l3
if layer == "layer1" and manual_layer_2 == 0 and manual_layer_3 == 0 and manual_layer_raw == 0:
        packet = l1

if layer == "layer2" and manual_layer_3 == 1 and manual_layer_raw == 1:
        packet = l2 / l3 / lRaw
if layer == "layer2" and manual_layer_3 == 1 and manual_layer_raw == 0:
        packet = l2 / l3
if layer == "layer2" and manual_layer_3 == 0 and manual_layer_raw == 1:
        packet = l2 / lRaw
if layer == "layer2" and manual_layer_3 == 0 and manual_layer_raw == 0:
        packet = l2


######## SHOW AND SEND PACKET(S) ########
#Show packet
packet.show2()

#Send Packet
#Layer1 (control layer 1)
if layer == "layer1" and loop == 0:
        sendp(packet,iface=send_interface)
if layer == "layer1" and loop == 1:
        sendp(packet,iface=send_interface, loop=1)

#Layer3 (automatic layer 1)
if layer == "layer2" and loop == 0:
        send((packet),iface=send_interface)
if layer == "layer2" and loop == 1:
        send((packet),iface=send_interface, loop=1)