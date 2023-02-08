#! /usr/bin/env python3



######## COPYRIGHT ########
# Copyright 2023 Jarno Baselier. All rights reserved.
# This software may be modified and distributed under the terms
# of the "Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International (CC BY-NC-SA 4.0) license. https://creativecommons.org/licenses/by-nc-sa/4.0/.

#This file act as a master file for defining all kinds of different ICS/SCADA (IA/PA/IoT) protocol packet segments and some explanations. This file is not constructed to deal with packet streams, like conducting the 3-way handshake. Look for case-specific examples in this repo if you need an example on how to use this knowledge in combination with different scenarios.

#Tip:
#Convert a long hex string to bytes: 
#codecs.decode('505f50524f4752414d', 'hex_codec')

######## IMPORTS ########
from scapy.all import *
import struct
import binascii
import threading
import time



######## SETTINGS / VARIABLES ########
#Setting variables
#This setting is to specify the layer where the package is send from. Options are "layer1 & layer3"
layer = "layer1"

#Set layer to 1 if you want to manually control it. If 0 then the computer calculates this layer
manual_layer_1 = 1 #Ethernet
manual_layer_3 = 1 #IP / ICMP / ARP
manual_layer_4 = 1 #TCP / UDP
manual_layer_raw = 1

#Source / Destination variables
#randomize ports: random.randint(20000,50000)
source_ip = '192.168.178.57'
destination_ip = '192.168.178.30'
source_port = random.randint(20000,50000)
destination_port = 102
source_mac = '8c:f3:19:00:a6:de' #HMI
destination_mac = '8c:f3:19:03:e4:b3' #PLC
send_interface = "Ethernet 2"

#Select if you want to loop the packet. 1 = yes and 0 = no
#Normal loop - send packets synchronous
loop = 0
#Threaded loop - send packets asynchronous
threaded = 0
nr_of_threads = 20

#Sniffing after sending. 1 = yes and 0 = no
#Note - Since the return traffic is usually faster then the startup of the sniffing process you might need to resent the package (run this script) in another terminal while the sniffer is listening.
sniffing = 0
#Number of return packets to sniff before the sniffer stops
nr_of_packets_to_sniff = 1
#Store sniffed packets if sniffing is on. 1 = yes and 0 = no
store_sniffed_packets = 1
store_location = "C:\\Users\\Redux Gamer\\Desktop\\sniffed_packages.pcap"



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
#https://github.com/rtlabs-com/p-net/blob/master/doc/profinet_basics.rst
#https://rt-labs.com/docs/p-net/profinet_details.html


"""
### = Profinet EXAMPLES = ###

#EXAMPLE - Blink HMI screen
profinet_frameid = int_to_bytes_2(65277) #fefd Hex
profinet_serviceId = int_to_bytes_1(4)
profinet_serviceType = int_to_bytes_1(0)
#profinet_xid is usually not important to controll the hardware
profinet_xid_1 = int_to_bytes_1(0)
profinet_xid_2 = int_to_bytes_1(0)
profinet_xid_3 = int_to_bytes_1(25) #19 Hex
profinet_xid_4 = int_to_bytes_1(18) #12 Hex
#profinet_reserved is usually not important to controll the hardware
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


#EXAMPLE - Reset to factory defaults
profinet_frameid = int_to_bytes_2(65277)
profinet_serviceId = int_to_bytes_1(4)
profinet_serviceType = int_to_bytes_1(0)
profinet_xid_1 = int_to_bytes_1(0)
profinet_xid_2 = int_to_bytes_1(0)
profinet_xid_3 = int_to_bytes_1(0)
profinet_xid_4 = int_to_bytes_1(3)
profinet_reserved = int_to_bytes_2(0)
profinet_dcpdatalength = int_to_bytes_2(6)
profinet_block_option_control = int_to_bytes_1(5)
profinet_block_suboption_signal = int_to_bytes_1(6)
profinet_block_dcpblocklength = int_to_bytes_2(2)
profinet_block_blockqualifier = int_to_bytes_2(22)

#Compile Raw part of Profinet package
Profinet = profinet_frameid + profinet_serviceId + profinet_serviceType + profinet_xid_1 + profinet_xid_2 + profinet_xid_3 + profinet_xid_4 + profinet_reserved + profinet_dcpdatalength + profinet_block_option_control + profinet_block_suboption_signal + profinet_block_dcpblocklength + profinet_block_blockqualifier


#EXAMPLE - Rename the device
profinet_frameid = int_to_bytes_2(65277) 
profinet_serviceId = int_to_bytes_1(4)
profinet_serviceType = int_to_bytes_1(0)
profinet_xid_1 = int_to_bytes_1(0)
profinet_xid_2 = int_to_bytes_1(0)
profinet_xid_3 = int_to_bytes_1(0)
profinet_xid_4 = int_to_bytes_1(3)
profinet_reserved = int_to_bytes_2(0)
profinet_dcpdatalength = int_to_bytes_2(10)
profinet_block_option_control = int_to_bytes_1(2)
profinet_block_suboption_signal = int_to_bytes_1(2)
profinet_block_dcpblocklength = int_to_bytes_2(6)
profinet_block_blockqualifier = int_to_bytes_2(1)
profinet_namestation = string_to_bytes("jarno")

#Compile Raw part of Profinet package
Profinet = profinet_frameid + profinet_serviceId + profinet_serviceType + profinet_xid_1 + profinet_xid_2 + profinet_xid_3 + profinet_xid_4 + profinet_reserved + profinet_dcpdatalength + profinet_block_option_control + profinet_block_suboption_signal + profinet_block_dcpblocklength + profinet_block_blockqualifier + profinet_namestation


#EXAMPLE - Give device new IP settings
profinet_frameid = int_to_bytes_2(65277)
profinet_serviceId = int_to_bytes_1(4)
profinet_serviceType = int_to_bytes_1(0)
profinet_xid_1 = int_to_bytes_1(0)
profinet_xid_2 = int_to_bytes_1(0)
profinet_xid_3 = int_to_bytes_1(0)
profinet_xid_4 = int_to_bytes_1(1)
profinet_reserved = int_to_bytes_2(0)
profinet_dcpdatalength = int_to_bytes_2(18)
profinet_block_option_control = int_to_bytes_1(1)
profinet_block_suboption_signal = int_to_bytes_1(2)
profinet_block_dcpblocklength = int_to_bytes_2(14)
profinet_block_blockqualifier = int_to_bytes_2(1)
#profinet_namestation = string_to_bytes("jarno")
#Give IP
profinet_ip1 = int_to_bytes_1(192)
profinet_ip2 = int_to_bytes_1(168)
profinet_ip3 = int_to_bytes_1(178)
profinet_ip4 = int_to_bytes_1(143)
profinet_subnet1 = int_to_bytes_1(255)
profinet_subnet2 = int_to_bytes_1(255)
profinet_subnet3 = int_to_bytes_1(255)
profinet_subnet4 = int_to_bytes_1(0)
profinet_gateway1 = int_to_bytes_1(192)
profinet_gateway2 = int_to_bytes_1(168)
profinet_gateway3 = int_to_bytes_1(178)
profinet_gateway4 = int_to_bytes_1(1)

#Compile Raw part of Profinet package
Profinet = profinet_frameid + profinet_serviceId + profinet_serviceType + profinet_xid_1 + profinet_xid_2 + profinet_xid_3 + profinet_xid_4 + profinet_reserved + profinet_dcpdatalength + profinet_block_option_control + profinet_block_suboption_signal + profinet_block_dcpblocklength + profinet_block_blockqualifier + profinet_ip1 + profinet_ip2 + profinet_ip3 + profinet_ip4 + profinet_subnet1 + profinet_subnet2 + profinet_subnet3 + profinet_subnet4 + profinet_gateway1 + profinet_gateway2 + profinet_gateway3 + profinet_gateway4


#EXAMPLE - DCP IDENTIFY DEVICES
profinet_frameid = int_to_bytes_2(65278)
profinet_serviceId = int_to_bytes_1(5)
profinet_serviceType = int_to_bytes_1(0)
profinet_xid_1 = int_to_bytes_1(0)
profinet_xid_2 = int_to_bytes_1(0)
profinet_xid_3 = int_to_bytes_1(0)
profinet_xid_4 = int_to_bytes_1(3)
profinet_reserved = int_to_bytes_2(1)
profinet_dcpdatalength = int_to_bytes_2(4)
profinet_block_option_control = int_to_bytes_1(255)
profinet_block_suboption_signal = int_to_bytes_1(255)
profinet_block_dcpblocklength = int_to_bytes_2(0)

#Compile Raw part of Profinet package
Profinet = profinet_frameid + profinet_serviceId + profinet_serviceType + profinet_xid_1 + profinet_xid_2 + profinet_xid_3 + profinet_xid_4 + profinet_reserved + profinet_dcpdatalength + profinet_block_option_control + profinet_block_suboption_signal + profinet_block_dcpblocklength

### = END Profinet EXAMPLES = ###
"""

#FrameID values:
#8000 = 32768 decimal = Profinet cyclic - Output CR
#8001 = 32769 decimal = Profinet cyclic - Input CR
#fc01 = 64513 decimal = ALARM_HIGH
#fe01 = 65025 decimal = ALARM_LOW
#fefc = 65276 decimal = Profinet acyclic, DCP - HELLO
#fefd = 65277 decimal = Profinet acyclic, DCP - GET_SET
#fefe = 65278 decimal = Profinet acyclic, DCP - Identify request
#fefe = 65278 decimal = Profinet acyclic, DCP - IIdentify response
profinet_frameid = int_to_bytes_2(65277) #The Frame ID identifies what kind of frame this is. For any “Identify request” (see the next two fields) it needs to be set to 0xfefe, and for any “Identify response” to 0xfeff. fefd = Profinet acyclic, DCP - GET_SET
#ServiceID defines the action on the specific device
profinet_serviceId = int_to_bytes_1(4)
#0 = request response (request) -  1 = Response Success (answer)
profinet_serviceType = int_to_bytes_1(0)
#profinet_xid is usually not important to controll the hardware. The Xid is a 32-bit random number which identifies this request. All responses need to contain the same ID for the receiver to figure out which request the just received response belongs to as there is no such thing as a connection on Ethernet Layer 2.
profinet_xid_1 = int_to_bytes_1(0)
profinet_xid_2 = int_to_bytes_1(0)
profinet_xid_3 = int_to_bytes_1(21)
profinet_xid_4 = int_to_bytes_1(18)
#profinet_reserved is usually not important to controll the hardware
profinet_reserved = int_to_bytes_2(0)
#dcpdatalength defines the size of the Data block. Profinet DCP runs via “Profinet acyclic realtime”.
profinet_dcpdatalength = int_to_bytes_2(8)
#DATA BLOCK / CONTROL SIGNAL BLOCK
#https://rt-labs.com/docs/p-net/profinet_details.html
#Option and Suboption define the action to take. Note, this is in combination with the serviceID
"""
Service IDs     Option  Suboption       Description     Contains
3               1       1               MAC address     
3, 4, 5, 6      1       2               IP parameter    IP address, netmask, gateway
3, 4, 5, 6      1       3               Full IP suite   IP address, netmask, gateway, DNS
3, 5            2       1               Type of station Device vendor
3, 4, 5, 6      2       2               Name of station Also permanent/temporary
3, 5, 6         2       3               Device ID       VendorID, DeviceID
3, 5            2       4               Device role     ?
3, 5            2       5               Device options  Which options are available
Filter only     2       6               Alias name      
6               2       8               OEM device ID   
4               5       1               Start transaction       
4               5       2               End transaction 
4               5       3               Signal (Flash LED)      Flash once
4               5       4               Response        
4               5       6               Reset to factory        Type of reset
5               255     255             All     
6               6       1               Device initiative       Issues Hello at power on
"""
profinet_block_option_control = int_to_bytes_1(5)
profinet_block_suboption_signal = int_to_bytes_1(3)
#Defines the size of the upcoming block
profinet_block_dcpblocklength = int_to_bytes_2(4)

#Use option when needed. When not needed, keep commented-out
#0 = Save value temporary - 1 = Save value permanently
#For device reset use: 0(hex) = mode0 - Reset to Factory (clear all default values) - 2(hex) = mode1 - Reset application data - 4(hex) = mode2 - Reset communication parameters - 6(hex) = mode3 - Reset engineering parameter - 8(hex) = mode4 - Reset all stored data - 16(hex) = mode8 - Reset device - 18(hex) = mode9 - Reset & Restore data
#profinet_block_blockqualifier = int_to_bytes_2(1)

#Name the station
#profinet_namestation = string_to_bytes("jarno")

#Give IP
#profinet_ip1 = int_to_bytes_1(192)
#profinet_ip2 = int_to_bytes_1(168)
#profinet_ip3 = int_to_bytes_1(178)
#profinet_ip4 = int_to_bytes_1(143)
#profinet_subnet1 = int_to_bytes_1(255)
#profinet_subnet2 = int_to_bytes_1(255)
#profinet_subnet3 = int_to_bytes_1(255)
#profinet_subnet4 = int_to_bytes_1(0)
#profinet_gateway1 = int_to_bytes_1(192)
#profinet_gateway2 = int_to_bytes_1(168)
#profinet_gateway3 = int_to_bytes_1(178)
#profinet_gateway4 = int_to_bytes_1(1)

#SignalValues / Blink Screen
profinet_block_blockqualifier = int_to_bytes_2(0)
profinet_block_signalvalue_1 =int_to_bytes_1(1)
profinet_block_signalvalue_2 =int_to_bytes_1(0)

#Compile Raw part of Profinet package
Profinet = profinet_frameid + profinet_serviceId + profinet_serviceType + profinet_xid_1 + profinet_xid_2 + profinet_xid_3 + profinet_xid_4 + profinet_reserved + profinet_dcpdatalength + profinet_block_option_control + profinet_block_suboption_signal + profinet_block_dcpblocklength + profinet_block_blockqualifier + profinet_block_signalvalue_1 + profinet_block_signalvalue_2



#=========================================================
#MODBUS
#https://ipc2u.com/articles/knowledge-base/detailed-description-of-the-modbus-tcp-protocol-with-command-examples/

#The Modbus TCP command consists of a portion of the Modbus RTU message and a special header. From the Modbus RTU message, the SlaveID address at the beginning and the CRC checksum at the end are removed, which forms the PDU, the Protocol Data Unit. 


"""
### = Modbus EXAMPLES = ###

#First, perform a valid 3-way handshake
#End the TCP stream with a FIN or RST command

#EXAMPLE - Write Multiple Coils

modbus_transaction_id1 = int_to_bytes_1(0)
modbus_transaction_id2 = int_to_bytes_1(transid)
modbus_protocol_id = int_to_bytes_2(0)
modbus_length = int_to_bytes_2(8)
modbus_unit_identifier = int_to_bytes_1(0)
modbus_function_code = int_to_bytes_1(15)
modbus_reference_number = int_to_bytes_2(0)
modbus_bit_count = int_to_bytes_2(8)
modbus_byte_count = int_to_bytes_1(1)
modbus_data = int_to_bytes_1(1)

#Compile Raw part of Modbus/TCP package
Modbus = modbus_transaction_id1 + modbus_transaction_id2 + modbus_protocol_id + modbus_length + modbus_unit_identifier + modbus_function_code + modbus_reference_number + modbus_bit_count + modbus_byte_count + modbus_data


#EXAMPLE - Read Input Registers

modbus_transaction_id1 = int_to_bytes_1(0)
modbus_transaction_id2 = int_to_bytes_1(transid)
modbus_protocol_id = int_to_bytes_2(0)
modbus_length = int_to_bytes_2(6)
modbus_unit_identifier = int_to_bytes_1(0)
modbus_function_code = int_to_bytes_1(4)
modbus_reference_number = int_to_bytes_2(0)
modbus_word_count = int_to_bytes_2(1)

#Compile Raw part of Modbus/TCP package
Modbus = modbus_transaction_id1 + modbus_transaction_id2 + modbus_protocol_id + modbus_length + modbus_unit_identifier + modbus_function_code + modbus_reference_number + modbus_word_count


#EXAMPLE - Write Multiple Registers
modbus_transaction_id1 = int_to_bytes_1(0)
modbus_transaction_id2 = int_to_bytes_1(transid)
modbus_protocol_id = int_to_bytes_2(0)
modbus_length = int_to_bytes_2(9)
modbus_unit_identifier = int_to_bytes_1(0)
modbus_function_code = int_to_bytes_1(16)
modbus_reference_number = int_to_bytes_2(0)
modbus_word_count = int_to_bytes_2(1)
modbus_byte_count = int_to_bytes_1(2)
register = int_to_bytes_2(0)

#Compile Raw part of Modbus/TCP package
Modbus = modbus_transaction_id1 + modbus_transaction_id2 + modbus_protocol_id + modbus_length + modbus_unit_identifier + modbus_function_code + modbus_reference_number + modbus_word_count + modbus_byte_count + register


#EXAMPLE - Read Discrete Inputs
modbus_transaction_id1 = int_to_bytes_1(0)
modbus_transaction_id2 = int_to_bytes_1(transid)
modbus_protocol_id = int_to_bytes_2(0)
modbus_length = int_to_bytes_2(6)
modbus_unit_identifier = int_to_bytes_1(0)
modbus_function_code = int_to_bytes_1(2)
modbus_reference_number = int_to_bytes_2(0)
modbus_bit_count = int_to_bytes_2(8)

#Compile Raw part of Modbus/TCP package
Modbus = modbus_transaction_id1 + modbus_transaction_id2 + modbus_protocol_id + modbus_length + modbus_unit_identifier + modbus_function_code + modbus_reference_number + modbus_bit_count

### = END Modbus EXAMPLES = ###
"""

#Transaction identifier - Stream counter - The actual use for the transaction identifier is for synchronization between messages of server and client. This function is not always implemented.
modbus_transaction_id1 = int_to_bytes_1(0)
modbus_transaction_id2 = int_to_bytes_1(transid)
#Protocol Identifier, set by the master. Will always be 0.
modbus_protocol_id = int_to_bytes_2(0)
#The number of bytes in the message that follows. It is counted from Unit Identifier to the end of the message. 
modbus_length = int_to_bytes_2(8)
#The unit ID is used when dealing with Modbus Bridges. Typical bridges convert Modbus TCP to Modbus serial or Modbus plus. The Unit ID is either the device Id of serial device or it is index number that references a Modbus plus layered address. Most traditional Modbus/TCP devices ignore the unit Id completely. This value is usually 0. This ID is also referred to as the SlaveID.
modbus_unit_identifier = int_to_bytes_1(0)
#Modbus
#1 = Read Coils - 2 = Read Discrete Inputs - 4 = Read Input Registers - 5 = Write Single Coil - 6 = Write Single Register - 7 = Read Exception Status (serial=only) - 15 = Write Multiple Coils - 16 = Write Multiple Registers - 20 = Read File Record - 21 = Write File Record - 22 = Mask Write Register - 23 = Read/Write Multiple Registers - 24 = Read FIFO
modbus_function_code = int_to_bytes_1(15)
#Address of the first byte in Hi register
modbus_reference_number = int_to_bytes_2(0)

#Use option when needed. When not needed, keep commented-out

#Write Multiple Coils
#The number registers in Lo Byte
#modbus_bit_count = int_to_bytes_2(8)
#The number of bytes that follows
#modbus_byte_count = int_to_bytes_1(1)
#The data to be written to the coil. Least signaficant is first coil. Coil 1 = 1, 2 = 2, 3 = 4, 4 = 8, 5 = 16, 6 = 32 etc.
#modbus_data = int_to_bytes_1(1)

#Read Input Registers
#The number of words to read
#modbus_word_count = int_to_bytes_2(1)

#Write Multiple Registers
#The number of words to write
#modbus_word_count = int_to_bytes_2(1)
#The number of bytes that follows
#modbus_byte_count = int_to_bytes_1(2)
##Register
#register_number = int_to_bytes_1(0)
#register_value = int_to_bytes_1(0)

#Read Discrete Inputs
#The number of bit values to be returned
#modbus_bit_count = int_to_bytes_2(8)

#Compile Raw part of Modbus/TCP package
Modbus = modbus_transaction_id1 + modbus_transaction_id2 + modbus_protocol_id + modbus_length + modbus_unit_identifier + modbus_function_code + modbus_reference_number


#=========================================================
#TPKT
#TPKT is officially defined as "ISO Transport Service on top of the TCP." "TCP" and "ISO" relate to two rival suites of networking protocols. TPKT enables translation between these two groups.
#TPKT is an "encapsulation" protocol. It carries the OSI packet in its own packet's data payload and then passes the resulting structure to TCP, from then on, the packet is processed as a TCP/IP packet. The OSI programs passing data to TPKT are unaware that their data will be carried over TCP/IP because TPKT emulates the OSI protocol Transport Service Access Point (TSAP).

#Version of TPKT (always 3)
tpkt_version = int_to_bytes_1(3)
#Reserved is always 0 and is ignored
tpkt_reserved = int_to_bytes_1(0)
tpkt_length = int_to_bytes_2(22)

#Compile Raw part of the TPKT package
TPKT = tpkt_version + tpkt_reserved + tpkt_length



#=========================================================
#ISO_8073 / Connection Oriented Transport Protocol / COTP
#COTP uses CLNP as its underlying network protocol.

#The Setup Communication Response is identical to the Setup Communication Request with the only difference that the Message Type has an ACK_DATA code of 0x03.
#Also does the response eventually provide different values for Max AMQ Caller, Max AMQ Callee and PDU Size.
#The values might be lower than in the request, but never higher.

#https://www.wireshark.org/docs/dfref/c/cotp.html

#ISO Size
iso_length = int_to_bytes_1(2)
#Protocol Data Unit Type DT (240) / ER / CR (224)
iso_pdu_type = int_to_bytes_1(240)
#Indicates  the  order in which the DT TPDU was transmitted by a transport entity.
iso_tpdu_number = int_to_bytes_1(128)
#This field has a few uses and is mostly used to identify the transport connection.
iso_dest_ref = int_to_bytes_2(0)
#Reference selected  by  the  transport  entity initiating   the   CR  TPDU  to  identify  the requested transport connection;
iso_src_ref = int_to_bytes_2(10)
#Bits 8-5 of octet 7 defines the preferred OPTION: transport protocol class to be  operated  over the   requested  transport  connection. This field shall take one of the following values:
#0000  Class 0 - 0001 Class 1 - 0010  Class 2 - 0011  Class 3 - 0100  Class 4
iso_class = int_to_bytes_1(0)
#1100 0001 (c1 / 193) for  the  identifier  of  the Calling TSAP (Transport Service Access Point). 1100 0010 (c2 / 194) for  the  identifier  of  the Called TSAP.
iso_parameter_code = int_to_bytes_1(193)
#Lengt of next parameter
iso_parameter_length = int_to_bytes_1(2)
#Transport Service Access Point ID
iso_source_tsap1 = int_to_bytes_1(2)
iso_source_tsap2 = int_to_bytes_1(0)
#1100 0001 (c1 / 193) for  the  identifier  of  the Calling TSAP (Transport Service Access Point). 1100 0010 (c2 / 194) for  the  identifier  of  the Called TSAP.
iso_parameter_code2 = int_to_bytes_1(194)
#Lengt of next parameter
iso_parameter_length2 = int_to_bytes_1(2)
#Transport Service Access Point ID
iso_dest_tsap1 = int_to_bytes_1(2)
iso_dest_tsap2 = int_to_bytes_1(0)
#1100 0001 (c1 / 193) for  the  identifier  of  the Calling TSAP (Transport Service Access Point). 1100 0010 (c2 / 194) for  the  identifier  of  the Called TSAP.
iso_parameter_code3 = int_to_bytes_1(192)
#Lengt of next parameter
iso_parameter_length3 = int_to_bytes_1(1)
#Proposed TPDU (Transaction Protocol Data Unit) Size
iso_tpdu_size = int_to_bytes_1(10)

#Compile Raw part of ISO_8073 package
ISO_8073 = iso_length + iso_pdu_type + iso_tpdu_number + iso_dest_ref + iso_src_ref + iso_class + iso_parameter_code + iso_parameter_length + iso_source_tsap1 + iso_source_tsap2 + iso_parameter_code2 + iso_parameter_length2 + iso_dest_tsap1 + iso_dest_tsap2 + iso_parameter_code3 + iso_parameter_length3 + iso_tpdu_size



#=========================================================
#SiemensS7
#https://packages.zeek.org/packages/view/ae81d07d-389a-11ed-ba82-0a598146b5c6
#http://gmiru.com/article/s7comm/
#http://gmiru.com/article/s7comm-part2/
#http://gmiru.com/resources/s7proto/constants.txt
#https://github.com/gymgit/s7-pcaps

#Special communication processors for the S7-400 series (CP 443) may use this protocol without the TCP/IP layers.
#The protocol is used by Siemens since the Simatic S7 product series was launched in 1994. The protocol is also used on top of other physical/network layers, like RS-485 with MPI (Multi-Point-Interface) or Profibus.

#To establish a connection to a S7 PLC there are 3 steps:
#1. Connect to PLC on TCP port 102 (uses the IP address of the PLC/CP)
#2. Connect on ISO layer (COTP Connect Request) (as a destination TSAP of two bytes length. The first byte of the destination TSAP codes the communication type (1=PG, 2=OP). The second byte of the destination TSAP codes the rack and slot number: This is the position of the PLC CPU. The slot number is coded in Bits 0-4, the rack number is coded in Bits 5-7.)
#3. Connect on S7comm layer (s7comm.param.func = 0xf0, Setup communication)

#S7 communication consists of (at least) the following protocols:
#COTP: ISO 8073 COTP Connection-Oriented Transport Protocol (spec. available as RFC905)
#TPKT: RFC1006 "ISO transport services on top of the TCP: Version 3", updated by RFC2126
#TCP: Typically, TPKT uses TCP as its transport protocol. The well known TCP port for TPKT traffic is 102. Keep in mind a 3-way handshake is needed before communication takes place. To start communicating commands an S7COMM "Setup Communication" command must be negotiated as well before sending commands.


"""
### = Step7 EXAMPLES = ###

#First perform a valid 3-way handshake
#Close the TCP stream with a FIN or RST package

#EXAMPLE - "Setup Step7 Communication Channel (after 3-way handshake)"
#TPKT
tpkt_version = int_to_bytes_1(3)
tpkt_reserved = int_to_bytes_1(0)
tpkt_spacer = int_to_bytes_1(0)
tpkt_length = int_to_bytes_1(25)

#Compile Raw part of the TPKT package
TPKT = tpkt_version + tpkt_reserved + tpkt_spacer + tpkt_length

#===================================
#ISO_8073
iso_length = int_to_bytes_1(2)
iso_pdu_type = int_to_bytes_1(240)
iso_tpdu_number = int_to_bytes_1(128)

#Compile Raw part of ISO_8073 package
ISO_8073 = iso_length + iso_pdu_type + iso_tpdu_number

#===================================
#STEP7
s7_protocol_id = int_to_bytes_1(50)
s7_rosctr = int_to_bytes_1(1)
s7_red_id = int_to_bytes_2(0)
s7_protocol_dataunit_ref = int_to_bytes_2(8449)
s7_param_length_pt1 = int_to_bytes_1(0)
s7_param_length_pt2 = int_to_bytes_1(8)
s7_data_length_pt1 = int_to_bytes_1(0)
s7_data_length_pt2 = int_to_bytes_1(0)
s7_function = int_to_bytes_1(240)
s7_reserved = int_to_bytes_1(0)
s7_max_amq_calling = int_to_bytes_2(1)
s7_max_amq_called = int_to_bytes_2(2)
s7_pdu_length = int_to_bytes_2(240)

#Compile Raw part of the Siemens S7 package
SiemensS7 = s7_protocol_id + s7_rosctr + s7_red_id + s7_protocol_dataunit_ref + s7_param_length_pt1 + s7_param_length_pt2 + s7_data_length_pt1 + s7_data_length_pt2 + s7_function + s7_reserved + s7_max_amq_calling + s7_max_amq_called + s7_pdu_length#+ s7_item_count + s7_variable_specification + s7_length_next + s7_syntaxid + s7_transportsize + s7_length_next_address_spec + s7_db_nr + s7_area_data_blocks + s7_address_pt1 + s7_address_pt2 + s7_address_pt3 + s7_return_code + s7_transport_size + s7_item_length + s7_item_data


#EXAMPLE - "Write data"
#TPKT
tpkt_version = int_to_bytes_1(3)
tpkt_reserved = int_to_bytes_1(0)
tpkt_spacer = int_to_bytes_1(0)
tpkt_length = int_to_bytes_1(36)

#Compile Raw part of the TPKT package
TPKT = tpkt_version + tpkt_reserved + tpkt_spacer + tpkt_length

#===================================
#ISO_8073
iso_length = int_to_bytes_1(2)
iso_pdu_type = int_to_bytes_1(240)
iso_tpdu_number = int_to_bytes_1(128)

#Compile Raw part of ISO_8073 package
ISO_8073 = iso_length + iso_pdu_type + iso_tpdu_number

#===================================
#STEP7
s7_protocol_id = int_to_bytes_1(50)
s7_rosctr = int_to_bytes_1(1)
s7_red_id = int_to_bytes_2(0)
s7_protocol_dataunit_ref1 = int_to_bytes_1(1)
s7_protocol_dataunit_ref2 = int_to_bytes_1(2)
s7_param_length_pt1 = int_to_bytes_1(0)
s7_param_length_pt2 = int_to_bytes_1(14)
s7_data_length_pt1 = int_to_bytes_1(0)
s7_data_length_pt2 = int_to_bytes_1(5)
s7_function = int_to_bytes_1(5)
s7_item_count = int_to_bytes_1(1)
#Item
s7_variable_specification = int_to_bytes_1(18)
s7_length_next = int_to_bytes_1(10)
s7_syntaxid = int_to_bytes_1(16)
s7_transportsize = int_to_bytes_1(1)
s7_length_next_address_spec = int_to_bytes_2(1)
s7_db_nr = int_to_bytes_2(1)
s7_area_data_blocks = int_to_bytes_1(132)
s7_address_pt1 = int_to_bytes_1(0)
s7_address_pt2 = int_to_bytes_1(0)
s7_address_pt3 = int_to_bytes_1(0)
#Data
s7_return_code = int_to_bytes_1(255)
s7_transport_size = int_to_bytes_1(3)
s7_item_length = int_to_bytes_2(1)
s7_item_data = int_to_bytes_1(1)

#Compile Raw part of the Siemens S7 package
SiemensS7 = s7_protocol_id + s7_rosctr + s7_red_id + s7_protocol_dataunit_ref1 + s7_protocol_dataunit_ref2 + s7_param_length_pt1 + s7_param_length_pt2 + s7_data_length_pt1 + s7_data_length_pt2 + s7_function + s7_item_count + s7_variable_specification + s7_length_next + s7_syntaxid + s7_transportsize + s7_length_next_address_spec + s7_db_nr + s7_area_data_blocks + s7_address_pt1 + s7_address_pt2 + s7_address_pt3 + s7_return_code + s7_transport_size + s7_item_length + s7_item_data


#EXAMPLE - "Read data"
#TPKT
tpkt_version = int_to_bytes_1(3)
tpkt_reserved = int_to_bytes_1(0)
tpkt_spacer = int_to_bytes_1(0)
tpkt_length = int_to_bytes_1(31)

#Compile Raw part of the TPKT package
TPKT = tpkt_version + tpkt_reserved + tpkt_spacer + tpkt_length

#===================================
#ISO_8073
iso_length = int_to_bytes_1(2)
iso_pdu_type = int_to_bytes_1(240)
iso_tpdu_number = int_to_bytes_1(128)

#Compile Raw part of ISO_8073 package
ISO_8073 = iso_length + iso_pdu_type + iso_tpdu_number

#===================================
#STEP7
s7_protocol_id = int_to_bytes_1(50)
s7_rosctr = int_to_bytes_1(1)
s7_red_id = int_to_bytes_2(0)
s7_protocol_dataunit_ref = int_to_bytes_2(258)
s7_param_length_pt1 = int_to_bytes_1(0)
s7_param_length_pt2 = int_to_bytes_1(14)
s7_data_length_pt1 = int_to_bytes_1(0)
s7_data_length_pt2 = int_to_bytes_1(0)
s7_function = int_to_bytes_1(4)
s7_item_count = int_to_bytes_1(1)
#Item
s7_variable_specification = int_to_bytes_1(18)
s7_length_next = int_to_bytes_1(10)
s7_syntaxid = int_to_bytes_1(16)
s7_transportsize = int_to_bytes_1(1)
s7_length_next_address_spec = int_to_bytes_2(1)
s7_db_nr = int_to_bytes_2(1)
s7_area_data_blocks = int_to_bytes_1(132)
s7_address_pt1 = int_to_bytes_1(0)
s7_address_pt2 = int_to_bytes_1(0)
s7_address_pt3 = int_to_bytes_1(0)

#Compile Raw part of the Siemens S7 package
SiemensS7 = s7_protocol_id + s7_rosctr + s7_red_id + s7_protocol_dataunit_ref + s7_param_length_pt1 + s7_param_length_pt2 + s7_data_length_pt1 + s7_data_length_pt2 + s7_function + s7_item_count + s7_variable_specification + s7_length_next + s7_syntaxid + s7_transportsize + s7_length_next_address_spec + s7_db_nr + s7_area_data_blocks + s7_address_pt1 + s7_address_pt2 + s7_address_pt3

### = END Step7 EXAMPLES = ###
"""


#Header
#Protocol (S7) identifier
s7_protocol_id = int_to_bytes_1(50)
#Remote Operating Service Control - Message type. 1 = 0x01-Job Request (send by the master (e.g. read/write memory, read/write blocks, start/stop device, setup communication)) - 2 = 0x02-Ack: simple acknowledgement sent by the slave with no data field - 3 = 0x03-Ack-Data: acknowledgement with optional data field, contains the reply to a job request - 7 = 0x07-Userdata: an extension of the original protocol, the parameter field contains the request/response id, (used for programming/debugging, SZL reads, security functions, time setup, cyclic read..)
s7_rosctr = int_to_bytes_1(1)
#Value that will always be 0
s7_red_id = int_to_bytes_2(0)
#Reference ID Used to Link Requests to Responses. Generated by the master, incremented with each new transmission, used to link responses to their requests. The PLC just copies it to the reply
s7_protocol_dataunit_ref = int_to_bytes_2(8449)
#The length of the parameter field, Big-Endian
s7_param_length_pt1 = int_to_bytes_1(0)
s7_param_length_pt2 = int_to_bytes_1(8)
#The length of the data field, Big-Endian
s7_data_length_pt1 = int_to_bytes_1(0)
s7_data_length_pt2 = int_to_bytes_1(0)
#Parameter (if needed) - 4 = Read Var - 5 = Write Var - 26 = Request Download - 27 = Download block - 28 = Download Ended - 29 = Start Upload - 30 = Upload - 31 = End Upload - 40 = PI Service - 41 = PLC Stop - 240 = Setup Communication
s7_function = int_to_bytes_1(240)
#Always 0
s7_reserved = int_to_bytes_1(0)
#Define how many unacknowledged requests a PLC (Callee) is able to accept from a client (Caller)
s7_max_amq_calling = int_to_bytes_2(1)
#Define how many unacknowledged requests the PLC (Callee) has accepted from the client (Caller)
s7_max_amq_called = int_to_bytes_2(2)
#Proposed PDU (Protocol Data Unit) Size
s7_pdu_length = int_to_bytes_2(240)

#Use below only when needed
"""
#The numbers of items
s7_item_count = int_to_bytes_1(1)
#This field determines the main type of the item struct, for read/write messages it always has the value 0x12 which stands for Variable Specification.
s7_variable_specification = int_to_bytes_1(18)
#This field determines the addressing mode and the format of the rest of the item structure. It has the constant value of 0x10 (16 decimal) for the any-type addressing.
s7_syntaxid = int_to_bytes_1(16)
#The type of the variable determines its length and how it should be interpreted. 
#BIT:[X] a single bit.
#WORD: two bytes wide unsigned integer.
#DINT: four bytes wide signed integer.
#REAL: four bytes wide IEEE floating point number.
#COUNTER: counter type used by the PLC program counters.
#An example address of a variable is "DB123X 2.1" which accesses the second bit (1) of the third byte (2) of the Data Block 123. In that case this value will be "1" = BIT.
s7_transportsize = int_to_bytes_1(1)
#Length of the following parameters that form the address
s7_length_next_address_spec = int_to_bytes_2(1)
#The database that is being targets. Usually there is 1 database.
s7_db_nr = int_to_bytes_2(1)
#Defines the type of memory area
#0x03 - System info of S200 family
#0x05 - System flags of S200 family
#0x06 - Analog inputs of S200 family
#0x07 - Analog outputs of S200 family
#0x1C - S7 counters (C)
#0x1D - S7 timers (T)
#0x1E - IEC counters (200 family)
#0x1F - IEC timers (200 family)
#0x80 - Direct peripheral access (P)
#0x81 - Inputs (I)
#0x82 - Outputs (Q)
#0x83 - Flags (M) (Merker)
#0x84 - Data blocks (DB)
#0x85 - Instance data blocks (DI)
#0x86 - Local data (L)
#0x87 - Unknown yet (V)
s7_area_data_blocks = int_to_bytes_1(132)
#contains the offset of the addressed variable in the selected memory area. Essentially, the addresses are translated to bit offsets and encoded on 3 bytes in network (big endian) byte order. In practice, the most significant 5 bits are never used since the address space is smaller than that. As an example DBX40.3 would be 0x000143 which is 40 * 8 + 3.
s7_address_pt1 = int_to_bytes_1(0)
s7_address_pt2 = int_to_bytes_1(0)
s7_address_pt3 = int_to_bytes_1(0)
#Data
#Tells if data is being returned or not. 0xFF means ok, data follows after this header. Other codes give reasons why no data is returned.
s7_return_code = int_to_bytes_1(255)
#Size of the next transport block
s7_transport_size = int_to_bytes_1(3)
#Size of the data
s7_item_length = int_to_bytes_2(1)
#The final data / values
s7_item_data = int_to_bytes_1(1)

#For setting up a communication channel
#Always set to 0
s7_reserved = int_to_bytes_1(0)
#Define how many unacknowledged requests a PLC (Callee) is able to accept from a client (Caller)
s7_max_amq_calling = int_to_bytes_2(1)
#Define how many unacknowledged requests the PLC (Callee) has accepted from the client (Caller)
s7_max_amq_called = int_to_bytes_2(2)
#Proposed PDU (Protocol Data Unit) Size
s7_pdu_length = int_to_bytes_2(240)

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

#When reading a variable
#This field determines the addressing mode and the format of the rest of the item structure. It has the constant value of 0x10 (16 decimal) for the any-type addressing.
s7_syntaxid = int_to_bytes_1(16)
#The type of the variable determines its length and how it should be interpreted. 
#BIT:[X] a single bit.
#WORD: two bytes wide unsigned integer.
#DINT: four bytes wide signed integer.
#REAL: four bytes wide IEEE floating point number.
#COUNTER: counter type used by the PLC program counters.
#An example address of a variable is "DB123X 2.1" which accesses the second bit (1) of the third byte (2) of the Data Block 123. In that case this value will be "1" = BIT.
s7_transportsize = int_to_bytes_1(1)
#Length of the following parameters that form the address
s7_length_next_address_spec = int_to_bytes_2(1)
#The database that is being targets. Usually there is 1 database.
s7_db_nr = int_to_bytes_2(1)
#Defines the type of memory area
#0x03 - System info of S200 family
#0x05 - System flags of S200 family
#0x06 - Analog inputs of S200 family
#0x07 - Analog outputs of S200 family
#0x1C - S7 counters (C)
#0x1D - S7 timers (T)
#0x1E - IEC counters (200 family)
#0x1F - IEC timers (200 family)
#0x80 - Direct peripheral access (P)
#0x81 - Inputs (I)
#0x82 - Outputs (Q)
#0x83 - Flags (M) (Merker)
#0x84 - Data blocks (DB)
#0x85 - Instance data blocks (DI)
#0x86 - Local data (L)
#0x87 - Unknown yet (V)
s7_area_data_blocks = int_to_bytes_1(132)
#contains the offset of the addressed variable in the selected memory area. Essentially, the addresses are translated to bit offsets and encoded on 3 bytes in network (big endian) byte order. In practice, the most significant 5 bits are never used since the address space is smaller than that. As an example DBX40.3 would be 0x000143 which is 40 * 8 + 3.
s7_address_pt1 = int_to_bytes_1(0)
s7_address_pt2 = int_to_bytes_1(0)
s7_address_pt3 = int_to_bytes_1(0)
"""

#Compile Raw part of the Siemens S7 package
SiemensS7 = s7_protocol_id + s7_rosctr + s7_red_id + s7_protocol_dataunit_ref + s7_param_length_pt1 + s7_param_length_pt2 + s7_data_length_pt1 + s7_data_length_pt2 + s7_function + s7_reserved + s7_max_amq_calling + s7_max_amq_called + s7_pdu_length#+ s7_item_count + s7_variable_specification + s7_length_next + s7_syntaxid + s7_transportsize + s7_length_next_address_spec + s7_db_nr + s7_area_data_blocks + s7_address_pt1 + s7_address_pt2 + s7_address_pt3 + s7_return_code + s7_transport_size + s7_item_length + s7_item_data



######## DEFINE THE CUSTOM PAYLOAD (RAW PACKAGE) ########

#Payload - Define what protocol to send as raw data
payload =  TPKT + ISO_8073 + SiemensS7 + Profinet + Modbus



######## REGULAR PACKET LAYERS (NON-RAW) ########

"""
#BASIC VALUES (in case of deletion)
l1 = Ether(dst=destination_mac,
        src=source_mac,
        #Profinet = 0x8892 (34962 in decimal) - Note that “Profinet cyclic realtime” and “Profinet acyclic realtime” run directly on Ethernet layer 2 (they do not use IP or UDP), so no manual l2 or l3.
        type=34962
     )
#IP
l3 = IP(version=4, 
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
l4 = TCP(sport=source_port,
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
"""

#Ethernet
l1 = Ether(dst=destination_mac,
        src=source_mac,
        #Profinet = 0x8892 (34962 in decimal) - Note that “Profinet cyclic realtime” and “Profinet acyclic realtime” run directly on Ethernet layer 2 (they do not use IP or UDP), so no manual l2 or l3.
        #type=34962
     )
#IP
l3 = IP(#version=4,
        flags=2,
        proto=6,
        #id=8000,
        src=source_ip,
        dst=destination_ip
     )
#TCP
#tcp_options = [("MSS" , 1460),('Timestamp', (1098453, 0)),("NOP",None),("WScale",2),("NOP",None),("NOP",None),("SAckOK","")]
tcp_options = [("MSS" , 1460),("SAckOK",""),('Timestamp', (4294901862, 0)),("NOP",None),("WScale",0)]
l4 = TCP(sport=source_port,
        dport=destination_port,
        #seq=920,
        #ack=570,
        #dataofs=5,
        #reserved=0,
        flags='PA',
        #window=3151,
        #chksum=0x9cbc,
        urgptr=0,
        #options=tcp_options
     )
#RAW
lRaw = raw = Raw(load = payload)



######## PACKET CONSTRUCTION ########
if layer == "layer1" and manual_layer_3 == 1 and manual_layer_4 == 1 and manual_layer_raw == 1:
        packet = l1 / l3 / l4 / lRaw
if layer == "layer1" and manual_layer_3 == 1 and manual_layer_4 == 0 and manual_layer_raw == 1:
        packet = l1 / l3 / lRaw
if layer == "layer1" and manual_layer_3 == 1 and manual_layer_4 == 1 and manual_layer_raw == 0:
        packet = l1 / l3 / l4
if layer == "layer1" and manual_layer_3 == 1 and manual_layer_4 == 0 and manual_layer_raw == 0:
        packet = l1 / l3
if layer == "layer1" and manual_layer_3 == 0 and manual_layer_4 == 1 and manual_layer_raw == 1:
        packet = l1 / l4 / lRaw
if layer == "layer1" and manual_layer_3 == 0 and manual_layer_4 == 0 and manual_layer_raw == 1:
        packet = l1 / lRaw
if layer == "layer1" and manual_layer_3 == 0 and manual_layer_4 == 1 and manual_layer_raw == 0:
        packet = l1/ l4
if layer == "layer1" and manual_layer_3 == 0 and manual_layer_4 == 0 and manual_layer_raw == 0:
        packet = l1

if layer == "layer3" and manual_layer_4 == 1 and manual_layer_raw == 1:
        packet = l3 / l4 / lRaw
if layer == "layer3" and manual_layer_4 == 1 and manual_layer_raw == 0:
        packet = l3 / l4
if layer == "layer3" and manual_layer_4 == 0 and manual_layer_raw == 1:
        packet = l3 / lRaw
if layer == "layer3" and manual_layer_4 == 0 and manual_layer_raw == 0:
        packet = l3



######## SHOW AND SEND PACKET(S) ########
#Show packet
print("=== THIS PACKET IS GENERATED AND SEND ===")
packet.show2()

def thread_sendp(name):
        sendp(packet,iface=send_interface)

def thread_send(name):
        send((packet),iface=send_interface)

#Send Packet
#Layer1 (control layer 1)
if layer == "layer1" and loop == 0:
        sendp(packet,iface=send_interface)
if layer == "layer1" and loop == 1:
        if threaded == 1:
                #Send threaded packet
                for index in range(nr_of_threads):
                        ts = threading.Thread(target=thread_sendp, args=(1,))
                        ts.start()
        else:
                #Just loop the packet
                sendp(packet,iface=send_interface, loop=1)

#Layer3 (automatic layer 1)
if layer == "layer3" and loop == 0:
        send((packet),iface=send_interface)
if layer == "layer3" and loop == 1:
        if threaded == 1:
                #Send threaded packet
                for index in range(nr_of_threads):
                        ts = threading.Thread(target=thread_send, args=(1,))
                        ts.start()
        else:
                #Just loop the packet
                send((packet),iface=send_interface, loop=1)
                


######## PACKET SNIFFING ########
def customSniffAction(packet):
        packet.show2()

if sniffing == 1:
        print("=== SNIFFED PACKAGES (MAX = " + str(nr_of_packets_to_sniff) + " PACKET) ===")
        capture = sniff(filter="ether src host " + destination_mac, prn=customSniffAction, count=nr_of_packets_to_sniff)

        if store_sniffed_packets == 1:
                wrpcap(store_location, capture)
