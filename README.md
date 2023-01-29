# ICS-Payload
A combination of Python scripts for working with ICS/SCADA (IA / PA / IoT) related protocols.

The "ics-payload.py" Python Script is the master script. This file allows you to send 1 custom package and holds all knowledge and a few examples for sending those packages en explaining all the package section. "ics-payload.py" in essence allows you to create custom network packages using Scapy. You can controll every aspect of the packages. Like in normal "Scapy" operation you can controll the "known" transport layers like Ethernet, IP, IPv4 etc. But this script defines some ICS/SCADA protocols giving you the ability to add the ICS/SCADA packages as a raw payload but still be able to alter and define every segment of the ICS/SCADA package. This way you can send custom packages to ICS/SCADA devices (that use Ethernet, IP or TCP as a transport layer) and controll these devices.

Besides the master script a few other example scripts are included that "tap" from the knowledge of the masterfile (ics-payload.py). These example show some (extended) examples.

This is a dynamic script and will be updated from time-to-time.

**Dependencies:**
- Python3
- Scapy (pip3 install Scapy)
- Threading (build in)
- BinAscii (build in)

**Like to say thanks?**
Please visit https://jarnobaselier.nl/ and find all the chanels and methods to say thank you!
