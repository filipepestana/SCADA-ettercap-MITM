# SCADA-ettercap-MITM
Ettercap plugins for DNP3 and IEC 60870-5-104

### Disclaimer
These ettercap plugins were developed for educational purposes ONLY,  to show how packets of the most popular SCADA communication protocols (IEC 104 and DNP3) can be modified. Do not use it without the permission of the SCADA's owner or for malicious purposes.

### References:

PMaynard's [104_spoof](https://github.com/PMaynard/ettercap-104-mitm/blob/master/plug-ins/104_spoof/104_spoof.c "Ettercap 104 MITM") used in [Towards Understanding Man-In-The-Middle Attacks on IEC 60870-5-104 SCADA Networks](https://ewic.bcs.org/content/ConWebDoc/53228)

[Ettercap Project](https://github.com/Ettercap/ettercap/ "Ettercap Project"):

* [dummy.c](https://github.com/Ettercap/ettercap/blob/master/plug-ins/dummy/dummy.c "Dummy plugin") plugin
* [find_ettercap.c](https://github.com/Ettercap/ettercap/blob/master/plug-ins/find_ettercap/find_ettercap.c "Find ettercap plugin") plugin
* [arp_cop.c](https://github.com/Ettercap/ettercap/blob/master/plug-ins/arp_cop/arp_cop.c "Arp plugin") plugin
* [ec_packet.h](https://github.com/Ettercap/ettercap/blob/master/include/ec_packet.h "Ettercap packet") - Packet object structure
* [ec_set.c](https://github.com/Ettercap/ettercap/blob/master/src/ec_set.c "Ettercap flags") - Ettercap flags
