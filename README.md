# PacketSnifferForLinux
Listen to your default NIC and decode/display packet information with filters for protocols and ip

This program will listen to your default NIC and decode and display packet information.
Currently there are two filters for packet display, protocol and ip filters.
-i [ip] will filter packets for only packets with destination ip [ip]
-p [protocol] will filter pckets for only packets of protocol [protocol] (currently only filters TCP, UDP, ICP, and ARP)

Most of the code is within network.h, ipraw.c only parses user input and works mainly as a driver for network.h

Complied and tested with gcc version (Debian 5.3.1-10) 5.3.1
