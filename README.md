# Spot_PacketSniffer
It's Spot, the commandline packet sniffer. _ha ha get it_

## Why am I doing this? 
I got curious over how wireshark worked after trying to use wireshark with my tcp proxy. 

## Libraries
libpcap - Developed this on an ubuntu vm, since I didn't want to use winpcap 

## Compile
gcc -o sniffer main.c -l pcap
_until I put in a makefile which will be soon_

