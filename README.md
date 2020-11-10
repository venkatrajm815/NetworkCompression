# NetworkCompression

This project is composed of two network applications- one running on a host server and one running on a client server- that detects network compression. This also includes a standalone application that can work in a noncomplient enviroment.

## Requirements

This requires a Linux VM, as well as libjson and pcap. You may obtain libjson and pcap by running sudo apt install libjson-c-dev and sudo apt-get install libpcap0.8-dev, respectivly.

## How to Run 

First, the JSON files must be properly edited. The JSON file contains configuration information for the network. Most specifically, the IP address must be set to the ip of the host vm. 

Then, compile using the following commnds: 

* gcc server.c -ljson-c -Wall -o server

on the host vm, and 

* gcc client.c -ljson-c -Wall -o client

on the client. 

To run the applications, use the following commands:

* ./server myconfig.json 

in the host vm, and

* ./client myconfig.json 

on the client VM immediatly after one another.

## Issues

Firstly, standalone is not finished. The code does not capture socket information properly, but sends packets correctly. 

Secondly, there are occasions when the code compiles, but doesn't work as intended when on different VMs. We are not sure what the problem with it is, but it might come from the fact that the IP addresses are sent improperly, or from the junk data in the JSON files after it compiles.

## Authors
Briant Shen
Venkatraj Mohan
