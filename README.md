# NetworkCompression

The goal of this project was to detect if network compression is present on a network path. This project is composed of two network applications - First one is a Client/Server Application and the Second one is a Standalone Application that can work work on any noncomplient environment.

## Requirements

This project requires a Linux VM, as well as some installations such as git, libjson, pcap, and WireShark if you want to capture the packets by yourself.
Here are some commands you can use:
* sudo apt install git
* sudo apt install libjson-c-dev
* sudo apt-get install libpcap0.9-dev
* sudo apt install wireshark


## How to Run 

Before running the applications either on the client side or server side, you must change the myconfig.json to suit your network details. For example, the IP address must be set to the IPv4 address of the server. 

After completing that step, you will have clone the project repository into both of your virtual machines using the command below:

* git clone "repo_name"

Then, to compile on the server and client VMs use the following commands, respectively: 

* gcc server.c -ljson-c -Wall -o server

* gcc client.c -ljson-c -Wall -o client


Finally, to run the applications on server and client VMS use the following commands, respectively:

* ./server myconfig.json 

* ./client myconfig.json 

After doing that, the client and server will output messages showing if there was a network compression detected or not.
You can also capture the packets using Wireshark and see how the packets are being sent to the server VM.

When using the standalone application, the steps on similar, you will use the following commands:

To compile:

* gcc standalone.c -lpcap -ljson-c -Wall -o standalone

To run:

* sudo ./standalone myconfig.json 

## Issues

Firstly, standalone is not finished. The code does not capture socket information properly, but sends packets correctly. 

Secondly, there are occasions when the code compiles, but doesn't work as intended when on different VMs. We are not sure what the problem with it is, but it might come from the fact that the IP addresses are sent improperly, or from the junk data in the JSON files after it compiles.

## Authors
Briant Shen

Venkatraj Mohan
