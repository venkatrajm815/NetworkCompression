#ifndef _UTIL_H_
#define _UTIL_H_

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h> 
#include <netinet/udp.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <time.h> 
#include <ctype.h>
#include <json-c/json.h>
#include <pcap.h>
#include <sys/ioctl.h> 
#include <netinet/ip.h>
#include <net/if.h>

uint16_t checksum(uint16_t *addr, int len);
uint16_t udp4_checksum(struct ip iphdr, struct udphdr udphdr, uint8_t *payload, int payloadlen);
uint16_t tcp4_checksum (struct ip iphdr, struct tcphdr tcphdr);
char * allocate_strmem(int len);
uint8_t * allocate_ustrmem(int len);
int * allocate_intmem(int len);
void receiveFile(int sockfd);
void highEntropy(int *data, int length);
void lowentropy(int *data, int length);
void setpacketid(int *data, int index);
void sendfile(int sockfd);
#endif
