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

#define BUFFER_SIZE 2000
#define THRESHOLD 100

uint16_t sumIP(uint16_t *address, int length);
uint16_t sumUDP(struct ip ip, struct udphdr udphdr, uint8_t *payload, int payloadlen);
uint16_t sumTCP(struct ip ip, struct tcphdr tcp);
char * allocateMemChar(int length);
uint8_t * allocateMemUnsChar(int length);
int * allocate_intmem(int len);
void receiveFile(int sockfd);
void highEntropy(int *data, int length);
void lowentropy(int *data, int length);
void setpacketid(int *data, int index);
void sendfile(int sockfd);
#endif
