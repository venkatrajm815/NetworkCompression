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
#include "util.h"

//standalone util funcs

//Creating number for IP header
uint16_t sumIP(uint16_t *address, int length) {
    int count = length;
    register uint32_t total = 0;
    uint16_t toreturn = 0;

    while(count > 1){
        total += *(address++); 
        count -= 2;
    }

    if(count > 0) {
        total += *(uint8_t *)address;
    }

    while (total >> 16) {
        total = (total & 0xffff) + (total >> 16);
    }
    toreturn = ~total;
    return (toreturn);
}

//Creating number for udp header
uint16_t sumUDP(struct ip ip, struct udphdr udphdr, uint8_t *payload, int payloadlen) {
    char BUFFER[IP_MAXPACKET];
    char *ptr;
    int len = 0;
    ptr = &BUFFER[0]; 

    //Enter 32 bit src IP addr into buffer
    memcpy (ptr, &ip.ip_src.s_addr, sizeof (ip.ip_src.s_addr));
    ptr += sizeof (ip.ip_src.s_addr);
    len += sizeof (ip.ip_src.s_addr);

    //Enter 32 bit dest IP addr into buffer
    memcpy (ptr, &ip.ip_dst.s_addr, sizeof (ip.ip_dst.s_addr));
    ptr += sizeof (ip.ip_dst.s_addr);
    len += sizeof (ip.ip_dst.s_addr);

    *ptr = 0; ptr++;
    len += 1;

    memcpy (ptr, &ip.ip_p, sizeof (ip.ip_p));
    ptr += sizeof (ip.ip_p);
    len += sizeof (ip.ip_p);

    memcpy (ptr, &udphdr.len, sizeof (udphdr.len));
    ptr += sizeof (udphdr.len);
    len += sizeof (udphdr.len);

    memcpy (ptr, &udphdr.source, sizeof (udphdr.source));
    ptr += sizeof (udphdr.source);
    len += sizeof (udphdr.source);

    memcpy (ptr, &udphdr.dest, sizeof (udphdr.dest));
    ptr += sizeof (udphdr.dest);
    len += sizeof (udphdr.dest);

    memcpy (ptr, &udphdr.len, sizeof (udphdr.len));
    ptr += sizeof (udphdr.len);
    len += sizeof (udphdr.len);

    *ptr = 0; ptr++;
    *ptr = 0; ptr++;
    len += 2;

    memcpy (ptr, payload, payloadlen);
    ptr += payloadlen;
    len += payloadlen;

    return sumIP ((uint16_t *) BUFFER, len);
}

//Creating unique IP for tcp header
uint16_t sumTCP (struct ip ip, struct tcphdr tcp)
{
    char *ptr;
    uint16_t svalue;
    char BUFFER[IP_MAXPACKET], cvalue;
     ptr = &BUFFER[0];
    int len = 0;

    memcpy (ptr, &ip.ip_src.s_addr, sizeof (ip.ip_src.s_addr));
    ptr += sizeof (ip.ip_src.s_addr);
    len += sizeof (ip.ip_src.s_addr);

    memcpy (ptr, &ip.ip_dst.s_addr, sizeof (ip.ip_dst.s_addr));
    ptr += sizeof (ip.ip_dst.s_addr);
    len += sizeof (ip.ip_dst.s_addr);

    *ptr = 0; 
    ptr++;
    len += 1;

    memcpy (ptr, &ip.ip_p, sizeof (ip.ip_p));
    ptr += sizeof (ip.ip_p);
    len += sizeof (ip.ip_p);

    svalue = htons (sizeof (tcp));
    memcpy (ptr, &svalue, sizeof (svalue));
    ptr += sizeof (svalue);
    len += sizeof (svalue);

    memcpy (ptr, &tcp.th_sport, sizeof (tcp.th_sport));
    ptr += sizeof (tcp.th_sport);
    len += sizeof (tcp.th_sport);

    memcpy (ptr, &tcp.th_dport, sizeof (tcp.th_dport));
    ptr += sizeof (tcp.th_dport);
    len += sizeof (tcp.th_dport);

    memcpy (ptr, &tcp.th_seq, sizeof (tcp.th_seq));
    ptr += sizeof (tcp.th_seq);
    len += sizeof (tcp.th_seq);

    memcpy (ptr, &tcp.th_ack, sizeof (tcp.th_ack));
    ptr += sizeof (tcp.th_ack);
    len += sizeof (tcp.th_ack);

    cvalue = (tcp.th_off << 4) + tcp.th_x2;
    memcpy (ptr, &cvalue, sizeof (cvalue));
    ptr += sizeof (cvalue);
    len += sizeof (cvalue);

    memcpy (ptr, &tcp.th_flags, sizeof (tcp.th_flags));
    ptr += sizeof (tcp.th_flags);
    len += sizeof (tcp.th_flags);

    memcpy (ptr, &tcp.th_win, sizeof (tcp.th_win));
    ptr += sizeof (tcp.th_win);
    len += sizeof (tcp.th_win);
    return sumIP((uint16_t *) BUFFER, len);
}

//Create an array of unsigned char
char * allocateMemChar(int length){
    if (length <= 0) {
        fprintf(stderr, "ERROR: Cannot allocate memory. Length is %i\n", length);
        exit(EXIT_FAILURE);
    }

    void *temp;
    temp = (char *)malloc(length * sizeof (char));
    if(temp == NULL){
        fprintf (stderr, "ERROR: Memory failled to allocate.\n");
        exit(EXIT_FAILURE);
    } else {
        memset(temp, 0, length * sizeof (char));
        return(temp);
    }
}

//Create an array of unsigned char
uint8_t * allocateMemUnsChar(int length){
    if (length <= 0) {
        fprintf(stderr, "ERROR: Cannot allocate memory. Length is %i\n", length);
        exit(EXIT_FAILURE);
    }

    void *temp;
    temp = (uint8_t *) malloc(length*sizeof(uint8_t));
    if(temp == NULL){
        fprintf (stderr, "ERROR: Memory failled to allocate.\n");
        exit(EXIT_FAILURE);
    } else {
        memset(temp, 0, length * sizeof (char));
        return(temp);
    }
}

//Create an array of ints
int * allocateMemInt(int length) {
    if (length <= 0) {
        fprintf (stderr, "ERROR: Length is %i\n", length);
        exit(EXIT_FAILURE);
    }
    void *temp;
    temp = (int *) malloc(length*sizeof(int));

    if(temp == NULL){
        fprintf (stderr, "ERROR: Memory failled to allocate.\n");
        exit(EXIT_FAILURE);
    } else {
        memset(temp, 0, length * sizeof (char));
        return(temp);
    }
}


//client util funcs
//This method is responsible for the filling with the high entropy data
void highEntropy(int *data, int length){
    FILE *f = fopen("/dev/urandom", "r");
    int temp;
    if(f == NULL){
        return;
    }
    for(int i = 2; i < length; i++){
        temp = (int) getc(f);
        data[i] = temp;
    }
}

//This method is responsible for the filling with the low entropy data
void lowentropy(int *data, int length){
    for(int i = 2; i < length; i++) {
        data[i] = 0;
    }
}

//This method is responsible for setting the id for the packets
void setpacketid(int *data, int index){
    unsigned int temp = index;
    unsigned char lower = (unsigned)temp & 0xff;
    unsigned char upper = (unsigned)temp >> 8; 
    data[0] = lower; //this is to set the first index to 'lower bit'
    data[1] = upper; //this is to set the first index to 'upper bit'
}

//This method sends the file using sockets
void sendfile(int sockfd){ 
    char buffer[BUFFER_SIZE];
    FILE *fp = fopen("myconfig.json","r");
    while (fgets(buffer, BUFFER_SIZE, fp) != NULL){
        write(sockfd,buffer,strlen(buffer));
    }   
    fclose(fp);
    printf("File sent.\n");
}
