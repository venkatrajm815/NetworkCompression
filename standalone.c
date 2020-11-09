#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h> 
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include "json-c/json.h"
#include <fcntl.h>
#include <time.h>


struct ipheader {

    unsigned char      iph_ihl:5, iph_ver:4;

    unsigned char      iph_tos;

    unsigned short int iph_len;

    unsigned short int iph_ident;

    unsigned char      iph_flag;

    unsigned short int iph_offset;

    unsigned int       iph_ttl;

    unsigned char      iph_protocol;

    unsigned short int iph_chksum;

    unsigned int       iph_sourceip;

    unsigned int       iph_destip;

};

struct udpheader {
    unsigned short int udph_srcport;

    unsigned short int udph_destport;

    unsigned short int udph_len;

    unsigned short int udph_chksum;

};

struct tcpheader {

    unsigned short int tcph_srcport;

    unsigned short int tcph_destport;

    unsigned int       tcph_seqnum;

    unsigned int       tcph_acknum;

    unsigned char      tcph_reserved:4, tcph_offset:4;

    unsigned int

       tcp_res:4,

       tcph_hlen:4,     //length of tcp header

       tcph_fin:1,      //finish flag

       tcph_syn:1,       

       tcph_rst:1,      //reset flag

       tcph_psh:1,      //push

       tcph_ack:1,      //acknowledge

       tcph_urg:1;      //urgent pointer

    unsigned short int tcph_win;

    unsigned short int tcph_chksum;

    unsigned short int tcph_urgptr;

};

unsigned short csum(unsigned short *buf, int nwords) {

        unsigned long sum;

        for (sum = 0; nwords > 0; nwords--)
            sum += *buf++;

        sum = (sum >> 16) + (sum &0xffff);
        sum += (sum >> 16);

        return (unsigned short)(~sum);

}

 
int main(int argc, char **argv)
{ 
    /* JSON PARSING */

    FILE *fp;
    char BUFFER[BUFFER_SIZE];
    struct json_object *jsonParsed;
    struct json_object *serverIPAddr;
    struct json_object *srcPortNumUDP;
    struct json_object *destPortNumUDP;
    struct json_object *destPortNumTCPHead;
    struct json_object *destPortNumTCPTail; 
    struct json_object *portNumTCP;
    struct json_object *udppayload;
    struct json_object *measurementTime;
    struct json_object *udpPackets;
    struct json_object *ttlPackets;
    enum{UDP_HDRLEN=8, ICMP_HDRLEN=8, TCP_HDRLEN=20, IP4_HDRLEN=20};

   //This checks if there is an error in executing the configuration file 
    if (argv[1] == NULL){
        printf("ERROR!\nnEnter ./'application name' myconfig.json\n");
        return EXIT_FAILURE;
    }
    
     //Opening of the JSON file
    fp = fopen(argv[1], "r"); 
    if(fp == NULL) {
        printf("There is an error opening the file!\n"); 
        return EXIT_FAILURE;
    }
    printf("Parsing through file.\n");
    fread(BUFFER, BUFFER_SIZE, 1, fp); 
    jsonParsed = json_tokener_parse(BUFFER);

    json_object_object_get_ex(jsonParsed, "serverIPAddr", &serverIPAddr);
    json_object_object_get_ex(jsonParsed, "srcPortNumUDP", &srcPortNumUDP);
    json_object_object_get_ex(jsonParsed, "destPortNumUDP", &destPortNumUDP);
    json_object_object_get_ex(jsonParsed, "destPortNumTCPHead", &destPortNumTCPHead);
    json_object_object_get_ex(jsonParsed, "destPortNumTCPTail", &destPortNumTCPTail);
    json_object_object_get_ex(jsonParsed, "portNumTCP", &portNumTCP);
    json_object_object_get_ex(jsonParsed, "udppayload", &udppayload);
    json_object_object_get_ex(jsonParsed, "measurementTime", &measurementTime);
    json_object_object_get_ex(jsonParsed, "udpPackets", &udpPackets);
    json_object_object_get_ex(jsonParsed, "ttlPackets", &ttlPackets);
    printf("The Parsing is SUCCESSFUL.");

    //saving json objects
    char *serverip2 = json_object_get_string(serverIPAddr);
    int srcportudp2 = json_object_get_int(srcPortNumUDP);
    int destportudp2 = json_object_get_int(destPortNumUDP);
    char *destporttcphead2 = json_object_get_string(destPortNumTCPHead);
    char *destporttcptail2 = json_object_get_string(destPortNumTCPTail);
    char *portnumtcp2 = json_object_get_string(portNumTCP);
    int payload2 = json_object_get_int(udppayload);
    int intermtime2 = json_object_get_int(measurementTime);
    int numudppackets2 = json_object_get_int(udpPackets);
    int ttl2 = json_object_get_int(ttlPackets);

    /* JSON PARSING ENDS */

    int sd_udp, sd_tcp;

    char buffer[1000];
    char buffer2[payload2];


    //header structs
    struct ipheader *ip = (struct ipheader *) buffer;

    struct tcpheader *tcp = (struct tcpheader *) (buffer + sizeof(struct ipheader));

    struct udpheader *udp = (struct udpheader *) (buffer + sizeof(struct ipheader));
    
    struct sockaddr_in sin, din, servaddr;
 
    memset(buffer2, 0, payload2);

    //Create a raw socket with UDP protocol

    sd_udp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    if(sd_udp < 0) {
        perror("socket() error");
        exit(1);
    }

    else {
        printf("UDP raw socket established.\n");
    }


    //TCP socket
    sd_tcp = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);


    if(sd_tcp < 0) {
       perror("socket() error");
       exit(1);
    }

    else {
        printf("TCP raw socket established.\n");
    }

    int one = 1;
    const int *val = &one;

    if (setsockopt (sd_tcp, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) == 0)
    {
        printf ("Error\n");
        exit(0);
    }
 
    // The address family

    sin.sin_family = AF_INET;

    din.sin_family = AF_INET;

    // Port numbers

    sin.sin_port = htons(destPortNumTCPHead);

    din.sin_port = htons(destPortNumTCPTail);

    // IP addresses

    sin.sin_addr.s_addr = inet_addr("192.168.1.16");

    din.sin_addr.s_addr = inet_addr("192.168.1.16");


    memset(&servaddr, 0, sizeof(serverIPAddr));
    
    // Filling server information
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(destportudp2);
    servaddr.sin_addr.s_addr = inet_addr("192.168.1.16");


    /***********************************************/


    //header definitions
    ip->iph_ihl = 5;

    ip->iph_ver = 4;

    ip->iph_tos = 0;

    ip->iph_len = sizeof(struct ipheader) + sizeof(struct tcpheader);

    ip->iph_ident = htons(rand());

    ip->iph_offset = 0;

    ip->iph_ttl = ttl2;

    ip->iph_protocol = 6; //TCP

    ip->iph_chksum = 0;

    ip->iph_sourceip  = inet_addr("192.168.1.16");

    ip->iph_destip = inet_addr("192.168.1.16");


    //UDP header's structure

    udp->udph_srcport = htons(9999);

    udp->udph_destport = htons(9999);

    udp->udph_len = htons(sizeof(struct udpheader));

    udp->udph_chksum = udp->udph_chksum = csum((unsigned short *)buffer, sizeof(struct ipheader) + sizeof(struct udpheader));


    //TCP

    tcp->tcph_srcport = htons(9998);

    tcp->tcph_destport = htons(9998);

    tcp->tcph_seqnum = htonl(1);

    tcp->tcph_acknum = 0;

    tcp->tcph_offset = 5;

    tcp->tcph_syn = 1;

    tcp->tcph_ack = 0;

    tcp->tcph_rst = 0;

    tcp->tcph_fin = 0;

    tcp->tcph_win = htons(32767);

    tcp->tcph_chksum = 0;

    tcp->tcph_urgptr = 0;


    /*Send the SYN packet
    if ( sendto (sd_tcp, buffer , ip->iph_len , 0 , (struct sockaddr *) &sin, sizeof (sin)) < 0)
    {
        printf ("Error sending syn packet.\n");
        exit(EXIT_FAILURE);
    }
    printf("SYN packet sent\n");*/

    int i;

    //copy ttl in buffer to send
    //sending udp packet train for low entropy
    for(i=0; i<numudppackets2; i++){
        setsockopt (sd_udp, IPPROTO_IP, IP_TTL, &ip->iph_ttl, sizeof (ip->iph_ttl));
        sendto(sd_udp, (char *)buffer2, sizeof(buffer2),
            0, (const struct sockaddr *) &servaddr,
            sizeof(servaddr));
    }
    printf("Low entropy sent\n");


    return 0;
}
