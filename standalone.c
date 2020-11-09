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

    char buffer1[1024];
    struct json_object *parsed_json;
    struct json_object *serverip;
    struct json_object *srcportudp;
    struct json_object *destportudp;
    struct json_object *destporttcphead;
    struct json_object *destporttcptail;
    struct json_object *portnumtcp;
    struct json_object *payload;
    struct json_object *intermtime;
    struct json_object *numudppackets;
    struct json_object *ttl;

    char *filename;
    FILE *fp;

    // getting file from command-line argument
    if (argc >= 2){
        filename = argv[1];
        printf("File name: %s\n", filename);
        fp = fopen(argv[1], "r");
        fread(buffer1, 1024, 1, fp);
        fclose(fp);
    }
    else {
        perror("fopen");
    }
    
    parsed_json = json_tokener_parse(buffer1);

    json_object_object_get_ex(parsed_json, "serverip", &serverip);
    json_object_object_get_ex(parsed_json, "srcportudp", &srcportudp);
    json_object_object_get_ex(parsed_json, "destportudp", &destportudp);
    json_object_object_get_ex(parsed_json, "destporttcphead", &destporttcphead);
    json_object_object_get_ex(parsed_json, "destporttcptail", &destporttcptail);
    json_object_object_get_ex(parsed_json, "portnumtcp", &portnumtcp);
    json_object_object_get_ex(parsed_json, "payload", &payload);
    json_object_object_get_ex(parsed_json, "intermtime", &intermtime);
    json_object_object_get_ex(parsed_json, "numudppackets", &numudppackets);
    json_object_object_get_ex(parsed_json, "ttl", &ttl);

    //saving json objects
    char *serverip2 = json_object_get_string(serverip);
    int srcportudp2 = json_object_get_int(srcportudp);
    int destportudp2 = json_object_get_int(destportudp);
    char *destporttcphead2 = json_object_get_string(destporttcphead);
    char *destporttcptail2 = json_object_get_string(destporttcptail);
    char *portnumtcp2 = json_object_get_string(portnumtcp);
    int payload2 = json_object_get_int(payload);
    int intermtime2 = json_object_get_int(intermtime);
    int numudppackets2 = json_object_get_int(numudppackets);
    int ttl2 = json_object_get_int(ttl);

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

    sin.sin_port = htons(destporttcphead);

    din.sin_port = htons(destporttcptail);

    // IP addresses

    sin.sin_addr.s_addr = inet_addr("192.168.1.16");

    din.sin_addr.s_addr = inet_addr("192.168.1.16");


    memset(&servaddr, 0, sizeof(servaddr));
    
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
