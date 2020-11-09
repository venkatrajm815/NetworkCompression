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

int main(int argc, char **argv) {
    FILE * fp;
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

    printf("(Testing) Preparing to send packets!\n");
    printf("Sending.\n");
    
    struct ip ip;
    struct tcphdr tcp;
    struct addrinfo hints, *res;
    struct sockaddr_in *ipv4, sin;
    struct ifreq ifr;
    uint8_t *tcpPacketHead, *udpPacket, *tcpPaketTail;
    int status, sd, *ip_flags, *tcp_flags;
    char *interface, *target, *src_ip, *dst_ip;
    void *tmp;
    const int on = 1;


    //Initialize prior struct and variables
    tcpPacketHead = allocateMemUnsChar (IP_MAXPACKET);
    tcpPaketTail = allocateMemUnsChar (IP_MAXPACKET);
    interface = allocateMemChar (40);
    target = allocateMemChar (40);
    src_ip = allocateMemChar (INET_ADDRSTRLEN);
    dst_ip = allocateMemChar (INET_ADDRSTRLEN);
    ip_flags = allocateMemInt (4);
    tcp_flags = allocateMemInt (8);

    // Sending Packet Through
    strcpy (interface, "enp0s3"); 
    sd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
    
    // Uses Socket Descripter to look up Interface
    if (sd < 0) {
        perror ("Socket failed to get descripter.");
        exit (EXIT_FAILURE);
    }

    // Finds interface name and mac address.
    memset (&ifr, 0, sizeof (ifr));
    snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
    if (ioctl (sd, SIOCGIFINDEX, &ifr) < 0) {
        perror ("Failed to find interface ");
        return (EXIT_FAILURE);
    }
    close (sd);

    // Source IPv4 address
    strcpy (src_ip, "10.0.0.249");

    // Destination URL or IPv4 address
    strcpy (target, json_object_get_string(serverIPAddr));

    memset (&hints, 0, sizeof (struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = hints.ai_flags | AI_CANONNAME;
    status = getaddrinfo (target, NULL, &hints, &res);
    
    // Resolving final target
    if (status != 0) {
        fprintf (stderr, "getaddrinfo failed!: %s\n", gai_strerror (status));
        exit (EXIT_FAILURE);
    }
    ipv4 = (struct sockaddr_in *) res->ai_addr;
    tmp = &(ipv4->sin_addr);
    if (inet_ntop (AF_INET, tmp, dst_ip, INET_ADDRSTRLEN) == NULL) {
        status = errno;
        fprintf (stderr, "inet_ntop() failed.\n%s", strerror (status));
        exit (EXIT_FAILURE);
    }
    freeaddrinfo(res);

    // Setting up information for the IPv4 header
    ip.ip_hl = IP4_HDRLEN / sizeof (uint32_t);
    ip.ip_v = 4; //protocol ver
    ip.ip_tos = 0; //service type
    ip.ip_len = htons(IP4_HDRLEN + TCP_HDRLEN); //datagram total length
    ip.ip_id = htons(0); //irrelevant, since we have a single datagram
    ip_flags[0] = 0;
    ip_flags[1] = 0;
    ip_flags[2] = 0;
    ip_flags[3] = 0;
    ip.ip_off = htons ((ip_flags[0] << 15) + (ip_flags[1] << 14) + (ip_flags[2] << 13) + ip_flags[3]);
    ip.ip_ttl = 255; //default max time
    ip.ip_p = IPPROTO_TCP; //transport layer protocol
    status = inet_pton(AF_INET, src_ip, &(ip.ip_src));
    
    // This is the source IPv4 address which is 32 bits
    if (status != 1) {
        fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
        exit (EXIT_FAILURE);
    }

    // This is the destination IPv4 address which is also 32 bits
    status = inet_pton(AF_INET, dst_ip, &(ip.ip_dst));
    if (status != 1) {
        fprintf(stderr, "inet_pton() failed.\nError message: %s", strerror (status));
        exit (EXIT_FAILURE);
    }
    ip.ip_sum = 0;
    ip.ip_sum = sumIP((uint16_t *) &ip, IP4_HDRLEN);

    //Setting up information for the TCP header
    tcp.th_sport = htons(8080); //get source
    tcp.th_dport = htons(json_object_get_int(destPortNumTCPHead)); //get dest
    tcp.th_seq = htonl(0); //get sequence
    tcp.th_ack = htonl(0); //get sequence
    tcp_flags[0] = 0; //FIN
    tcp_flags[1] = 1; //SYN
    tcp_flags[2] = 1; //RST
    tcp_flags[3] = 0; //PSH
    tcp_flags[4] = 0; //ACK
    tcp.th_flags = 0;
    for (int i = 0; i < 8; i++) {
        tcp.th_flags += (tcp_flags[i] << i);
    }
    tcp.th_sum = sumTCP(ip, tcp);
    tcp.th_sum = sumTCP(ip, tcp);
    memcpy(tcpPaketTail, &ip, IP4_HDRLEN * sizeof (uint8_t));
    memcpy((tcpPaketTail + IP4_HDRLEN), &tcp, TCP_HDRLEN * sizeof (uint8_t));
    
    memset(&sin, 0, sizeof (struct sockaddr_in));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ip.ip_dst.s_addr;
    sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    // Check to see if socket failed
    if (sd < 0) {
        perror("socket() failed ");
        exit(EXIT_FAILURE);
    }

    //Make flag so socket expects at IPv4.
    if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof (on)) < 0) {
        perror("Failed to set IP_HDRINCL. ");
        exit(EXIT_FAILURE);
    }

    // Bind socket to interface index.
    if (setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof (ifr)) < 0) {
        perror("Failed interface bind. ");
        exit(EXIT_FAILURE);
    }

    struct udphdr udp;

    uint8_t * data = allocateMemUnsChar(json_object_get_int(udppayload));
    
    // UDP data
    int datalen = json_object_get_int(udppayload);
    memset(data, 0, json_object_get_int(udppayload));
    ip.ip_p = IPPROTO_UDP;
    ip.ip_ttl = json_object_get_int(ttlPackets);


    // IPv4 header sumIP (16 bits): set to 0 when calculating sumIP
    ip.ip_sum = 0;
    ip.ip_sum = sumIP((uint16_t *) &ip, IP4_HDRLEN);

    // UDP header
    udp.source = htons(4950);
    udp.dest = htons(9999);
    udp.len = htons (UDP_HDRLEN + datalen);
    udp.check = sumUDP (ip, udp, data, datalen);
    udpPacket = allocateMemUnsChar (IP_MAXPACKET);
  
    // IPv4 header
    memcpy(udpPacket, &ip, IP4_HDRLEN * sizeof (uint8_t));

    // UDP header
    memcpy(udpPacket + IP4_HDRLEN, &udp, UDP_HDRLEN);

    // Send ethernet frame to socket.
    if (sendto(sd, tcpPacketHead, IP4_HDRLEN + TCP_HDRLEN, 0, (struct sockaddr *) &sin, sizeof (struct sockaddr)) < 0)  {
        perror("sendto() failed ");
        exit(EXIT_FAILURE);
    }

    printf("All the packets have been sent SUCCESSFULLY.\n");
    close(sd);
    return(EXIT_SUCCESS);
}
