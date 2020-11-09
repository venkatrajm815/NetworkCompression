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

//Creating number for IP header
uint16_t checksum(uint16_t *addr, int len) {
    int count = len;
    register uint32_t sum = 0;
    uint16_t answer = 0;

    while(count > 1){
        sum += *(addr++); 
        count -= 2;
    }

    if(count > 0) {
        sum += *(uint8_t *)addr;
    }

    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    answer = ~sum;
    return (answer);
}

//this function creates unique checksum for the UDP headers
uint16_t udp4_checksum(struct ip iphdr, struct udphdr udphdr, uint8_t *payload, int payloadlen) {#include <stdio.h>
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
char * allocateMemChar(int length)
{
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

    char buf[IP_MAXPACKET];
    char *ptr;
    int chksumlen = 0;
    int i;

    ptr = &buf[0];  // ptr points to beginning of buffer buf

    // Copy source IP address into buf (32 bits)
    memcpy (ptr, &iphdr.ip_src.s_addr, sizeof (iphdr.ip_src.s_addr));
    ptr += sizeof (iphdr.ip_src.s_addr);
    chksumlen += sizeof (iphdr.ip_src.s_addr);

    // Copy destination IP address into buf (32 bits)
    memcpy (ptr, &iphdr.ip_dst.s_addr, sizeof (iphdr.ip_dst.s_addr));
    ptr += sizeof (iphdr.ip_dst.s_addr);
    chksumlen += sizeof (iphdr.ip_dst.s_addr);

    // Copy zero field to buf (8 bits)
    *ptr = 0; ptr++;
    chksumlen += 1;

    // Copy transport layer protocol to buf (8 bits)
    memcpy (ptr, &iphdr.ip_p, sizeof (iphdr.ip_p));
    ptr += sizeof (iphdr.ip_p);
    chksumlen += sizeof (iphdr.ip_p);

    // Copy UDP length to buf (16 bits)
    memcpy (ptr, &udphdr.len, sizeof (udphdr.len));
    ptr += sizeof (udphdr.len);
    chksumlen += sizeof (udphdr.len);

    // Copy UDP source port to buf (16 bits)
    memcpy (ptr, &udphdr.source, sizeof (udphdr.source));
    ptr += sizeof (udphdr.source);
    chksumlen += sizeof (udphdr.source);

    // Copy UDP destination port to buf (16 bits)
    memcpy (ptr, &udphdr.dest, sizeof (udphdr.dest));
    ptr += sizeof (udphdr.dest);
    chksumlen += sizeof (udphdr.dest);

    // Copy UDP length again to buf (16 bits)
    memcpy (ptr, &udphdr.len, sizeof (udphdr.len));
    ptr += sizeof (udphdr.len);
    chksumlen += sizeof (udphdr.len);

    // Copy UDP checksum to buf (16 bits)
    // Zero, since we don't know it yet
    *ptr = 0; ptr++;
    *ptr = 0; ptr++;
    chksumlen += 2;

    // Copy payload to buf
    memcpy (ptr, payload, payloadlen);
    ptr += payloadlen;
    chksumlen += payloadlen;

    return checksum ((uint16_t *) buf, chksumlen);
}

//this function creates unique checksum for the TCP headers
uint16_t tcp4_checksum (struct ip iphdr, struct tcphdr tcphdr) {
    uint16_t svalue;
    char buf[IP_MAXPACKET], cvalue;
    char *ptr;
    int chksumlen = 0;

    // ptr points to beginning of buffer buf
    ptr = &buf[0];

    // Copy source IP address into buf (32 bits)
    memcpy (ptr, &iphdr.ip_src.s_addr, sizeof (iphdr.ip_src.s_addr));
    ptr += sizeof (iphdr.ip_src.s_addr);
    chksumlen += sizeof (iphdr.ip_src.s_addr);

    // Copy destination IP address into buf (32 bits)
    memcpy (ptr, &iphdr.ip_dst.s_addr, sizeof (iphdr.ip_dst.s_addr));
    ptr += sizeof (iphdr.ip_dst.s_addr);
    chksumlen += sizeof (iphdr.ip_dst.s_addr);

    // Copy zero field to buf (8 bits)
    *ptr = 0; ptr++;
    chksumlen += 1;

    // Copy transport layer protocol to buf (8 bits)
    memcpy (ptr, &iphdr.ip_p, sizeof (iphdr.ip_p));
    ptr += sizeof (iphdr.ip_p);
    chksumlen += sizeof (iphdr.ip_p);

    // Copy TCP length to buf (16 bits)
    svalue = htons (sizeof (tcphdr));
    memcpy (ptr, &svalue, sizeof (svalue));
    ptr += sizeof (svalue);
    chksumlen += sizeof (svalue);

    // Copy TCP source port to buf (16 bits)
    memcpy (ptr, &tcphdr.th_sport, sizeof (tcphdr.th_sport));
    ptr += sizeof (tcphdr.th_sport);
    chksumlen += sizeof (tcphdr.th_sport);

    // Copy TCP destination port to buf (16 bits)
    memcpy (ptr, &tcphdr.th_dport, sizeof (tcphdr.th_dport));
    ptr += sizeof (tcphdr.th_dport);
    chksumlen += sizeof (tcphdr.th_dport);

    // Copy sequence number to buf (32 bits)
    memcpy (ptr, &tcphdr.th_seq, sizeof (tcphdr.th_seq));
    ptr += sizeof (tcphdr.th_seq);
    chksumlen += sizeof (tcphdr.th_seq);

    // Copy acknowledgement number to buf (32 bits)
    memcpy (ptr, &tcphdr.th_ack, sizeof (tcphdr.th_ack));
    ptr += sizeof (tcphdr.th_ack);
    chksumlen += sizeof (tcphdr.th_ack);

    // Copy data offset to buf (4 bits) and
    // copy reserved bits to buf (4 bits)
    cvalue = (tcphdr.th_off << 4) + tcphdr.th_x2;
    memcpy (ptr, &cvalue, sizeof (cvalue));
    ptr += sizeof (cvalue);
    chksumlen += sizeof (cvalue);

    // Copy TCP flags to buf (8 bits)
    memcpy (ptr, &tcphdr.th_flags, sizeof (tcphdr.th_flags));
    ptr += sizeof (tcphdr.th_flags);
    chksumlen += sizeof (tcphdr.th_flags);

    // Copy TCP window size to buf (16 bits)
    memcpy (ptr, &tcphdr.th_win, sizeof (tcphdr.th_win));
    ptr += sizeof (tcphdr.th_win);
    chksumlen += sizeof (tcphdr.th_win);
    return checksum ((uint16_t *) buf, chksumlen);
}

// Allocate memory for an array of chars
char * allocate_strmem(int len) {
    void *tmp;

    if (len <= 0) {
        fprintf(stderr, "ERROR: Cannot allocate memory because len = %i in allocate_strmem().\n", len);
        exit(EXIT_FAILURE);
    }

    tmp = (char *)malloc(len * sizeof (char));
    if (tmp != NULL){
        memset(tmp, 0, len * sizeof (char));
        return(tmp);
    } else {
        fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_strmem().\n");
        exit(EXIT_FAILURE);
    }
}

// Allocate memory for an array of unsigned chars.
uint8_t * allocate_ustrmem(int len) {
    void *tmp;

    if (len <= 0) {
        fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_ustrmem().\n", len);
        exit (EXIT_FAILURE);
    }

    tmp = (uint8_t *) malloc (len * sizeof (uint8_t));
    if (tmp != NULL) {
        memset (tmp, 0, len * sizeof (uint8_t));
        return (tmp);
    } else {
        fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
        exit (EXIT_FAILURE);
    }
}

// Allocate memory for an array of ints.
int * allocate_intmem(int len) {
    void *tmp;

    if (len <= 0) {
        fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_intmem().\n",len);
        exit(EXIT_FAILURE);
    }

    tmp = (int *)malloc(len * sizeof(int));
    if(tmp != NULL){
        memset (tmp, 0, len * sizeof(int));
        return (tmp);
    } else{
        fprintf(stderr,"ERROR: Cannot allocate memory for array allocate_intmem().\n");
        exit(EXIT_FAILURE);
    }
}


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
