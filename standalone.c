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

//This creates a number for the IP header
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

//This creates a number for the UDP header
uint16_t sumUDP(struct ip ip, struct udphdr udphdr, uint8_t *payload, int payloadlen) {
    char BUFFER[IP_MAXPACKET];
    char *ptr;
    int len = 0;
    ptr = &BUFFER[0]; 
    
    //Writing of addresses into buffer and incrementing of length
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

    *ptr = 0; 
    ptr++;
    *ptr = 0; 
    ptr++;
    len += 2;

    memcpy (ptr, payload, payloadlen);
    ptr += payloadlen;
    len += payloadlen;

    return sumIP ((uint16_t *) BUFFER, len);
}

//This creates a number for the TCP header
uint16_t sumTCP(struct ip ip, struct tcphdr tcp)
{
    char *ptr;
    uint16_t svalue;
    char BUFFER[IP_MAXPACKET], cvalue;
     ptr = &BUFFER[0];
    int len = 0;
    
    //Writing of addresses into buffer and incrementing of length
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

//This creates an array of characters
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

//This creates an array of unsigned characters
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

//This creates an array of integers
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
    //Here we go through the file and put the contents into buffer, then we parse through the myconfig.json and convert it into a JSON object
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
    printf("The Parsing is SUCCESSFUL.\n");
    printf("Sending Packets.\n");
    
    struct ip ip;
    struct tcphdr tcp;
    struct addrinfo hints, *res;
    struct sockaddr_in *ipv4, sin;
    struct ifreq ifr;
    uint8_t *tcpPacketHead, *udpPacket, *tcpPaketTail;
    int status, sd, *ip_flags, *tcp_flags;
    char *interface, *target, *src_ip, *dst_ip;
    void *tmp;
   
    //Memory is getting allocated for struct and variables
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
    
    //Uses Socket Descripter to look up Interface
    if (sd < 0) {
        perror ("Socket failed to get descripter.");
        exit (EXIT_FAILURE);
    }

    //Finds interface name and mac address.
    memset (&ifr, 0, sizeof (ifr));
    snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
    if (ioctl (sd, SIOCGIFINDEX, &ifr) < 0) {
        perror ("Failed to find interface ");
        return (EXIT_FAILURE);
    }
    close (sd);

  
    //Destination URL or IPv4 address
    strcpy (target, json_object_get_string(serverIPAddr));

    memset (&hints, 0, sizeof (struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = hints.ai_flags | AI_CANONNAME;
    status = getaddrinfo (target, NULL, &hints, &res);
    
   

    //Setting up information for the TCP header and assigning values for the packets
    tcp.th_sport = htons(8080); 
    tcp.th_dport = htons(json_object_get_int(destPortNumTCPHead)); 
    tcp.th_seq = htonl(0); 
    tcp.th_ack = htonl(0); 
    tcp_flags[0] = 0; 
    tcp_flags[1] = 1;
    tcp_flags[2] = 1; 
    tcp_flags[3] = 0; 
    tcp_flags[4] = 0;
    tcp.th_flags = 0;
    for (int i = 0; i < 8; i++) {
        tcp.th_flags += (tcp_flags[i] << i);
    }

    struct udphdr udp;

    uint8_t * data = allocateMemUnsChar(json_object_get_int(udppayload));
    
    // UDP data
    int datalen = json_object_get_int(udppayload);
    memset(data, 0, json_object_get_int(udppayload));
    ip.ip_p = IPPROTO_UDP;
    ip.ip_ttl = json_object_get_int(ttlPackets);


    // Calculating sumIP
    ip.ip_sum = 0;
    ip.ip_sum = sumIP((uint16_t *) &ip, IP4_HDRLEN);

    // UDP header
    udp.source = htons(4950);
    udp.dest = htons(9999);
    udp.len = htons (UDP_HDRLEN + datalen);
    udp.check = sumUDP (ip, udp, data, datalen);
    udpPacket = allocateMemUnsChar (IP_MAXPACKET);
  
    printf("All the packets have been sent SUCCESSFULLY.\n");
    close(sd);
    return(EXIT_SUCCESS);
}
