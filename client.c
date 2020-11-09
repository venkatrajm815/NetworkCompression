#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>      
#include <errno.h>
#include <time.h> 
#include <ctype.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <json-c/json.h>
#include "util.h"

int main(int argc, char * argv[]){
    int sockfd, DF;
    char buffer[BUFFER_SIZE], compression[25];
    FILE *fp;
    struct sockaddr_in addrServer;
    struct sockaddr_in addClient;
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
    fread(buffer, BUFFER_SIZE, 1, fp); 
    jsonParsed = json_tokener_parse(buffer);

    //This is where store the parsed data from the JSON file into variables
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
    
    //This is the Pre-Probing Phase
    
    //This is where we begin the creation of the socket
    printf("Socket is being created.\n");
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0){ 
        printf("Socket Creation has FAILED.\n"); 
        exit(EXIT_FAILURE); 
    } else {
        printf("Socket Creation is SUCCESSFUL.\n"); 
    }

    //Here we fill all the information involving the ip address: involves the binding to the ip address and binding to the port
    memset(&addrServer, 0, sizeof(addrServer));
    addrServer.sin_family = AF_INET; 
    addrServer.sin_addr.s_addr = inet_addr(json_object_get_string(serverIPAddr)); 
    addrServer.sin_port = htons(json_object_get_int(portNumTCP));
    
    //This is where we connect the server and client sockets together
    printf("Connecting sockets.\n");
    if (connect(sockfd, (struct sockaddr *)&addrServer, sizeof(addrServer)) != 0){ 
    printf("Connection to the server has FAILED.\n"); 
    exit(EXIT_FAILURE); 
    }else{
        printf("Connection to the server is SUCCESSFUL.\n"); 
    }
    //Lastly, we send file and close the socket
    sendfile(sockfd); 
    close(sockfd); 

    //This is the Probing Phase

    int udp[json_object_get_int(udppayload) + 2];
    //This puts a zero for everything in the client address 
    memset(&addClient, 0, sizeof(addClient));
    addClient.sin_family = AF_INET; 
    addClient.sin_addr.s_addr = htonl(INADDR_ANY);
    addClient.sin_port = htons(json_object_get_int(srcPortNumUDP));
    addrServer.sin_port = htons(json_object_get_int(destPortNumUDP));

    //We begin creating the UDP socket
    //Print message based on if it was succesful or not 
    printf("Creating Socket.\n");
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ){ 
        perror("UDP Socket Creation has FAILED\n"); 
        exit(EXIT_FAILURE); 
    }else{
        printf("UDP Socket Creation is SUCCESSFUL\n");
    }
    
    //This is the setting of the DON'T fragment 
    printf("Setting the DON'T fragment bit.\n");
    DF = IP_PMTUDISC_DO;
    if(setsockopt(sockfd, IPPROTO_IP, IP_MTU_DISCOVER, &DF, sizeof(DF)) < 0){
        printf("ERROR while setting DON'T fragment bit.\n");
    }else{
        printf("DON'T fragment bit set SUCCESSFULLY.\n");
    }
    
    //A check to see if the socket bind passed, prints error message if failed  
    if(bind(sockfd, (struct sockaddr *)&addClient, sizeof(addClient)) < 0){
        printf("UDP Socket Bind has FAILED.\n");
        exit(EXIT_FAILURE);
    }
    sleep(5);

    //This is the sending of the LOW entropy data
    lowentropy(udp, json_object_get_int(udppayload)+2);
    printf("Sending Low Entropy Data.\n");
    for(int i = 1; i < json_object_get_int(udpPackets) + 1; i++){
        setpacketid(udp, i);
        sendto(sockfd, udp, json_object_get_int(udppayload) + 2, MSG_CONFIRM, (const struct sockaddr *) &addrServer, sizeof(addrServer));
    }
    printf("Low Entropy data has been sent.\n");

    //Sleeping using the inter-measurement time from the json object
    printf("Sleeping.\n");
    sleep(json_object_get_int(measurementTime));

    //This is the sending of the HIGH entropy data
    highEntropy(udp, json_object_get_int(udppayload)+2);
    printf("Sending High Entropy Data.\n");
    for(int i = 1; i < json_object_get_int(udpPackets) + 1; i++){
        setpacketid(udp, i);
        sendto(sockfd, udp, json_object_get_int(udppayload)+2, MSG_CONFIRM, (const struct sockaddr *) &addrServer, sizeof(addrServer));
    }
    printf("High entropy data has been sent.\n");
    sleep(5);

    //This is Post-Probing Phase
    
    //This is the creating of the TCP socket
    printf("Socket is being created.\n");
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0){ 
        printf("Socket Creation has FAILED.\n"); 
        exit(EXIT_FAILURE); 
    } 
    else{
        printf("Socket Creation is SUCCESSFUL.\n"); 
    }
    
    //Here we fill all the information involving the ip address: involves the binding to the ip address and binding to the port
    memset(&addrServer, 0, sizeof(addrServer));
    addrServer.sin_family = AF_INET; 
    addrServer.sin_addr.s_addr = inet_addr(json_object_get_string(serverIPAddr)); 
    addrServer.sin_port = htons(json_object_get_int(portNumTCP));
    
    //This is where we connect the client socket to the server socket
    printf("Connecting client socket to server socket.\n");
    if (connect(sockfd, (struct sockaddr *)&addrServer, sizeof(addrServer)) != 0){ 
    printf("Connection to the server has FAILED.\n"); 
    exit(EXIT_FAILURE); 
    } 
    else{
        printf("Connection to the server is SUCCESSFUL.\n"); 
    }   
    
    //Gets and prints the server's response: No compression detected or compression detected
    recv(sockfd, &compression, sizeof(compression), 0);
    printf("The servers's response is : %s\n" , compression);
    
    //Lastly, closes the socket
    close(sockfd); 
    return 0;
}
