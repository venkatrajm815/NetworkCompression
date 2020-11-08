#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>          
#include <string.h>           
#include <netdb.h>           
#include <sys/types.h>        
#include <sys/socket.h>       
#include <netinet/in.h>       
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>
#include <json-c/json.h>

#define BUFFER_SIZE 2000
#define THRESHOLD 100

void receive_file(int sockfd){
    char buffer[BUFFER_SIZE];
    FILE *fp = fopen("myconfig.json","w");
    if(fp == NULL){
        printf("There is an error in opening the file.");
        return exit(EXIT_FAILURE);
    }

    while(read(sockfd, buffer, BUFFER_SIZE) > 0) {
        fprintf(fp,"%s", buffer);
    }
    printf("Config File received!\n");
    fclose(fp);
} 

int main(int argc, char * argv[]){
    FILE * fp;
    int sockfd;
    int connfd; 
    int i;
    int packet_id;
    unsigned int len;
    char buffer[BUFFER_SIZE], message[25];
    clock_t start; 
    clock_t end;
    double timeTotal;
    double timeLE;
    double timeHE;
    struct sockaddr_in addrServer;
    struct sockaddr_in addrClient;
    struct json_object *jsonParsed;
    struct json_object *serverIPAddr;
    struct json_object *srcPortNumUDP;
    struct json_object *destPortNumUDP;
    struct json_object *destPortNumTCPhead;
    struct json_object *destPortNumTCPtail; 
    struct json_object *portNumTCP;
    struct json_object *udppayload;
    struct json_object *measurementTime;
    struct json_object *udpPackets;
    struct json_object *ttlPackets;

    if(argv[1] == NULL){
        printf("ERROR!\nEnter ./'application name' myconfig.json\n");
        return EXIT_FAILURE;
    }
    
    //THIS IS THE Pre-Probing Phase

    //Creating socket
    printf("Creating Socket...\n");
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0) {
        perror("The TCP Socket Creation has Failed\n");
        exit(EXIT_FAILURE);
    } else {
        printf("The TCP Socket Creation is Successful\n");
    }

    //Fills in server information
    memset(&addrServer, 0 , sizeof(addrServer));
    memset(&addrClient, 0, sizeof(addrClient));
    addrServer.sin_family = AF_INET; 
    addrServer.sin_addr.s_addr = inet_addr("192.168.1.30"); 
    addrServer.sin_port = htons(9999);

    //This binds the socket with the server address
    printf("Binding...\n");
    if ((bind(sockfd, (struct sockaddr *) &addrServer, sizeof(addrServer))) != 0){ 
        printf("TCP Socket Bind Has Failed\n"); 
        exit(EXIT_FAILURE); 
    } 
    else{
        printf("TCP Socket Bind Has Succeeded\n"); 
    }

    //Listen to receive connections at port
    printf("Listening...\n");
    if ((listen(sockfd, 5)) != 0)
    { 
        printf("Listening Has Failed\n"); 
        exit(EXIT_FAILURE); 
    } 
    
    //Accept the connection
    len = sizeof(addrClient); 
    if ((connfd = accept(sockfd, (struct sockaddr *) &addrClient, &len)) < 0)
    { 
        printf("TCP Connection Has Failed\n"); 
        exit(0); 
    } 
    else
    {
        printf("TCP Connection Has Established\n"); 
    }

    //Calling function to receive file from connection
    receive_file(connfd);

    //File parsing happens here
    fp = fopen(argv[1],"r"); //opens the file myconfig.json
    fread(buffer, BUFFER_SIZE, 1, fp); //reads files and puts contents inside buffer
    jsonParsed = json_tokener_parse(buffer); //call the json tokenizer

    //Storing the data into the correct variables
    json_object_object_get_ex(jsonParsed, "serverIPAddr", &serverIPAddr);
    json_object_object_get_ex(jsonParsed, "srcPortNumUDP", &srcPortNumUDP);
    json_object_object_get_ex(jsonParsed, "destPortNumUDP", &destPortNumUDP);
    json_object_object_get_ex(jsonParsed, "destPortNumTCPhead", &destPortNumTCPhead);
    json_object_object_get_ex(jsonParsed, "destPortNumTCPtail", &destPortNumTCPtail);
    json_object_object_get_ex(jsonParsed, "portNumTCP", &portNumTCP);
    json_object_object_get_ex(jsonParsed, "udppayload", &udppayload);
    json_object_object_get_ex(jsonParsed, "measurementTime", &measurementTime);
    json_object_object_get_ex(jsonParsed, "udpPackets", &udpPackets);
    json_object_object_get_ex(jsonParsed, "ttlPackets", &ttlPackets);

    close(sockfd);
    close(connfd);


    //PROBING PHASE//


    //Set up the server address for the udp header
    int UDPbuffer[json_object_get_int(udppayload)+2];
    memset(&UDPbuffer, 0 , json_object_get_int(udppayload)+2);
    addrServer.sin_addr.s_addr = inet_addr(json_object_get_string(serverIPAddr));
    addrServer.sin_port = htons(json_object_get_int(destPortNumUDP));

    //Creation of UDP socket
    printf("Creating Socket...\n");
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) { 
        perror("UDP Socket Creation Failed"); 
        exit(EXIT_FAILURE); 
    } else {
        printf("UDP Socket Creation Successful\n");
    }

    //Bind the socket to the udp port
    printf("Binding...\n");
    if (bind(sockfd, (const struct sockaddr *)&addrServer, sizeof(addrServer))<0) { 
        perror("UDP Socket Bind Failed"); 
        exit(EXIT_FAILURE); 
    } else {
        printf("UDP Socket Bind Successful\n");
    }

    //Receive low entropy data
    printf("Receiving low entropy..\n");
    start = clock();
    for(i = 0; i < json_object_get_int(udpPackets); i++) {
        recvfrom(sockfd, UDPbuffer, json_object_get_int(udppayload)+2, 0, ( struct sockaddr *) &addrClient, &len); //receive packets into buffer
        packet_id = (int)(((unsigned)UDPbuffer[1] << 8) | UDPbuffer[0]); //reconstruct the packet id
        printf("Retrieved Low Entropy Packet Number: %d\n", packet_id);
    }
    end = clock();
    timeTotal  = (((double)end) - ((double)start)) / ((double)CLOCKS_PER_SEC);
    timeLE = timeTotal * 1000;
    printf("Low Entropy Time: %f\n", timeLE);

    //Sleeping inter measurement time
    printf("Sleeping...\n"); 
    sleep(json_object_get_int(measurementTime));

    //Receive high entropy data
    printf("Receiving high entropy..\n");
    memset(&UDPbuffer, 0, json_object_get_int(udppayload)+2);
    start = clock();
    for(i = 0; i < json_object_get_int(udpPackets); i++) {
        recvfrom(sockfd, UDPbuffer, json_object_get_int(udppayload)+2, 0, ( struct sockaddr *) &addrClient, &len); //store packets into buffer
        packet_id = (((unsigned)UDPbuffer[1] << 8) | UDPbuffer[0]);
        printf("Retrieved High Entropy Packet Number: %d\n", packet_id);
    }
    end = clock();
    timeTotal  = (((double)end) - ((double)start)) / ((double)CLOCKS_PER_SEC);
    timeHE = timeTotal * 1000;
    printf("High Entropy Time: %f\n", timeHE);

    //Calculate the time and then send back the data
    if((timeHE - timeLE) > THRESHOLD) {
        strcpy(message, "COMPRESSION DETECTED\0");
    } else {
        strcpy(message, "NO COMPRESSION DETECTED\0");
    }
    
    //Post-Probing-TCP//
    printf("Creating Socket...\n");
    if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("TCP Socket Creation Failed\n");
        exit(EXIT_FAILURE);
    }
    else {
        printf("TCP Socket Creation Successful\n");
    }

    //Fill in IP header
    memset(&addrServer, 0 , sizeof(addrServer));
    memset(&addrClient, 0, sizeof(addrClient));
    addrServer.sin_family = AF_INET; // IPv4
    addrServer.sin_addr.s_addr = inet_addr(json_object_get_string(serverIPAddr));
    addrServer.sin_port = htons(json_object_get_int(portNumTCP));

    //Bind TCP socket to port
    printf("Binding...\n");
    if ((bind(sockfd, (struct sockaddr *) &addrServer, sizeof(addrServer))) != 0) { 
        printf("TCP Socket Bind Failed\n"); 
        exit(EXIT_FAILURE); 
    } else {
        printf("TCP Socket Bind Successful\n"); 
    }

    //Listen to receive connections at port
    printf("Listening...\n");
    if ((listen(sockfd, 5)) != 0) { 
        printf("Listening Failed\n"); 
        exit(EXIT_FAILURE); 
    } 
    
    //Accept the connection
    len = sizeof(addrClient);
    if ((connfd = accept(sockfd, (struct sockaddr *) &addrClient, &len)) < 0) { 
        printf("TCP Connection Failed\n"); 
        exit(0); 
    } else {
        printf("TCP Connection Established\n"); 
    }

    //Send the TCP message
    send(connfd, message, strlen(message), 0);
    
    close(sockfd);
    return 0;
}
