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

#define BUFFER_SIZE 2000
#define THRESHOLD 100

//This method is responsible for opening of the configuration file and reading through it
void receiveFile(int sockfd){
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
    
    //This checks if there is an error in executing the configuration file 
    if(argv[1] == NULL){
        printf("ERROR!\nEnter ./'application name' myconfig.json\n");
        return EXIT_FAILURE;
    }
    
    //Opening of the JSON file
    fp = fopen(argv[1],"r");
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
    json_object_object_get_ex(jsonParsed, "destPortNumTCPhead", &destPortNumTCPhead);
    json_object_object_get_ex(jsonParsed, "destPortNumTCPtail", &destPortNumTCPtail);
    json_object_object_get_ex(jsonParsed, "portNumTCP", &portNumTCP);
    json_object_object_get_ex(jsonParsed, "udppayload", &udppayload);
    json_object_object_get_ex(jsonParsed, "measurementTime", &measurementTime);
    json_object_object_get_ex(jsonParsed, "udpPackets", &udpPackets);
    json_object_object_get_ex(jsonParsed, "ttlPackets", &ttlPackets);
    printf("The Parsing is SUCCESSFUL.\n");
    
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
    memset(&addrClient, 0, sizeof(addrClient));
    addrServer.sin_family = AF_INET; 
    addrServer.sin_addr.s_addr = inet_addr(json_object_get_string(serverIPAddr)); 
    addrServer.sin_port = htons(json_object_get_int(portNumTCP));

    //This is where we bind the socket with the server address
    printf("Binding sockets.\n");
    if ((bind(sockfd, (struct sockaddr *) &addrServer, sizeof(addrServer))) != 0){ 
        printf("Socket Binding has FAILED\n"); 
        exit(EXIT_FAILURE); 
    } 
    else{
        printf("Socket Bind is SUCCESSFULL\n"); 
    }

    //Here, we listen to see if there are any connections to be received at the port
    printf("Listening.\n");
    if ((listen(sockfd, 5)) != 0){ 
        printf("Listening Has FAILED.\n"); 
        exit(EXIT_FAILURE); 
    } 
    
    //This is where we accept the TCP connection and connect the client and server together 
    len = sizeof(addrClient); 
    if ((connfd = accept(sockfd, (struct sockaddr *) &addrClient, &len)) < 0){ 
        printf("Connection to the client has FAILED.\n"); 
        exit(0); 
    } else{
        printf("Connection to the client is SUCCESSFUL.\n"); 
    }

    //We call receiveFile to receive the connection
    receiveFile(connfd);

     
    
    //Lastly, we close the sockets
    close(sockfd);
    close(connfd);
    
    //This is the Probing Phase

    //Set up the server address for the udp header
    int UDPbuffer[json_object_get_int(udppayload)+2];
    memset(&UDPbuffer, 0 , json_object_get_int(udppayload)+2);
    addrServer.sin_addr.s_addr = inet_addr(json_object_get_string(serverIPAddr));
    addrServer.sin_port = htons(json_object_get_int(destPortNumUDP));

    //We begin creating the UDP socket
    //Print message based on if it was successful or not 
    printf("Creating Socket.\n");
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ){ 
        perror("UDP Socket Creation has FAILED\n"); 
        exit(EXIT_FAILURE); 
    } else{
        printf("UDP Socket Creation is SUCCESSFUL\n");
    }

    //Bind the socket to the udp port
    //A check to see if the socket bind passed, prints error message if failed  
    printf("Binding socket.\n");
    if (bind(sockfd, (const struct sockaddr *)&addrServer, sizeof(addrServer))<0) { 
        perror("UDP Socket Binding has FAILED."); 
        exit(EXIT_FAILURE); 
    } else {
        printf("UDP Socket Binding is SUCCESSFUL.\n");
    }

    //This is the receiving of the low entropy data, print message for each data packet
    printf("Receiving Low Entropy Data.\n");
    start = clock();
    for(int i = 0; i < json_object_get_int(udpPackets); i++) {
        recvfrom(sockfd, UDPbuffer, json_object_get_int(udppayload) + 2, 0, (struct sockaddr*) &addrClient, &len); 
        packet_id = (int)(((unsigned)UDPbuffer[1] << 8) | UDPbuffer[0]); 
        printf("Received Low Entropy Data, Packet Number: %d\n", packet_id);
    }
    end = clock();
    //This is the calculation of time for the low entropy data to be received
    timeTotal  = (((double)end) - ((double)start)) / ((double)CLOCKS_PER_SEC);
    timeLE = timeTotal * 1000;
    printf("Low Entropy Time: %f\n", timeLE);

    //Sleeping using the inter measurement time
    printf("Sleeping.\n"); 
    sleep(json_object_get_int(measurementTime));

    //This is the receiving of the high entropy data, print message for each data packet
    printf("Receiving High Entropy Data.\n");
    memset(&UDPbuffer, 0, json_object_get_int(udppayload)+2);
    start = clock();
    for(int i = 0; i < json_object_get_int(udpPackets); i++) {
        recvfrom(sockfd, UDPbuffer, json_object_get_int(udppayload) + 2, 0, (struct sockaddr*) &addrClient, &len); 
        packet_id = (((unsigned)UDPbuffer[1] << 8) | UDPbuffer[0]);
        printf("Received High Entropy Data, Packet Number: %d\n", packet_id);
    }
    end = clock();
    //This is the calculation of time for the high entropy data to be received
    timeTotal  = (((double)end) - ((double)start)) / ((double)CLOCKS_PER_SEC);
    timeHE = timeTotal * 1000;
    printf("High Entropy Time: %f\n", timeHE);

    //Calculate the difference between the high entropy data time and low entropy data time 
    //and checks if it greater than or less than the threshold time. Then stores the result into message.
    if((timeHE - timeLE) > THRESHOLD) {
        strcpy(message, "COMPRESSION DETECTED.\0");
    } else {
        strcpy(message, "NO COMPRESSION DETECTED.\0");
    }
    
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
    memset(&addrServer, 0 , sizeof(addrServer));
    memset(&addrClient, 0, sizeof(addrClient));
    addrServer.sin_family = AF_INET; 
    addrServer.sin_addr.s_addr = inet_addr(json_object_get_string(serverIPAddr));
    addrServer.sin_port = htons(json_object_get_int(portNumTCP));

    //Bind TCP socket to port
    printf("Binding socket.\n");
    if ((bind(sockfd, (struct sockaddr *) &addrServer, sizeof(addrServer))) != 0) { 
        printf("TCP Socket Binding has FAILED.\n"); 
        exit(EXIT_FAILURE); 
    } else {
        printf("TCP Socket Binding is SUCCESSFUL.\n"); 
    }

    //Listen to receive connections at port
    printf("Listening.\n");
    if ((listen(sockfd, 5)) != 0) { 
        printf("Listening Failed.\n"); 
        exit(EXIT_FAILURE); 
    } 
    
    //Accepting of the connection, print message based on if connection failed or was established
    len = sizeof(addrClient);
    if ((connfd = accept(sockfd, (struct sockaddr *) &addrClient, &len)) < 0) { 
        printf("TCP Connection has FAILED.\n"); 
        exit(0); 
    } else {
        printf("TCP Connection is SUCCESSFUL.\n"); 
    }

    //This sends the TCP message
    send(connfd, message, strlen(message), 0);
    
    //Lastly, closes the socket
    close(sockfd);
    return 0;
}
