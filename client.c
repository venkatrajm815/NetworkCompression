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

//This method is responsible for the filling with the high entropy data
void read_high_entropy_data(int *data, int length){
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
void read_low_entropy_data(int *data, int length){
    for(int i = 2; i < length; i++) {
        data[i] = 0;
    }
}

//This method is responsible for setting the id for the packets
void set_packet_id(int *data, int index){
    unsigned int temp = index;
    unsigned char lower = (unsigned)temp & 0xff;
    unsigned char upper = (unsigned)temp >> 8; 
    data[0] = lower; //this is to set the first index to 'lower bit'
    data[1] = upper; //this is to set the first index to 'upper bit'
}

//This method sends the file using sockets#include <stdio.h>
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

//This method is responsible for the filling with the high entropy data
void read_high_entropy_data(int *data, int length){
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
void read_low_entropy_data(int *data, int length){
    for(int i = 2; i < length; i++) {
        data[i] = 0;
    }
}

//This method is responsible for setting the id for the packets
void set_packet_id(int *data, int index){
    unsigned int temp = index;
    unsigned char lower = (unsigned)temp & 0xff;
    unsigned char upper = (unsigned)temp >> 8; 
    data[0] = lower; //this is to set the first index to 'lower bit'
    data[1] = upper; //this is to set the first index to 'upper bit'
}

//This method sends the file using sockets
void send_file(int sockfd){ 
    char buffer[BUFFER_SIZE];                        
    FILE *fp=fopen("myconfig.json","r");   	
    while (fgets(buffer,BUFFER_SIZE,fp) != NULL ){
        write(sockfd,buffer,strlen(buffer)); 
    }	
    fclose(fp);
    printf("The File was successfully sent.\n");
}

int main(int argc, char * argv[]){
    int sockfd, DF;
    char buffer[BUFFER_SIZE], compression[25];
    FILE *fp;
    struct sockaddr_in server_address, client_address;
    struct json_object *parsed_json, *Server_IP_Address, *Source_Port_Number_UDP, *Destination_Port_Number_UDP,
    *Destination_Port_Number_TCP_Head, *Destination_Port_Number_TCP_Tail, *Port_Number_TCP, 
    *Size_UDP_Payload, *Inter_Measurement_Time, *Number_UDP_Packets, *TTL_UDP_Packets;

    //This checks if there is an error in executing the configuration file 
    if (argv[1] == NULL){
        printf("There is an error in executing the configuration file! \n The proper usage would be ./'name of executable' 'my_config_file'.json\n");
        return EXIT_FAILURE;
    }


    //This is the Pre-Probing Phase
	
    fp = fopen(argv[1],"r"); 
    if(fp == NULL) {
        printf("There is an error opening the file!\n"); 
        return EXIT_FAILURE;
    }
    printf("Parsing...\n");
    //Here we go through the file and put the contents into buffer, then we parse through the myconfig.json and convert it into a JSON object	
    fread(buffer, BUFFER_SIZE, 1, fp); 
    parsed_json = json_tokener_parse(buffer);

    //This is where store the parsed data from the JSON file into variables
    json_object_object_get_ex(parsed_json, "Server_IP_Address", &Server_IP_Address);
    json_object_object_get_ex(parsed_json, "Source_Port_Number_UDP", &Source_Port_Number_UDP);
    json_object_object_get_ex(parsed_json, "Destination_Port_Number_UDP", &Destination_Port_Number_UDP);
    json_object_object_get_ex(parsed_json, "Destination_Port_Number_TCP_Head", &Destination_Port_Number_TCP_Head);
    json_object_object_get_ex(parsed_json, "Destination_Port_Number_TCP_Tail", &Destination_Port_Number_TCP_Tail);
    json_object_object_get_ex(parsed_json, "Port_Number_TCP", &Port_Number_TCP);
    json_object_object_get_ex(parsed_json, "Size_UDP_Payload", &Size_UDP_Payload);
    json_object_object_get_ex(parsed_json, "Inter_Measurement_Time", &Inter_Measurement_Time);
    json_object_object_get_ex(parsed_json, "Number_UDP_Packets", &Number_UDP_Packets);
    json_object_object_get_ex(parsed_json, "TTL_UDP_Packets", &TTL_UDP_Packets);
    printf("The Parsing is Successful!\n");

    //This is where we begin the creation of the socket
    printf("Socket is being created.\n");
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0){ 
        printf("Socket Creation has FAILED.\n"); 
        exit(EXIT_FAILURE); 
    } 
    else{
        printf("Socket Creation is SUCCESSFUL.\n"); 
    }

    //Here we fill all the information involving the ip address: involves the binding to the ip address and binding to the port
    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET; 
    server_address.sin_addr.s_addr = inet_addr(json_object_get_string(Server_IP_Address)); 
    server_address.sin_port = htons(json_object_get_int(Port_Number_TCP));
    
    //This is where we connect the server and client sockets together
    printf("Connecting sockets.\n");
    if (connect(sockfd, (struct sockaddr *)&server_address, sizeof(server_address)) != 0){ 
	printf("Connection to the server has FAILED.\n"); 
	exit(EXIT_FAILURE); 
    } 
    else{
        printf("Connection to the server is SUCCESSFUL.\n"); 
    }
    //Lastly, we send and close the socket
    send_file(sockfd); 
    close(sockfd); 

    //This is the Probing Phase

    int datagram[json_object_get_int(Size_UDP_Payload) + 2];
    //This puts a zero for everything in the client address	
    memset(&client_address, 0, sizeof(client_address));
    client_address.sin_family = AF_INET; 
    client_address.sin_addr.s_addr = htonl(INADDR_ANY);
    client_address.sin_port = htons(json_object_get_int(Source_Port_Number_UDP));
    server_address.sin_port = htons(json_object_get_int(Destination_Port_Number_UDP));

    //We begin creating the UDP socket
    //Print message based on if it was succesful or not	
    printf("Creating Socket.\n");
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ){ 
        perror("UDP Socket Creation has FAILED\n"); 
        exit(EXIT_FAILURE); 
    }
    else{
        printf("UDP Socket Creation is SUCCESSFUL\n");
    }
    
    //This is the setting of the DON'T fragment
    DF = IP_PMTUDISC_DO; 
    printf("Setting DON'T FRAGMENT bit...\n");
    if(setsockopt(sockfd, IPPROTO_IP, IP_MTU_DISCOVER, &DF, sizeof(DF)) < 0){
        printf("Unable to set DON'T FRAGMENT bit\n");
    }
    else{
        printf("DON'T FRAGMENT bit set correctly!\n");
    }
    
    //A check to see if the socket bind passed, prints error message if failed	
    if(bind(sockfd, (struct sockaddr *)&client_address, sizeof(client_address)) < 0){
        printf("UDP Socket Bind Failed\n");
        exit(EXIT_FAILURE);
    }
    sleep(5);

    //This is the sending of the LOW entropy data
    read_low_entropy_data(datagram, json_object_get_int(Size_UDP_Payload)+2);
    printf("Sending Low Entropy Data.\n");
    for(int i = 1; i < json_object_get_int(Number_UDP_Packets) + 1; i++){
        set_packet_id(datagram, i);
        sendto(sockfd, datagram, json_object_get_int(Size_UDP_Payload) + 2, MSG_CONFIRM, (const struct sockaddr *) &server_address, sizeof(server_address));
    }
    printf("Low Entropy data has been sent.\n");

    //Sleeping using the inter-measurement time from the json object
    printf("Sleeping.\n");
    sleep(json_object_get_int(Inter_Measurement_Time));

    //This is the sending of the HIGH entropy data
    read_high_entropy_data(datagram, json_object_get_int(Size_UDP_Payload)+2);
    printf("Sending High Entropy Data.\n");
    for(int i = 1; i < json_object_get_int(Number_UDP_Packets) + 1; i++){
        set_packet_id(datagram, i);
        sendto(sockfd, datagram, json_object_get_int(Size_UDP_Payload)+2, MSG_CONFIRM, (const struct sockaddr *) &server_address, sizeof(server_address));
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
    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET; 
    server_address.sin_addr.s_addr = inet_addr(json_object_get_string(Server_IP_Address)); 
    server_address.sin_port = htons(json_object_get_int(Port_Number_TCP));
    
    //This is where we connect the client socket to the server socket
    printf("Connecting client socket to server socket.\n");
    if (connect(sockfd, (struct sockaddr *)&server_address, sizeof(server_address)) != 0){ 
	printf("Connection to the server has FAILED.\n"); 
	exit(EXIT_FAILURE); 
    } 
    else{
        printf("Connection to the server is SUCCESSFUL.\n"); 
    }	

    recv(sockfd, &compression, sizeof(compression), 0);
    printf("The servers's response is : %s\n" , compression);

    close(sockfd); 
    return 0;
}

void send_file(int sockfd){ 
    char buffer[BUFFER_SIZE];                        
    FILE *fp=fopen("myconfig.json","r");   	
    while (fgets(buffer,BUFFER_SIZE,fp) != NULL ){
        write(sockfd,buffer,strlen(buffer)); 
    }	
    fclose(fp);
    printf("The File was successfully sent.\n");
}

int main(int argc, char * argv[]){
    int sockfd, DF;
    char buffer[BUFFER_SIZE], compression[25];
    FILE *fp;
    struct sockaddr_in server_address, client_address;
    struct json_object *parsed_json, *Server_IP_Address, *Source_Port_Number_UDP, *Destination_Port_Number_UDP,
    *Destination_Port_Number_TCP_Head, *Destination_Port_Number_TCP_Tail, *Port_Number_TCP, 
    *Size_UDP_Payload, *Inter_Measurement_Time, *Number_UDP_Packets, *TTL_UDP_Packets;

    //This checks if there is an error in executing the configuration file 
    if (argv[1] == NULL){
        printf("There is an error in executing the configuration file! \n The proper usage would be ./'name of executable' 'my_config_file'.json\n");
        return EXIT_FAILURE;
    }


    //This is the Pre-Probing Phase
	
    fp = fopen(argv[1],"r"); 
    if(fp == NULL) {
        printf("There is an error opening the file!\n"); 
        return EXIT_FAILURE;
    }
    printf("Parsing...\n");
    //Here we go through the file and put the contents into buffer, then we parse through the myconfig.json and convert it into a JSON object	
    fread(buffer, BUFFER_SIZE, 1, fp); 
    parsed_json = json_tokener_parse(buffer);

    //This is where store the parsed data from the JSON file into variables
    json_object_object_get_ex(parsed_json, "Server_IP_Address", &Server_IP_Address);
    json_object_object_get_ex(parsed_json, "Source_Port_Number_UDP", &Source_Port_Number_UDP);
    json_object_object_get_ex(parsed_json, "Destination_Port_Number_UDP", &Destination_Port_Number_UDP);
    json_object_object_get_ex(parsed_json, "Destination_Port_Number_TCP_Head", &Destination_Port_Number_TCP_Head);
    json_object_object_get_ex(parsed_json, "Destination_Port_Number_TCP_Tail", &Destination_Port_Number_TCP_Tail);
    json_object_object_get_ex(parsed_json, "Port_Number_TCP", &Port_Number_TCP);
    json_object_object_get_ex(parsed_json, "Size_UDP_Payload", &Size_UDP_Payload);
    json_object_object_get_ex(parsed_json, "Inter_Measurement_Time", &Inter_Measurement_Time);
    json_object_object_get_ex(parsed_json, "Number_UDP_Packets", &Number_UDP_Packets);
    json_object_object_get_ex(parsed_json, "TTL_UDP_Packets", &TTL_UDP_Packets);
    printf("The Parsing is Successful!\n");

    //This is where we begin the creation of the socket
    printf("Socket is being created.\n");
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0){ 
        printf("Socket Creation has FAILED.\n"); 
        exit(EXIT_FAILURE); 
    } 
    else{
        printf("Socket Creation is SUCCESSFUL.\n"); 
    }

    //Here we fill all the information involving the ip address: involves the binding to the ip address and binding to the port
    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET; 
    server_address.sin_addr.s_addr = inet_addr(json_object_get_string(Server_IP_Address)); 
    server_address.sin_port = htons(json_object_get_int(Port_Number_TCP));
    
    //This is where we connect the server and client sockets together
    printf("Connecting sockets.\n");
    if (connect(sockfd, (struct sockaddr *)&server_address, sizeof(server_address)) != 0){ 
	printf("Connection to the server has FAILED.\n"); 
	exit(EXIT_FAILURE); 
    } 
    else{
        printf("Connection to the server is SUCCESSFUL.\n"); 
    }
    //Lastly, we send and close the socket
    send_file(sockfd); 
    close(sockfd); 

    //This is the Probing Phase

    int datagram[json_object_get_int(Size_UDP_Payload) + 2];
    //This puts a zero for everything in the client address	
    memset(&client_address, 0, sizeof(client_address));
    client_address.sin_family = AF_INET; 
    client_address.sin_addr.s_addr = htonl(INADDR_ANY);
    client_address.sin_port = htons(json_object_get_int(Source_Port_Number_UDP));
    server_address.sin_port = htons(json_object_get_int(Destination_Port_Number_UDP));

    //We begin creating the UDP socket
    //Print message based on if it was succesful or not	
    printf("Creating Socket.\n");
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ){ 
        perror("UDP Socket Creation has FAILED\n"); 
        exit(EXIT_FAILURE); 
    }
    else{
        printf("UDP Socket Creation is SUCCESSFUL\n");
    }
    
    //This is the setting of the DON'T fragment
    DF = IP_PMTUDISC_DO; 
    printf("Setting DON'T FRAGMENT bit...\n");
    if(setsockopt(sockfd, IPPROTO_IP, IP_MTU_DISCOVER, &DF, sizeof(DF)) < 0){
        printf("Unable to set DON'T FRAGMENT bit\n");
    }
    else{
        printf("DON'T FRAGMENT bit set correctly!\n");
    }
    
    //A check to see if the socket bind passed, prints error message if failed	
    if(bind(sockfd, (struct sockaddr *)&client_address, sizeof(client_address)) < 0){
        printf("UDP Socket Bind Failed\n");
        exit(EXIT_FAILURE);
    }
    sleep(5);

    //This is the sending of the LOW entropy data
    read_low_entropy_data(datagram, json_object_get_int(Size_UDP_Payload)+2);
    printf("Sending Low Entropy Data.\n");
    for(int i = 1; i < json_object_get_int(Number_UDP_Packets) + 1; i++){
        set_packet_id(datagram, i);
        sendto(sockfd, datagram, json_object_get_int(Size_UDP_Payload) + 2, MSG_CONFIRM, (const struct sockaddr *) &server_address, sizeof(server_address));
    }
    printf("Low Entropy data has been sent.\n");

    //Sleeping using the inter-measurement time from the json object
    printf("Sleeping.\n");
    sleep(json_object_get_int(Inter_Measurement_Time));

    //This is the sending of the HIGH entropy data
    read_high_entropy_data(datagram, json_object_get_int(Size_UDP_Payload)+2);
    printf("Sending High Entropy Data.\n");
    for(int i = 1; i < json_object_get_int(Number_UDP_Packets) + 1; i++){
        set_packet_id(datagram, i);
        sendto(sockfd, datagram, json_object_get_int(Size_UDP_Payload)+2, MSG_CONFIRM, (const struct sockaddr *) &server_address, sizeof(server_address));
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
    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET; 
    server_address.sin_addr.s_addr = inet_addr(json_object_get_string(Server_IP_Address)); 
    server_address.sin_port = htons(json_object_get_int(Port_Number_TCP));
    
    //This is where we connect the client socket to the server socket
    printf("Connecting client socket to server socket.\n");
    if (connect(sockfd, (struct sockaddr *)&server_address, sizeof(server_address)) != 0){ 
	printf("Connection to the server has FAILED.\n"); 
	exit(EXIT_FAILURE); 
    } 
    else{
        printf("Connection to the server is SUCCESSFUL.\n"); 
    }	

    recv(sockfd, &compression, sizeof(compression), 0);
    printf("The servers's response is : %s\n" , compression);

    close(sockfd); 
    return 0;
}
