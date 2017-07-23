
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h> 
#include <string.h> 

#include <sys/socket.h>
#include <arpa/inet.h> 
#include <net/ethernet.h>
#include <netinet/tcp.h>   
#include <netinet/ip.h>  

#include "packet.h"


int main(int argc, char* argv[])
{
 //   pcap_if_t *alldevsp , *device;
    int res ;
    pcap_t *handle; 
    const u_char *pkt_data;
    struct pcap_pkthdr *header;


    char errbuf[100] , *devname ; /*, devs[100][100];
    int count = 1 , n;
     
   
    printf("Finding available devices ... ");
    if( pcap_findalldevs( &alldevsp , errbuf) )
    {
        printf("Error finding devices : %s" , errbuf);
        exit(1);
    }
    printf("Done");
     
    //Print the available devices
    printf("\nAvailable Devices are :\n");
    for(device = alldevsp ; device != NULL ; device = device->next)
    {
        printf("%d. %s - %s\n" , count , device->name , device->description);
        if(device->name != NULL)
        {
            strcpy(devs[count] , device->name);
        }
        count++;
    }
     
   
    printf("Enter the number of the device you want to sniff : ");
    scanf("%d" , &n);
    devname = devs[n];*/

    devname = argv[1];


    printf("Opening device %s for sniffing ... " , devname);
    handle = pcap_open_live(devname , 65536 , 1 , 0 , errbuf);

    if (handle == NULL) 
    {
        fprintf(stderr, "Couldn't open device %s : %s\n" , devname , errbuf);
        exit(1);
    }
    printf("Done\n");    

    //pcap_loop(handle , -1 , process_packet , NULL);

    

    while((res = pcap_next_ex( handle, &header, &pkt_data)) >= 0){

        if(res == 0)
            /* Timeout elapsed */
            continue;       
        print_tcp_packet(pkt_data , header->len);       

    }
    
    if(res == -1){
        printf("Error reading the packets: %s\n", pcap_geterr(handle));
        return -1;
    }
    return 0;   
}