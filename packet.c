
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

struct sockaddr_in source,dest;
int tcp=0,i,j; 


void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    int size = header->len;
     
      struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
   
    switch (iph->protocol) 
    {          
        case 6:  
            ++tcp;
            print_tcp_packet(buffer , size);
            break;                
         
        default:          
            break;
    }    
}
 
void print_ethernet_header(const u_char *Buffer, int Size)
{
    struct ethhdr *eth = (struct ethhdr *)Buffer;
     
    printf("\n"); 
    printf("Eth |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
    printf("Eth |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );   
}
 
void print_ip_header(const u_char * Buffer, int Size)
{
    print_ethernet_header(Buffer , Size);
   
    unsigned short iphdrlen;
         
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
    iphdrlen =iph->ihl*4;
     
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
     
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
     
    printf("\n");
    printf("IP |-Source IP        : %s\n" , inet_ntoa(source.sin_addr) );
    printf("TP |-Destination IP   : %s\n" , inet_ntoa(dest.sin_addr) );
}
 
void print_tcp_packet(const u_char * Buffer, int Size)
{
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
    iphdrlen = iph->ihl*4;
     
    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
             
    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
     
    printf("\n\n--------------------TCP Packet------------------\n");  
         
    print_ip_header(Buffer,Size);
         
    printf("\n");
    printf("TCP |-Source Port      : %u\n",ntohs(tcph->source));
    printf("TCP |-Destination Port : %u\n",ntohs(tcph->dest));  

    printf("\n");
    printf("                        DATA Dump                         ");
    printf("\n");   
         
    printf("Data Payload\n");    
    PrintData(Buffer + header_size , Size - header_size );
                         
    printf("\n------------------------------------------------");
}
 

void PrintData (const u_char * data , int Size)
{
    int i , j;
    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)  
        {
            printf("         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    printf("%c",(unsigned char)data[j]); 
                 
                else printf(".");
            }
            printf("\n");
        } 
         
        if(i%16==0) printf("   ");
            printf(" %02X",(unsigned int)data[i]);
                 
        if( i==Size-1) 
        {
            for(j=0;j<15-i%16;j++) 
            {
              printf("   "); 
            }
             
            printf("         ");
             
            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128) 
                {
                  printf("%c",(unsigned char)data[j]);
                }
                else
                {
                  printf(".");
                }
            }
             
            printf( "\n" );
        }
    }
}