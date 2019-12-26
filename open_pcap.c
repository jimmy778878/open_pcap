#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<arpa/inet.h>
#include<net/ethernet.h>
#include<pcap/pcap.h>
#include<time.h>
#include<netinet/ip.h>
#include<netinet/tcp.h>
#include<netinet/udp.h>

void handle_ip(const u_char * content)
{
	struct ip *ip = (struct ip *)(content + ETHER_HDR_LEN);
	u_char protocol = ip->ip_p;
	char source_ip[INET_ADDRSTRLEN];
	char destination_ip[INET_ADDRSTRLEN];

	memset(source_ip,0,sizeof(source_ip));
	memset(destination_ip,0,sizeof(destination_ip));

	inet_ntop(AF_INET,&ip->ip_src,source_ip,sizeof(source_ip));
	inet_ntop(AF_INET,&ip->ip_dst,destination_ip,sizeof(destination_ip));
	printf("source ip : %s\n",source_ip);	
	printf("destination ip : %s\n\n",destination_ip);

	if(protocol==IPPROTO_TCP){
	        printf("TCP : ");
	        struct tcphdr *tcp = (struct tcphdr*)(content + ETHER_HDR_LEN  + (4 * ip->ip_hl));

        	printf("\tsource port : %5u\n",ntohs(tcp->th_sport));
	        printf("\tdestination port : %5u\n",ntohs(tcp->th_dport));
	}
	else if(protocol==IPPROTO_UDP){
		printf("UDP : ");
		struct udphdr *udp = (struct udphdr*)(content + ETHER_HDR_LEN + (4 * ip->ip_hl));
		printf("\tsource port : %5u\n",ntohs(udp->uh_sport));
                printf("\tdestination port : %5u\n",ntohs(udp->uh_dport));

	}	
}


int main(int argc,char *argv[])
{
	if(argc<3){
		return 0;
	}
	if(getopt(argc,argv,"r:")!='r'){
		return 0;
	}
	char errorbuf[PCAP_ERRBUF_SIZE];
	int ip_packet_count=0;
	pcap_t *handle = pcap_open_offline(argv[2],errorbuf);
	while(1){
		struct pcap_pkthdr *header = NULL;
		const u_char *content = NULL;
		int ret = pcap_next_ex(handle , &header , &content);
		if(ret==1){
			char time[32];
			strftime(time , sizeof(time) , "%Y/%m/%d %X" , localtime(&header->ts.tv_sec));	
			printf("timestamp : %s\n\n" , time );
		
			char dst_mac[32];
			char src_mac[32];
			struct ether_header *ethernet = (struct ether_header *)content;
			u_char * s_mac = ethernet->ether_shost;
			u_char * d_mac = ethernet->ether_dhost;
        		sprintf(src_mac, "%02x:%02x:%02x:%02x:%02x:%02x", s_mac[0], s_mac[1], s_mac[2], s_mac[3], s_mac[4], s_mac[5]);
			sprintf(dst_mac, "%02x:%02x:%02x:%02x:%02x:%02x", d_mac[0], d_mac[1], d_mac[2], d_mac[3], d_mac[4], d_mac[5]);
			printf("source MAC : %s\n",src_mac);
			printf("destination MAC : %s\n",dst_mac);
			printf("\n");	

			if(ntohs(ethernet->ether_type) == ETHERTYPE_IP){
				ip_packet_count++;
				handle_ip(content);			
			}
			printf("\n----------------------------------------------\n\n");
		}
		else{
			break;
		}	
	}
	printf("total ip packets : %d\n",ip_packet_count);
	pcap_close(handle);
	return 0;
}
