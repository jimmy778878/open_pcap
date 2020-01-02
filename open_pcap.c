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
#define case1
//#define case2
struct ip_counter{
	char s[INET_ADDRSTRLEN];
	char d[INET_ADDRSTRLEN];
	int count;
}ip_counter[100];
int ip_pair=0;

void handle_ip(const u_char * content)
{
	struct ip *ip = (struct ip *)(content + ETHER_HDR_LEN);
	
	char *source_ip = calloc(INET_ADDRSTRLEN , sizeof(char));
	char *destination_ip = calloc(INET_ADDRSTRLEN , sizeof(char));
	inet_ntop(AF_INET , &ip->ip_src , source_ip , INET_ADDRSTRLEN*sizeof(char));
	inet_ntop(AF_INET , &ip->ip_dst , destination_ip , INET_ADDRSTRLEN*sizeof(destination_ip));

#ifdef case1
	int i=0,find=0;
	for(i=0;i<ip_pair;i++){
		if(( strcmp(ip_counter[i].s , source_ip)||strcmp(ip_counter[i].d , destination_ip) )==0){
			find=1;
			ip_counter[i].count++;
		}
	}
#endif
#ifdef case2
	int i=0,find=0;
	for(i=0;i<ip_pair;i++){
		if(( strcmp(ip_counter[i].s , source_ip)||strcmp(ip_counter[i].d , destination_ip) )==0){
			find=1;
			ip_counter[i].count++;
		}
		else if(( strcmp(ip_counter[i].s , destination_ip)||strcmp(ip_counter[i].d , source_ip) )==0){
			find=1;
			ip_counter[i].count++;
		}
	}
#endif

	if(!find){
		ip_pair++;
		strcpy(ip_counter[i].s , source_ip);
		strcpy(ip_counter[i].d , destination_ip);
		ip_counter[i].count=1;
	}

	printf("source ip : %s\n",source_ip);   
	printf("destination ip : %s\n\n",destination_ip);
	
	
	if(ip->ip_p==IPPROTO_TCP){
	        printf("TCP : ");
	        struct tcphdr *tcp = (struct tcphdr*)(content + ETHER_HDR_LEN  + (4 * ip->ip_hl));
        	printf("\tsource port : %d\n",ntohs(tcp->source));
	        printf("\tdestination port : %d\n",ntohs(tcp->dest));
	}
	else if(ip->ip_p==IPPROTO_UDP){
		printf("UDP : ");
		struct udphdr *udp = (struct udphdr*)(content + ETHER_HDR_LEN + (4 * ip->ip_hl));
		printf("\tsource port : %d\n",ntohs(udp->source));
                printf("\tdestination port : %d\n",ntohs(udp->dest));

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
			
                        struct ether_header *ethernet = (struct ether_header *)content;
                      	u_char *s = ethernet->ether_shost;
			u_char *d = ethernet->ether_dhost;
			printf("source MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",*s,*(s+1),*(s+2),*(s+3),*(s+4),*(s+5));
                        printf("destination MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",*d,*(d+1),*(d+2),*(d+3),*(d+4),*(d+5));

			printf("\n");	

			if(ntohs(ethernet->ether_type) == ETHERTYPE_IP){
				handle_ip(content);			
			}
			printf("\n----------------------------------------------\n\n");
		}
		else{
			break;
		}	
	}

	printf("----------------------------------------------\n");
#ifdef case1
	for(int i=0;i<ip_pair;i++){
		printf("pair %d : \n",i);
		printf("source ip : %s\n",ip_counter[i].s);
		printf("destination ip : %s\n",ip_counter[i].d);
		printf("pair amount: %d\n",ip_counter[i].count);
		printf("------------------------\n\n");
	}
#endif
#ifdef case2
	for(int i=0;i<ip_pair;i++){
                printf("pair %d : \n",i);
                printf("ip1 : %s\n",ip_counter[i].s);
                printf("ip2 : %s\n",ip_counter[i].d);
                printf("pair amount: %d\n",ip_counter[i].count);
                printf("------------------------\n\n");
        }
#endif
	pcap_close(handle);
	return 0;
}
