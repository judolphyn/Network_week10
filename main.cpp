#include <pcap.h>
#include <cstdio>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/ioctl.h> 
#include <sys/socket.h>
#include <net/if.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include "headers.h"

#define SIZE_ETHERNET 14

void usage(){
	printf("syntax : tcp-block <interface> <pattern>\n");
	printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

bool packet_analysis(const u_char* packet, const char* pattern, int len){
	const struct sniff_ethernet *ethernet; /* The ethernet header */
	const struct sniff_ip *ip; /* The IP header */
	const struct sniff_tcp *tcp; /* The TCP header */
	const u_char *payload; /* Packet payload */
	
	u_int size_ip;
	u_int size_tcp;

	/* ethernet parse */
	ethernet = (struct sniff_ethernet*)(packet);
	if (ethernet->ether_type != 0x0008){
		printf("   * Not IPv4 Type\n");
		return false;
	}

	/* ip header parse */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	if (ip->ip_p != 6){
		printf("   * Not TCP Type\n"); 
		return false;
	}
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) { // ip length should be bigger than 19 
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return false;
	}

	/* tcp header parse */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) { // tcp length should be bigger than 19 
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return false;
	}

	/* payload parse */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	int payload_len = len - (SIZE_ETHERNET + size_ip + size_tcp);
	printf("   * Payload len is %d\n\n", payload_len);
	if (payload_len <= 0) {
		return false;
	}
	
	/* pattern matching */
	int pattern_len = strlen(pattern);
	int i;
	for(i=0;i<= payload_len - pattern_len;i++){
		if(strncmp((char*)(payload+i),pattern,pattern_len) == 0) 
			return true;
	}
	return false;
}

u_short ip_checksum(u_char* ip_header){
	int i;
	int sum = 0;
	for(i=0;i<20;i+=2){
		sum += *(u_short*)(ip_header + i);
	}
	// if temp is over than 
	u_short chk = sum >> 16;
	chk = chk + sum & 0xffff;
	return chk ^ 0xffff;
}

u_short tcp_checksum(u_char* ip_header, u_char* tcp_header, int message_len){
	int i;
	int sum = 0;
	for (i=12;i<20;i+=2){
		sum += *(u_short*)(ip_header + i);
	}
	sum += htons(6); // protocol = tcp
	sum += htons(20+message_len); // tcp header data length

	for(i=0;i<20+message_len;i+=2){
		sum += *(u_short*)(tcp_header + i);
	}
	u_short chk = sum >> 16 ;
	chk = chk + sum & 0xffff;
	return ~chk;
} 

void tcp_block(pcap_t* handle, const u_char* packet, const char* pattern, int len){
	const struct sniff_ethernet *ethernet; /* The ethernet header */
	const struct sniff_ip *ip; /* The IP header */
	const struct sniff_tcp *tcp; /* The TCP header */
	const u_char *payload; /* Packet payload */
	
	u_int size_ip;
	u_int size_tcp;
	int i, j;

	ethernet = (struct sniff_ethernet*)(packet);
	
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;

	// foward packet.
	u_char* foward_packet;
	foward_packet = (u_char*)malloc(54);
	memset(foward_packet,0,54);
	
	// ethernet header
	memcpy(foward_packet,ethernet,14);

	// ip header 
	memcpy(foward_packet+14,ip,20);
	struct sniff_ip* foward_ip = (sniff_ip*)((u_char*)foward_packet+14);
	*((char*)foward_ip) = 0x45;
	foward_ip->ip_len = htons(40);

	foward_ip->ip_sum = 0;
	foward_ip->ip_sum = ip_checksum((u_char*)foward_ip);
	
	//tcp header
	memcpy(foward_packet+34,tcp,20);
	struct sniff_tcp* foward_tcp = (sniff_tcp*)((u_char*)foward_packet+34);

	foward_tcp->th_flags = 0x04;
	foward_tcp->th_sum = 0;
	foward_tcp->th_sum = tcp_checksum((u_char*)foward_ip, (u_char*)foward_tcp, 0);

	int res = pcap_sendpacket(handle,foward_packet,54);
	if (res != 0) printf("send foward packet Error!!\n");



	// backward packet.
	u_char* backward_packet;
	backward_packet = (u_char*)malloc(65);
	memset(backward_packet,0,65);
	
	// ethernet header
	memcpy(backward_packet,ethernet,14);
	memcpy(backward_packet,ethernet+6,6); //dmac to smac

	// ip header 
	memcpy(backward_packet+14,ip,20);
	memcpy(backward_packet+14+12,ip+16,4); //sip to dip
	memcpy(backward_packet+14+16,ip+12,4); //dip to sip

	struct sniff_ip* backward_ip = (sniff_ip*)((u_char*)backward_packet+14);
	*((char*)backward_ip) = 0x45;
	backward_ip->ip_len = htons(51); //40+11

	backward_ip->ip_sum = 0;
	backward_ip->ip_sum = ip_checksum((u_char*)backward_ip);
	
	//tcp header
	memcpy(backward_packet+34,tcp,20);
	memcpy(backward_packet+34,tcp+2,2); //sport to dport
	memcpy(backward_packet+34+2,tcp,2); //dport to sport
	memcpy(backward_packet+54,"blocked!!!",11);
	struct sniff_tcp* backward_tcp = (sniff_tcp*)((u_char*)backward_packet+34);

	backward_tcp->th_flags = 0x01;
	backward_tcp->th_sum = 0;
	backward_tcp->th_sum = tcp_checksum((u_char*)backward_ip,(u_char*)backward_tcp,11);

	res = pcap_sendpacket(handle,backward_packet,65);
	if (res != 0) printf("send backward packet Error!!\n");
	return;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        usage();
        return -1;
    }
    char* interface = argv[1];
    char* pattern = argv[2];
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", interface, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        if (packet_analysis(packet,pattern,header->caplen)){
        	printf("wow it's great!\n\n\n\n");
        	tcp_block(handle,packet,pattern,header->caplen);
        }
        printf("packet check complete\n\n\n");
    }
    pcap_close(handle);

    return 0;
}
