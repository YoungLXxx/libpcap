#include <pcap.h> 
#include <stdio.h>
#include <arpa/inet.h>
#include "myheader.h"
#include <ctype.h>

/*************************************************************
 功能：回调函数，处理抓到的数据包
 第一个参数是pcap_loop的最后一个参数，当收到足够数量的包后pcap_loop会调用callback回调函数（本函数中为getPacket），同时将pcap_loop()的user参数传递给它，
 第二个参数是收到的数据包的pcap_pkthdr类型的指针，
 第三个参数是收到的数据包数据
 **************************************************************/
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) 
{ 
	int i=0;
	int size_data=0;
	printf("\nGot a packet\n"); 
	struct ethheader *eth=(struct ethheader *)packet;
	switch (ntohs(eth->ether_type))
    {
    case TYPE_IP:{
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
        printf("	From: %s\n",inet_ntoa(ip->iph_sourceip));
        printf("	To: %s\n",inet_ntoa(ip->iph_destip));

        struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + sizeof(struct ipheader));

        printf("	Source Port: %d\n",ntohs(tcp->tcp_sport));
        printf("	Destination Port: %d\n",ntohs(tcp->tcp_dport));
    

        switch(ip->iph_protocol) {
            case IPPROTO_TCP:
                printf("	Protocol: TCP\n");
                break;
            case IPPROTO_UDP:
                printf("	Protocol: UDP\n");
                break;
            case IPPROTO_ICMP:
                printf("	Protocol: ICMP\n");
                break;
            default:
                printf("	Protocol: Others\n");
                break;
            }


        char *data = (u_char *)packet + sizeof(struct ethheader) + sizeof(struct ipheader) + sizeof(struct tcpheader);
        size_data = ntohs(ip->iph_len) - (sizeof(struct ipheader) + sizeof(struct tcpheader));
        if (size_data > 0) {
            printf("   Payload (%d bytes):\n", size_data);
            for(i = 0; i < size_data; i++) {
            if (isprint(*data))
                printf("%c", *data);
            else
                printf(".");
            data++;
            }
        }
    }
        break;
    case TYPE_ARP:
        printf("arp packet arrived!\n");
        break;
    case TYPE_LSC:{
        printf("lsc packet arrived!\n");
    }
        break;
    default:
        break;
    }
	
return;

}

int main() 
{ 
	pcap_t *handle; 
	char errbuf[PCAP_ERRBUF_SIZE]; //定义存储错误信息的字符串，执行嗅探的设备
	struct bpf_program fp; 
	char filter_exp[] = "ether dst ff:ff:ff:ff:ff:ff and(ether proto 0x0806 or ether proto 0x0800)"; 
	bpf_u_int32 net;

	// Step 1: Open live pcap session on NIC with interface name
    /*
    返回指定接口的pcap_t类型指针，后面的所有操作都要使用这个指针。
        第一个参数是第一步获取的网络接口字符串，可以直接使用硬编码。
	    第二个参数是对于每个数据包，从开头要抓多少个字节，我们可以设置这个值来只抓每个数据包的头部，而不关心具体的内容。典型的以太网帧长度是1518字节，但其他的某些协议的数据包会更长一点，但任何一个协议的一个数据包长度都必然小于65535个字节。
	    第三个参数指定是否打开混杂模式(Promiscuous Mode)，0表示非混杂模式，任何其他值表示混合模式。如果要打开混杂模式，那么网卡必须也要打开混杂模式，可以使用如下的命令打开eth0混杂模式：ifconfig eth0 promisc
	    第四个参数指定需要等待的毫秒数，超过这个数值后，第3步获取数据包的这几个函数就会立即返回。0表示一直等待直到有数据包到来。
	    第五个参数是存放出错信息的数组
    */
	handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);

	// Step 2: Compile filter_exp into BPF psuedo-code 
	pcap_compile(handle, &fp, filter_exp, 0, net); 
	pcap_setfilter(handle, &fp);

	// Step 3: Capture packets 
	pcap_loop(handle, -1, got_packet, NULL);

	pcap_close(handle); //Close the handle 
	return 0;
}
