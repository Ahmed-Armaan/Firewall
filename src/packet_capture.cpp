#include "packet_capture.h"
#include <cstdio>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

void custom_pcap_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes){
    printf("length of captured packet : %d\n", h->len);
    printf("length of portion present : %d\n", h->caplen);
    printf("%ld:%ld\n", h->ts.tv_sec, h->ts.tv_usec);

    struct ethhdr *eth_hdr = (struct ethhdr *)(bytes);
    struct iphdr *ip_hdr = (struct iphdr *)(bytes + sizeof(struct ethhdr));

    printf("source MAC address : ");
    for(int i = 0; i < 6; i++)
        printf("%x", eth_hdr->h_source[i]);
    printf("\n");

    printf("destination MAC address : ");
    for(int i = 0; i < 6; i++)
        printf("%x", eth_hdr->h_dest[i]);
    printf("\n");

    switch(ip_hdr->protocol){
        case IPPROTO_TCP:{
            printf("TCP protocol\n");
            struct tcphdr *tcp_hdr = (struct tcphdr *)(bytes + sizeof(struct ethhdr) + ip_hdr->ihl);
            printf("source port used = %d\n", ntohs(tcp_hdr->th_sport));
            printf("destination port used = %d\n", ntohs(tcp_hdr->th_dport));
            break;
        }
        case IPPROTO_UDP:{
            printf("UDP protocol\n");
            struct udphdr *udp_hdr = (struct udphdr*)(bytes + sizeof(struct ethhdr) + ip_hdr->ihl);
            printf("source port used = %d\n", ntohs(udp_hdr->uh_sport));
            printf("destination port used = %d\n", ntohs(udp_hdr->uh_dport));
            break;
        }
        default:{
            printf("protocol unhandled\n");
        }
    }
    printf("---------------------------------------------------------------------------------------------------------------------\n");
}

int capture(){
    char errbuf[PCAP_ERRBUF_SIZE];
    int opts = PCAP_CHAR_ENC_UTF_8;
    char source[] = "wlo1";
    pcap_t* p;

    if(pcap_init(opts, errbuf) != 0){
        printf("%s\n", errbuf);
        return 0;
    }

    p = pcap_create(source, errbuf);
    if(p == NULL){
        printf("%s\n", errbuf);
        return 0;
    }

    if(pcap_set_snaplen(p, 65535) != 0){
        printf("%s\n", pcap_geterr(p));
        return 0;
    }

    if(pcap_set_promisc(p, 0) != 0){
        printf("%s\n", pcap_geterr(p));
        return 0;
    }

    if(pcap_set_timeout(p, 1000) != 0){
        printf("%s\n", pcap_geterr(p));
        return 0;
    }

    int activate = pcap_activate(p);
    if(activate < 0){
        printf("%s\n", pcap_geterr(p));
        return 0;
    }
    else if(activate == PCAP_WARNING_PROMISC_NOTSUP)
        printf("\033[91mWarning : promiscuous mode requested but not supported\033[00m\n");
    else if(activate == PCAP_WARNING)
        printf("%s\n", pcap_geterr(p));

    if(pcap_loop(p, -1, custom_pcap_handler, NULL) < 0){
        printf("%s\n", pcap_geterr(p));
        pcap_close(p);
        return 0;
    }

    pcap_close(p);
    return 1;
}
