#include "packet_capture.h"

void* get_mac() { // find mac address of the device
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct ifreq ifreq;
    strcpy(ifreq.ifr_name, "wlo1");  

    if (ioctl(fd, SIOCGIFHWADDR, &ifreq) == -1) {
        printf("ioctl failed\n");
        close(fd);
        return nullptr;
    }

    close(fd);
    unsigned char* mac_buffer = (unsigned char*)malloc(6);
    if (mac_buffer == nullptr) {
        printf("Memory allocation failed\n");
        return nullptr;
    }
    memcpy(mac_buffer, ifreq.ifr_hwaddr.sa_data, 6);

    return (void*)mac_buffer;
}

void custom_pcap_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) { // capture and handle packets
    printf("Length of captured packet: %d\n", h->len);
    printf("Length of portion present: %d\n", h->caplen);
    printf("%ld:%ld\n", h->ts.tv_sec, h->ts.tv_usec);

    struct ethhdr *eth_hdr = (struct ethhdr *)(bytes);
    struct iphdr *ip_hdr = (struct iphdr *)(bytes + sizeof(struct ethhdr));
    unsigned char *mac_address = (unsigned char *)get_mac(); 
    unsigned char mac_addr_buf[6];

    printf("Source MAC address: ");
    memcpy(mac_addr_buf, eth_hdr->h_source, 6);
    for(int i = 0; i < 6; i++)
        printf("%02x", eth_hdr->h_source[i]);
    printf("\n");

    printf("Destination MAC address: ");
    for(int i = 0; i < 6; i++)
        printf("%02x", eth_hdr->h_dest[i]);
    printf("\n");

    switch(ip_hdr->protocol){
        case IPPROTO_TCP: {
            printf("TCP protocol\n");
            struct tcphdr *tcp_hdr = (struct tcphdr *)(bytes + sizeof(struct ethhdr) + (ip_hdr->ihl * 4));
            printf("Source port used = %d\n", ntohs(tcp_hdr->th_sport));
            printf("Destination port used = %d\n", ntohs(tcp_hdr->th_dport));
            break;
        }
        case IPPROTO_UDP: {
            printf("UDP protocol\n");
            struct udphdr *udp_hdr = (struct udphdr*)(bytes + sizeof(struct ethhdr) + (ip_hdr->ihl * 4));
            printf("Source port used = %d\n", ntohs(udp_hdr->uh_sport));
            printf("Destination port used = %d\n", ntohs(udp_hdr->uh_dport));
            break;
        }
        default: {
            printf("Protocol unhandled\n");
            break;
        }
    }

    if(memcmp(mac_addr_buf, mac_address, 6) == 0)
        printf("Packet Sent\n");
    else
        printf("Packet Received\n");

    printf("--------------------------------------------------------------------------------------------------------------------------------------------------\n");

    free(mac_address); 
}

int capture(){ // pcap setup
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

