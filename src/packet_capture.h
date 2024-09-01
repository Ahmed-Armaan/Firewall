#ifndef CAPTURER_H
#define CAPTURER_H

#include <pcap.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <cstring>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/socket.h>
#include <unistd.h>

void custom_pcap_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
int capture();

#endif 
