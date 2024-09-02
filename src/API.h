#ifndef API_H
#define API_H

#include <string>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>
#include <chrono>
#include <arpa/inet.h>

struct Data {
	unsigned char *s_mac;
	unsigned char *d_mac;
	unsigned int s_ip;
	unsigned int d_ip;
	int s_port;
	int d_port;
};

void send_to_server(const struct Data& data);
int api(struct Data data);

#endif
