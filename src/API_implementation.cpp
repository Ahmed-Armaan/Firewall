#include "API.h"

struct Data server_data;

void send_to_server(const struct Data& data) {
    int sock;
    struct sockaddr_in server_addr;
    char request[1024];
    char json_data[256];
    snprintf(json_data, sizeof(json_data),
             "{\"s_mac\": \"%02X:%02X:%02X:%02X:%02X:%02X\", \"d_mac\": \"%02X:%02X:%02X:%02X:%02X:%02X\", \"s_ip\": %u, \"d_ip\": %u, \"s_port\": %d, \"d_port\": %d}",
             data.s_mac[0], data.s_mac[1], data.s_mac[2],
             data.s_mac[3], data.s_mac[4], data.s_mac[5],
             data.d_mac[0], data.d_mac[1], data.d_mac[2],
             data.d_mac[3], data.d_mac[4], data.d_mac[5],
             data.s_ip, data.d_ip, data.s_port, data.d_port);

    // Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(3000);

    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr) <= 0) {
        perror("Invalid address or Address not supported");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Connect to the server
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection Failed");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Prepare HTTP POST request
    snprintf(request, sizeof(request),
             "GET / HTTP/1.1\r\n"
             "Host: localhost\r\n"
             "Content-Type: application/json\r\n"
             "Content-Length: %zu\r\n"
             "Connection: close\r\n\r\n"
             "%s",
             strlen(json_data), json_data);

    // Send the request
    send(sock, request, strlen(request), 0);
    close(sock);
}

int api( struct Data data) {
    server_data = data;
    // Send data to the server
    send_to_server(server_data);

    return 0;
}
