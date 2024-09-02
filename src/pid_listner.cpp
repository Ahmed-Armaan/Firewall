#include <iostream>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>

#define NETLINK_BUFSIZE 8192

void get_interfaces() {
    int sock_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock_fd < 0) {
        perror("Socket creation failed");
        return;
    }

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;

    if (bind(sock_fd, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        perror("Bind failed");
        close(sock_fd);
        return;
    }

    struct {
        struct nlmsghdr nlh;
        struct rtgenmsg g;
    } req;

    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtgenmsg));
    req.nlh.nlmsg_type = RTM_GETLINK;  // Request to get link info
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq = 1;
    req.nlh.nlmsg_pid = getpid();  // This process' PID
    req.g.rtgen_family = AF_PACKET;  // Get all interfaces

    if (send(sock_fd, &req, req.nlh.nlmsg_len, 0) < 0) {
        perror("Send failed");
        close(sock_fd);
        return;
    }

    char buffer[NETLINK_BUFSIZE];
    int len;
    while ((len = recv(sock_fd, buffer, sizeof(buffer), 0)) > 0) {
        struct nlmsghdr *msg_hdr = (struct nlmsghdr *)buffer;
        while (NLMSG_OK(msg_hdr, len)) {
            if (msg_hdr->nlmsg_type == NLMSG_DONE) {
                break;
            } else if (msg_hdr->nlmsg_type == RTM_NEWLINK) {
                struct ifinfomsg *ifinfo = (struct ifinfomsg *)NLMSG_DATA(msg_hdr);
                struct rtattr *attr = (struct rtattr *)IFLA_RTA(ifinfo);
                int attr_len = msg_hdr->nlmsg_len - NLMSG_LENGTH(sizeof(*ifinfo));
                
                for (; RTA_OK(attr, attr_len); attr = RTA_NEXT(attr, attr_len)) {
                    if (attr->rta_type == IFLA_IFNAME) {
                        std::cout << "Interface: " << (char *)RTA_DATA(attr) << std::endl;
                    }
                }
            }
            msg_hdr = NLMSG_NEXT(msg_hdr, len);
        }
    }

    close(sock_fd);
}

int main() {
    get_interfaces();
    return 0;
}
