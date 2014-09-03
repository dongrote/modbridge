#include <asm/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#ifndef NTF_SELF
#define NTF_SELF (0x02)
#endif

#define NLMSG_TAIL(nmsg) \
    ((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

#ifndef NDA_RTA
#define NDA_RTA(r) \
    ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ndmsg))))
#endif

struct req {
    struct nlmsghdr n;
    struct ndmsg ndm;
    char buf[256];
};

int netif_get_ifindex(const char *ifname) {
    int sockfd;
    struct ifreq ifr;

    sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if(-1 == sockfd) {
        return -1;
    }

    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
    if(ioctl(sockfd, SIOCGIFINDEX, &ifr, sizeof(ifr))) {
        close(sockfd);
        return -1;
    }
    close(sockfd);

    return ifr.ifr_ifindex;
}

int addattr_l(struct nlmsghdr *n, int maxlen, int type, const void *data,
        int alen)
{
    int len = RTA_LENGTH(alen);
    struct rtattr *rta;

    if(NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen) {
        fprintf(stderr, "%s error: message exceeded bound of %d\n",
                __FUNCTION__, maxlen);
        return -1;
    }

    rta = NLMSG_TAIL(n);
    rta->rta_type = type;
    rta->rta_len = len;
    memcpy(RTA_DATA(rta), data, alen);
    n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
    return 0;
}

int addattr32(struct nlmsghdr *n, int maxlen, int type, uint32_t data)
{
    return addattr_l(n, maxlen, type, &data, sizeof(uint32_t));
}

void fparse_msg(FILE *f, struct msghdr *msg, int status) {
    struct nlmsghdr *h;
    char *buf = msg->msg_iov->iov_base;

    for(h = (struct nlmsghdr*)buf; status >= sizeof(*h); ) {
        int len = h->nlmsg_len;
        int l = len - sizeof(*h);

        if(NLMSG_ERROR == h->nlmsg_type) {
            struct nlmsgerr *err = (struct nlmsgerr*)NLMSG_DATA(h);
            if(l < sizeof(*err)) {
                fprintf(f, "ERROR truncated\n");
            } else {
                if (!err->error) {
                    fprintf(f, "ERROR: success\n");
                    return;
                }
                fprintf(f, "RTNETLINK answers: %s\n", strerror(-err->error));
                errno = -err->error;
            }
        }

        status -= NLMSG_ALIGN(len);
        h = (struct nlmsghdr*)(((char*)h) + NLMSG_ALIGN(len));
    }
}

int main(int argc, char **argv) {
    int skt, ret;
    struct req req;
    struct msghdr msg;
    struct sockaddr_nl nladdr;
    struct iovec iov;
    char *ifname = "br0", *via = "eth0";
    struct ether_addr ethaddr, *paddr;
    char buffer[1024];

    paddr = ether_aton("0:1:2:3:4:5");
    if(NULL == paddr) {
        return -1;
    }
    memcpy(&ethaddr, paddr, sizeof(ethaddr));

    memset(&req, 0, sizeof(req));

    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(req.ndm));
    req.n.nlmsg_flags = NLM_F_REQUEST|NLM_F_CREATE|NLM_F_EXCL;
    req.n.nlmsg_type = RTM_NEWNEIGH;
    req.ndm.ndm_family = PF_BRIDGE;
    req.ndm.ndm_state = NUD_REACHABLE | NUD_NOARP;
    /** this might be the interface that is a port within the bridge */
    //req.ndm.ndm_ifindex = netif_get_ifindex(ifname);
    req.ndm.ndm_ifindex = netif_get_ifindex(via);

    addattr_l(&req.n, sizeof(req), NDA_LLADDR, &ethaddr, ETH_ALEN);

    memset(&nladdr, 0, sizeof(nladdr));
    nladdr.nl_family = AF_NETLINK;
    nladdr.nl_pid = 0;
    nladdr.nl_groups = 0;

    iov.iov_base = &req.n;
    iov.iov_len = req.n.nlmsg_len;

    req.ndm.ndm_flags |= NTF_SELF;

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &nladdr;
    msg.msg_namelen = sizeof(nladdr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    skt = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
    if(-1 == skt) {
        perror("socket");
        return -1;
    }

    ret = sendmsg(skt, &msg, 0);
    fprintf(stderr, "sendmsg returned %d\n", ret);
    if(ret < 0) {
        perror("sendmsg");
    }

    iov.iov_base = buffer;
    iov.iov_len = sizeof(buffer);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    ret = recvmsg(skt, &msg, 0);
    fprintf(stderr, "recvmsg returned %d\n", ret);
    fparse_msg(stderr, &msg, ret);

    close(skt);
    return 0;
}
