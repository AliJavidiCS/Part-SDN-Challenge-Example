#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define BUF_SIZE 1600

// Checksum calculation 
// Check out this link: https://en.wikipedia.org/wiki/Internet_checksum

unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    for (; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

// Creat the TUN interface
int tun_alloc(char *dev) {
    struct ifreq ifr = {0};
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        perror("open /dev/net/tun");
        exit(1);
    }

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (*dev)
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        perror("ioctl(TUNSETIFF)");
        exit(1);
    }

    strcpy(dev, ifr.ifr_name);
    return fd;
}

int main() {
    char if_name[IFNAMSIZ] = "tun0";
    int tun_fd = tun_alloc(if_name);
    char cmd[256];

    // Create the interface and set its IP address
    snprintf(cmd, sizeof(cmd), "ip addr add 10.0.0.1/24 dev %s", if_name);
    system(cmd);
    snprintf(cmd, sizeof(cmd), "ip link set dev %s up", if_name);
    system(cmd);

    printf("Interface %s is up with IP 10.0.0.1\n", if_name);

    unsigned char buf[BUF_SIZE];
    while (1) {
        int nread = read(tun_fd, buf, sizeof(buf));
        if (nread < 0) {
            perror("Reading from tun_fd");
            exit(1);
        }

        struct iphdr *ip = (struct iphdr *)buf;
        if (ip->protocol == IPPROTO_ICMP) {
            struct icmphdr *icmp = (struct icmphdr *)(buf + ip->ihl * 4);

            if (icmp->type == ICMP_ECHO) {
                printf("Got ICMP Echo Request, sending reply\n");

                // Generate Reply packets 
                struct in_addr src, dst;
                src.s_addr = ip->saddr;
                dst.s_addr = ip->daddr;

                ip->saddr = dst.s_addr;
                ip->daddr = src.s_addr;

                icmp->type = ICMP_ECHOREPLY;
                icmp->checksum = 0;
                icmp->checksum = checksum(icmp, nread - ip->ihl * 4);

                ip->check = 0;
                ip->check = checksum(ip, ip->ihl * 4);

                write(tun_fd, buf, nread);
            }
        }
    }

    return 0;
}
