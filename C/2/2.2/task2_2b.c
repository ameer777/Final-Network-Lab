#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h> 
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h> 

#define ECHO_REQUEST 8

#define SRC_IP "1.1.1.1"
#define DEST_IP "10.9.0.5"

struct sniff_ip {
    u_char ip_vhl;		/* version << 4 | header length >> 2 */
    u_char ip_tos;		/* type of service */
    u_short ip_len;		/* total length */
    u_short ip_id;		/* identification */
    u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* don't fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
    u_char ip_ttl;		/* time to live */
    u_char ip_p;		/* protocol */
    u_short ip_sum;		/* checksum */
    struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

struct sniff_icmp {
    u_char type;
    u_char code;
    u_short checksum;
    u_short id;
    u_short seq;
};

int main()
{
    struct sockaddr_in sin;
    int sd = 0;
    char buffer[1024] = {0};
    const char *opt = "br-b0536f20c0fc";
    const int len = strnlen(opt, 20);
    
    struct sniff_ip *ip = (struct sniff_ip *) buffer;
    struct sniff_icmp *icmp = (struct sniff_icmp *) (buffer + sizeof(struct sniff_ip));
    char *data = buffer + sizeof(struct sniff_ip) + sizeof(struct sniff_icmp);

    sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sd < 0) {
        exit(-1);
    }

    setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, opt, len);

    sin.sin_family = AF_INET;

	strcpy(data , "icmp");

    ip->ip_len = 100;
    ip->ip_id = htons(43231);
    ip->ip_ttl = 255;
    ip->ip_vhl = (4 << 4) | (20 >> 2);
    ip->ip_p = IPPROTO_ICMP;
    ip->ip_src.s_addr = inet_addr(SRC_IP);
    ip->ip_dst.s_addr = inet_addr(DEST_IP);

    icmp->code = 0;
    icmp->type = ECHO_REQUEST;
    icmp->id = 20;
    icmp->seq = 20;
    icmp->checksum = 0x2bf9;

    if (sendto(sd, buffer, ip->ip_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        exit(-1);
    }

    return 0;
}