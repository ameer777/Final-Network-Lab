#include <stdlib.h>
#include <stdio.h> 
#include <sys/socket.h>
#include <string.h>
#include <netinet/in.h> 
#include <sys/types.h>
#include <arpa/inet.h>

#define SRC_IP "10.9.0.1"
#define DEST_IP "8.8.8.8"

/* ip */
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


/* tcp */
  typedef u_int tcp_seq;

struct sniff_tcp {
    u_short th_sport;  /* source port */
    u_short th_dport;  /* destination port */
    tcp_seq th_seq;    /* sequence number */
    tcp_seq th_ack;    /* acknowledgement number */
    u_char th_offx2;  /* data offset, rsvd */
  #define TH_OFF(th)  (((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
  #define TH_FIN 0x01
  #define TH_SYN 0x02
  #define TH_RST 0x04
  #define TH_PUSH 0x08
  #define TH_ACK 0x10
  #define TH_URG 0x20
  #define TH_ECE 0x40
  #define TH_CWR 0x80
  #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;    /* window */
    u_short th_sum;    /* checksum */
    u_short th_urp;    /* urgent pointer */
};

int main()
{
    int sd;
    struct sockaddr_in sin;
    char buffer[1024];
    const char *opt = "enp0s3";
    const int len = strnlen(opt, 6);
    
    struct sniff_ip *ip = (struct sniff_ip *) buffer;
    struct sniff_tcp *tcp = (struct sniff_tcp *) (buffer + sizeof(struct sniff_ip));
    char *data = buffer + sizeof(struct sniff_ip) + sizeof(struct sniff_tcp);

    sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sd < 0) {
        exit(-1);
    }

    sin.sin_family = AF_INET;
    ip->ip_vhl = (4 << 4) | (20 >> 2);
    ip->ip_tos = 0;
    ip->ip_src.s_addr = inet_addr(SRC_IP);
    ip->ip_dst.s_addr = inet_addr(DEST_IP);
    ip->ip_id = htons(87654);
    ip->ip_off = 0;
    ip->ip_ttl = 50;
    ip->ip_len = 50;
    ip->ip_p = IPPROTO_TCP;
    ip->ip_sum = 0;

    tcp->th_sport = htons(8000);
    tcp->th_dport = htons(9000);
    tcp->th_seq = htonl(1);
    tcp->th_ack = 0;
    tcp->th_offx2 = 20;
    tcp->th_flags = TH_FIN;
    tcp->th_ack = 0;
    tcp->th_win = htons(32767);
    tcp->th_sum = 0;
    tcp->th_urp = 0;
    
    strcpy(data , "tcp message");

    if (sendto(sd, buffer, ip->ip_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        exit(-1);
    }
}