#include <pcap.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h> 
#include <string.h>

#define ECHO_REPLY 0

struct sniff_icmp {
    u_char type;
    u_char code;
    u_short checksum;
    u_short id;
    u_short seq;
};

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN  6

  /* Ethernet header */
struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
};

 /* IP header */
struct sniff_ip {
    u_char ip_vhl;    /* version << 4 | header length >> 2 */
    u_char ip_tos;    /* type of service */
    u_short ip_len;    /* total length */
    u_short ip_id;    /* identification */
    u_short ip_off;    /* fragment offset field */
  #define IP_RF 0x8000    /* reserved fragment flag */
  #define IP_DF 0x4000    /* don't fragment flag */
  #define IP_MF 0x2000    /* more fragments flag */
  #define IP_OFFMASK 0x1fff  /* mask for fragmenting bits */
    u_char ip_ttl;    /* time to live */
    u_char ip_p;    /* protocol */
    u_short ip_sum;    /* checksum */
    struct in_addr ip_src,ip_dst; /* source and dest address */
};
  #define IP_HL(ip)    (((ip)->ip_vhl) & 0x0f)
  #define IP_V(ip)    (((ip)->ip_vhl) >> 4)

// function for calculating checksum for the packet to be sent
unsigned short csum(unsigned short *ptr,int nbytes) 
{
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;

    return(answer);
}

// this function is getting the data + headers and creating a new packet to be spoofed as ping
void ping(struct in_addr src_ip, struct in_addr dst_ip, char *recv_data, int data_len, u_short id, u_short seq)
{
    // creating vars for the packet
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

    memcpy(data, recv_data, data_len);

    sin.sin_family = AF_INET;
    // filling ip values
    ip->ip_len = 100;
    ip->ip_id = htons(43231);
    ip->ip_ttl = 255;
    ip->ip_vhl = (4 << 4) | (20 >> 2);
    ip->ip_p = IPPROTO_ICMP;
    ip->ip_src = src_ip;
    ip->ip_dst = dst_ip;
    // filling icmp values
    icmp->code = 0;
    icmp->type = ECHO_REPLY;
    icmp->id = id;
    icmp->seq = seq;
    icmp->checksum = 0;
    icmp->checksum = csum((unsigned short *)icmp, sizeof(struct sniff_icmp) + data_len);


    // send the data to the network
    if (sendto(sd, buffer, ip->ip_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        exit(-1);
    }
}

// this function is called when packet is recieved
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct sniff_ip *ip = (struct sniff_ip *)(packet + sizeof(struct sniff_ethernet));
    struct sniff_icmp *icmp = (struct sniff_icmp *)(packet + sizeof(struct sniff_ethernet) + sizeof(struct sniff_ip));
    char *data = (u_char *)packet + sizeof(struct sniff_ethernet) + sizeof(struct sniff_ip) + sizeof(struct sniff_icmp);
    int data_len = ntohs(ip->ip_len) - (sizeof(struct sniff_ip)) - sizeof(struct sniff_icmp);

    if (ip->ip_p == 1) {
        if (icmp->type == 8) {
            printf("Got a packet\n");
            printf("source IP: %s\n", inet_ntoa(ip->ip_src));
            printf("destination IP:  %s\n", inet_ntoa(ip->ip_dst));
            printf("protocol:  %d\n", (ip->ip_p));

            ping(ip->ip_dst, ip->ip_src, data, data_len, icmp->id, icmp->seq);
        }
    }
}


int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "ip proto icmp";
    bpf_u_int32 net;

    // Step 1: Open live pcap session
    handle = pcap_open_live("br-b0536f20c0fc", BUFSIZ, 1, 1000, errbuf);

    // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);

    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle); //Close the handle
    return 0;
}