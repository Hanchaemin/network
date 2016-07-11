#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#define ETHER_ADDR_LEN	6

const struct sniff_ethernet *ethernet; /* The ethernet header */
const struct sniff_ip *ip; /* The IP header */
const struct sniff_tcp *tcp; /* The TCP header */
const char *payload; /* Packet payload */

    /* Ethernet header */
    struct sniff_ethernet {
        u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
        u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
        u_short ether_type; /* IP? ARP? RARP? etc */
    };

    /* IP header */
    struct sniff_ip {
        u_char ip_vhl;		/* version << 4 | header length >> 2 */
        u_char ip_tos;		/* type of service */
        u_short ip_len;		/* total length */
        u_short ip_id;		/* identification */
        u_short ip_off;		/* fragment offset field */
    #define IP_RF 0x8000		/* reserved fragment flag */
    #define IP_DF 0x4000		/* dont fragment flag */
    #define IP_MF 0x2000		/* more fragments flag */
    #define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
        u_char ip_ttl;		/* time to live */
        u_char ip_p;		/* protocol */
        u_short ip_sum;		/* checksum */
        struct in_addr ip_src,ip_dst; /* source and dest address */
    };
    #define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
    #define IP_V(ip)		(((ip)->ip_vhl) >> 4)

    /* TCP header */
    typedef u_int tcp_seq;

    struct sniff_tcp {
        u_short th_sport;	/* source port */
        u_short th_dport;	/* destination port */
        tcp_seq th_seq;		/* sequence number */
        tcp_seq th_ack;		/* acknowledgement number */
        u_char th_offx2;	/* data offset, rsvd */
    #define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
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
        u_short th_win;		/* window */
        u_short th_sum;		/* checksum */
        u_short th_urp;		/* urgent pointer */
};

struct libnet_ethernet_hdr
{
u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
u_int16_t ether_type;                 /* protocol */
};

struct libnet_ipv4_hdr
{
#if (LIBNET_LIL_ENDIAN)
u_int8_t ip_hl:4,      /* header length */
       ip_v:4;         /* version */
#endif
#if (LIBNET_BIG_ENDIAN)
u_int8_t ip_v:4,       /* version */
       ip_hl:4;        /* header length */
#endif
u_int8_t ip_tos;       /* type of service */
#ifndef IPTOS_LOWDELAY
#define IPTOS_LOWDELAY      0x10
#endif
#ifndef IPTOS_THROUGHPUT
#define IPTOS_THROUGHPUT    0x08
#endif
#ifndef IPTOS_RELIABILITY
#define IPTOS_RELIABILITY   0x04
#endif
#ifndef IPTOS_LOWCOST
#define IPTOS_LOWCOST       0x02
#endif
u_int16_t ip_len;         /* total length */
u_int16_t ip_id;          /* identification */
u_int16_t ip_off;
#ifndef IP_RF
#define IP_RF 0x8000        /* reserved fragment flag */
#endif
#ifndef IP_DF
#define IP_DF 0x4000        /* dont fragment flag */
#endif
#ifndef IP_MF
#define IP_MF 0x2000        /* more fragments flag */
#endif
#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
#endif
u_int8_t ip_ttl;          /* time to live */
u_int8_t ip_p;            /* protocol */
u_int16_t ip_sum;         /* checksum */
struct in_addr ip_src, ip_dst; /* source and dest address */
};

struct libnet_tcp_hdr
{
u_int16_t th_sport;       /* source port */
u_int16_t th_dport;       /* destination port */
u_int32_t th_seq;          /* sequence number */
u_int32_t th_ack;          /* acknowledgement number */
#if (LIBNET_LIL_ENDIAN)
u_int8_t th_x2:4,         /* (unused) */
       th_off:4;        /* data offset */
#endif
#if (LIBNET_BIG_ENDIAN)
u_int8_t th_off:4,        /* data offset */
       th_x2:4;         /* (unused) */
#endif
u_int8_t  th_flags;       /* control flags */
#ifndef TH_FIN
#define TH_FIN    0x01      /* finished send data */
#endif
#ifndef TH_SYN
#define TH_SYN    0x02      /* synchronize sequence numbers */
#endif
#ifndef TH_RST
#define TH_RST    0x04      /* reset the connection */
#endif
#ifndef TH_PUSH
#define TH_PUSH   0x08      /* push data to the app layer */
#endif
#ifndef TH_ACK
#define TH_ACK    0x10      /* acknowledge */
#endif
#ifndef TH_URG
#define TH_URG    0x20      /* urgent! */
#endif
#ifndef TH_ECE
#define TH_ECE    0x40
#endif
#ifndef TH_CWR
#define TH_CWR    0x80
#endif
u_int16_t th_win;         /* window */
u_int16_t th_sum;         /* checksum */
u_int16_t th_urp;         /* urgent pointer */
};

int main(int argc, char *argv[]) {

            pcap_t *handle;			/* Session handle */
            char *dev;			/* The device to sniff on */
            char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
            struct bpf_program fp;		/* The compiled filter */
            char filter_exp[] = "tcp";	/* The filter expression */
            bpf_u_int32 mask;		/* Our netmask */
            bpf_u_int32 net;		/* Our IP */
            struct pcap_pkthdr header;	/* The header that pcap gives us */
            const u_char *packet;		/* The actual packet */
            struct libnet_ethernet_hdr * pEth;    // 이더넷 헤더 *
            struct libnet_ipv4_hdr * pIph;    // IP헤더 *
            struct libnet_tcp_hdr *pTcp;

            /* Define the device */
            dev = pcap_lookupdev(errbuf);
            if (dev == NULL) {
                fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
                return(2);
            }
            /* Find the properties for the device */
            if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
                fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
                net = 0;
                mask = 0;
            }
            /* Open the session in promiscuous mode */
            handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
            if (handle == NULL) {
                fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
                return(2);
            }
            /* Compile and apply the filter */
            if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
                fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
                return(2);
            }
            if (pcap_setfilter(handle, &fp) == -1) {
                fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
                return(2);
            }

            while(1)
            {
            /* Grab a packet */
            packet = pcap_next(handle, &header);
            if(packet ==0)
                continue;

            pEth = (struct libnet_ethernet_hdr *)packet;
            pIph = (struct libnet_ipv4_hdr *)(packet + sizeof(*pEth));
            pTcp = (struct libnet_tcp_hdr *) (packet + sizeof(*pIph)+ sizeof(*pEth));

            /* Print its length */
            //got_packet(dev,&header,packet);
            printf("Jacked a packet with length of [%d]\n", header.len);
            /* And close the session */

            printf("eth.smac : %02X : %02X : %02X : %02X : %02X : %02X \n",pEth->ether_shost[0],pEth->ether_shost[1],pEth->ether_shost[2],pEth->ether_shost[3],pEth->ether_shost[4],pEth->ether_shost[5]);
            printf("eth.dmac : %02X : %02X : %02X : %02X : %02X : %02X \n",pEth->ether_dhost[0],pEth->ether_dhost[1],pEth->ether_dhost[2],pEth->ether_dhost[3],pEth->ether_dhost[4],pEth->ether_dhost[5]);
            printf("ip.sip : %s \n", inet_ntoa(pIph->ip_src));
            printf("ip.dip : %s \n", inet_ntoa(pIph->ip_dst));
            printf("tcp.sport: %u \n", ntohs(pTcp->th_sport));
            printf("tcp.dport: %u \n", ntohs(pTcp->th_dport));
            printf("----------------------------\n");
            }
}


