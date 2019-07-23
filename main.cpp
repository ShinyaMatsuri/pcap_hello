#include <stdio.h>
#include <pcap.h>
#include <stdint.h>
#include <arpa/inet.h>

#define ETH_ALEN 6

#define ETHERTYPE_IPV4 0x0800 //IPv4
#define ETHERTYPE_ARP 0x0806 //ARP
#define ETHERTYPE_IPV6 0x08dd //IPv6
#define ETHERTYPE_REVARP 0x8035 //Reverse ARP
#define ETHERTYPE_AT 0x8098 //AppleTalk protocol
#define ETHERTYPE_LOOPBACK 0x9000 //used to test interfaces

typedef uint32_t tcp_seq;
struct tcp_header
{
    __extension__ union
    {
        struct
        {
            uint16_t th_sport; //soource port
            uint16_t th_dport; //destination port
            tcp_seq th_seq; //sequence num
            tcp_seq th_ack; //acknowledgement num

        #if __BYTE_ORDER == __LITTLE_ENDIAN

            uint8_t th_x2 : 4; //unused
            uint8_t th_off : 4; //data offset
        #endif

        #if __BYTE_ORDER == __BIG_ENDIAN
            uint8_t th_off : 4; //data offset
            uint8_t th_x2 : 4; //unused
        #endif

            uint8_t th_flags;

        #define TH_FIN 0x01
        #define TH_SYN 0x02
        #define TH_RST 0x04
        #define TH_PUSH 0x08
        #define TH_ACK 0x10
        #define TH_URG 0x20

            uint16_t th_win; //window
            uint16_t th_sum; //chksum
            uint16_t th_urp; //urgent pointer
        };

        struct
        {
            uint16_t source;
            uint16_t dest;
            uint32_t seq;
            uint32_t ack_seq;

        #if __BYTE_ORDER == __LITTLE_ENDIAN
            uint16_t resl : 4;
            uint16_t doff : 4;
            uint16_t fin : 1;
            uint16_t syn : 1;
            uint16_t rst : 1;
            uint16_t psh : 1;
            uint16_t ack : 1;
            uint16_t urg : 1;
            uint16_t res2 : 2;

        #elif __BYTE_ORDER == __BIG_ENDIAN
            uint16_t doff : 4;
            uint16_t res1 : 4;
            uint16_t res2 : 2;
            uint16_t urg : 1;
            uint16_t ack : 1;
            uint16_t psh : 1;
            uint16_t rst : 1;
            uint16_t syn : 1;
            uint16_t fin : 1;

        #else
        #error "Adjust your <bits/endian.h> defines"
        #endif

            uint16_t window;
            uint16_t check;
            uint16_t urg_ptr;
        };
    };
};

struct ip_header
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint32_t ip_hl : 4; //header len
    uint32_t ip_v : 4; //ver
#endif

#if __BYTE_ORDER == __BIG_ENDIAN
    uint32_t ip_v : 4; //ver
    uint32_t ip_hl : 4; //header len
#endif

    uint8_t ip_tos; //type of service
    uint16_t ip_len; //total len
    uint16_t ip_id; //identification
    uint16_t ip_off; //fragment offset field

#define IP_RF 0x8000 //reversed fragment flag
#define IP_DF 0x4000 //dont fragment flag
#define IP_MF 0x2000 //more fragments flag
#define IP_OFFMASK 0x1fff //mask for fragmenting bits

    uint8_t ip_ttl; //time to live
    uint8_t ip_p; //protocol
    uint16_t ip_sum; //chksum

    uint8_t ip_src[4];
    uint8_t ip_dst[4]; //source and dest addr
};

struct ether_header
{
    uint8_t dst[ETH_ALEN];
    uint8_t src[ETH_ALEN];
    uint16_t ether_type;
} __attribute__ ((__packed__));

void usage() {
    printf("syntax: pcap_test <interface>\n");
    printf("smaple: pcap_test wlan0\n");
}

void _printPacket(const unsigned char *p, uint32_t size)
{
    int len = 0;
    while(len < size) {
        printf("%02X ", *(p++));
        if(!(++len % 16)) printf("\n");
    }
}

void printPacket(const unsigned char *p, const struct pcap_pkthdr *h)
{
    _printPacket(p, h->len);
}

int main(int argc, char* argv[]) {
    if(argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if(handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    while(1) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if(!res) continue;
        if(res == -1 || res == -2) break;

        const ether_header *eth = (ether_header *)packet;
        const ip_header *ips = (ip_header *)(packet + sizeof(ether_header));
        const tcp_header *tcps = (tcp_header *)(packet + sizeof(ether_header) + sizeof(ip_header));

        printf("%u bytes captured\n",header->caplen);
        int i=0;

        if(ntohs(eth->ether_type) == ETHERTYPE_IPV4) printf("IPv4\n");
        else if(ntohs(eth->ether_type) == ETHERTYPE_ARP) printf("ARP\n");
        else if(ntohs(eth->ether_type) == ETHERTYPE_IPV6) printf("IPv6\n");

        printf("[SMAC] ");
        while(1) {
            printf("%02x",eth->src[i]);
            if(i>4) break;
            printf(":");
            i++;
        }
        printf("  ->  [DMAC] ");
        i=0;
        while(1) {
            printf("%02x",eth->dst[i]);
            if(i>4) {printf("\n"); break;}
            printf(".");
            i++;
        }
        printf("[SMAC_IP] ");
        i=0;
        while(1) {
            printf("%u",ips->ip_src[i]);
            if(i>2) break;
            printf(".");
            i++;
        }
        printf("  ->  [DMAC_IP] ");
        i=0;
        while(1) {
            printf("%u",ips->ip_dst[i]);
            if(i>2) {printf("\n"); break;}
            printf(":");
            i++;
        }

        printf("TCP SRC PORT : %u\n", tcps->th_sport);
        printf("TCP DEST PORT : %u\n", tcps->th_dport);
        uint32_t tcp_size = (ntohs(ips->ip_len) - ((ips->ip_hl + tcps->th_off) * 4));
        if(tcp_size > 0) {
            printPacket(packet + sizeof(ether_header) + sizeof(ip_header) + sizeof(tcp_header), tcp_size);
        }
    }

    pcap_close(handle);
    return 0;
}
