#include <stdio.h>
#include <pcap.h>
#include <stdint.h>
#define ETH_ALEN 6

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
        printf("%u bytes captured\n",header->caplen);
        int i=0;
        while(1) {
            printf("%02x",eth->src[i]);
            if(i>4) {printf("\n"); break;}
            printf(":");
            i++;
        }
    }

    pcap_close(handle);
    return 0;
}
