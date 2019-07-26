#include <stdio.h>
#include <pcap.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>

#include "Protocol/all.h"
#include "packet.h"

#define MAC_LENGTH 6
#define IPV4_LENGTH 4

const char *HTTP_METHOD_HTTP = "HTTP";
const char *HTTP_METHOD_GET = "GET";
const char *HTTP_METHOD_POST = "POST";
const char *HTTP_METHOD_PUT = "PUT";
const char *HTTP_METHOD_DELETE = "DELETE";
const char *HTTP_METHOD_CONNECT = "CONNECT";
const char *HTTP_METHOD_OPTIONS = "OPTIONS";
const char *HTTP_METHOD_TRACE = "TRACE";
const char *HTTP_METHOD_PATCH = "PATCH";

const void *H_METHOD[9] =
{
    HTTP_METHOD_HTTP,
    HTTP_METHOD_GET,
    HTTP_METHOD_POST,
    HTTP_METHOD_PUT,
    HTTP_METHOD_DELETE,
    HTTP_METHOD_CONNECT,
    HTTP_METHOD_OPTIONS,
    HTTP_METHOD_TRACE,
    HTTP_METHOD_PATCH
};
/*
bool checkHTTPMethod(const uint8_t *data, const char *httpMethod, uint32_t size)
{
    int httpMethodSize = strlen(httpMethod);
    if(size <= httpMethodSize) return false;
    return memcmp(data, httpMethod, httpMethodSize) == 0;
}

bool is HTTPProtocol(const uint8_t *p, uint32_t size)
{
    for(int i = 0; i < (sizeof(H_METHOD) / sizeof(void *)); i++) {
        bool isFind = checkHTTPMethod(p, (const char *)H_METHOD[i], size);
        if(isFind) return isFind;
    }
    return false;
}
*/
bool http_check(const u_char *DATA)
{
    for(int i = 0; i < 9; i++) {
        if(!strncmp((const char *)DATA, (const char *)H_METHOD[i], strlen((const char *)H_METHOD[i]))) {
            printf("%s/",(const char *)H_METHOD[i]);
            return true;
        }
    }
    return false;
}


void usage()
{
    printf("syntax: pcap_test <interface>\n");
    printf("smaple: pcap_test wlan0\n");
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        usage();
        return -1;
    }

    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    while (1)
    {
        struct pcap_pkthdr *header;
        const u_char *packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (!res)
            continue;
        if (res == -1 || res == -2)
            break;

        int packetIndex = 0;
        const ether_header *eth = (ether_header *)packet;
        packetIndex += sizeof(ether_header);
        int i = 0;
        printf("%u bytes captured\n", header->caplen);
        printMACAddress(eth->dst);
        printf("\n");
        printMACAddress(eth->src);
        printf("\n");
        if (ntohs(eth->ether_type) == ETHERTYPE_IPV4)
        {
            const ip_header *ips = (ip_header *)(packet + packetIndex);
            packetIndex += sizeof(ip_header);

            printf("[SMAC_IP] ");
            i = 0;
            while (1)
            {
                printf("%u", ips->ip_src[i]);
                if (i > 2)
                    break;
                printf(".");
                i++;
            }
            printf("  ->  [DMAC_IP] ");
            i = 0;
            while (1)
            {
                printf("%u", ips->ip_dst[i]);
                if (i > 2)
                {
                    printf("\n");
                    break;
                }
                printf(".");
                i++;
            }
            printf("IPv4\n");
            if (ips->ip_p == IPPROTO_TCP)
            {
                const tcp_header *tcps = (tcp_header *)(packet + packetIndex);
                packetIndex += sizeof(tcp_header);

                printf("TCP SRC PORT : %u\n", tcps->th_sport);
                printf("TCP DEST PORT : %u\n", tcps->th_dport);
                uint32_t tcp_size = tcps->th_off * 4;

                const u_char *data = (u_char *)(packet + packetIndex);
                uint dlen = (ntohs(ips->ip_len) - ((ips->ip_hl + tcps->th_off) * 4));
                if(dlen) {
                    if(http_check(data)) printHTTP(data);
                    else printPacket(data, dlen);
                }
            }
            else if (ips->ip_p == IPPROTO_UDP)
            {
                const udp_header *udps = (udp_header *)(packet + packetIndex);
                packetIndex += sizeof(udp_header);

                printf("UDP SRC PORT : %u\n", ntohs(udps->uh_sport));
                printf("UDP DEST PORT : %u\n", ntohs(udps->uh_dport));

                const u_char *data = (u_char *)(packet + packetIndex);
                uint dlen = (ntohs(ips->ip_len) - ips->ip_hl * 4 - sizeof(udp_header));
                if(dlen) printPacket(data, dlen);
            }
            else if(ips->ip_p == IPPROTO_ICMP) {
                const icmp_header *icm = (icmp_header *)(packet + packetIndex);
                packetIndex += sizeof(icmp_header);
        
                printf("ICMP Type : %u\n", icm->type);
                printf("ICMP Code : %u\n", icm->code);
                printf("ICMP Checksum : 0x%X\n", icm->checksum);

                const u_char *data = (u_char *)(packet + packetIndex);
                uint dlen = (ntohs(ips->ip_len) - ips->ip_hl * 4 - sizeof(icmp_header));
                if(dlen) printPacket(data, dlen);
            }
        }
        else if (ntohs(eth->ether_type) == ETHERTYPE_ARP)
        {
            printf("ARP\n");
            const arp_header *arps = (arp_header *)(packet + packetIndex);
            packetIndex += sizeof(arp_header);
            printMACAddress(arps->sender_mac);
            printMACAddress(arps->target_mac);
        }
        else if (ntohs(eth->ether_type) == ETHERTYPE_IPV6) printf("IPv6\n");
    }

    pcap_close(handle);
    return 0;
}
