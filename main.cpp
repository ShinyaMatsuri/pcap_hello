#include <stdio.h>
#include <pcap.h>
#include <stdint.h>
#include <arpa/inet.h>
#include "Protocol/all.h"
#include "packet.h"

#define MAC_LENGTH 6
#define IPV4_LENGTH 4

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
                uint32_t tcp_size = (ntohs(ips->ip_len) - ((ips->ip_hl + tcps->th_off) * 4));
                if (tcp_size > 0)
                    printPacket(packet + packetIndex, tcp_size);
                const u_char *data = (u_char *)(packet + packetIndex);
                packetIndex += sizeof(u_char);
                uint dlen = (ntohs(ips->ip_len) - ((ips->ip_hl + tcps->th_off) * 4));
                if(dlen) {
                    if(http_check) printHTTP(data);
                }
            }
            else if (ips->ip_p == IPPROTO_UDP)
            {
                const udp_header *udps = (udp_header *)(packet + packetIndex);
                packetIndex += sizeof(udp_header);

                printf("UDP SRC PORT : %u\n", ntohs(udps->uh_sport));
                printf("UDP DEST PORT : %u\n", ntohs(udps->uh_dport));
                uint32_t udp_size = (ntohs(ips->ip_len) - sizeof(ip_header) - sizeof(udp_header));
                if (udp_size > 0) printPacket(packet + packetIndex, udp_size);
            }
            else if(ips->ip_p == 1) {
                const icmp_header *icm = (icmp_header *)(packet + packetIndex);
                packetIndex += sizeof(icmp_header);
        
                uint32_t icmp_size = (ntohs(ips->ip_len) - sizeof(ip_header) - sizeof(icmp_header));
                printf("ICMP Type : %u\n", icm->type);
                printf("ICMP Code : %u\n", icm->code);
                printf("ICMP Checksum : 0x%X\n", icm->checksum);
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
