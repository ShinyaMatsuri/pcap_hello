#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include "Protocol/all.h"

void printPacket(const unsigned char *p, uint32_t size)
{
    puts("DATA\n===========================");
    for (int i = 1; i <= size; i++)
    {
        printf("%02X ", p[i - 1]);
        if (!(i % 8))
        {
            if (!(i % 16))
                puts("");
            else
                printf(" ");
        }
    }
    puts("\n===========================");
    for (int i = 1; i <= size; i++)
    {
        printf("%c", p[i - 1] >= 32 && p[i - 1] <= 126 ? p[i - 1] : '.');
        if (!(i % 8))
        {
            if (!(i % 16))
                puts("");
            else
                printf(" ");
        }
    }
    puts("\n===========================");
}

void printMACAddress(mac_addr mac)
{
    printf("%02X:%02X:%02X:%02X:%02X:%02X\n", mac.oui[0], mac.oui[1], mac.oui[2], mac.nic[0], mac.nic[1], mac.nic[2]);
}