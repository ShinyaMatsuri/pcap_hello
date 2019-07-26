#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include "Protocol/all.h"

void printPacket(const unsigned char *p, uint32_t size)
{
    int i = 1;
    puts("DATA\n===============================================================================");
    for (; i <= size; i++) {
        printf("%02X ", p[i - 1]);
        if (!(i % 8)) {
            if (!(i % 16)) {
                printf("        ");
                for (int j = i-15; j <= i; j++) {
                    printf("%c", p[j - 1] >= 32 && p[j - 1] <= 126 ? p[j - 1] : '.');
                    if (!(j % 8)) {
                        if (!(j % 16)) puts("");
                        else printf(" ");
                    }
                }
                puts("");
            }
            else
                printf(" ");
        }
    }
    if(size%16) {
        printf("     ");
        if((16-size%16)/8) printf(" ");
        for(int j = size % 16; j <= 16; j++) printf("   ");
        i -= size % 16;
        for(; i <= size; i++) {
            printf("%c", p[i - 1] >= 32 && p[i - 1] <= 126 ? p[i - 1] : '.');
            if(!(i % 8)) {
                if(!(i % 16)) puts("");
                else printf(" ");
            }
        }
    }
    puts("\n===============================================================================");
}

void printMACAddress(mac_addr mac)
{
    printf("%02X:%02X:%02X:%02X:%02X:%02X\n", mac.oui[0], mac.oui[1], mac.oui[2], mac.nic[0], mac.nic[1], mac.nic[2]);
}

void printHTTP(const u_char *DATA)
{
    puts("HTTP_DATA\n===============================================================================");
    puts((char*)DATA);
    puts("\n===============================================================================");
}