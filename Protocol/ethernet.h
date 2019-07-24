#pragma once
#include <stdint.h>

#define ETHERTYPE_IPV4 0x0800 //IPv4
#define ETHERTYPE_ARP 0x0806 //ARP
#define ETHERTYPE_IPV6 0x08dd //IPv6
#define ETHERTYPE_REVARP 0x8035 //Reverse ARP
#define ETHERTYPE_AT 0x8098 //AppleTalk protocol
#define ETHERTYPE_LOOPBACK 0x9000 //used to test interfaces

#define ETH_ALEN 6



struct mac_addr
{
    uint8_t oui[3];
    uint8_t nic[3];
};

struct ether_header
{
    mac_addr dst;
    mac_addr src;
    uint16_t ether_type;
} __attribute__ ((__packed__));
