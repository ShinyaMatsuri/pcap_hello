#pragma once
#include <stdint.h>
#include "ethernet.h"
#include "IP.h"
#define ARPHRD_ETHER 1 //Ethernet 10/100Mbps

#define ARPOP_REQUEST 1 //ARP request
#define ARPOP_REPLY 2 //ARP reply
#define ARPOP_RRQUEST 3 //RARP request
#define ARPOP_RREPLY 4 //RARP reply
#define ARPOP_InREQUEST 8 //InARP request
#define ARPOP_InREPLY 9 //InARP reply
#define ARPOP_NAK 10 //ARP NAK

#define ARPPRO_IPV4 0x0800

struct __attribute__((aligned(1),packed)) arp_header
{
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_size;
    uint8_t protocol_size;
    uint16_t opcode;

    mac_addr sender_mac;
    ip_addr sender_ip;
    mac_addr target_mac;
    ip_addr target_ip;
};