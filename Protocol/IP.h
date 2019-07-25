#pragma once
#include <stdint.h>

struct ip_addr
{
    uint8_t a;
    uint8_t b;
    uint8_t c;
    uint8_t d;
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