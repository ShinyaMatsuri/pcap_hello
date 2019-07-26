#pragma once
#include <stdio.h>
#include <pcap.h>
#include <stdint.h>
#include <arpa/inet.h>
#include "Protocol/all.h"

void printPacket(const unsigned char *p, uint32_t size);
void printMACAddress(mac_addr mac);
void printHTTP(const u_char *DATA);