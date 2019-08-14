#pragma once
#include <cstdint>



typedef struct ETHheader {
    uint8_t destMac[6];
    uint8_t srcMac[6];
    uint16_t type;
} eth_header;

typedef struct arp {
    uint16_t hardware_type;
    uint16_t protocol_type;

    uint8_t hardware_addr_len;
    uint8_t protocol_addr_len;

    uint16_t operation;

    uint8_t Sender_Mac[6];
    uint8_t Sender_Ip[4];

    uint8_t Target_Mac[6];
    uint8_t Target_Ip[4];
} arp_header;

typedef struct pack{
    eth_header eth;
    arp_header arp;
} packet;

typedef struct _session{
    uint8_t targetIP[4];
    uint8_t targetMAC[6];

    uint8_t senderIP[4];
    uint8_t senderMAC[6];
} session;
