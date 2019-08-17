#pragma once
#include "main.h"


int checkSourceMac(const u_char* packet, uint8_t *MAC);

int checkDestMAC(const u_char* packet, uint8_t *MAC);

int checkTargetIP(const u_char * packet, uint8_t *IP);

int checkSourceIP(const u_char * packet, uint8_t *IP);

int checkARP(const u_char * recv_pack, uint8_t *senderIP, uint8_t *targetIP);

void spoofHeader(uint8_t *packet, uint8_t *DestMac, uint8_t *SourceMac);

void makeARPpacket(uint8_t *packbuf, uint8_t *DestMAC, uint8_t *SourceMac, uint16_t type, uint8_t *SenderMac, uint8_t *TargetMac, uint8_t *Senderip, uint8_t *Targetip);

void sendPacket(pcap_t *fp, uint8_t *packet, int length);

