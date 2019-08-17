#include "main.h"

int checkDestMAC(const u_char* packet, uint8_t *MAC){
    if(memcmp(packet,MAC,6)==0) return 1;
    return 0;
}

int checkSourceMac(const u_char* packet, uint8_t *MAC){
    if(memcmp(packet+6, MAC, 6) == 0) return 1;
    return 0;
}

int checkTargetIP(const u_char * packet, uint8_t *IP){
    if(memcmp(packet+14+24, IP, 4) == 0) return 1;
    return 0;
}

int checkSenderIP(const u_char * packet, uint8_t *IP){
    if(memcmp(packet+14+14, IP, 4) == 0) return 1;
    return 0;
}


int checkARP(const u_char * recv_pack, uint8_t *senderIP, uint8_t *targetIP){

    if(recv_pack[12] == 0x08 && recv_pack[13] == 0x06){

        if(checkSenderIP(recv_pack, targetIP) == 1){
            if(checkTargetIP(recv_pack, senderIP) == 1){
               return 2;
            }
        }
        return 1;
    }
    return 0;
}

void spoofHeader(uint8_t *packet, uint8_t *DestMac, uint8_t *SourceMac){
    memcpy(packet, DestMac , 6);
    memcpy(packet+6, SourceMac, 6);
}


void makeARPpacket(uint8_t *packbuf, uint8_t *DestMAC, uint8_t *SourceMac, uint16_t opcode, uint8_t *SenderMac, uint8_t *TargetMac, uint8_t *Senderip, uint8_t *Targetip){
    packet arp_packet;
    int length;
    memcpy(arp_packet.eth.srcMac, SourceMac, 6);           //src : me
    memcpy(arp_packet.eth.destMac, DestMAC, 6);//"\xFF\xFF\xFF\xFF\xFF\xFF",6);  //dest : broadcast
    arp_packet.eth.type = htons(0x0806);	//arp

    arp_packet.arp.hardware_type = htons(1);       // hardware_type 1 : Ethernet
    arp_packet.arp.protocol_type = htons(0x0800);  // protocol_type 0x0800 : IPv4
    arp_packet.arp.hardware_addr_len = 6;          // MAC len = 6
    arp_packet.arp.protocol_addr_len = 4;             // IP len =4


    arp_packet.arp.operation=htons(opcode);             //opcode = 1: request

    memcpy(arp_packet.arp.Sender_Mac, SenderMac,6);
    memcpy(arp_packet.arp.Target_Mac, TargetMac,6);


    memcpy(arp_packet.arp.Sender_Ip, Senderip, 4);
    memcpy(arp_packet.arp.Target_Ip, Targetip, 4);

    length = sizeof(arp_packet);
    memcpy(packbuf, &arp_packet, length);
}


void sendPacket(pcap_t *fp, uint8_t *packet, int length){

    if ((pcap_sendpacket(fp, packet, length)) != 0) {
        fprintf(stderr, "Error sending packet: %s / packet size : %d\n", pcap_geterr(fp), length);
    }

}


