#include "main.h"


void get_my_MAC(uint8_t *mac){
    struct ifreq ifr;
    struct ifconf ifc;
    char buf[1024];
    int success = 0;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1) { /* handle error*/ };

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) { /* handle error */ }

    struct ifreq* it = ifc.ifc_req;
    const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

    for (; it != end; ++it) {
        strcpy(ifr.ifr_name, it->ifr_name);
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
            if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
                if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                    success = 1;
                    break;
                }
            }
        }
        else { /* handle error */ }
    }

    if (success) memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);

}


void getIP(char *str, uint8_t *ip){
    sscanf(str,"%u.%u.%u.%u",&ip[0],&ip[1],&ip[2],&ip[3]);  //get ip from argv
}


void get_my_IP(char *str, uint8_t *myIP){
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    int status = pcap_findalldevs(&alldevs, errbuf);

    if(status != 0)
    {
        printf("%s\n", errbuf);
    }

    for(pcap_if_t *d=alldevs; d!=NULL; d=d->next)
    {
        if(strcmp(d->name, str) == 0){
            for(pcap_addr_t *a=d->addresses; a!=NULL; a=a->next)
             {
                    if(a->addr->sa_family == AF_INET)
                    {
                        sscanf(inet_ntoa((reinterpret_cast<struct sockaddr_in*>(a->addr))->sin_addr),"%u.%u.%u.%u",&myIP[0],&myIP[1],&myIP[2],&myIP[3]);
                    }
             }
            break;
        }
    }
    pcap_freealldevs(alldevs);
}
