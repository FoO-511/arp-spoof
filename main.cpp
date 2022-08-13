#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "arp.h"

void usage()
{
	printf("syntax: arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
	printf("sample: arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

int main(int argc, char *argv[])
{
	if (argc < 4 || argc % 2 != 0)
	{
		usage();
		return -1;
	}

	char *interface = argv[1];
	char *sender_ip = argv[2];
	char *target_ip = argv[3];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_live(interface, 0, 0, 0, errbuf);
	if (handle == nullptr)
	{
		fprintf(stderr, "couldn't open device %s(%s)\n", interface, errbuf);
		return -1;
	}

	Mac random_mac_;
	random_mac_ = random_mac_.randomMac();

	std::string str = std::string(random_mac_);
	printf("%s\n", str.c_str());

	EthArpPacket packet;

	packet.eth_.dmac_ = Mac("00:00:00:00:00:00");
	/* 나중에 본인 맥 자동으로 가져오는 부분 구현할  것 */
	packet.eth_.smac_ = Mac("00:0c:29:95:fd:64");
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac("00:00:00:00:00:00");
	packet.arp_.sip_ = htonl(Ip("0.0.0.0"));
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(Ip("0.0.0.0"));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&packet), sizeof(EthArpPacket));
	if (res != 0)
	{
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	pcap_close(handle);
}
