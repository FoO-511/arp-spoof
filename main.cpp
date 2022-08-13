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
	pcap_t *pcap = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf); // BUFSIZ 8192
	if (pcap == nullptr)
	{
		fprintf(stderr, "couldn't open device %s(%s)\n", interface, errbuf);
		return -1;
	}

	Mac myMac = Mac("00:93:37:BF:F8:A1"); // host's mac
	Ip myIp = Ip("10.1.1.109");			  // vm's ip
	Mac smac, tmac;
	Ip sip = Ip(sender_ip);
	Ip tip = Ip(target_ip);

	smac = get_mac_via_arp(pcap, myMac, myIp, sip);
	printf("sender mac:  %s\n", std::string(smac).c_str());
	tmac = get_mac_via_arp(pcap, myMac, myIp, tip);
	printf("target mac:  %s\n", std::string(tmac).c_str());

	pcap_close(pcap);
}
