#include "arp.h"

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