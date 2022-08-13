#pragma once

#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final
{
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

EthArpPacket *get_mac_with_ip()
{
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac("00:00:00:00:00:00");
    packet.eth_.smac_ = Mac();
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
}