#pragma once

#include "pch.h"
#include "ethhdr.h"
#include "arphdr.h"
#include "iphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final
{
    EthHdr eth_;
    ArpHdr arp_;
};

struct EthIpPacket final
{
    EthHdr eth_;
    IpHdr ip_;
};

struct ArpReqs
{
    Mac smac_;
    Mac tmac_;
    Ip sip_;
    Ip tip_;

    ArpReqs() {}
    ArpReqs(Mac smac, Mac tmac, Ip sip, Ip tip)
    {
        smac_ = smac;
        tmac_ = tmac;
        sip_ = sip;
        tip_ = tip;
    }
};

struct ArpTArgs
{
    pcap_t *pcap_;
    ArpReqs arpReqs_;
    Mac retMac_;

    ArpTArgs(){};
    ArpTArgs(pcap_t *pcap, ArpReqs arpReqs)
    {
        pcap_ = pcap;
        arpReqs_ = arpReqs;
    }
};

struct ArpSpoofReqs
{
    ArpReqs arpReqs_;
    Mac myMac_;
    Ip myIp_;
    char *interface_;
};

#pragma pack(pop)

EthArpPacket gen_arp_req(Mac smac_, Ip sip_, Ip tip_);
EthArpPacket gen_arp_reply(Mac smac_, Mac tmac_, Ip sip_, Ip tip_);

Mac get_arp_reply_mac(const u_char *packet, Mac dmac_, Ip sip_, Ip tip_);

Mac get_mac_via_arp(pcap_t *pcap, Mac myMac, Ip myIp, Ip tip_);
void *t_get_mac_via_arp(void *argv);

int send_arp_reply(pcap_t *pcap, EthArpPacket packet);
void *t_send_arp_replys(void *argv);

int arp_reply_to_req(const u_char *packet);
int relay_ip_packet(const u_char *packet);

int arp_spoof(ArpSpoofReqs arpSpoofReqs);
void *t_arp_spoof(void *argv);