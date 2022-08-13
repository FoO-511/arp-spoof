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

EthArpPacket gen_arp_req(Mac smac_, Ip sip_, Ip tip_);
Mac get_arp_reply_mac(const u_char *packet, Mac dmac_, Ip sip_, Ip tip_);
Mac get_mac_via_arp(pcap_t *pcap, Mac myMac, Ip myIp, Ip tip_);