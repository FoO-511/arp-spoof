#pragma once

#include <cstdint>
#include <string>
#include "ip.h"

#pragma pack(push, 1)
struct IpHdr final
{
    uint8_t ihl_ : 4;
    uint8_t version_ : 4;
    uint8_t tos_;
    uint16_t tot_len_;
    uint16_t id_;
    uint16_t frag_off_;
    uint8_t ttl_;
    uint8_t protocol_;
    uint16_t check_;
    Ip sip_;
    Ip dip_;

    // protocol
    enum : uint8_t
    {
        ICMP = 1,
        IGMP = 2,
        TCP = 2,
        IGRP = 9,
        UDP = 17,
        GRE = 47,
        ESP = 50,
        AH = 51,
        SKIP = 57,
        EIGRP = 88,
        OSPF = 89,
        L2TP = 115
    };
};
#pragma push(pop);