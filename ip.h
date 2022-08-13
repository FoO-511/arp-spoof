#pragma once

#include <cstdint>
#include <string>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>

struct Ip final
{
	static const int SIZE = 4;

	// constructor
	Ip() {}
	Ip(const uint32_t r) : ip_(r) {}
	Ip(const std::string r);

	// casting operator
	operator uint32_t() const { return ip_; } // default
	explicit operator std::string() const;

	// comparison operator
	bool operator==(const Ip &r) const { return ip_ == r.ip_; }

	bool isLocalHost() const
	{ // 127.*.*.*
		uint8_t prefix = (ip_ & 0xFF000000) >> 24;
		return prefix == 0x7F;
	}

	bool isBroadcast() const
	{ // 255.255.255.255
		return ip_ == 0xFFFFFFFF;
	}

	bool isMulticast() const
	{ // 224.0.0.0 ~ 239.255.255.255
		uint8_t prefix = (ip_ & 0xFF000000) >> 24;
		return prefix >= 0xE0 && prefix < 0xF0;
	}

	Ip getMyIp()
	{
		struct ifreq s;
		int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

		strcpy(s.ifr_name, "eth0");
		if (0 == ioctl(fd, SIOCGIFHWADDR, &s))
		{
			int i;
			for (i = 0; i < 6; ++i)
				printf(" %02x", (unsigned char)s.ifr_addr.sa_data[i]);
			puts("\n");
		}
		return Ip("0.0.0.0");
	}

protected:
	uint32_t ip_;
};
